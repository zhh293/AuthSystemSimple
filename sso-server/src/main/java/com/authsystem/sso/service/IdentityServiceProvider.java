package com.authsystem.sso.service;

import com.authsystem.sso.config.SsoProperties;
import com.authsystem.sso.contracts.IdentityService;
import com.authsystem.sso.contracts.dto.AuthenticationRequest;
import com.authsystem.sso.contracts.dto.AuthenticationResult;
import com.authsystem.sso.contracts.dto.SessionLookupRequest;
import com.authsystem.sso.contracts.dto.SessionView;
import com.authsystem.sso.domain.StoredSession;
import com.authsystem.sso.domain.UserAccount;
import com.authsystem.sso.storage.AuditRepository;
import com.authsystem.sso.storage.RefreshTokenFamilyRevocationService;
import com.authsystem.sso.storage.UserAccountRepository;
import com.authsystem.sso.observability.SsoMetrics;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.dubbo.config.annotation.DubboService;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

@DubboService(interfaceClass = IdentityService.class, version = "1.0.0")
public class IdentityServiceProvider implements IdentityService {
    private static final String SESSION_PREFIX = "sso:tgc:";
    private static final String LOGIN_PREFIX = "sso:login-attempt:";
    private static final DefaultRedisScript<Long> RATE_LIMIT_SCRIPT = new DefaultRedisScript<>(
            "local a=redis.call('INCR',KEYS[1]); if a==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]); end; "
                    + "local b=redis.call('INCR',KEYS[2]); if b==1 then redis.call('EXPIRE',KEYS[2],ARGV[1]); end; "
                    + "if a>b then return a else return b end", Long.class);
    private final UserAccountRepository users;
    private final AuditRepository audit;
    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final SsoProperties properties;
    private final SsoMetrics metrics;
    private final CredentialAuthenticator credentialAuthenticator;
    private final RefreshTokenFamilyRevocationService refreshTokenFamilies;
    private final SecureRandom random = new SecureRandom();

    public IdentityServiceProvider(UserAccountRepository users, AuditRepository audit, StringRedisTemplate redis,
            ObjectMapper mapper, SsoProperties properties, SsoMetrics metrics,
            CredentialAuthenticator credentialAuthenticator, RefreshTokenFamilyRevocationService refreshTokenFamilies) {
        this.users = users; this.audit = audit; this.redis = redis; this.mapper = mapper;
        this.properties = properties; this.metrics = metrics;
        this.credentialAuthenticator = credentialAuthenticator;
        this.refreshTokenFamilies = refreshTokenFamilies;
    }

    @Override public AuthenticationResult authenticate(AuthenticationRequest request) {
        String address = request == null ? "" : safeAddress(request.getRemoteAddress());
        try {
            return authenticateRequest(request);
        } catch (RuntimeException e) {
            metrics.authentication(SsoMetrics.AuthenticationOutcome.DEPENDENCY_ERROR);
            try {
                audit.record("LOGIN", "IDENTITY_PROVIDER_UNAVAILABLE", null, address, UUID.randomUUID().toString());
            } catch (RuntimeException auditFailure) {
                e.addSuppressed(auditFailure);
            }
            throw new IdentityProviderUnavailableException();
        }
    }

    private AuthenticationResult authenticateRequest(AuthenticationRequest request) {
        String address = request == null ? "" : safeAddress(request.getRemoteAddress());
        String suppliedUsername = request == null || request.getUsername() == null ? "" : request.getUsername();
        String rawPassword = request == null || request.getPassword() == null ? "" : request.getPassword();
        if (suppliedUsername.length() > 128 || rawPassword.length() > 1024) {
            audit.record("LOGIN", "FAILURE", null, address, UUID.randomUUID().toString());
            metrics.authentication(SsoMetrics.AuthenticationOutcome.FAILURE);
            return new AuthenticationResult(false, null, null, 0);
        }
        String username = suppliedUsername.trim().toLowerCase(java.util.Locale.ROOT);
        String throttleKey = LOGIN_PREFIX + hmacHex(properties.getRateLimitHmacKey(), address + "\n" + username);
        String addressThrottleKey = LOGIN_PREFIX + hmacHex(properties.getRateLimitHmacKey(), address);
        Long attempts = redis.execute(RATE_LIMIT_SCRIPT, java.util.List.of(throttleKey, addressThrottleKey), Long.toString(properties.getLoginWindowSeconds()));
        if (attempts == null || attempts > properties.getLoginMaxAttempts()) {
            audit.record("LOGIN", "THROTTLED", null, address, UUID.randomUUID().toString());
            metrics.authentication(SsoMetrics.AuthenticationOutcome.THROTTLED);
            return new AuthenticationResult(false, null, null, 0);
        }
        Optional<UserAccount> candidate = username.isBlank() ? Optional.empty() : users.findByUsername(username);
        boolean passwordMatches;
        boolean accountEnabled;
        passwordMatches = credentialAuthenticator.verify(username, rawPassword, candidate.orElse(null));
        accountEnabled = candidate.isPresent() && candidate.get().enabled()
                && users.isEnabledBySubject(candidate.get().subject());
        if (candidate.isEmpty() || !accountEnabled || !passwordMatches) {
            audit.record("LOGIN", "FAILURE", candidate.filter(UserAccount::enabled).map(UserAccount::subject).orElse(null), address, UUID.randomUUID().toString());
            metrics.authentication(SsoMetrics.AuthenticationOutcome.FAILURE);
            return new AuthenticationResult(false, null, null, 0);
        }
        String cookieValue = randomToken(32);
        long expiresAt = Instant.now().plusSeconds(properties.getSessionTtlSeconds()).getEpochSecond();
        StoredSession session = new StoredSession(candidate.get().subject(), expiresAt);
        String sessionKey = SESSION_PREFIX + digest(cookieValue);
        try {
            redis.opsForValue().set(sessionKey, mapper.writeValueAsString(session), java.time.Duration.ofSeconds(properties.getSessionTtlSeconds()));
            audit.record("LOGIN", "SUCCESS", candidate.get().subject(), address, UUID.randomUUID().toString());
            metrics.authentication(SsoMetrics.AuthenticationOutcome.SUCCESS);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to serialize session", e);
        } catch (RuntimeException e) {
            redis.delete(sessionKey);
            throw e;
        }
        return new AuthenticationResult(true, cookieValue, candidate.get().subject(), properties.getSessionTtlSeconds());
    }

    @Override public SessionView findSession(SessionLookupRequest request) {
        if (request == null || request.getSessionCookieValue() == null || request.getSessionCookieValue().isBlank()) {
            metrics.session(SsoMetrics.SessionOutcome.INACTIVE);
            return new SessionView(false, null, 0);
        }
        String json = redis.opsForValue().get(SESSION_PREFIX + digest(request.getSessionCookieValue()));
        if (json == null) {
            metrics.session(SsoMetrics.SessionOutcome.INACTIVE);
            return new SessionView(false, null, 0);
        }
        try {
            StoredSession session = mapper.readValue(json, StoredSession.class);
            long remaining = session.expiresAtEpochSecond() - Instant.now().getEpochSecond();
            if (remaining <= 0) {
                metrics.session(SsoMetrics.SessionOutcome.INACTIVE);
                return new SessionView(false, null, 0);
            }
            if (!users.isEnabledBySubject(session.subject())) {
                refreshTokenFamilies.revokeAllForSubject(session.subject());
                redis.delete(SESSION_PREFIX + digest(request.getSessionCookieValue()));
                metrics.session(SsoMetrics.SessionOutcome.ACCOUNT_DISABLED);
                return new SessionView(false, null, 0);
            }
            metrics.session(SsoMetrics.SessionOutcome.ACTIVE);
            return new SessionView(true, session.subject(), remaining);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to read session", e);
        }
    }

    @Override public void revokeSession(SessionLookupRequest request) {
        if (request == null || request.getSessionCookieValue() == null || request.getSessionCookieValue().isBlank()) return;
        String digest = digest(request.getSessionCookieValue());
        String sessionKey = SESSION_PREFIX + digest;
        String subject = null;
        RuntimeException failure = null;
        try {
            String json = redis.opsForValue().get(sessionKey);
            if (json != null) {
                StoredSession session = mapper.readValue(json, StoredSession.class);
                subject = session == null ? null : session.subject();
                if (subject == null || subject.isBlank()) {
                    failure = new IllegalStateException("Stored session has no subject");
                }
            }
        } catch (JsonProcessingException e) {
            failure = new IllegalStateException("Unable to read session for global logout");
        } catch (RuntimeException e) {
            failure = e;
        }
        if (subject != null && !subject.isBlank()) {
            try {
                refreshTokenFamilies.revokeAllForSubject(subject);
            } catch (RuntimeException e) {
                if (failure == null) failure = e;
                else failure.addSuppressed(e);
            }
        }
        try {
            redis.delete(sessionKey);
        } catch (RuntimeException e) {
            if (failure == null) failure = e;
            else failure.addSuppressed(e);
        }
        if (failure != null) throw new IllegalStateException("Global logout revocation could not be confirmed");
        audit.record("LOGOUT", "SUCCESS", null, null, UUID.randomUUID().toString());
    }

    private String digest(String value) { return hmacHex(properties.getSessionHmacKey(), value); }
    private String hmacHex(String key, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new IllegalStateException("Session HMAC is not configured", e); }
    }
    private String randomToken(int bytes) { byte[] value = new byte[bytes]; random.nextBytes(value); return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private String safeAddress(String value) { return value == null ? "" : value.substring(0, Math.min(value.length(), 64)); }
}
