package com.authsystem.sso.client.session;

import com.authsystem.sso.client.config.SsoClientProperties;
import com.authsystem.sso.client.crypto.RefreshTokenCipher;
import com.authsystem.sso.client.crypto.TokenDigests;
import com.authsystem.sso.client.protocol.AuthorizationRequestFactory;
import com.authsystem.sso.client.protocol.IdTokenValidator;
import com.authsystem.sso.client.protocol.OAuthTokenClient;
import com.authsystem.sso.client.protocol.OidcMetadataClient;
import com.authsystem.sso.client.security.Pkce;
import com.authsystem.sso.client.store.SsoAuthorizationRequestStore;
import com.authsystem.sso.client.store.SsoTokenStore;
import com.authsystem.sso.client.store.SsoRefreshLock;
import com.authsystem.sso.client.observability.SsoClientMetrics;
import com.authsystem.sso.client.session.SsoLogoutListener.SsoLogoutEvent;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

public final class SsoSessionService {
    private static final int MAX_ACCESS_TOKEN_CHARS = 8192;
    private static final Duration REFRESH_LOCK_WAIT = Duration.ofSeconds(8);
    private static final Duration ROTATION_OVERLAP_TTL = REFRESH_LOCK_WAIT.plusSeconds(2);
    private final SsoClientProperties properties;
    private final SsoAuthorizationRequestStore transactions;
    private final SsoTokenStore tokens;
    private final OAuthTokenClient tokenClient;
    private final IdTokenValidator idTokens;
    private final SsoPrincipalMapper mapper;
    private final OidcMetadataClient metadata;
    private final Clock clock;
    private final SsoRefreshLock refreshCoordinator;
    private final SsoClientMetrics metrics;
    private final java.util.List<SsoLogoutListener> logoutListeners;
    private final byte[] hmacKey, encryptionKey, bindingKey;

    public SsoSessionService(SsoClientProperties properties, SsoAuthorizationRequestStore transactions,
        SsoTokenStore tokens,
        OAuthTokenClient tokenClient, IdTokenValidator idTokens, SsoPrincipalMapper mapper,
        OidcMetadataClient metadata, Clock clock, SsoRefreshLock refreshCoordinator, SsoClientMetrics metrics,
        java.util.List<SsoLogoutListener> logoutListeners) {
        this.properties = properties;
        this.transactions = transactions;
        this.tokens = tokens;
        this.tokenClient = tokenClient;
        this.idTokens = idTokens;
        this.mapper = mapper;
        this.metadata = metadata;
        this.clock = clock;
        this.refreshCoordinator = refreshCoordinator;
        this.metrics = metrics;
        this.logoutListeners = java.util.List.copyOf(logoutListeners);
        this.hmacKey = decodeKey(properties.lookupHmacKey(), 32, "lookupHmacKey");
        this.bindingKey = deriveKey(this.hmacKey, "browser-binding");
        this.encryptionKey = decodeKey(properties.refreshEncryptionKey(), 32, "refreshEncryptionKey");
    }
    public AuthorizationRequestFactory.LoginRequest beginLogin(String returnPath) {
        metrics.login("started");
        try {
            var result = new AuthorizationRequestFactory(properties, metadata, transactions, clock, bindingKey).create(returnPath);
            metrics.login("succeeded");
            return result;
        } catch (RuntimeException e) {
            metrics.login("failed");
            throw e;
        }
    }
    public String browserBindingCookieName(String state) {
        if (state == null || state.isBlank() || state.length()>512)
            return null;
        return AuthorizationRequestFactory.browserBindingCookieName(properties.clientId(), state, bindingKey);
    }
    public void cancelAuthorization(String state) {
        if (state != null && !state.isBlank() && state.length() <= 512)
            transactions.consume(state);
    }
    public Completion complete(String code, String state, String browserBinding) {
        try {
            Completion result = completeInternal(code, state, browserBinding);
            metrics.callback("succeeded");
            return result;
        } catch (RuntimeException e) {
            metrics.callback("failed");
            throw e;
        }
    }
    private Completion completeInternal(String code, String state, String browserBinding) {
        if (code == null || code.isBlank() || code.length()>4096 || state == null || state.isBlank() ||
            state.length()>512)
            throw new IllegalArgumentException("Invalid authorization callback");
        SsoAuthorizationTransaction tx = transactions.consume(state).orElseThrow(() -> new IllegalArgumentException("Authorization transaction is invalid or expired"));
        if (browserBinding == null || !constantTimeEquals(tx.browserBindingDigest(), TokenDigests.hmacSha256(browserBinding,
                    bindingKey)))
            throw new IllegalArgumentException("Authorization transaction is invalid or expired");
        OAuthTokenClient.TokenResponse response = tokenClient.exchangeCode(code, tx.codeVerifier());
        SsoPrincipal principal;
        try {
            if (response.idToken() == null)
                throw new IllegalArgumentException("Authorization server omitted ID token");
            VerifiedIdTokenClaims claims = claimsWithinGrantedScopes(idTokens.validate(response.idToken(),
                    tx.nonce()), response.scope());
            principal = mapper.map(claims);
            if (principal == null || !claims.subject().equals(principal.subject()))
                throw new IllegalArgumentException("Principal mapping must preserve the verified subject");
        } catch (RuntimeException invalidIdentity) {
            try {
                tokenClient.revokeRefreshToken(response.refreshToken());
            } catch (RuntimeException ignored) {
            }
            throw invalidIdentity;
        }
        Instant now = clock.instant(), familyExpiry = now.plus(properties.familyLifetime());
        SsoTokenRecord record = record(response, principal, familyExpiry, tx.nonce());
        try {
            tokens.saveCurrent(null, response.accessToken(), record, null, java.time.Duration.ZERO);
        } catch (RuntimeException storeFailure) {
            try {
                tokenClient.revokeRefreshToken(response.refreshToken());
            } catch (RuntimeException ignored) {
            }
            throw new com.authsystem.sso.client.protocol.SsoClientDependencyException("Application token store is unavailable",
                storeFailure);
        }
        return new Completion(response.accessToken(), principal, tx.returnPath(), now.plusSeconds(response.expiresIn()),
            familyExpiry);
    }
    public Optional<SsoTokenRecord> authenticate(String accessToken) {
        return resolve(accessToken).map(Session::record);
    }
    public Optional<Session> resolve(String accessToken) {
        if (accessToken == null || accessToken.isBlank() || accessToken.length()>MAX_ACCESS_TOKEN_CHARS)
            return Optional.empty();
        Optional<SsoTokenRecord> found = tokens.findByAccessToken(accessToken);
        if (found.isEmpty())
            return findRotatedSession(accessToken);
        SsoTokenRecord record = found.get();
        if (!properties.issuer().equals(record.issuer()) || !properties.clientId().equals(record.clientId())) {
            tokens.deleteByAccessToken(accessToken);
            return Optional.empty();
        }
        if (!record.refreshFamilyExpiresAt().isAfter(clock.instant())) {
            tokens.deleteByAccessToken(accessToken);
            return Optional.empty();
        }
        if (record.accessTokenExpiresAt().isAfter(clock.instant().plus(properties.refreshSkew())))
            return Optional.of(new Session(accessToken,
                    record, false));
        metrics.refresh("attempted");
        if (refreshCoordinator == null) {
            metrics.refresh("failed");
            return Optional.empty();
        }
        Duration lockLease = properties.connectTimeout().plus(properties.responseTimeout()).multipliedBy(2).plusSeconds(5);
        Optional<SsoRefreshLock.Lease> lease = refreshCoordinator.acquire(record.accessTokenDigest(),
            REFRESH_LOCK_WAIT,
            lockLease);
        if (lease.isEmpty()) {
            metrics.refresh("failed");
            return findRotatedSession(accessToken);
        }
        try(SsoRefreshLock.Lease ignored = lease.get()) {
            Optional<SsoTokenRecord> current = tokens.findByAccessToken(accessToken);
            if (current.isEmpty())
                return findRotatedSession(accessToken);
            record = current.get();
            if (!record.refreshFamilyExpiresAt().isAfter(clock.instant())) {
                tokens.deleteByAccessToken(accessToken);
                return Optional.empty();
            }
            if (record.accessTokenExpiresAt().isAfter(clock.instant().plus(properties.refreshSkew())))
                return Optional.of(new Session(accessToken,
                        record, false));
            String oldRefresh;
            try {
                oldRefresh = decryptRefreshToken(record);
            } catch (RuntimeException badCipher) {
                metrics.refresh("failed");
                tokens.deleteByAccessToken(accessToken);
                return Optional.empty();
            }
            String refreshFingerprint = TokenDigests.hmacSha256(oldRefresh, hmacKey);
            boolean claimed;
            try {
                claimed = tokens.claimRefreshAttempt(refreshFingerprint, record.refreshFamilyExpiresAt().plus(Duration.ofMinutes(5)));
            } catch (RuntimeException unavailable) {
                metrics.refresh("failed");
                try {
                    tokens.deleteByAccessToken(accessToken);
                } catch (RuntimeException cleanupFailure) {
                }
                return Optional.empty();
            }
            if (!claimed) {
                Optional<Session> rotated = findRotatedSession(accessToken);
                if (rotated.isPresent()) {
                    metrics.refresh("succeeded");
                    return rotated;
                }
                metrics.refresh("failed");
                try {
                    tokens.deleteByAccessToken(accessToken);
                } catch (RuntimeException cleanupFailure) {
                }
                return Optional.empty();
            }
            OAuthTokenClient.TokenResponse response;
            java.util.List<String> previouslyGrantedScopes = record.grantedScopes().isEmpty()?java.util.List.of("openid"):record.grantedScopes();
            try {
                response = tokenClient.refresh(oldRefresh, previouslyGrantedScopes);
            } catch (RuntimeException failed) {
                metrics.refresh("failed");
                tokens.deleteByAccessToken(accessToken);
                return Optional.empty();
            }
            if (!record.refreshFamilyExpiresAt().isAfter(clock.instant())) {
                metrics.refresh("failed");
                discardRefreshOutcome(accessToken, response.accessToken(), response.refreshToken());
                return Optional.empty();
            }
            SsoPrincipal refreshedPrincipal = record.principal();
            if (response.idToken() != null)
                try {
                VerifiedIdTokenClaims refreshedClaims = claimsWithinGrantedScopes(idTokens.validateRefresh(response.idToken(),
                        record.principal().subject(), record.idTokenNonceDigest()), response.scope());
                refreshedPrincipal = mapper.map(refreshedClaims);
                if (refreshedPrincipal == null || !record.principal().subject().equals(refreshedPrincipal.subject()))
                    throw new IllegalArgumentException("Principal mapping must preserve the verified subject");
            } catch (RuntimeException invalidIdentity) {
                metrics.refresh("failed");
                discardRefreshOutcome(accessToken, response.accessToken(), response.refreshToken());
                return Optional.empty();
            }
            Instant expiry = clock.instant().plusSeconds(response.expiresIn());
            String newDigest = TokenDigests.hmacSha256(response.accessToken(), hmacKey);
            java.util.List<String> refreshedScopes = java.util.List.of(response.scope().split(" "));
            SsoTokenRecord replacement = new SsoTokenRecord(properties.issuer(), properties.clientId(),
                newDigest, encryptRefreshToken(response.refreshToken(), newDigest, record.refreshFamilyExpiresAt()),
                "primary", refreshedPrincipal, expiry, record.refreshFamilyExpiresAt(), record.idTokenNonceDigest(),
                refreshedScopes);
            String overlap = encryptOverlap(accessToken, response.accessToken(), record.refreshFamilyExpiresAt());
            try {
                tokens.saveCurrent(accessToken, response.accessToken(), replacement, overlap, ROTATION_OVERLAP_TTL);
            } catch (RuntimeException writeFailed) {
                metrics.refresh("failed");
                discardRefreshOutcome(accessToken, response.accessToken(), response.refreshToken());
                return Optional.empty();
            }
            Optional<Session> result;
            try {
                result = tokens.findByAccessToken(response.accessToken()).map(updated -> new Session(response.accessToken(),
                        updated, true));
            } catch (RuntimeException readFailed) {
                metrics.refresh("failed");
                discardRefreshOutcome(accessToken, response.accessToken(), response.refreshToken());
                return Optional.empty();
            }
            if (result.isEmpty()) {
                metrics.refresh("failed");
                discardRefreshOutcome(accessToken, response.accessToken(), response.refreshToken());
                return Optional.empty();
            }
            metrics.refresh("succeeded");
            return result;
        }
    }
    private Optional<Session> findRotatedSession(String oldAccessToken) {
        Optional<String> encrypted = tokens.findOverlapAccessToken(oldAccessToken);
        if (encrypted.isEmpty())
            return Optional.empty();
        try {
            String oldDigest = TokenDigests.hmacSha256(oldAccessToken, hmacKey);
            String[] payload = RefreshTokenCipher.decrypt(encrypted.get(), encryptionKey, overlapAad(oldDigest)).split(":",
                2);
            if (payload.length != 2)
                return Optional.empty();
            String current = new String(Base64.getUrlDecoder().decode(payload[0]), StandardCharsets.UTF_8);
            Instant familyExpiry = Instant.parse(payload[1]);
            return tokens.findByAccessTokenFresh(current).filter(record -> record.refreshFamilyExpiresAt().equals(familyExpiry)
&& record.refreshFamilyExpiresAt().isAfter(clock.instant())
&& record.accessTokenExpiresAt().isAfter(clock.instant().plus(properties.refreshSkew()))
&& properties.issuer().equals(record.issuer()) && properties.clientId().equals(record.clientId())
&& record.accessTokenDigest().equals(TokenDigests.hmacSha256(current, hmacKey)))
            .map(record -> new Session(current, record, true));
        } catch (RuntimeException invalid) {
            return Optional.empty();
        }
    }
    private String encryptOverlap(String oldAccess, String newAccess, Instant familyExpiry) {
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(newAccess.getBytes(StandardCharsets.UTF_8))+":"+familyExpiry;
        return RefreshTokenCipher.encrypt(payload, encryptionKey, overlapAad(TokenDigests.hmacSha256(oldAccess,
                    hmacKey)));
    }
    private byte[] overlapAad(String oldDigest) {
        return (properties.issuer()+"\n"+properties.clientId()+"\n"+oldDigest+"\nrotation-overlap").getBytes(StandardCharsets.UTF_8);
    }
    public void logout(String accessToken) {
        if (accessToken == null || accessToken.isBlank() || accessToken.length()>MAX_ACCESS_TOKEN_CHARS)
            return;
        String currentToken = accessToken;
        Optional<SsoTokenRecord> current = tokens.findByAccessToken(accessToken);
        if (current.isEmpty()) {
            Optional<Session> rotated = findRotatedSession(accessToken);
            if (rotated.isPresent()) {
                currentToken = rotated.get().accessToken();
                current = Optional.of(rotated.get().record());
            }
        }
        String refreshToken = null;
        if (current.isPresent()) {
            current = tokens.removeCurrentBySubjectAndClient(current.get().principal().subject(), properties.clientId());
            if (current.isPresent())
                try {
                refreshToken = decryptRefreshToken(current.get());
            } catch (RuntimeException ignored) {
            }
        }
        tokens.deleteByAccessToken(currentToken);
        if (!currentToken.equals(accessToken))
            tokens.deleteByAccessToken(accessToken);
        boolean revoked = false;
        if (refreshToken != null)
            try {
            revoked = tokenClient.revokeRefreshToken(refreshToken);
        } catch (RuntimeException ignored) {
            revoked = false;
        }
        metrics.revoke(revoked?"succeeded":"failed");
        SsoLogoutEvent event = new SsoLogoutEvent(properties.clientId(), clock.instant(), revoked);
        for (SsoLogoutListener listener:logoutListeners)
            try {
            listener.onLogout(event);
        } catch (RuntimeException ignored) {
            /* local logout is already complete */
        }
    }
    private SsoTokenRecord record(OAuthTokenClient.TokenResponse response, SsoPrincipal principal, Instant familyExpiry,
        String nonce) {
        String digest = TokenDigests.hmacSha256(response.accessToken(), hmacKey);
        return new SsoTokenRecord(properties.issuer(), properties.clientId(), digest, encryptRefreshToken(response.refreshToken(),
                digest, familyExpiry), "primary", principal, clock.instant().plusSeconds(response.expiresIn()),
            familyExpiry, TokenDigests.sha256(nonce), java.util.List.of(response.scope().split(" ")));
    }
    private void discardRefreshOutcome(String oldAccessToken, String newAccessToken, String refreshToken) {
        RuntimeException cleanupFailure = null;
        try {
            tokens.deleteByAccessToken(newAccessToken);
        } catch (RuntimeException failure) {
            cleanupFailure = failure;
        }
        try {
            tokens.deleteByAccessToken(oldAccessToken);
        } catch (RuntimeException failure) {
            if (cleanupFailure == null)
                cleanupFailure = failure;
            else cleanupFailure.addSuppressed(failure);
        }
        try {
            tokenClient.revokeRefreshToken(refreshToken);
        } catch (RuntimeException ignored) {
        }
        if (cleanupFailure != null)
            throw cleanupFailure;
    }
    private VerifiedIdTokenClaims claimsWithinGrantedScopes(VerifiedIdTokenClaims verified, String grantedScope) {
        java.util.Map<String, Object> allowed = new java.util.HashMap<>();
        java.util.List<String> scopes = java.util.List.of(grantedScope.split(" "));
        boolean profile = scopes.contains("profile"), email = scopes.contains("email");
        for (var claim:verified.claims().entrySet()) {
            String name = claim.getKey();
            boolean permitted = switch (name) {
                case "email", "email_verified" -> email;
                case "name", "preferred_username", "given_name", "family_name" -> profile;
                default -> false;
            };
            if (permitted)
                allowed.put(name, claim.getValue());
        }
        return new VerifiedIdTokenClaims(verified.subject(), verified.issuer(), verified.audience(), verified.issuedAt(),
            verified.expiresAt(), allowed);
    }
    private String encryptRefreshToken(String refreshToken, String accessDigest, Instant familyExpiry) {
        return RefreshTokenCipher.encrypt(refreshToken, encryptionKey, refreshTokenAad(properties.issuer(),
                properties.clientId(), accessDigest, familyExpiry));
    }
    private String decryptRefreshToken(SsoTokenRecord record) {
        return RefreshTokenCipher.decrypt(record.encryptedRefreshToken(), encryptionKey, refreshTokenAad(record.issuer(),
                record.clientId(), record.accessTokenDigest(), record.refreshFamilyExpiresAt()));
    }
    private static byte[] refreshTokenAad(String issuer, String client, String digest, Instant familyExpiry) {
        return (issuer+"\n"+client+"\n"+digest+"\n"+familyExpiry.toEpochMilli()).getBytes(StandardCharsets.UTF_8);
    }
    private static byte[] decodeKey(String value, int length, String name) {
        try {
            byte[] key = Base64.getDecoder().decode(value);
            if (key.length != length)
                throw new IllegalArgumentException(name+" must be base64-encoded "+(length*8)+"-bit material");
            return key;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(name+" must be base64-encoded "+(length*8)+"-bit material");
        }
    }
    private static byte[] deriveKey(byte[] key, String purpose) {
        try {
            return java.util.Arrays.copyOf(java.security.MessageDigest.getInstance("SHA-256").digest((Base64.getEncoder().encodeToString(key)+purpose).getBytes(StandardCharsets.UTF_8)),
                32);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
    private static boolean constantTimeEquals(String a, String b) {
        return a != null && b != null && java.security.MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
            b.getBytes(StandardCharsets.UTF_8));
    }
    public record Completion(String accessToken, SsoPrincipal principal, String returnPath, Instant accessTokenExpiresAt,
        Instant refreshFamilyExpiresAt) {
    }
    public record Session(String accessToken, SsoTokenRecord record, boolean refreshed) {
    }
}
