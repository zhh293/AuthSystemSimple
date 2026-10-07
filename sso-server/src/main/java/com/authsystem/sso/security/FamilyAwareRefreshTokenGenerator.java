package com.authsystem.sso.security;

import com.authsystem.sso.config.SsoProperties;
import com.authsystem.sso.storage.AuditRepository;
import com.authsystem.sso.observability.SsoMetrics;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.transaction.support.TransactionTemplate;

/** Adds absolute family expiry and atomic single-use rotation to SAS refresh token generation. */
public final class FamilyAwareRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {
    private static final String PREFIX = "hmac-sha256:";
    private final OAuth2TokenGenerator<OAuth2Token> delegate;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final SsoProperties properties;
    private final AuditRepository audit;
    private final SsoMetrics metrics;

    @SuppressWarnings("unchecked")
    public FamilyAwareRefreshTokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token> delegate,
            JdbcTemplate jdbc, TransactionTemplate transaction, SsoProperties properties, AuditRepository audit,
            SsoMetrics metrics) {
        this.delegate = (OAuth2TokenGenerator<OAuth2Token>) delegate;
        this.jdbc = jdbc;
        this.transaction = transaction;
        this.properties = properties;
        this.audit = audit;
        this.metrics = metrics;
    }

    @Override public OAuth2Token generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) return delegate.generate(context);
        OAuth2Token generated = delegate.generate(context);
        if (!(generated instanceof OAuth2RefreshToken refreshToken)) return generated;

        AuthorizationGrantType grantType = context.getAuthorizationGrantType();
        OAuth2Authorization authorization = context.getAuthorization();
        if (authorization == null) throw new IllegalStateException("Refresh token generation requires an authorization");
        String familyId = authorization.getId();
        String newDigest = tokenDigest(refreshToken.getTokenValue());
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(grantType)) {
            createFamily(context, familyId, refreshToken, newDigest);
            metrics.refresh(SsoMetrics.RefreshOutcome.FAMILY_CREATED);
            return refreshToken;
        }
        if (!AuthorizationGrantType.REFRESH_TOKEN.equals(grantType)) return refreshToken;

        OAuth2Authorization.Token<OAuth2RefreshToken> previous = authorization.getRefreshToken();
        if (previous == null) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        List<String> previousDigests = tokenDigests(previous.getToken().getTokenValue());
        Instant absoluteExpiry = rotate(context, familyId, previousDigests, newDigest, refreshToken.getIssuedAt());
        Instant tokenExpiry = refreshToken.getExpiresAt().isBefore(absoluteExpiry)
                ? refreshToken.getExpiresAt() : absoluteExpiry;
        return new OAuth2RefreshToken(refreshToken.getTokenValue(), refreshToken.getIssuedAt(), tokenExpiry);
    }

    private void createFamily(OAuth2TokenContext context, String familyId, OAuth2RefreshToken token, String digest) {
        transaction.executeWithoutResult(status -> {
            jdbc.update("insert into oauth_refresh_token_family (family_id, client_id, subject_id, current_token_digest, expires_at) values (?, ?, ?, ?, ?)",
                    familyId, context.getRegisteredClient().getClientId(), context.getPrincipal().getName(), digest,
                    java.sql.Timestamp.from(token.getExpiresAt()));
            jdbc.update("insert into oauth_refresh_token_history (token_digest, family_id, token_status, issued_at) values (?, ?, 'ACTIVE', ?)",
                    digest, familyId, java.sql.Timestamp.from(token.getIssuedAt()));
        });
    }

    private Instant rotate(OAuth2TokenContext context, String familyId, List<String> previousDigests,
            String nextDigest, Instant issuedAt) {
        RotationResult result = transaction.execute(status -> {
            List<FamilyRow> rows = jdbc.query("select current_token_digest, expires_at, revoked from oauth_refresh_token_family where family_id = ? for update",
                    (rs, row) -> new FamilyRow(rs.getString(1), rs.getTimestamp(2).toInstant(), rs.getBoolean(3)), familyId);
            if (rows.isEmpty()) return new RotationResult(false, null, false);
            FamilyRow family = rows.get(0);
            String previousDigest = previousDigests.stream().filter(family.currentDigest()::equals).findFirst().orElse(null);
            boolean replay = previousDigest == null;
            if (family.revoked() || !family.expiresAt().isAfter(Instant.now()) || replay) {
                jdbc.update("update oauth_refresh_token_family set revoked = true where family_id = ?", familyId);
                return new RotationResult(false, family.expiresAt(), replay);
            }
            int updated = jdbc.update("update oauth_refresh_token_family set current_token_digest = ? where family_id = ? and current_token_digest = ? and revoked = false",
                    nextDigest, familyId, previousDigest);
            if (updated != 1) {
                jdbc.update("update oauth_refresh_token_family set revoked = true where family_id = ?", familyId);
                return new RotationResult(false, family.expiresAt(), true);
            }
            int consumed = jdbc.update("update oauth_refresh_token_history set token_status = 'USED', consumed_at = ? where token_digest = ? and family_id = ? and token_status = 'ACTIVE'",
                    java.sql.Timestamp.from(issuedAt), previousDigest, familyId);
            if (consumed != 1) {
                jdbc.update("update oauth_refresh_token_family set revoked = true where family_id = ?", familyId);
                return new RotationResult(false, family.expiresAt(), true);
            }
            jdbc.update("insert into oauth_refresh_token_history (token_digest, family_id, token_status, issued_at) values (?, ?, 'ACTIVE', ?)",
                    nextDigest, familyId, java.sql.Timestamp.from(issuedAt));
            return new RotationResult(true, family.expiresAt(), false);
        });
        if (result == null || !result.success()) {
            if (result != null && result.replay()) {
                metrics.refresh(SsoMetrics.RefreshOutcome.REPLAY_REJECTED);
                audit.record("REFRESH_TOKEN_REPLAY", "FAMILY_REVOKED", context.getPrincipal().getName(), null,
                        java.util.UUID.randomUUID().toString());
            } else {
                metrics.refresh(SsoMetrics.RefreshOutcome.INVALID_REJECTED);
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        metrics.refresh(SsoMetrics.RefreshOutcome.ROTATED);
        return result.expiresAt();
    }

    private String tokenDigest(String value) {
        return tokenDigests(value).get(0);
    }

    private List<String> tokenDigests(String value) {
        List<String> result = new ArrayList<>();
        result.add(PREFIX + hmac(properties.getTokenStorageHmacKey(), value));
        for (String key : properties.getTokenStorageHmacPreviousKeys()) result.add(PREFIX + hmac(key, value));
        return result;
    }

    private String hmac(String key, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Refresh token HMAC is unavailable", e);
        }
    }

    private record FamilyRow(String currentDigest, Instant expiresAt, boolean revoked) { }
    private record RotationResult(boolean success, Instant expiresAt, boolean replay) { }
}
