package com.authsystem.sso.storage;

import com.authsystem.sso.config.SsoProperties;
import com.authsystem.sso.observability.SsoMetrics;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/** Stores high-entropy protocol credentials as keyed digests while keeping SAS lookup semantics. */
public final class DigestingJdbcOAuth2AuthorizationService extends JdbcOAuth2AuthorizationService {
    private static final String DIGEST_PREFIX = "hmac-sha256:";
    private static final OAuth2TokenType CODE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
    private static final OAuth2TokenType STATE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
    private static final OAuth2TokenType USER_CODE = new OAuth2TokenType(OAuth2ParameterNames.USER_CODE);
    private static final OAuth2TokenType DEVICE_CODE = new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE);
    private final List<String> hmacKeys;
    private final JdbcOperations jdbc;
    private final AuditRepository audit;
    private final SsoMetrics metrics;

    public DigestingJdbcOAuth2AuthorizationService(JdbcOperations jdbc, RegisteredClientRepository clients,
            SsoProperties properties, AuditRepository audit, SsoMetrics metrics) {
        super(jdbc, clients);
        this.jdbc = jdbc;
        this.audit = audit;
        this.metrics = metrics;
        Assert.hasText(properties.getTokenStorageHmacKey(), "tokenStorageHmacKey must be configured");
        this.hmacKeys = new ArrayList<>();
        this.hmacKeys.add(properties.getTokenStorageHmacKey());
        this.hmacKeys.addAll(properties.getTokenStorageHmacPreviousKeys());
        OAuth2AuthorizationParametersMapper defaultMapper = new OAuth2AuthorizationParametersMapper();
        setAuthorizationParametersMapper(authorization -> digestTokenColumns(defaultMapper.apply(authorization)));
    }

    @Override public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        if (tokenType != null && OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return super.findByToken(token, tokenType);
        }
        if (tokenType == null) {
            OAuth2Authorization byState = super.findByToken(token, STATE);
            if (byState != null) return byState;
            for (OAuth2TokenType candidate : List.of(CODE, OAuth2TokenType.ACCESS_TOKEN,
                    OAuth2TokenType.REFRESH_TOKEN, USER_CODE, DEVICE_CODE)) {
                OAuth2Authorization authorization = findByToken(token, candidate);
                if (authorization != null) return authorization;
            }
            return null;
        }
        for (String digest : digests(token)) {
            if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType) && isUsedOrExpiredRefreshToken(digest)) return null;
            OAuth2Authorization authorization = super.findByToken(digest, tokenType);
            if (authorization != null) {
                if (isFamilyRevoked(authorization.getId())) return null;
                return restorePresentedToken(authorization, token, tokenType);
            }
        }
        // Preserve tokens written before digest storage was enabled or before its JDBC type handling was corrected.
        OAuth2Authorization legacy = super.findByToken(token, tokenType);
        if (legacy != null) {
            if (isFamilyRevoked(legacy.getId())) return null;
            return restorePresentedToken(legacy, token, tokenType);
        }
        return null;
    }

    @Override public void save(OAuth2Authorization authorization) {
        super.save(authorization);
        OAuth2Authorization.Token<OAuth2RefreshToken> refresh = authorization.getRefreshToken();
        if (refresh != null && refresh.isInvalidated()) {
            jdbc.update("update oauth_refresh_token_family set revoked = true where family_id = ?", authorization.getId());
        }
    }

    @Override public void remove(OAuth2Authorization authorization) {
        super.remove(authorization);
        jdbc.update("update oauth_refresh_token_family set revoked = true where family_id = ?", authorization.getId());
    }

    private boolean isUsedOrExpiredRefreshToken(String tokenDigest) {
        List<RefreshRow> rows = jdbc.query("select h.family_id, h.token_status, f.expires_at, f.revoked, f.subject_id "
                        + "from oauth_refresh_token_history h join oauth_refresh_token_family f on f.family_id = h.family_id "
                        + "where h.token_digest = ?",
                (rs, row) -> new RefreshRow(rs.getString(1), rs.getString(2), rs.getTimestamp(3).toInstant(), rs.getBoolean(4), rs.getString(5)), tokenDigest);
        if (rows.isEmpty()) return false;
        RefreshRow refresh = rows.get(0);
        if ("USED".equals(refresh.status()) || refresh.revoked() || !refresh.expiresAt().isAfter(java.time.Instant.now())) {
            jdbc.update("update oauth_refresh_token_family set revoked = true where family_id = ?", refresh.familyId());
            if ("USED".equals(refresh.status())) {
                metrics.refresh(SsoMetrics.RefreshOutcome.REPLAY_REJECTED);
                audit.record("REFRESH_TOKEN_REPLAY", "FAMILY_REVOKED", refresh.subjectId(), null,
                        java.util.UUID.randomUUID().toString());
            }
            return true;
        }
        return false;
    }

    private boolean isFamilyRevoked(String familyId) {
        List<FamilyStatus> states = jdbc.query("select revoked, expires_at from oauth_refresh_token_family where family_id = ?",
                (rs, row) -> new FamilyStatus(rs.getBoolean(1), rs.getTimestamp(2).toInstant()), familyId);
        return !states.isEmpty() && (states.get(0).revoked() || !states.get(0).expiresAt().isAfter(java.time.Instant.now()));
    }

    private record RefreshRow(String familyId, String status, java.time.Instant expiresAt, boolean revoked, String subjectId) { }
    private record FamilyStatus(boolean revoked, java.time.Instant expiresAt) { }

    private List<SqlParameterValue> digestTokenColumns(List<SqlParameterValue> input) {
        List<SqlParameterValue> result = new ArrayList<>(input);
        // SAS 1.5.8 mapper order: code value 8, access value 12, refresh value 22,
        // user-code value 26, and device-code value 30 (zero-based positions below).
        for (int index : List.of(7, 11, 21, 25, 29)) {
            SqlParameterValue parameter = result.get(index);
            Object value = parameter.getValue();
            if (value instanceof byte[] bytes && bytes.length > 0) {
                String text = new String(bytes, StandardCharsets.UTF_8);
                if (!text.startsWith(DIGEST_PREFIX)) {
                    result.set(index, new SqlParameterValue(parameter.getSqlType(),
                    (DIGEST_PREFIX + digest(text, hmacKeys.get(0))).getBytes(StandardCharsets.UTF_8)));
                }
            } else if (value instanceof String text && !text.isBlank() && !text.startsWith(DIGEST_PREFIX)) {
                result.set(index, new SqlParameterValue(parameter.getSqlType(),
                        (DIGEST_PREFIX + digest(text, hmacKeys.get(0))).getBytes(StandardCharsets.UTF_8)));
            }
        }
        return result;
    }

    private OAuth2Authorization restorePresentedToken(OAuth2Authorization source, String presented,
            OAuth2TokenType tokenType) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.from(source);
        if (CODE.equals(tokenType)) {
            replace(builder, source, OAuth2AuthorizationCode.class,
                    token -> new OAuth2AuthorizationCode(presented, token.getIssuedAt(), token.getExpiresAt()));
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            replace(builder, source, OAuth2AccessToken.class, token -> new OAuth2AccessToken(
                    token.getTokenType(), presented, token.getIssuedAt(), token.getExpiresAt(), token.getScopes()));
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            replace(builder, source, OAuth2RefreshToken.class,
                    token -> new OAuth2RefreshToken(presented, token.getIssuedAt(), token.getExpiresAt()));
        } else if (USER_CODE.equals(tokenType)) {
            replace(builder, source, OAuth2UserCode.class,
                    token -> new OAuth2UserCode(presented, token.getIssuedAt(), token.getExpiresAt()));
        } else if (DEVICE_CODE.equals(tokenType)) {
            replace(builder, source, OAuth2DeviceCode.class,
                    token -> new OAuth2DeviceCode(presented, token.getIssuedAt(), token.getExpiresAt()));
        }
        return builder.build();
    }

    private static <T extends OAuth2Token> void replace(OAuth2Authorization.Builder builder,
            OAuth2Authorization source, Class<T> tokenType, java.util.function.Function<T, T> replacement) {
        OAuth2Authorization.Token<T> stored = source.getToken(tokenType);
        if (stored != null) builder.token(replacement.apply(stored.getToken()), metadata -> metadata.putAll(stored.getMetadata()));
    }

    private List<String> digests(String value) {
        List<String> values = new ArrayList<>(hmacKeys.size());
        for (String key : hmacKeys) values.add(DIGEST_PREFIX + digest(value, key));
        return values;
    }

    private String digest(String value, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Token storage HMAC is unavailable", e);
        }
    }
}
