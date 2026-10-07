package com.authsystem.sso.client.protocol;

import com.authsystem.sso.client.session.VerifiedIdTokenClaims;
import com.authsystem.sso.client.crypto.TokenDigests;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Performs protocol checks after the configured decoder has verified the JWS using trusted JWKS. */
public final class IdTokenValidator {
    private final JwtDecoder decoder;
    private final String issuer, clientId;
    private final Clock clock;
    private final Duration clockSkew;
    public IdTokenValidator(JwtDecoder decoder, String issuer, String clientId, Clock clock, Duration clockSkew) {
        this.decoder = decoder;
        this.issuer = issuer;
        this.clientId = clientId;
        this.clock = clock;
        this.clockSkew = clockSkew;
    }
    public VerifiedIdTokenClaims validate(String compact, String expectedNonce) {
        return validateClaims(compact, expectedNonce, null, null, true);
    }
    /** Validates a refresh-grant ID Token against the existing authenticated subject and login nonce. */
    public VerifiedIdTokenClaims validateRefresh(String compact, String expectedSubject, String expectedNonceDigest) {
        return validateClaims(compact, null, expectedSubject, expectedNonceDigest, false);
    }
    private VerifiedIdTokenClaims validateClaims(String compact, String expectedNonce, String expectedSubject,
        String expectedNonceDigest, boolean nonceRequired) {
        Jwt jwt;
        try {
            jwt = decoder.decode(compact);
        } catch (org.springframework.security.oauth2.jwt.JwtException failure) {
            Throwable cause = failure;
            while (cause != null) {
                if (cause instanceof java.io.IOException || cause instanceof org.springframework.web.client.ResourceAccessException)
                    throw new SsoClientDependencyException("OIDC signing keys are unavailable", failure);
                cause = cause.getCause();
            }
            throw new IllegalArgumentException("ID token validation failed");
        }
        String tokenIssuer = jwt.getClaimAsString("iss");
        String subject = jwt.getSubject();
        Object audClaim = jwt.getClaims().get("aud");
        List<String> audience = audClaim instanceof String s ? List.of(s) : audClaim instanceof List<?> l ? l.stream().filter(String.class::isInstance).map(String.class::cast).toList() : List.of();
        String authorizedParty = jwt.getClaimAsString("azp");
        Instant issuedAt = jwt.getIssuedAt(), expiresAt = jwt.getExpiresAt(), now = clock.instant();
        String nonce = jwt.getClaimAsString("nonce");
        if (!issuer.equals(tokenIssuer) || !audience.contains(clientId) || (audience.size() > 1 && !clientId.equals(authorizedParty))
|| (authorizedParty != null && !clientId.equals(authorizedParty)) || subject == null || subject.isBlank()
|| issuedAt == null || expiresAt == null || issuedAt.isAfter(now.plus(clockSkew))
|| !expiresAt.isAfter(now.minus(clockSkew)) || (nonceRequired && nonce == null)
|| (expectedNonce != null && !constantTimeEquals(nonce, expectedNonce))
|| (nonce != null && expectedSubject != null && (expectedNonceDigest == null || !constantTimeEquals(TokenDigests.sha256(nonce),
                        expectedNonceDigest)))
|| (expectedSubject != null && !expectedSubject.equals(subject))) {
            throw new IllegalArgumentException("ID token validation failed");
        }
        Map<String, Object> minimal = new java.util.HashMap<>();
        for (String key : List.of("name", "email", "email_verified", "preferred_username", "given_name",
                "family_name")) {
            Object value = jwt.getClaims().get(key);
            if (value != null)
                minimal.put(key, value);
        }
        return new VerifiedIdTokenClaims(subject, tokenIssuer, clientId, issuedAt, expiresAt, minimal);
    }
    private static boolean constantTimeEquals(String left, String right) {
        return left != null && right != null && java.security.MessageDigest.isEqual(left.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            right.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
