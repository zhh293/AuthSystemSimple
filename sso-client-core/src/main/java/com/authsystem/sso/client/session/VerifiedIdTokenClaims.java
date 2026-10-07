package com.authsystem.sso.client.session;

import java.time.Instant;
import java.util.Map;

/** Contains only claims accepted by the configured ID-token validator. */
public record VerifiedIdTokenClaims(String subject, String issuer, String audience,
    Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
    public VerifiedIdTokenClaims {
        claims = Map.copyOf(claims);
    }
}
