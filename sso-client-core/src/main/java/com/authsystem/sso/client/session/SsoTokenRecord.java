package com.authsystem.sso.client.session;

import java.time.Instant;
import java.util.List;

/** Refresh token is ciphertext when persisted by production stores. */
public record SsoTokenRecord(String issuer, String clientId, String accessTokenDigest,
    String encryptedRefreshToken, String encryptionKeyId,
    SsoPrincipal principal, Instant accessTokenExpiresAt,
    Instant refreshFamilyExpiresAt, String idTokenNonceDigest,
    List<String> grantedScopes) {
    public SsoTokenRecord {
        grantedScopes = grantedScopes == null ? List.of() : List.copyOf(grantedScopes);
    }

    public SsoTokenRecord(
        String issuer,
        String clientId,
        String accessTokenDigest,
        String encryptedRefreshToken,
        String encryptionKeyId,
        SsoPrincipal principal,
        Instant accessTokenExpiresAt,
        Instant refreshFamilyExpiresAt) {
        this(issuer, clientId, accessTokenDigest, encryptedRefreshToken, encryptionKeyId,
            principal, accessTokenExpiresAt, refreshFamilyExpiresAt, null, List.of());
    }

    public SsoTokenRecord(
        String issuer,
        String clientId,
        String accessTokenDigest,
        String encryptedRefreshToken,
        String encryptionKeyId,
        SsoPrincipal principal,
        Instant accessTokenExpiresAt,
        Instant refreshFamilyExpiresAt,
        String idTokenNonceDigest) {
        this(issuer, clientId, accessTokenDigest, encryptedRefreshToken, encryptionKeyId,
            principal, accessTokenExpiresAt, refreshFamilyExpiresAt, idTokenNonceDigest, List.of());
    }
}
