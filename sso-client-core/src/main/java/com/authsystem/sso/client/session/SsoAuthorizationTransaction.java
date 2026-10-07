package com.authsystem.sso.client.session;

import java.time.Instant;

public record SsoAuthorizationTransaction(String nonce, String codeVerifier,
    String browserBindingDigest, String returnPath,
    Instant createdAt, Instant expiresAt) {
}
