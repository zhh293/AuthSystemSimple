package com.authsystem.sso.crypto;

import java.util.Map;

public record LoginCryptoSessionResponse(String version, String sessionId, String keyId, String curve,
        Map<String, String> serverPublicKey, long expiresAt) { }
