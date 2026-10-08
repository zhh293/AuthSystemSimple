package com.authsystem.sso.crypto;

import java.util.Map;

public record LoginCryptoEnvelope(String version, String sessionId, String keyId,
        Map<String, String> clientPublicKey, String requestId, long timestamp,
        String nonce, String ciphertext, String tag) { }
