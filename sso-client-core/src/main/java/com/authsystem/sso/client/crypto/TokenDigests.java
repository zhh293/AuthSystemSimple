package com.authsystem.sso.client.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class TokenDigests {
    private TokenDigests() {
    }

    public static String hmacSha256(String token, byte[] key) {
        if (token == null || token.isBlank() || key == null || key.length < 32) {
            throw new IllegalArgumentException("Token and 256-bit key are required");
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(mac.doFinal(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA-256 is unavailable", e);
        }
    }

    public static String sha256(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Value is required");
        }

        try {
            return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(java.security.MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
