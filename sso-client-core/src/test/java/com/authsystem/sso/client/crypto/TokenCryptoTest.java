package com.authsystem.sso.client.crypto;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class TokenCryptoTest {
    private final byte[] key = new byte[32];
    @Test void refreshCipherAuthenticatesCiphertext() {
        Arrays.fill(key, (byte)7);
        String encrypted = RefreshTokenCipher.encrypt("sensitive-refresh-token", key);
        assertNotEquals("sensitive-refresh-token", encrypted);
        assertEquals("sensitive-refresh-token", RefreshTokenCipher.decrypt(encrypted, key));
        byte[] changed = java.util.Base64.getDecoder().decode(encrypted);
        changed[changed.length-1] ^= 1;
        assertThrows(IllegalStateException.class, () -> RefreshTokenCipher.decrypt(java.util.Base64.getEncoder().encodeToString(changed),
                key));
    }
    @Test void accessTokenLookupUsesKeyedDigest() {
        Arrays.fill(key, (byte)3);
        String first = TokenDigests.hmacSha256("opaque-token", key);
        assertEquals(first, TokenDigests.hmacSha256("opaque-token", key));
        assertNotEquals(first, TokenDigests.hmacSha256("different-token", key));
        assertFalse(first.contains("opaque-token"));
    }
    @Test void refreshCipherAuthenticatesRecordContext() {
        Arrays.fill(key, (byte)9);
        byte[] context = "issuer|client|digest|family-expiry".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String encrypted = RefreshTokenCipher.encrypt("refresh", key, context);
        assertEquals("refresh", RefreshTokenCipher.decrypt(encrypted, key, context));
        assertThrows(IllegalStateException.class, () -> RefreshTokenCipher.decrypt(encrypted, key, "other-context".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }
}
