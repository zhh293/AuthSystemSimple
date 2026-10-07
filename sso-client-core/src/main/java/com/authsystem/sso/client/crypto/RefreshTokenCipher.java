package com.authsystem.sso.client.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/** AES-256-GCM envelope; the key id supports controlled key rotation. */
public final class RefreshTokenCipher {
    private static final SecureRandom RANDOM = new SecureRandom();
    private RefreshTokenCipher() {
    }
    public static String encrypt(String plaintext, byte[] key) {
        return encrypt(plaintext, key, new byte[0]);
    }
    public static String encrypt(String plaintext, byte[] key, byte[] associatedData) {
        if (key == null || key.length != 32)
            throw new IllegalArgumentException("AES-256 key required");
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128,
                    iv));
            cipher.updateAAD(associatedData);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] envelope = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, envelope, 0, iv.length);
            System.arraycopy(ciphertext, 0, envelope, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(envelope);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to encrypt refresh token", e);
        }
    }
    public static String decrypt(String envelope, byte[] key) {
        return decrypt(envelope, key, new byte[0]);
    }
    public static String decrypt(String envelope, byte[] key, byte[] associatedData) {
        if (key == null || key.length != 32)
            throw new IllegalArgumentException("AES-256 key required");
        try {
            byte[] bytes = Base64.getDecoder().decode(envelope);
            if (bytes.length < 29)
                throw new IllegalArgumentException("Invalid ciphertext envelope");
            byte[] iv = java.util.Arrays.copyOfRange(bytes, 0, 12), ciphertext = java.util.Arrays.copyOfRange(bytes,
                12, bytes.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128,
                    iv));
            cipher.updateAAD(associatedData);
            return new String(cipher.doFinal(ciphertext), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to decrypt refresh token", e);
        }
    }
}
