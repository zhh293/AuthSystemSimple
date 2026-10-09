package com.authsystem.sso.crypto;

import com.authsystem.sso.config.SsoProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class LoginCryptoService {
    private static final String PREFIX = "sso:login-crypto:";
    private static final String CURVE = "P-256";
    private static final String VERSION = "v1";
    private static final int MAX_B64 = 8192;
    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final SsoProperties properties;
    private final SecureRandom random = new SecureRandom();

    public LoginCryptoService(StringRedisTemplate redis, ObjectMapper mapper, SsoProperties properties) {
        this.redis = redis; this.mapper = mapper; this.properties = properties;
    }

    public LoginCryptoSessionResponse createSession(String remoteAddress) {
        String address = remoteAddress == null ? "" : remoteAddress.substring(0, Math.min(64, remoteAddress.length()));
        long now = Instant.now().getEpochSecond();
        String rateKey = PREFIX + "rate:" + Integer.toHexString(address.hashCode()) + ":" + (now / properties.getLoginCryptoWindowSeconds());
        Long count = redis.opsForValue().increment(rateKey);
        if (count != null && count == 1L) redis.expire(rateKey, Duration.ofSeconds(properties.getLoginCryptoWindowSeconds() + 1));
        if (count != null && count > properties.getLoginCryptoMaxSessionsPerIp()) throw new LoginCryptoRateLimitException();
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            String sessionId = token(24);
            String keyId = properties.getLoginCryptoKeyId();
            StoredSession stored = new StoredSession(
                    b64(pair.getPrivate().getEncoded()), keyId, publicJwk((ECPublicKey) pair.getPublic()));
            redis.opsForValue().set(PREFIX + sessionId, mapper.writeValueAsString(stored),
                    Duration.ofSeconds(properties.getLoginCryptoSessionTtlSeconds()));
            return new LoginCryptoSessionResponse(VERSION, sessionId, keyId, CURVE,
                    stored.serverPublicKey(), now + properties.getLoginCryptoSessionTtlSeconds());
        } catch (Exception e) {
            throw new LoginCryptoException("unable to create crypto session", e);
        }
    }

    public LoginCredentials decrypt(LoginCryptoEnvelope envelope) {
        validateEnvelope(envelope);
        String json = redis.opsForValue().getAndDelete(PREFIX + envelope.sessionId());
        if (json == null) throw new LoginCryptoException("expired crypto session");
        try {
            StoredSession stored = mapper.readValue(json, StoredSession.class);
            if (!java.util.Objects.equals(stored.keyId(), envelope.keyId())) throw new LoginCryptoException("key id mismatch");
            PrivateKey serverPrivate = KeyFactory.getInstance("EC").generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getUrlDecoder().decode(stored.serverPrivateKey())));
            PublicKey clientPublic = publicKey(envelope.clientPublicKey());
            byte[] aesKey = hkdf(ecdh(serverPrivate, clientPublic), envelope.sessionId(), envelope.keyId());
            byte[] nonce = decode(envelope.nonce(), 32);
            byte[] ciphertext = decode(envelope.ciphertext(), MAX_B64);
            byte[] tag = decode(envelope.tag(), 32);
            if (nonce.length != 12 || tag.length != 16) throw new LoginCryptoException("invalid gcm parameters");
            byte[] combined = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad(envelope));
            byte[] plain = cipher.doFinal(combined);
            LoginCredentials credentials = mapper.readValue(plain, LoginCredentials.class);
            if (credentials.username() == null || credentials.password() == null
                    || credentials.username().length() > 128 || credentials.password().length() > 1024) {
                throw new LoginCryptoException("invalid credentials");
            }
            return credentials;
        } catch (LoginCryptoException e) { throw e;
        } catch (Exception e) { throw new LoginCryptoException("unable to decrypt login request", e); }
    }

    private void validateEnvelope(LoginCryptoEnvelope e) {
        if (e == null || !VERSION.equals(e.version()) || !properties.getLoginCryptoKeyId().equals(e.keyId())
                || blank(e.sessionId()) || blank(e.requestId()) || e.clientPublicKey() == null
                || e.timestamp() < Instant.now().getEpochSecond() - properties.getLoginCryptoClockSkewSeconds()
                || e.timestamp() > Instant.now().getEpochSecond() + properties.getLoginCryptoClockSkewSeconds())
            throw new LoginCryptoException("invalid crypto envelope");
        if (e.requestId().length() > 128 || e.sessionId().length() > 128) throw new LoginCryptoException("invalid envelope size");
    }

    private byte[] ecdh(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(privateKey); agreement.doPhase(publicKey, true); return agreement.generateSecret();
    }

    private byte[] hkdf(byte[] secret, String sessionId, String keyId) throws Exception {
        byte[] salt = sha256(("sso-login-v1|" + sessionId).getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(secret);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] info = ("sso-login-aes-256-gcm|" + keyId).getBytes(StandardCharsets.UTF_8);
        mac.update(info); mac.update((byte) 1); return java.util.Arrays.copyOf(mac.doFinal(), 32);
    }

    private byte[] aad(LoginCryptoEnvelope e) {
        String key = VERSION + "|" + e.sessionId() + "|" + e.keyId() + "|" + e.requestId() + "|" + e.timestamp()
                + "|" + canonicalPublicKey(e.clientPublicKey());
        return key.getBytes(StandardCharsets.UTF_8);
    }

    private PublicKey publicKey(Map<String, String> jwk) throws Exception {
        if (!"EC".equals(jwk.get("kty")) || !CURVE.equals(jwk.get("crv"))) throw new IllegalArgumentException("curve");
        byte[] x = Base64.getUrlDecoder().decode(jwk.get("x")); byte[] y = Base64.getUrlDecoder().decode(jwk.get("y"));
        if (x.length != 32 || y.length != 32) throw new IllegalArgumentException("coordinate size");
        java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1")); ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(unsigned(x, y), spec));
    }

    private Map<String, String> publicJwk(ECPublicKey key) {
        return Map.of("kty", "EC", "crv", CURVE, "x", b64(fixed(key.getW().getAffineX())), "y", b64(fixed(key.getW().getAffineY())));
    }
    private java.security.spec.ECPoint unsigned(byte[] x, byte[] y) { return new java.security.spec.ECPoint(new java.math.BigInteger(1, x), new java.math.BigInteger(1, y)); }
    private byte[] fixed(java.math.BigInteger value) { byte[] raw = value.toByteArray(); byte[] out = new byte[32]; int copy = Math.min(raw.length, 32); System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy); return out; }
    private String canonicalPublicKey(Map<String, String> key) { return key.get("crv") + ":" + key.get("kty") + ":" + key.get("x") + ":" + key.get("y"); }
    private byte[] decode(String value, int max) { if (value == null || value.length() > max) throw new LoginCryptoException("invalid encoded value"); try { return Base64.getUrlDecoder().decode(value); } catch (IllegalArgumentException e) { throw new LoginCryptoException("invalid encoded value"); } }
    private byte[] sha256(byte[] value) throws Exception { return java.security.MessageDigest.getInstance("SHA-256").digest(value); }
    private String token(int bytes) { byte[] value = new byte[bytes]; random.nextBytes(value); return b64(value); }
    private String b64(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private boolean blank(String value) { return value == null || value.isBlank(); }
    public record StoredSession(String serverPrivateKey, String keyId, Map<String, String> serverPublicKey) { }
}

