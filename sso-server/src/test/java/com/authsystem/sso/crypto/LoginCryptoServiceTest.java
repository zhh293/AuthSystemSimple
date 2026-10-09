package com.authsystem.sso.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authsystem.sso.config.SsoProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

class LoginCryptoServiceTest {
    private static final String KEY_ID = "test-login-key";
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private final ObjectMapper mapper = new ObjectMapper();
    private final SsoProperties properties = new SsoProperties();
    private final AtomicReference<String> storedSession = new AtomicReference<>();
    private LoginCryptoService service;

    @BeforeEach
    void setUp() {
        properties.setLoginCryptoKeyId(KEY_ID);
        properties.setLoginCryptoMaxSessionsPerIp(30);
        properties.setLoginCryptoWindowSeconds(60);
        properties.setLoginCryptoSessionTtlSeconds(120);
        properties.setLoginCryptoClockSkewSeconds(300);
        when(redis.opsForValue()).thenReturn(values);
        when(values.increment(anyString())).thenReturn(1L);
        when(redis.expire(anyString(), any(Duration.class))).thenReturn(true);
        doAnswer(invocation -> {
            storedSession.set(invocation.getArgument(1));
            return null;
        }).when(values).set(anyString(), anyString(), any(Duration.class));
        when(values.getAndDelete(anyString())).thenAnswer(invocation -> storedSession.getAndSet(null));
        service = new LoginCryptoService(redis, mapper, properties);
    }

    @Test
    void decryptsBrowserCompatibleEcdhHkdfAesGcmEnvelopeAndConsumesSessionOnce() throws Exception {
        LoginCryptoSessionResponse session = service.createSession("192.0.2.10");
        LoginCryptoEnvelope envelope = encryptFor(session, "alice", "correct horse battery staple");

        assertThat(service.decrypt(envelope)).isEqualTo(new LoginCredentials("alice", "correct horse battery staple"));
        assertThatThrownBy(() -> service.decrypt(envelope))
                .isInstanceOf(LoginCryptoException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rejectsAuthenticatedDataTamperingAndDoesNotReturnCredentials() throws Exception {
        LoginCryptoSessionResponse session = service.createSession("192.0.2.10");
        LoginCryptoEnvelope valid = encryptFor(session, "alice", "secret-password");
        LoginCryptoEnvelope tampered = new LoginCryptoEnvelope(valid.version(), valid.sessionId(), valid.keyId(),
                valid.clientPublicKey(), "different-request", valid.timestamp(), valid.nonce(), valid.ciphertext(), valid.tag());

        assertThatThrownBy(() -> service.decrypt(tampered)).isInstanceOf(LoginCryptoException.class);
    }

    @Test
    void rejectsMalformedAndStaleEnvelopesBeforeReadingRedis() {
        LoginCryptoEnvelope invalid = new LoginCryptoEnvelope("v2", "session", KEY_ID, Map.of(), "request",
                Instant.now().getEpochSecond(), "AA", "AA", "AA");

        assertThatThrownBy(() -> service.decrypt(invalid)).isInstanceOf(LoginCryptoException.class);
    }

    private LoginCryptoEnvelope encryptFor(LoginCryptoSessionResponse session, String username, String password)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair client = generator.generateKeyPair();
        Map<String, String> clientJwk = jwk((ECPublicKey) client.getPublic());
        ECPublicKey serverPublic = decodeJwk(session.serverPublicKey());
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(client.getPrivate());
        agreement.doPhase(serverPublic, true);
        byte[] aesKey = deriveKey(agreement.generateSecret(), session.sessionId(), session.keyId());

        String requestId = "unit-test-request-id";
        long timestamp = Instant.now().getEpochSecond();
        byte[] nonce = new byte[12];
        Arrays.fill(nonce, (byte) 7);
        String canonicalJwk = clientJwk.get("crv") + ":" + clientJwk.get("kty") + ":" + clientJwk.get("x") + ":" + clientJwk.get("y");
        byte[] aad = ("v1|" + session.sessionId() + "|" + session.keyId() + "|" + requestId + "|" + timestamp + "|" + canonicalJwk)
                .getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        byte[] ciphertextAndTag = cipher.doFinal(mapper.writeValueAsBytes(Map.of("username", username, "password", password)));
        int tagLength = 16;
        return new LoginCryptoEnvelope("v1", session.sessionId(), session.keyId(), clientJwk, requestId, timestamp,
                b64(nonce), b64(Arrays.copyOf(ciphertextAndTag, ciphertextAndTag.length - tagLength)),
                b64(Arrays.copyOfRange(ciphertextAndTag, ciphertextAndTag.length - tagLength, ciphertextAndTag.length)));
    }

    private static ECPublicKey decodeJwk(Map<String, String> jwk) throws Exception {
        byte[] x = Base64.getUrlDecoder().decode(jwk.get("x"));
        byte[] y = Base64.getUrlDecoder().decode(jwk.get("y"));
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                new java.security.spec.ECPoint(new BigInteger(1, x), new BigInteger(1, y)),
                parameters.getParameterSpec(java.security.spec.ECParameterSpec.class)));
    }

    private static Map<String, String> jwk(ECPublicKey key) {
        return Map.of("kty", "EC", "crv", "P-256", "x", b64(fixed(key.getW().getAffineX())),
                "y", b64(fixed(key.getW().getAffineY())));
    }

    private static byte[] deriveKey(byte[] secret, String sessionId, String keyId) throws Exception {
        byte[] salt = MessageDigest.getInstance("SHA-256").digest(("sso-login-v1|" + sessionId).getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(secret);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(("sso-login-aes-256-gcm|" + keyId).getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 1);
        return Arrays.copyOf(mac.doFinal(), 32);
    }

    private static byte[] fixed(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[32];
        int copy = Math.min(raw.length, result.length);
        System.arraycopy(raw, raw.length - copy, result, result.length - copy, copy);
        return result;
    }

    private static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
