package com.authsystem.sso.client.protocol;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import java.time.Instant;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdTokenValidatorTest {
    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final Instant now = Instant.parse("2026-10-01T12:00:00Z");
    private final IdTokenValidator validator = new IdTokenValidator(decoder, "https://sso.example.test",
        "portal", java.time.Clock.fixed(now, java.time.ZoneOffset.UTC), java.time.Duration.ofSeconds(60));
    private Jwt jwt(String issuer, List<String> audiences, String nonce) {
        return jwt(issuer, audiences, nonce, "user-1");
    }
    private Jwt jwt(String issuer, List<String> audiences, String nonce, String subject) {
        return Jwt.withTokenValue("verified-by-decoder").header("alg", "RS256").issuer(issuer).subject(subject).audience(audiences).issuedAt(now.minusSeconds(10)).expiresAt(now.plusSeconds(300)).claim("nonce",
            nonce).claim("name", "User").build();
    }
    @Test void acceptsExpectedIssuerAudienceAndNonce() throws Exception {
        when(decoder.decode("compact")).thenReturn(jwt("https://sso.example.test", List.of("portal"),
                "n-1"));
        var claims = validator.validate("compact", "n-1");
        assertEquals("user-1", claims.subject());
        assertEquals("User", claims.claims().get("name"));
    }
    @Test void rejectsWrongIssuerAudienceAndNonce() throws Exception {
        when(decoder.decode("wrong-issuer")).thenReturn(jwt("https://other.example.test", List.of("portal"),
                "n-1"));
        when(decoder.decode("wrong-aud")).thenReturn(jwt("https://sso.example.test", List.of("other"),
                "n-1"));
        when(decoder.decode("wrong-nonce")).thenReturn(jwt("https://sso.example.test", List.of("portal"),
                "other"));
        assertThrows(IllegalArgumentException.class, () -> validator.validate("wrong-issuer", "n-1"));
        assertThrows(IllegalArgumentException.class, () -> validator.validate("wrong-aud", "n-1"));
        assertThrows(IllegalArgumentException.class, () -> validator.validate("wrong-nonce", "n-1"));
    }
    @Test void refreshIdTokenMustKeepTheExistingSubjectAndAnyReturnedNonce() throws Exception {
        when(decoder.decode("refresh-token")).thenReturn(jwt("https://sso.example.test", List.of("portal"),
                "login-nonce", "user-1"));
        when(decoder.decode("wrong-nonce")).thenReturn(jwt("https://sso.example.test", List.of("portal"),
                "other-nonce", "user-1"));
        when(decoder.decode("changed-subject")).thenReturn(jwt("https://sso.example.test", List.of("portal"),
                "login-nonce", "user-2"));
        when(decoder.decode("without-nonce")).thenReturn(jwt("https://sso.example.test", List.of("portal"),
                null, "user-1"));
        String nonceDigest = com.authsystem.sso.client.crypto.TokenDigests.sha256("login-nonce");
        assertEquals("user-1", validator.validateRefresh("refresh-token", "user-1", nonceDigest).subject());
        assertEquals("user-1", validator.validateRefresh("without-nonce", "user-1", nonceDigest).subject());
        assertThrows(IllegalArgumentException.class, () -> validator.validateRefresh("wrong-nonce", "user-1",
                nonceDigest));
        assertThrows(IllegalArgumentException.class, () -> validator.validateRefresh("changed-subject",
                "user-1", nonceDigest));
    }
}
