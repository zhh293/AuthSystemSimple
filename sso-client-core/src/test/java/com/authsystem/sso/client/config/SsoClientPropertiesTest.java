package com.authsystem.sso.client.config;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.List;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class SsoClientPropertiesTest {
    private SsoClientProperties properties(boolean secure, String sameSite) {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        return new SsoClientProperties("https://sso.example.test", "portal", "secret", "https://rp.example.test/sso/callback",
            "portal_access_token", "/", "Lax", Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4),
            Duration.ofSeconds(30), Duration.ofHours(12), List.of("openid", "profile", "resource.read"),
            List.of("/app/**"),
            secure, false, key, key, "sso:rp");
    }
    @Test void acceptsSafeProductionConfiguration() {
        assertEquals("https://sso.example.test", properties(true, "Lax").issuer());
    }
    @Test void rejectsInsecureSameSiteNone() {
        assertThrows(IllegalArgumentException.class, () -> new SsoClientProperties("http://localhost:8080",
                "portal", "secret", "http://localhost:8082/cb", "portal_at", "/", "None", Duration.ofMinutes(5),
                Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30), Duration.ofHours(1),
                List.of("openid"),
                List.of(), false, true, "a", "b", "sso:rp"));
    }
    @Test void rejectsInsecureTransportOutsideExplicitLocalDevelopment() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        assertThrows(IllegalArgumentException.class, () -> new SsoClientProperties("http://sso.example.test",
                "portal", "secret", "https://rp.example.test/cb", "portal_at", "/", "Lax", Duration.ofMinutes(5),
                Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30), Duration.ofHours(1),
                List.of("openid"),
                List.of(), true, true, key, key, "sso:rp"));
        assertThrows(IllegalArgumentException.class, () -> new SsoClientProperties("https://sso.example.test",
                "portal", "secret", "http://rp.example.test/cb", "portal_at", "/", "Lax", Duration.ofMinutes(5),
                Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30), Duration.ofHours(1),
                List.of("openid"),
                List.of(), true, true, key, key, "sso:rp"));
    }
    @Test void rejectsDuplicateScopes() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        assertThrows(IllegalArgumentException.class, () -> new SsoClientProperties("https://sso.example.test",
                "portal", "secret", "https://rp.example.test/cb", "portal_at", "/", "Lax", Duration.ofMinutes(5),
                Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30), Duration.ofHours(1),
                List.of("openid",
                    "profile", "profile"), List.of(), true, false, key, key, "sso:rp"));
    }
}
