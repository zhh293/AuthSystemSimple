package com.authsystem.sso.client.protocol;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthorizationRequestFactoryTest {
    @Test void allowsOnlySameOriginRelativeReturnPaths() {
        assertEquals("/account?tab=profile", AuthorizationRequestFactory.safeReturnPath("/account?tab=profile"));
        assertEquals("/", AuthorizationRequestFactory.safeReturnPath("https://evil.example/"));
        assertEquals("/", AuthorizationRequestFactory.safeReturnPath("//evil.example/path"));
        assertEquals("/", AuthorizationRequestFactory.safeReturnPath("/%2f%2fevil.example/"));
        assertEquals("/", AuthorizationRequestFactory.safeReturnPath("/\\\\evil.example"));
        assertEquals("/", AuthorizationRequestFactory.safeReturnPath("/a/%25252525252f%252f%252fevil.example"));
        assertEquals("/", AuthorizationRequestFactory.safeReturnPath("/a/%2e%2e/admin"));
        assertEquals("/", AuthorizationRequestFactory.safeReturnPath("/"+"a".repeat(4096)));
    }
    @Test void browserBindingCookieNameIsClientScopedAndStateDerived() {
        byte[] key = new byte[32];
        String name = AuthorizationRequestFactory.browserBindingCookieName("portal", "state-value", key);
        assertEquals("portal_sso_tx_"+com.authsystem.sso.client.crypto.TokenDigests.hmacSha256("state-value",
                key).substring(0, 22), name);
        assertNotEquals(name, AuthorizationRequestFactory.browserBindingCookieName("another-client", "state-value",
                key));
    }
}
