package com.authsystem.sso.client.security;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PkceTest {
    @Test void computesRfc7636S256Challenge() {
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.challengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }
    @Test void randomValuesAreUrlSafeAndHaveRequestedEntropy() {
        String value = Pkce.randomUrlSafe(32);
        assertTrue(value.matches("[A-Za-z0-9_-]{43}"));
        assertNotEquals(value, Pkce.randomUrlSafe(32));
    }
}
