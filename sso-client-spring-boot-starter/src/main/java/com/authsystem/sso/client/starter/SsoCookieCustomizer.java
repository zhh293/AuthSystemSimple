package com.authsystem.sso.client.starter;

import java.time.Duration;

/** May shorten cookie lifetime; mandatory Secure/HttpOnly/SameSite/path settings remain SDK controlled. */
@FunctionalInterface
public interface SsoCookieCustomizer {
    Duration maxAge(CookieKind kind, Duration maximum);
    enum CookieKind {
        ACCESS_TOKEN, BROWSER_TRANSACTION
    }
}
