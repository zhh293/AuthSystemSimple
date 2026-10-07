package com.authsystem.sso.client.starter;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import java.time.Duration;

final class SsoCookieSupport {
    private SsoCookieSupport() {
    }

    static String value(jakarta.servlet.http.HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    static void write(
        HttpServletResponse response,
        SsoClientSettings settings,
        SsoCookieCustomizer customizer,
        SsoCookieCustomizer.CookieKind kind,
        String name,
        String value,
        String path,
        Duration age) {
        Duration customized = customizer.maxAge(kind, age);
        if (customized == null || customized.isNegative()) {
            throw new IllegalArgumentException("Cookie customizer returned an invalid lifetime");
        }
        if (customized.compareTo(age) > 0) {
            customized = age;
        }

        ResponseCookie cookie = ResponseCookie.from(name, value)
        .httpOnly(true)
        .secure(settings.isSecureCookie())
        .sameSite(settings.getCookieSameSite())
        .path(path)
        .maxAge(customized)
        .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    static void clear(
        HttpServletResponse response,
        SsoClientSettings settings,
        String name,
        String path) {
        ResponseCookie cookie = ResponseCookie.from(name, "")
        .httpOnly(true)
        .secure(settings.isSecureCookie())
        .sameSite(settings.getCookieSameSite())
        .path(path)
        .maxAge(Duration.ZERO)
        .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
