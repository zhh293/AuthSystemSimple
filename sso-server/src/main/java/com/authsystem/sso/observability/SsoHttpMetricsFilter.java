package com.authsystem.sso.observability;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Measures selected protocol and login endpoints using a fixed route allowlist. */
@Component
public final class SsoHttpMetricsFilter extends OncePerRequestFilter {
    private static final Map<String, String> ENDPOINTS = Map.ofEntries(
            Map.entry("/oauth2/authorize", "authorize"),
            Map.entry("/oauth2/token", "token"),
            Map.entry("/oauth2/revoke", "revoke"),
            Map.entry("/oauth2/jwks", "jwks"),
            Map.entry("/userinfo", "userinfo"),
            Map.entry("/.well-known/openid-configuration", "discovery"),
            Map.entry("/login", "login"),
            Map.entry("/login/submit", "login_submit"),
            Map.entry("/logout", "logout"));

    private final SsoMetrics metrics;

    public SsoHttpMetricsFilter(SsoMetrics metrics) {
        this.metrics = metrics;
    }

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !ENDPOINTS.containsKey(path);
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        String endpoint = ENDPOINTS.get(path);
        long startedAt = System.nanoTime();
        String statusClass = "exception";
        try {
            filterChain.doFilter(request, response);
            int statusGroup = response.getStatus() / 100;
            statusClass = statusGroup >= 1 && statusGroup <= 5 ? statusGroup + "xx" : "other";
        } catch (IOException | ServletException | RuntimeException exception) {
            throw exception;
        } finally {
            metrics.httpRequest(endpoint, statusClass, Duration.ofNanos(System.nanoTime() - startedAt));
        }
    }
}
