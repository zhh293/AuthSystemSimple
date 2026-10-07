package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.session.SsoAuthentication;
import com.authsystem.sso.client.session.SsoSessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.AntPathMatcher;
import java.io.IOException;
import java.time.Duration;
import java.time.Clock;

public final class SsoAuthenticationFilter extends OncePerRequestFilter {
    private final SsoClientSettings settings;
    private final String cookieName;
    private final SsoSessionService sessions;
    private final SsoCookieCustomizer cookies;
    private final SsoFailureHandler failures;
    private final Clock clock;
    private final AntPathMatcher paths = new AntPathMatcher();
    SsoAuthenticationFilter(SsoClientSettings settings, String cookieName, SsoSessionService sessions,
        SsoCookieCustomizer cookies,
        SsoFailureHandler failures, Clock clock) {
        this.settings = settings;
        this.cookieName = cookieName;
        this.sessions = sessions;
        this.cookies = cookies;
        this.failures = failures;
        this.clock = clock;
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (path.equals(settings.getLoginPath()) || path.equals(settings.getCallbackPath()) || path.equals(settings.getLogoutPath())
|| matches(settings.getPublicPaths(), path) || !matches(settings.getProtectedPaths(), path)) {
            chain.doFilter(request, response);
            return;
        }
        String token = SsoCookieSupport.value(request, cookieName);
        if (token != null && !token.isBlank()) {
            try {
                var session = sessions.resolve(token);
                if (session.isPresent()) {
                    var value = session.get();
                    SecurityContextHolder.getContext().setAuthentication(new SsoAuthentication(value.record().principal()));
                    if (value.refreshed())
                        try {
                        SsoCookieSupport.write(response, settings, cookies, SsoCookieCustomizer.CookieKind.ACCESS_TOKEN,
                            cookieName, value.accessToken(), settings.getCookiePath(), Duration.between(clock.instant(),
                                value.record().refreshFamilyExpiresAt()));
                    } catch (RuntimeException cookieFailure) {
                        SecurityContextHolder.clearContext();
                        try {
                            sessions.logout(value.accessToken());
                        } catch (RuntimeException ignored) {
                        }
                        try {
                            SsoCookieSupport.clear(response, settings, cookieName, settings.getCookiePath());
                        } catch (RuntimeException ignored) {
                        }
                        failures.handle(SsoFailureHandler.Failure.DEPENDENCY_UNAVAILABLE, response);
                        return;
                    }
                    chain.doFilter(request, response);
                    return;
                }
            } catch (RuntimeException dependencyFailure) {
                failures.handle(SsoFailureHandler.Failure.DEPENDENCY_UNAVAILABLE, response);
                return;
            }
            SsoCookieSupport.clear(response, settings, cookieName, settings.getCookiePath());
        }
        if (settings.isApiUnauthorizedAsJson() && (path.startsWith("/api/") || request.getHeader("Accept") != null &&
                request.getHeader("Accept").contains(MediaType.APPLICATION_JSON_VALUE))) {
            failures.handle(SsoFailureHandler.Failure.AUTHENTICATION_REJECTED, response);
            return;
        }
        String returnTo = path+(request.getQueryString() == null?"":"?"+request.getQueryString());
        response.sendRedirect(request.getContextPath()+settings.getLoginPath()+"?"+java.net.URLEncoder.encode(settings.getReturnToParameter(),
                java.nio.charset.StandardCharsets.UTF_8)+"="+java.net.URLEncoder.encode(com.authsystem.sso.client.protocol.AuthorizationRequestFactory.safeReturnPath(returnTo),
                java.nio.charset.StandardCharsets.UTF_8));
    }
    private boolean matches(java.util.List<String> patterns, String path) {
        return patterns != null && patterns.stream().anyMatch(pattern -> paths.match(pattern, path));
    }
}
