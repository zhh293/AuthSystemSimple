package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.protocol.AuthorizationRequestFactory;
import com.authsystem.sso.client.session.SsoCurrentUser;
import com.authsystem.sso.client.session.SsoSessionService;
import com.authsystem.sso.client.protocol.SsoClientDependencyException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.time.Clock;

@RestController
public final class SsoClientController {
    private final SsoClientSettings settings;
    private final String accessCookie;
    private final SsoSessionService sessions;
    private final SsoCookieCustomizer cookies;
    private final SsoFailureHandler failures;
    private final Clock clock;
    SsoClientController(SsoClientSettings settings, String accessCookie, SsoSessionService sessions, SsoCookieCustomizer cookies,
        SsoFailureHandler failures, Clock clock) {
        this.settings = settings;
        this.accessCookie = accessCookie;
        this.sessions = sessions;
        this.cookies = cookies;
        this.failures = failures;
        this.clock = clock;
    }

    @GetMapping("${sso.client.login-path:/sso/login}")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String returnTo = request.getParameter(settings.getReturnToParameter());
            var login = sessions.beginLogin(AuthorizationRequestFactory.safeReturnPath(returnTo));
            SsoCookieSupport.write(response, settings, cookies, SsoCookieCustomizer.CookieKind.BROWSER_TRANSACTION,
                login.browserBindingCookieName(), login.browserBinding(), settings.getCallbackPath(),
                settings.getTransactionTtl());
            response.sendRedirect(login.authorizationUri());
        } catch (SsoClientDependencyException unavailable) {
            failures.handle(SsoFailureHandler.Failure.DEPENDENCY_UNAVAILABLE, response);
        } catch (RuntimeException failure) {
            failures.handle(SsoFailureHandler.Failure.AUTHENTICATION_REJECTED, response);
        }
    }

    @GetMapping("${sso.client.callback-path:/sso/callback}")
    public void callback(@RequestParam(name = "code", required = false) String code, @RequestParam(name = "state",
            required = false) String state,
        @RequestParam(name = "error", required = false) String error, HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
        SsoSessionService.Completion completed = null;
        try {
            if (error != null || code == null || code.length()>4096 || state == null || state.length()>512) {
                sessions.cancelAuthorization(state);
                throw new IllegalArgumentException("Callback rejected");
            }
            String bindingCookieName = sessions.browserBindingCookieName(state);
            completed = sessions.complete(code, state, SsoCookieSupport.value(request, bindingCookieName));
            Duration age = Duration.between(clock.instant(), completed.refreshFamilyExpiresAt());
            SsoCookieSupport.write(response, settings, cookies, SsoCookieCustomizer.CookieKind.ACCESS_TOKEN,
                accessCookie, completed.accessToken(), settings.getCookiePath(), age);
            SsoCookieSupport.clear(response, settings, sessions.browserBindingCookieName(state), settings.getCallbackPath());
            response.sendRedirect(request.getContextPath()+AuthorizationRequestFactory.safeReturnPath(completed.returnPath()));
        } catch (SsoClientDependencyException unavailable) {
            cleanupUndeliveredSession(completed, response);
            clearBindingCookie(response, state);
            failures.handle(SsoFailureHandler.Failure.DEPENDENCY_UNAVAILABLE, response);
        } catch (RuntimeException failure) {
            cleanupUndeliveredSession(completed, response);
            clearBindingCookie(response, state);
            failures.handle(SsoFailureHandler.Failure.AUTHENTICATION_REJECTED, response);
        } catch (IOException responseFailure) {
            cleanupUndeliveredSession(completed, response);
            clearBindingCookie(response, state);
            throw responseFailure;
        }
    }

    private void cleanupUndeliveredSession(SsoSessionService.Completion completed, HttpServletResponse response) {
        if (completed == null)
            return;
        try {
            sessions.logout(completed.accessToken());
        } catch (RuntimeException ignored) {
        }
        try {
            SsoCookieSupport.clear(response, settings, accessCookie, settings.getCookiePath());
        } catch (RuntimeException ignored) {
        }
    }

    @PostMapping("${sso.client.logout-path:/sso/logout}")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        if (!(request.getAttribute(org.springframework.security.web.csrf.CsrfToken.class.getName()) instanceof org.springframework.security.web.csrf.CsrfToken)) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }
        String token = SsoCookieSupport.value(request, accessCookie);
        try {
            if (token != null && !token.isBlank())
                sessions.logout(token);
            response.setStatus(HttpStatus.NO_CONTENT.value());
        } finally {
            SsoCookieSupport.clear(response, settings, accessCookie, settings.getCookiePath());
        }
    }

    @GetMapping("${sso.client.status-path:/sso/status}")
    public Map<String, Object> status() {
        if (!settings.isStatusEnabled())
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND);
        return SsoCurrentUser.get().<Map<String, Object>>map(user -> Map.of("authenticated", true, "subject",
                user.subject()))
        .orElseGet(() -> Map.of("authenticated", false));
    }

    private void clearBindingCookie(HttpServletResponse response, String state) {
        String cookieName = sessions.browserBindingCookieName(state);
        if (cookieName != null)
            SsoCookieSupport.clear(response, settings, cookieName, settings.getCallbackPath());
    }

}
