package com.authsystem.sso.web;

import com.authsystem.sso.config.SsoProperties;
import com.authsystem.sso.contracts.IdentityService;
import com.authsystem.sso.contracts.dto.AuthenticationRequest;
import com.authsystem.sso.contracts.dto.AuthenticationResult;
import com.authsystem.sso.contracts.dto.SessionLookupRequest;
import com.authsystem.sso.observability.SsoMetrics;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.ServletException;
import java.io.IOException;
import org.apache.dubbo.config.annotation.DubboReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {
    private final SsoProperties properties;
    private final SecurityContextRepository securityContextRepository;
    private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
    private final SsoMetrics metrics;
    @DubboReference(version = "1.0.0", check = false)
    private IdentityService identityService;

    public LoginController(SsoProperties properties, SecurityContextRepository securityContextRepository,
            SessionAuthenticationStrategy sessionAuthenticationStrategy, SsoMetrics metrics) {
        this.properties = properties;
        this.securityContextRepository = securityContextRepository;
        this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
        this.metrics = metrics;
    }

    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    public String loginPage(HttpServletRequest request, HttpServletResponse response, Model model) {
        CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrf == null) csrf = (CsrfToken) request.getAttribute("_csrf");
        if (csrf == null) throw new IllegalStateException("CSRF token unavailable");
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        model.addAttribute("csrf", csrf);
        model.addAttribute("loginError", "true".equals(request.getParameter("error")));
        return "login";
    }

    @PostMapping(value = "/login/submit", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public void login(@RequestParam String username, @RequestParam String password, HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (username.length() > 128 || password.length() > 1024) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setStatus(HttpServletResponse.SC_SEE_OTHER);
            response.setHeader(HttpHeaders.LOCATION, "/login?error=true");
            return;
        }
        AuthenticationResult result;
        try {
            result = identityService.authenticate(new AuthenticationRequest(username, password, request.getRemoteAddr()));
        } catch (RuntimeException e) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setHeader("Referrer-Policy", "no-referrer");
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return;
        }
        if (result == null) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setHeader("Referrer-Policy", "no-referrer");
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return;
        }
        if (!result.isAuthenticated()) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setStatus(HttpServletResponse.SC_SEE_OTHER);
            response.setHeader(HttpHeaders.LOCATION, "/login?error=true");
            return;
        }
        if (result.getSessionCookieValue() == null || result.getSessionCookieValue().isBlank()
                || result.getSubject() == null || result.getSubject().isBlank() || result.getExpiresInSeconds() <= 0) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setHeader("Referrer-Policy", "no-referrer");
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return;
        }
        ResponseCookie cookie = ResponseCookie.from(properties.getSessionCookie(), result.getSessionCookieValue())
                .httpOnly(true).secure(properties.isCookieSecure()).sameSite("Lax").path(properties.getCookiePath())
                .maxAge(result.getExpiresInSeconds()).build();
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        var authentication = UsernamePasswordAuthenticationToken.authenticated(result.getSubject(), null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        sessionAuthenticationStrategy.onAuthentication(authentication, request, response);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        new SavedRequestAwareAuthenticationSuccessHandler().onAuthenticationSuccess(request, response, authentication);
    }

    @GetMapping("/session")
    @ResponseBody
    public java.util.Map<String, Boolean> session() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean authenticated = authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof org.springframework.security.authentication.AnonymousAuthenticationToken);
        return java.util.Map.of("authenticated", authenticated);
    }

    @PostMapping("/logout")
    @ResponseBody
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        metrics.logout();
        String tgc = readSessionCookie(request);
        boolean remoteRevocationConfirmed = true;
        try {
            identityService.revokeSession(new SessionLookupRequest(tgc));
        } catch (RuntimeException e) {
            remoteRevocationConfirmed = false;
        } finally {
            if (!remoteRevocationConfirmed) metrics.logoutDependencyFailure();
            new SecurityContextLogoutHandler().logout(request, response, SecurityContextHolder.getContext().getAuthentication());
            ResponseCookie expired = ResponseCookie.from(properties.getSessionCookie(), "").httpOnly(true).secure(properties.isCookieSecure())
                    .sameSite("Lax").path(properties.getCookiePath()).maxAge(0).build();
            response.addHeader(HttpHeaders.SET_COOKIE, expired.toString());
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setHeader("Referrer-Policy", "no-referrer");
            response.setStatus(remoteRevocationConfirmed ? HttpServletResponse.SC_NO_CONTENT : HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }

    private String readSessionCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) if (properties.getSessionCookie().equals(cookie.getName())) return cookie.getValue();
        return null;
    }

}
