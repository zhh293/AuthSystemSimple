package com.authsystem.sso.security;

import com.authsystem.sso.config.SsoProperties;
import com.authsystem.sso.contracts.IdentityService;
import com.authsystem.sso.contracts.dto.SessionLookupRequest;
import com.authsystem.sso.contracts.dto.SessionView;
import com.authsystem.sso.observability.SsoMetrics;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.dubbo.config.annotation.DubboReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class TgcAuthenticationFilter extends OncePerRequestFilter {
    private final SsoProperties properties;
    private final SecurityContextRepository securityContextRepository;
    private final SsoMetrics metrics;
    @DubboReference(version = "1.0.0", check = false)
    private IdentityService identityService;

    public TgcAuthenticationFilter(SsoProperties properties, SecurityContextRepository securityContextRepository,
            SsoMetrics metrics) {
        this.properties = properties;
        this.securityContextRepository = securityContextRepository;
        this.metrics = metrics;
    }

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return "/logout".equals(path) && "POST".equals(request.getMethod());
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String tgc = readTgc(request);
        SessionView session;
        try {
            session = tgc == null ? null : identityService.findSession(new SessionLookupRequest(tgc));
        } catch (RuntimeException e) {
            failClosed(request, response);
            return;
        }
        if (tgc != null && (session == null || session.isActive()
                && (session.getSubject() == null || session.getSubject().isBlank()))) {
            failClosed(request, response);
            return;
        }
        if (session != null && session.isActive() && session.getSubject() != null && !session.getSubject().isBlank()) {
            Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(session.getSubject(), null,
                    AuthorityUtils.createAuthorityList("ROLE_USER"));
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);
        } else {
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);
            if (tgc != null) {
                ResponseCookie expired = ResponseCookie.from(properties.getSessionCookie(), "").httpOnly(true)
                        .secure(properties.isCookieSecure()).sameSite("Lax").path(properties.getCookiePath()).maxAge(0).build();
                response.addHeader(HttpHeaders.SET_COOKIE, expired.toString());
            }
        }
        filterChain.doFilter(request, response);
    }

    private void failClosed(HttpServletRequest request, HttpServletResponse response) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        metrics.session(SsoMetrics.SessionOutcome.DEPENDENCY_ERROR);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
    }

    private String readTgc(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) if (properties.getSessionCookie().equals(cookie.getName())) return cookie.getValue();
        return null;
    }
}
