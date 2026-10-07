package com.authsystem.sso.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import com.authsystem.sso.storage.UserAccountRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/** Handles OIDC UserInfo using opaque access-token lookup, without persisting ID Token claims. */
@Component
public class OpaqueUserInfoFilter extends OncePerRequestFilter {
    private final String endpointPath;
    private final OAuth2AuthorizationService authorizations;
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final UserAccountRepository accountRepository;

    public OpaqueUserInfoFilter(AuthorizationServerSettings settings, OAuth2AuthorizationService authorizations,
            JdbcTemplate jdbc, ObjectMapper objectMapper, UserAccountRepository users) {
        this.endpointPath = settings.getOidcUserInfoEndpoint();
        this.authorizations = authorizations;
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.accountRepository = users;
    }

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !endpointPath.equals(path);
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        if (!"GET".equals(request.getMethod()) && !"POST".equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            response.setHeader(HttpHeaders.ALLOW, "GET, POST");
            return;
        }
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            unauthorized(response);
            return;
        }
        String tokenValue = authorizationHeader.substring(7);
        if (!StringUtils.hasText(tokenValue) || tokenValue.length() > 4096 || tokenValue.chars().anyMatch(Character::isWhitespace)) {
            unauthorized(response);
            return;
        }
        OAuth2Authorization authorization = authorizations.findByToken(tokenValue, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            unauthorized(response);
            return;
        }
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        if (accessToken == null || !accessToken.isActive()) {
            unauthorized(response);
            return;
        }
        if (!accessToken.getToken().getScopes().contains(OidcScopes.OPENID)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"insufficient_scope\"");
            return;
        }

        try {
            if (!accountRepository.isEnabledBySubject(authorization.getPrincipalName())) {
                unauthorized(response);
                return;
            }
        } catch (RuntimeException e) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setHeader(HttpHeaders.RETRY_AFTER, "1");
            return;
        }

        List<UserProfile> profiles = jdbc.query(
                "select subject_id, display_name, email, email_verified from sso_user where subject_id = ?",
                (rs, row) -> new UserProfile(rs.getString("subject_id"), rs.getString("display_name"),
                        rs.getString("email"), rs.getBoolean("email_verified")), authorization.getPrincipalName());
        if (profiles.isEmpty()) {
            unauthorized(response);
            return;
        }
        UserProfile user = profiles.get(0);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", user.subject());
        if (accessToken.getToken().getScopes().contains(OidcScopes.PROFILE)
                && user.name() != null && !user.name().isBlank()) claims.put("name", user.name());
        if (accessToken.getToken().getScopes().contains(OidcScopes.EMAIL)
                && user.email() != null && !user.email().isBlank()) {
            claims.put("email", user.email());
            claims.put("email_verified", user.emailVerified());
        }
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), claims);
    }

    private void unauthorized(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
    }

    private record UserProfile(String subject, String name, String email, boolean emailVerified) { }
}
