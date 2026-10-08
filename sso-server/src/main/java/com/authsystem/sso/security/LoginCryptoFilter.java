package com.authsystem.sso.security;

import com.authsystem.sso.crypto.LoginCryptoEnvelope;
import com.authsystem.sso.crypto.LoginCryptoService;
import com.authsystem.sso.config.SsoProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.stereotype.Component;

@Component
public final class LoginCryptoFilter extends OncePerRequestFilter {
    public static final String CREDENTIALS_ATTRIBUTE = LoginCryptoFilter.class.getName() + ".credentials";
    private final LoginCryptoService crypto;
    private final ObjectMapper mapper;
    private final SsoProperties properties;
    public LoginCryptoFilter(LoginCryptoService crypto, ObjectMapper mapper, SsoProperties properties) { this.crypto = crypto; this.mapper = mapper; this.properties = properties; }
    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        return !properties.isLoginCryptoEnabled() || !"POST".equalsIgnoreCase(request.getMethod()) || !"/login/submit".equals(request.getRequestURI());
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            if (request.getContentType() == null || !request.getContentType().toLowerCase().startsWith(MediaType.APPLICATION_JSON_VALUE)) throw new IllegalArgumentException();
            if (request.getContentLengthLong() > 65536) throw new IllegalArgumentException();
            LoginCryptoEnvelope envelope = mapper.readValue(request.getInputStream(), LoginCryptoEnvelope.class);
            request.setAttribute(CREDENTIALS_ATTRIBUTE, crypto.decrypt(envelope));
        } catch (Exception e) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setHeader("Referrer-Policy", "no-referrer");
            response.setStatus(HttpServletResponse.SC_SEE_OTHER);
            response.setHeader(HttpHeaders.LOCATION, "/login?error=true");
            return;
        }
        chain.doFilter(request, response);
    }
}
