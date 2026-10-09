package com.authsystem.sso.security;

import com.authsystem.sso.config.SsoProperties;
import com.authsystem.sso.observability.SsoMetrics;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TgcAuthenticationFilterTest {
    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void preservesAuthenticatedOAuthClientOnTokenRequestWithoutBrowserTgc() throws Exception {
        TgcAuthenticationFilter filter = new TgcAuthenticationFilter(
                new SsoProperties(), mock(SecurityContextRepository.class), mock(SsoMetrics.class));
        OAuth2ClientAuthenticationToken client = mock(OAuth2ClientAuthenticationToken.class);
        when(client.isAuthenticated()).thenReturn(true);
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(client);
        SecurityContextHolder.setContext(context);

        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(new MockHttpServletRequest("POST", "/oauth2/token"),
                new MockHttpServletResponse(), chain);

        verify(chain).doFilter(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
        Authentication actual = SecurityContextHolder.getContext().getAuthentication();
        assertSame(client, actual);
    }
}
