package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.session.SsoSessionService;
import com.authsystem.sso.client.session.SsoPrincipal;
import com.authsystem.sso.client.session.SsoTokenRecord;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SsoAuthenticationFilterTest {
    @Test
    void redirectUsesConfiguredReturnParameterAndOmitsServletContextPath() throws ServletException, IOException {
        SsoClientSettings settings = new SsoClientSettings();
        settings.setProtectedPaths(List.of("/**"));
        settings.setPublicPaths(List.of());
        settings.setReturnToParameter("next");
        SsoSessionService sessions = mock(SsoSessionService.class);
        SsoAuthenticationFilter filter = new SsoAuthenticationFilter(settings, "portal_access_token",
            sessions,
                (kind, maximum) -> maximum, new DefaultSsoFailureHandler(), Clock.systemUTC());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/private/page");
        request.setContextPath("/app");
        request.setQueryString("tab=profile");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getRedirectedUrl()).isEqualTo("/app/sso/login?next=%2Fprivate%2Fpage%3Ftab%3Dprofile");
        verifyNoInteractions(sessions);
    }

    @Test
    void apiDetectionUsesApplicationPathWhenDeployedUnderAContextPath() throws ServletException, IOException {
        SsoClientSettings settings = new SsoClientSettings();
        settings.setProtectedPaths(List.of("/**"));
        settings.setPublicPaths(List.of());
        SsoAuthenticationFilter filter = new SsoAuthenticationFilter(settings, "portal_access_token",
            mock(SsoSessionService.class),
                (kind, maximum) -> maximum, new DefaultSsoFailureHandler(), Clock.systemUTC());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/api/orders");
        request.setContextPath("/app");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("authentication_failed");
    }

    @Test
    void failedCookieWriteAfterRefreshRevokesAndClearsTheRotatedSession() throws ServletException, IOException {
        SsoClientSettings settings = new SsoClientSettings();
        settings.setProtectedPaths(List.of("/**"));
        settings.setPublicPaths(List.of());
        SsoSessionService sessions = mock(SsoSessionService.class);
        Instant now = Instant.now();
        SsoTokenRecord record = new SsoTokenRecord("https://issuer.example.test", "portal", "digest",
            "encrypted",
            "primary",
            new SsoPrincipal("subject", "User", null, java.util.Map.of()), now.plusSeconds(300), now.plusSeconds(3600));
        when(sessions.resolve("old-access-token")).thenReturn(java.util.Optional.of(new SsoSessionService.Session("new-access-token",
                    record, true)));
        SsoAuthenticationFilter filter = new SsoAuthenticationFilter(settings, "portal_access_token",
            sessions,
                (kind, maximum) -> kind == SsoCookieCustomizer.CookieKind.ACCESS_TOKEN?java.time.Duration.ofSeconds(-1):maximum,
            new DefaultSsoFailureHandler(), Clock.systemUTC());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/private/page");
        request.setCookies(new jakarta.servlet.http.Cookie("portal_access_token", "old-access-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        verify(sessions).logout("new-access-token");
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getHeader("Set-Cookie")).contains("portal_access_token=").contains("Max-Age=0");
        assertThat(chain.getRequest()).isNull();
    }
}
