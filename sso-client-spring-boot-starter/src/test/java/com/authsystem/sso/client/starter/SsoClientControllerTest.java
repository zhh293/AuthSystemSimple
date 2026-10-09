package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.session.SsoSessionService;
import com.authsystem.sso.client.session.SsoPrincipal;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

class SsoClientControllerTest {
    @Test
    void callbackSetsOnlyTheApplicationAccessCookieAndRedirectsToAQueryFreePath() throws Exception {
        SsoSessionService sessions = mock(SsoSessionService.class);
        when(sessions.browserBindingCookieName("state-value")).thenReturn("browser-binding");
        Instant expiry = Instant.now().plusSeconds(600);
        when(sessions.complete("code-value", "state-value", "binding-value"))
        .thenReturn(new SsoSessionService.Completion("access-value", new SsoPrincipal("subject", "User",
                    null, java.util.Map.of()), "/account", expiry, expiry));
        SsoClientController controller = controller(sessions);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/portal");
        request.setCookies(new Cookie("browser-binding", "binding-value"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller.callback("code-value", "state-value", null, request, response);

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo("/portal/account");
        List<String> cookies = response.getHeaders("Set-Cookie");
        assertThat(cookies).hasSize(2);
        assertThat(cookies).anyMatch(value -> value.contains("portal_access_token=access-value")
&& value.contains("HttpOnly") && value.contains("Secure"));
        assertThat(cookies).anyMatch(value -> value.contains("browser-binding=") && value.contains("Max-Age=0"));
        assertThat(String.join(" ", cookies)).doesNotContain("refresh-value", "id-token", "code-value");
        verify(sessions).complete("code-value", "state-value", "binding-value");
    }

    @Test
    void logoutRevokesAndClearsAccessCookieAfterSecurityFilterValidation() {
        SsoSessionService sessions = mock(SsoSessionService.class);
        SsoClientController controller = controller(sessions);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("portal_access_token", "access-value"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller.logout(request, response);

        verify(sessions).logout("access-value");
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(response.getHeader("Set-Cookie")).contains("portal_access_token=").contains("Max-Age=0");
    }

    @Test
    void callbackRevokesPersistedSessionWhenCookieIssuanceFails() throws Exception {
        SsoSessionService sessions = mock(SsoSessionService.class);
        when(sessions.browserBindingCookieName("state-value")).thenReturn("browser-binding");
        Instant expiry = Instant.now().plusSeconds(600);
        when(sessions.complete("code-value", "state-value", "binding-value"))
        .thenReturn(new SsoSessionService.Completion("access-value", new SsoPrincipal("subject", "User",
                    null, java.util.Map.of()), "/", expiry, expiry));
        SsoCookieCustomizer rejectingCookies = (kind, maximum) -> kind == SsoCookieCustomizer.CookieKind.ACCESS_TOKEN?Duration.ofSeconds(-1):maximum;
        SsoClientController controller = controller(sessions, rejectingCookies);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("browser-binding", "binding-value"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller.callback("code-value", "state-value", null, request, response);

        verify(sessions).logout("access-value");
        List<String> cookies = response.getHeaders("Set-Cookie");
        assertThat(cookies).anyMatch(value -> value.contains("portal_access_token=") && value.contains("Max-Age=0"));
        assertThat(cookies).anyMatch(value -> value.contains("browser-binding=") && value.contains("Max-Age=0"));
    }

    private static SsoClientController controller(SsoSessionService sessions) {
        return controller(sessions, (kind, maximum) -> maximum);
    }

    private static SsoClientController controller(SsoSessionService sessions, SsoCookieCustomizer cookies) {
        SsoClientSettings settings = new SsoClientSettings();
        return new SsoClientController(settings, "portal_access_token", sessions, cookies,
                (failure, response) -> {
            }, Clock.systemUTC());
    }
}
