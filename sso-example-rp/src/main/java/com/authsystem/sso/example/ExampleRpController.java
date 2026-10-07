package com.authsystem.sso.example;

import java.util.LinkedHashMap;
import java.util.Map;
import java.time.Duration;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.context.annotation.Profile;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.HtmlUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
@Profile("!sso-sdk")
public class ExampleRpController {
    private static final Logger LOGGER = LoggerFactory.getLogger(ExampleRpController.class);
    private final OAuth2AuthorizedClientRepository authorizedClients;
    private final ClientRegistrationRepository registrations;
    private final RestClient restClient;
    private final String revocationUri;
    private final boolean secureCookie;

    public ExampleRpController(OAuth2AuthorizedClientRepository authorizedClients,
            ClientRegistrationRepository registrations, RestClient restClient,
            @Value("${sso.revocation-uri}") String revocationUri,
            @Value("${SSO_ISSUER:http://localhost:8080}") String issuer,
            @Value("${server.servlet.session.cookie.secure:true}") boolean secureCookie) {
        this.authorizedClients = authorizedClients;
        this.registrations = registrations;
        this.restClient = restClient;
        String configuredRevocationUri = revocationUri == null || revocationUri.isBlank()
                ? issuer.replaceAll("/+$", "") + "/oauth2/revoke" : revocationUri;
        this.revocationUri = validateRevocationUri(issuer, configuredRevocationUri);
        this.secureCookie = secureCookie;
    }

    private static String validateRevocationUri(String issuer, String revocationEndpoint) {
        URI issuerUri = URI.create(issuer);
        URI endpointUri = URI.create(revocationEndpoint);
        if (!"https".equalsIgnoreCase(endpointUri.getScheme()) && !"http".equalsIgnoreCase(endpointUri.getScheme())) {
            throw new IllegalArgumentException("SSO revocation URI must use HTTP or HTTPS");
        }
        boolean sameOrigin = endpointUri.getScheme().equalsIgnoreCase(issuerUri.getScheme())
                && endpointUri.getHost() != null && issuerUri.getHost() != null
                && endpointUri.getHost().equalsIgnoreCase(issuerUri.getHost())
                && effectivePort(endpointUri) == effectivePort(issuerUri);
        if (!sameOrigin || endpointUri.getRawUserInfo() != null || endpointUri.getRawFragment() != null) {
            throw new IllegalArgumentException("SSO revocation URI must use the configured issuer origin");
        }
        return endpointUri.toString();
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() != -1) return uri.getPort();
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    @GetMapping(value = "/", produces = "text/html;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<String> home(@AuthenticationPrincipal OidcUser user, CsrfToken csrfToken,
            @RequestParam(required = false) String logout) {
        String accountState = user == null ? "Not signed in" : "Signed in with OIDC";
        String logoutState = "confirmed".equals(logout) ? "Remote token revocation was confirmed."
                : "unconfirmed".equals(logout) ? "Local sign-out completed; remote token revocation was not confirmed." : "";
        String html = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"referrer\" content=\"no-referrer\"><title>SSO Example RP</title></head><body>"
                + "<h1>SSO Example RP</h1><p>" + accountState + "</p><p>" + logoutState + "</p>"
                + "<p><a href=\"/oauth2/authorization/sso\">Sign in with SSO</a></p>"
                + "<p><a href=\"/api/me\">View the verified user profile</a></p>"
                + "<form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\""
                + HtmlUtils.htmlEscape(csrfToken.getParameterName()) + "\" value=\""
                + HtmlUtils.htmlEscape(csrfToken.getToken()) + "\"><button type=\"submit\">Sign out of this app</button></form>"
                + "</body></html>";
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("Referrer-Policy", "no-referrer")
                .header("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
                .body(html);
    }

    @GetMapping("/api/me")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> profile(@AuthenticationPrincipal OidcUser user) {
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("subject", user.getSubject());
        profile.put("name", user.getFullName());
        if (user.getEmail() != null) profile.put("email", user.getEmail());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(profile);
    }

    @PostMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        OAuth2AuthorizedClient client = authorizedClients.loadAuthorizedClient("sso", authentication, request);
        boolean remoteRevoked = revoke(client);
        authorizedClients.removeAuthorizedClient("sso", authentication, request, response);
        new SecurityContextLogoutHandler().logout(request, response, authentication);
        response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from("JSESSIONID", "")
                .httpOnly(true).secure(secureCookie).sameSite("Lax").path("/").maxAge(Duration.ZERO).build().toString());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.LOCATION, remoteRevoked ? "/?logout=confirmed" : "/?logout=unconfirmed");
        response.setStatus(HttpServletResponse.SC_SEE_OTHER);
    }

    private boolean revoke(OAuth2AuthorizedClient client) {
        if (client == null) return true;
        ClientRegistration registration = registrations.findByRegistrationId("sso");
        if (registration == null || registration.getClientSecret() == null) return false;

        OAuth2RefreshToken refreshToken = client.getRefreshToken();
        String tokenValue;
        String tokenTypeHint;
        if (refreshToken != null) {
            tokenValue = refreshToken.getTokenValue();
            tokenTypeHint = "refresh_token";
        } else {
            OAuth2AccessToken accessToken = client.getAccessToken();
            tokenValue = accessToken.getTokenValue();
            tokenTypeHint = "access_token";
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", tokenValue);
        form.add("token_type_hint", tokenTypeHint);
        try {
            var revocationResponse = restClient.post().uri(revocationUri)
                    .headers(headers -> headers.setBasicAuth(registration.getClientId(), registration.getClientSecret()))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
            return revocationResponse.getStatusCode().is2xxSuccessful();
        } catch (RestClientException e) {
            LOGGER.warn("SSO token revocation could not be confirmed; clearing the local RP session");
            return false;
        }
    }
}
