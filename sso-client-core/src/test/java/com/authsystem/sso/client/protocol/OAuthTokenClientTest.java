package com.authsystem.sso.client.protocol;

import com.authsystem.sso.client.config.SsoClientProperties;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.http.HttpMethod.POST;

class OAuthTokenClientTest {
    private static final String ISSUER = "https://issuer.example.test";
    private static final String CLIENT_ID = "portal";
    private static final String CLIENT_SECRET = "pa:ss /+";

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(GrantFlow.class)
    void doesNotRetryOneTimeAuthorizationCodeOrRefreshRequestsOnServerError(GrantFlow grantFlow) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST)).andRespond(withServerError());
        RestClient http = builder.build();
        OAuthTokenClient client = new OAuthTokenClient(http, properties(), new OidcMetadataClient(ISSUER,
                http, java.time.Clock.systemUTC(), Duration.ofMinutes(10)));

        assertThatThrownBy(() -> {
                if (grantFlow == GrantFlow.AUTHORIZATION_CODE)
                    client.exchangeCode("one-time-code", "verifier-value");
                else client.refresh("refresh-value", List.of("openid"));
            }).isInstanceOf(SsoClientDependencyException.class);
        server.verify();
    }

    @Test
    void exchangesCodeOnceUsingRfc6749FormEncodedClientSecretBasic() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        String formEncodedSecret = URLEncoder.encode(CLIENT_SECRET, StandardCharsets.UTF_8);
        String credentials = CLIENT_ID+":"+formEncodedSecret;
        String expected = "Basic "+Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST)).andExpect(header("Authorization",
                expected))
        .andExpect(content().string(org.hamcrest.Matchers.allOf(
                    org.hamcrest.Matchers.containsString("grant_type=authorization_code"),
                    org.hamcrest.Matchers.containsString("code=one-time-code"),
                    org.hamcrest.Matchers.containsString("code_verifier=verifier-value"))))
        .andRespond(withSuccess("{\"access_token\":\"opaque-access\",\"refresh_token\":\"refresh-value\",\"token_type\":\"Bearer\",\"id_token\":\"id-token\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));

        SsoClientProperties properties = properties();
        RestClient http = builder.build();
        OidcMetadataClient metadata = new OidcMetadataClient(ISSUER, http, java.time.Clock.systemUTC(),
            Duration.ofMinutes(10));
        OAuthTokenClient client = new OAuthTokenClient(http, properties, metadata);

        OAuthTokenClient.TokenResponse response = client.exchangeCode("one-time-code", "verifier-value");

        assertThat(response.accessToken()).isEqualTo("opaque-access");
        assertThat(response.refreshToken()).isEqualTo("refresh-value");
        assertThat(response.idToken()).isEqualTo("id-token");
        assertThat(response.scope()).isEqualTo("openid");
        server.verify();
    }

    @Test
    void rejectsNonBearerTokenResponses() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST))
        .andRespond(withSuccess("{\"access_token\":\"opaque-access\",\"refresh_token\":\"refresh-value\",\"token_type\":\"MAC\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));
        RestClient http = builder.build();
        SsoClientProperties properties = properties();
        OAuthTokenClient client = new OAuthTokenClient(http, properties, new OidcMetadataClient(ISSUER,
                http,
                java.time.Clock.systemUTC(), Duration.ofMinutes(10)));

        assertThatThrownBy(() -> client.exchangeCode("one-time-code", "verifier-value"))
        .isInstanceOf(IllegalStateException.class);
        server.verify();
    }

    @Test
    void rejectsScopesNotRequestedByTheClient() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST))
        .andRespond(withSuccess("{\"access_token\":\"opaque-access\",\"refresh_token\":\"refresh-value\",\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"openid email\"}",
                MediaType.APPLICATION_JSON));
        RestClient http = builder.build();
        OAuthTokenClient client = new OAuthTokenClient(http, properties(), new OidcMetadataClient(ISSUER,
                http, java.time.Clock.systemUTC(), Duration.ofMinutes(10)));

        assertThatThrownBy(() -> client.exchangeCode("one-time-code", "verifier-value"))
        .isInstanceOf(IllegalStateException.class);
        server.verify();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "", "openid openid"
        })
    void rejectsExplicitlyEmptyOrDuplicatedScopeValues(String scope) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST))
        .andRespond(withSuccess("{\"access_token\":\"opaque-access\",\"refresh_token\":\"refresh-value\",\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\""+scope+"\"}",
                MediaType.APPLICATION_JSON));
        RestClient http = builder.build();
        OAuthTokenClient client = new OAuthTokenClient(http, properties(), new OidcMetadataClient(ISSUER,
                http, java.time.Clock.systemUTC(), Duration.ofMinutes(10)));

        assertThatThrownBy(() -> client.exchangeCode("one-time-code", "verifier-value"))
        .isInstanceOf(IllegalStateException.class);
        server.verify();
    }

    @Test
    void refreshResponseWithoutScopeRetainsThePreviouslyGrantedSubset() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST))
        .andExpect(header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (CLIENT_ID + ":" + URLEncoder.encode(CLIENT_SECRET, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8))))
        .andExpect(content().string(org.hamcrest.Matchers.allOf(
                    org.hamcrest.Matchers.containsString("grant_type=refresh_token"),
                    org.hamcrest.Matchers.containsString("refresh_token=refresh-value"))))
        .andRespond(withSuccess("{\"access_token\":\"opaque-access\",\"refresh_token\":\"refresh-value\",\"token_type\":\"Bearer\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));
        RestClient http = builder.build();
        SsoClientProperties properties = properties(List.of("openid", "profile", "email"));
        OAuthTokenClient client = new OAuthTokenClient(http, properties, new OidcMetadataClient(ISSUER,
                http,
                java.time.Clock.systemUTC(), Duration.ofMinutes(10)));

        OAuthTokenClient.TokenResponse response = client.refresh("refresh-value", List.of("openid"));

        assertThat(response.scope()).isEqualTo("openid");
        server.verify();
    }

    private SsoClientProperties properties() {
        return properties(List.of("openid"));
    }
    private SsoClientProperties properties(List<String> scopes) {
        String key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        return new SsoClientProperties(ISSUER, CLIENT_ID, CLIENT_SECRET, ISSUER+"/callback", "portal_access_token",
            "/", "Lax",
            Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30),
            Duration.ofHours(12),
            scopes, List.of("/**"), true, false, key, key, "sso:rp");
    }

    private enum GrantFlow {
        AUTHORIZATION_CODE, REFRESH_TOKEN
    }
}
