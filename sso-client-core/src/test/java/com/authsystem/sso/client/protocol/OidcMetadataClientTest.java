package com.authsystem.sso.client.protocol;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.Clock;
import java.time.Duration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class OidcMetadataClientTest {
    private static final String ISSUER = "https://issuer.example.test";
    private static final String DISCOVERY = ISSUER + "/.well-known/openid-configuration";

    @Test
    void loadsOnlySameOriginEndpointsAndCachesMetadata() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(DISCOVERY)).andRespond(withSuccess(metadata(ISSUER,
                    ISSUER + "/authorize", ISSUER + "/token", ISSUER + "/jwks"), MediaType.APPLICATION_JSON));
        OidcMetadataClient client = new OidcMetadataClient(ISSUER, builder.build(), Clock.systemUTC(),
            Duration.ofMinutes(10));

        OidcProviderMetadata first = client.get();
        OidcProviderMetadata second = client.get();

        assertThat(first).isSameAs(second);
        assertThat(first.tokenEndpoint().toString()).isEqualTo(ISSUER + "/token");
        server.verify();
    }

    @Test
    void rejectsDiscoveryMetadataWithDifferentIssuer() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(DISCOVERY)).andRespond(withSuccess(metadata("https://attacker.example.test",
                    ISSUER + "/authorize", ISSUER + "/token", ISSUER + "/jwks"), MediaType.APPLICATION_JSON));
        OidcMetadataClient client = new OidcMetadataClient(ISSUER, builder.build(), Clock.systemUTC(),
            Duration.ofMinutes(10));

        assertThatThrownBy(client::get).isInstanceOf(IllegalStateException.class).hasMessageContaining("issuer metadata mismatch");
        server.verify();
    }

    @Test
    void rejectsCrossOriginTokenAndSigningKeyEndpoints() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(DISCOVERY)).andRespond(withSuccess(metadata(ISSUER,
                    ISSUER + "/authorize", "https://attacker.example.test/token", ISSUER + "/jwks"), MediaType.APPLICATION_JSON));
        OidcMetadataClient client = new OidcMetadataClient(ISSUER, builder.build(), Clock.systemUTC(),
            Duration.ofMinutes(10));

        assertThatThrownBy(client::get).isInstanceOf(IllegalStateException.class).hasMessageContaining("outside the trusted issuer origin");
        server.verify();
    }

    private static String metadata(String issuer, String authorization, String token, String jwks) {
        return "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + authorization
        + "\",\"token_endpoint\":\"" + token + "\",\"jwks_uri\":\"" + jwks + "\"}";
    }
}
