package com.authsystem.sso.client.session;

import com.authsystem.sso.client.config.SsoClientProperties;
import com.authsystem.sso.client.observability.SsoClientMetrics;
import com.authsystem.sso.client.protocol.AuthorizationRequestFactory;
import com.authsystem.sso.client.protocol.IdTokenValidator;
import com.authsystem.sso.client.protocol.OAuthTokenClient;
import com.authsystem.sso.client.protocol.OidcMetadataClient;
import com.authsystem.sso.client.store.SsoAuthorizationRequestStore;
import com.authsystem.sso.client.store.SsoRefreshLock;
import com.authsystem.sso.client.store.SsoTokenStore;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.http.HttpMethod.POST;

class SsoLoginFlowTest {
    private static final String ISSUER = "https://issuer.example.test";
    private static final Instant NOW = Instant.parse("2026-05-01T12:00:00Z");

    @Test
    void beginsPkceLoginAndCompletesBoundCallbackOnce() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST))
        .andExpect(content().string(org.hamcrest.Matchers.allOf(
                    org.hamcrest.Matchers.containsString("grant_type=authorization_code"),
                    org.hamcrest.Matchers.containsString("code=authorization-code"),
                    org.hamcrest.Matchers.containsString("code_verifier="))))
        .andRespond(withSuccess("{\"access_token\":\"opaque-access\",\"refresh_token\":\"refresh-secret\",\"token_type\":\"Bearer\",\"id_token\":\"signed-id-token\",\"expires_in\":300,\"scope\":\"openid\"}",
                MediaType.APPLICATION_JSON));

        byte[] key = new byte[32];
        String secret = Base64.getEncoder().encodeToString(key);
        SsoClientProperties properties = new SsoClientProperties(ISSUER, "portal", "client-secret", "https://rp.example.test/sso/callback",
            "portal_access_token", "/", "Lax",
            Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30),
            Duration.ofHours(12),
            List.of("openid", "profile"), List.of("/**"), true, false, secret, secret, "sso:rp");
        MutableClock clock = new MutableClock(NOW);
        RestClient http = builder.build();
        OidcMetadataClient metadata = new OidcMetadataClient(ISSUER, http, clock, Duration.ofMinutes(15));
        InMemoryTransactions transactions = new InMemoryTransactions();
        InMemoryTokens tokens = new InMemoryTokens();
        AtomicReference<String> expectedNonce = new AtomicReference<>();
        JwtDecoder decoder = compact -> Jwt.withTokenValue(compact).header("alg", "RS256").issuer(ISSUER).subject("subject-1")
        .audience(List.of("portal")).issuedAt(NOW.minusSeconds(5)).expiresAt(NOW.plusSeconds(300)).claim("nonce",
            expectedNonce.get())
        .claim("name", "User").claim("email", "user@example.test").build();
        SsoSessionService service = new SsoSessionService(properties, transactions, tokens, new OAuthTokenClient(http,
                properties, metadata),
            new IdTokenValidator(decoder, ISSUER, "portal", clock, Duration.ofSeconds(60)), claims -> new SsoPrincipal(claims.subject(),
                    (String) claims.claims().get("name"), (String) claims.claims().get("email"), claims.claims()),
            metadata, clock, (family, wait, lease) -> Optional.of(() -> {
                }), new SsoClientMetrics(new SimpleMeterRegistry()), List.of());

        AuthorizationRequestFactory.LoginRequest login = service.beginLogin("/account?tab=profile");
        Map<String, String> authorization = query(URI.create(login.authorizationUri()).getRawQuery());
        String state = authorization.get("state");
        expectedNonce.set(authorization.get("nonce"));
        assertThat(authorization).containsEntry("code_challenge_method", "S256").containsKey("code_challenge");
        String verifier = transactions.values.get(state).codeVerifier();
        assertThat(verifier).hasSizeBetween(43, 128);
        assertThat(login.authorizationUri()).doesNotContain("code_verifier", verifier);
        assertThat(com.authsystem.sso.client.security.Pkce.challengeS256(verifier))
        .isEqualTo(authorization.get("code_challenge"));
        assertThat(login.browserBindingCookieName()).isEqualTo(service.browserBindingCookieName(state));

        SsoSessionService.Completion completion = service.complete("authorization-code", state, login.browserBinding());

        assertThat(completion.accessToken()).isEqualTo("opaque-access");
        assertThat(completion.returnPath()).isEqualTo("/account?tab=profile");
        assertThat(tokens.findByAccessToken("opaque-access")).isPresent();
        assertThat(tokens.findByAccessToken("opaque-access").orElseThrow().principal().attributes()).doesNotContainKeys("name",
            "email");
        assertThat(tokens.findByAccessToken("opaque-access").orElseThrow().idTokenNonceDigest())
        .isEqualTo(com.authsystem.sso.client.crypto.TokenDigests.sha256(authorization.get("nonce")));
        assertThat(tokens.findByAccessToken("opaque-access").orElseThrow().grantedScopes()).containsExactly("openid");
        assertThat(transactions.consume(state)).isEmpty();

        AuthorizationRequestFactory.LoginRequest abandoned = service.beginLogin("/");
        String abandonedState = query(URI.create(abandoned.authorizationUri()).getRawQuery()).get("state");
        service.cancelAuthorization(abandonedState);
        assertThat(transactions.values).doesNotContainKey(abandonedState);
        service.cancelAuthorization("x".repeat(513));
        server.verify();
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> result = new java.util.HashMap<>();
        for (String pair:raw.split("&")) {
            String[] parts = pair.split("=", 2);
            result.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8), URLDecoder.decode(parts[1],
                    StandardCharsets.UTF_8));
        }
        return result;
    }
    private static final class InMemoryTransactions implements SsoAuthorizationRequestStore {
        private final Map<String, SsoAuthorizationTransaction> values = new ConcurrentHashMap<>();
        public void save(String state, SsoAuthorizationTransaction transaction) {
            values.put(state, transaction);
        }
        public Optional<SsoAuthorizationTransaction> consume(String state) {
            return Optional.ofNullable(values.remove(state));
        }
    }
    private static final class InMemoryTokens implements SsoTokenStore {
        private final Map<String, SsoTokenRecord> values = new ConcurrentHashMap<>();
        private final java.util.Set<String> refreshAttempts = ConcurrentHashMap.newKeySet();
        public Optional<SsoTokenRecord> findByAccessToken(String token) {
            return Optional.ofNullable(values.get(token));
        }
        public void saveCurrent(String oldToken, String newToken, SsoTokenRecord record, String overlap,
            Duration overlapTtl) {
            if (oldToken != null)
                values.remove(oldToken);
            values.put(newToken, record);
        }
        public Optional<String> findOverlapAccessToken(String token) {
            return Optional.empty();
        }
        public boolean claimRefreshAttempt(String fingerprint, Instant retainUntil) {
            return refreshAttempts.add(fingerprint);
        }
        public void deleteByAccessToken(String token) {
            values.remove(token);
        }
        public Optional<SsoTokenRecord> removeCurrentBySubjectAndClient(String subject, String clientId) {
            return values.entrySet().stream().filter(entry -> entry.getValue().principal().subject().equals(subject) &&
                entry.getValue().clientId().equals(clientId)).findFirst().map(entry -> values.remove(entry.getKey()));
        }
    }
    private static final class MutableClock extends Clock {
        private final Instant instant;
        private MutableClock(Instant instant) {
            this.instant = instant;
        }
        @Override public ZoneId getZone() {
            return ZoneOffset.UTC;
        }
        @Override public Clock withZone(ZoneId zone) {
            return this;
        }
        @Override public Instant instant() {
            return instant;
        }
    }
}
