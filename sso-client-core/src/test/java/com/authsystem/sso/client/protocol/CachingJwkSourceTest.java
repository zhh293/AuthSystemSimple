package com.authsystem.sso.client.protocol;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class CachingJwkSourceTest {
    private static final String JWKS_URI = "https://issuer.example.test/jwks";

    @Test
    void refreshesOnceForUnknownKidAndReturnsNewTrustedKey() throws Exception {
        RSAKey originalKey = trustedKey("original-key");
        RSAKey rotatedKey = trustedKey("rotated-key");
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(JWKS_URI)).andRespond(withSuccess(keySet(originalKey), MediaType.APPLICATION_JSON));
        server.expect(requestTo(JWKS_URI)).andRespond(withSuccess(keySet(rotatedKey), MediaType.APPLICATION_JSON));
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CachingJwkSource source = source(builder, clock);
        assertThat(source.get(selector("original-key"), null)).hasSize(1);
        clock.advance(Duration.ofSeconds(6));

        List<?> matches = source.get(selector("rotated-key"), null);

        assertThat(matches).hasSize(1);
        assertThat(source.cacheAge()).isZero();
        server.verify();
    }

    @Test
    void usesPreviouslyTrustedKeyDuringConfiguredStaleIfErrorWindow() throws Exception {
        RSAKey key = trustedKey("stable-key");
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(JWKS_URI)).andRespond(withSuccess(keySet(key), MediaType.APPLICATION_JSON));
        server.expect(requestTo(JWKS_URI)).andRespond(withServerError());
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CachingJwkSource source = source(builder, clock);
        assertThat(source.get(selector("stable-key"), null)).hasSize(1);

        clock.advance(Duration.ofMinutes(6));
        assertThat(source.get(selector("stable-key"), null)).hasSize(1);

        server.verify();
    }

    @Test
    void rejectsJwksWithMoreThanOneHundredEntries() throws Exception {
        RSAKey key = trustedKey("repeated-key");
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        RSAKey[] keys = new RSAKey[101];
        java.util.Arrays.fill(keys, key);
        server.expect(requestTo(JWKS_URI)).andRespond(withSuccess(keySet(keys), MediaType.APPLICATION_JSON));
        CachingJwkSource source = source(builder, Clock.systemUTC());

        assertThatThrownBy(() -> source.get(selector("repeated-key"), null))
        .isInstanceOf(com.nimbusds.jose.KeySourceException.class)
        .rootCause().hasMessageContaining("too many key entries");
        server.verify();
    }

    @Test
    void rateLimitsRepeatedFetchFailuresBeforeAnyKeyHasBeenCached() throws Exception {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(JWKS_URI)).andRespond(withServerError());
        RSAKey recovered = trustedKey("recovered-key");
        server.expect(requestTo(JWKS_URI)).andRespond(withSuccess(keySet(recovered), MediaType.APPLICATION_JSON));
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CachingJwkSource source = source(builder, clock);

        assertThatThrownBy(() -> source.get(selector("missing-key"), null))
        .isInstanceOf(com.nimbusds.jose.KeySourceException.class);
        assertThatThrownBy(() -> source.get(selector("missing-key"), null))
        .isInstanceOf(com.nimbusds.jose.KeySourceException.class);
        clock.advance(Duration.ofSeconds(6));
        assertThat(source.get(selector("recovered-key"), null)).hasSize(1);

        server.verify();
    }

    private static CachingJwkSource source(RestClient.Builder builder, Clock clock) {
        return new CachingJwkSource(builder.build(), JWKS_URI, clock, Duration.ofMinutes(5), Duration.ofHours(1));
    }

    private static JWKSelector selector(String kid) {
        return new JWKSelector(new JWKMatcher.Builder().keyID(kid).build());
    }

    private static RSAKey trustedKey(String kid) throws Exception {
        return new RSAKeyGenerator(2048).keyID(kid).keyUse(KeyUse.SIGNATURE)
        .algorithm(JWSAlgorithm.RS256).generate().toPublicJWK();
    }

    private static String keySet(RSAKey... keys) {
        return "{\"keys\":["+java.util.Arrays.stream(keys).map(RSAKey::toJSONString).collect(java.util.stream.Collectors.joining(","))+"]}";
    }

    private static final class MutableClock extends Clock {
        private Instant instant;
        private MutableClock(Instant instant) {
            this.instant = instant;
        }
        private void advance(Duration duration) {
            instant = instant.plus(duration);
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
