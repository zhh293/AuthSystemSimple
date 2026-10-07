package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.crypto.RefreshTokenCipher;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.authsystem.sso.client.protocol.SsoClientDependencyException;
import com.authsystem.sso.client.session.SsoPrincipal;
import com.authsystem.sso.client.session.SsoTokenRecord;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.time.Duration;
import java.util.Map;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RedisSsoStoresCryptoTest {
    @Test
    void caffeineCacheAvoidsRepeatedRedisReadsWithinConfiguredTtl() throws Exception {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked") ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        SsoTokenRecord record = new SsoTokenRecord("https://issuer", "portal", "digest", "encrypted",
            "key-1",
            new SsoPrincipal("user-1", "User", null, Map.of()), Instant.now().plusSeconds(60), Instant.now().plusSeconds(3600));
        when(values.get(anyString())).thenReturn(new ObjectMapper().findAndRegisterModules().writeValueAsString(record));
        RedisSsoTokenStore store = new RedisSsoTokenStore(redis, new ObjectMapper().findAndRegisterModules(), new byte[32], "portal",
            "sso:rp", Duration.ofMillis(250));

        assertThat(store.findByAccessToken("raw-access-token")).contains(record);
        assertThat(store.findByAccessToken("raw-access-token")).contains(record);

        verify(values, org.mockito.Mockito.times(1)).get(anyString());
    }

    @Test
    void refreshAttemptUsesAtomicSetIfAbsentAndRetainsMarkerToExpiry() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked") ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.setIfAbsent(anyString(), eq("1"), any(Duration.class))).thenReturn(true, false, true);
        RedisSsoTokenStore store = new RedisSsoTokenStore(redis, new ObjectMapper(), new byte[32], "portal",
            "sso:rp", Duration.ZERO);
        Instant retainUntil = Instant.now().plusSeconds(300);

        assertThat(store.claimRefreshAttempt("refresh-generation-one", retainUntil)).isTrue();
        assertThat(store.claimRefreshAttempt("refresh-generation-one", retainUntil)).isFalse();
        assertThat(store.claimRefreshAttempt("refresh-generation-two", retainUntil)).isTrue();
        ArgumentCaptor<String> redisKey = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
        verify(values, org.mockito.Mockito.times(3)).setIfAbsent(redisKey.capture(), eq("1"), ttl.capture());
        assertThat(redisKey.getValue()).contains("refresh-attempt:{").doesNotContain("refresh-generation-one",
            "refresh-generation-two");
        assertThat(redisKey.getAllValues()).allSatisfy(value -> assertThat(value)
            .doesNotContain("refresh-generation-one", "refresh-generation-two"));
        assertThat(redisKey.getAllValues().get(0)).isEqualTo(redisKey.getAllValues().get(1))
        .isNotEqualTo(redisKey.getAllValues().get(2));
        assertThat(ttl.getAllValues()).allSatisfy(value -> assertThat(value).isBetween(Duration.ofSeconds(1),
                Duration.ofSeconds(300)));
    }

    @Test
    void refreshAttemptStoreFailureIsSurfacedAsDependencyFailure() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked") ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.setIfAbsent(anyString(), eq("1"), any(Duration.class))).thenThrow(new IllegalStateException("redis unavailable"));
        RedisSsoTokenStore store = new RedisSsoTokenStore(redis, new ObjectMapper(), new byte[32], "portal",
            "sso:rp", Duration.ZERO);

        assertThatThrownBy(() -> store.claimRefreshAttempt("refresh-generation-one", Instant.now().plusSeconds(60)))
        .isInstanceOf(SsoClientDependencyException.class);
    }

    @Test
    void authorizationTransactionCiphertextIsBoundToClientAndState() {
        byte[] key = new byte[32];
        byte[] transaction = RedisAuthorizationRequestStore.transactionAad("portal", key, "state-one");
        String ciphertext = RefreshTokenCipher.encrypt("transaction-json", key, transaction);

        assertThatThrownBy(() -> RefreshTokenCipher.decrypt(ciphertext, key,
                RedisAuthorizationRequestStore.transactionAad("portal", key, "state-two")))
        .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> RefreshTokenCipher.decrypt(ciphertext, key,
                RedisAuthorizationRequestStore.transactionAad("another-client", key, "state-one")))
        .isInstanceOf(IllegalStateException.class);
    }
}
