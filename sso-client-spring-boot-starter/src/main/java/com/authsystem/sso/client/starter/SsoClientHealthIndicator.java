package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.config.SsoClientProperties;
import com.authsystem.sso.client.protocol.OidcMetadataClient;
import com.authsystem.sso.client.protocol.CachingJwkSource;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.data.redis.core.StringRedisTemplate;

final class SsoClientHealthIndicator implements HealthIndicator {
    private final SsoClientProperties properties;
    private final OidcMetadataClient metadata;
    private final CachingJwkSource jwks;
    private final StringRedisTemplate redis;
    SsoClientHealthIndicator(SsoClientProperties properties, OidcMetadataClient metadata, CachingJwkSource jwks,
        StringRedisTemplate redis) {
        this.properties = properties;
        this.metadata = metadata;
        this.jwks = jwks;
        this.redis = redis;
    }
    @Override public Health health() {
        try {
            metadata.get();
            jwks.ensureAvailable();
            if (!properties.localStore()) {
                String ping = redis.execute((org.springframework.data.redis.core.RedisCallback<String>) connection -> connection.ping());
                if (ping == null || !"PONG".equalsIgnoreCase(ping))
                    throw new IllegalStateException("Redis readiness probe did not return PONG");
            }
            return Health.up().withDetail("discovery", "available").withDetail("jwksCacheAgeSeconds",
                jwks.cacheAge() == null?0:jwks.cacheAge().toSeconds()).withDetail("tokenStore",
                properties.localStore()?"local-single-instance":"available").build();
        } catch (Exception unavailable) {
            return Health.down().withDetail("dependency", "unavailable").build();
        }
    }
}
