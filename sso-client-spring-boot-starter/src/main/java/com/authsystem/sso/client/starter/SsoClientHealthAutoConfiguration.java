package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.config.SsoClientProperties;
import com.authsystem.sso.client.protocol.CachingJwkSource;
import com.authsystem.sso.client.protocol.OidcMetadataClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.boot.actuate.health.HealthIndicator;

/** Registers readiness integration only when the host application includes Actuator. */
@AutoConfiguration(after = SsoClientAutoConfiguration.class)
@ConditionalOnClass(name = "org.springframework.boot.actuate.health.HealthIndicator")
@ConditionalOnProperty(prefix = "sso.client", name = "enabled", havingValue = "true")
public class SsoClientHealthAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean(HealthIndicator.class)
    HealthIndicator ssoClientHealthIndicator(SsoClientProperties properties, OidcMetadataClient metadata,
        CachingJwkSource jwks, ObjectProvider<StringRedisTemplate> redis) {
        return new SsoClientHealthIndicator(properties, metadata, jwks,
            properties.localStore() ? null : redis.getObject());
    }
}
