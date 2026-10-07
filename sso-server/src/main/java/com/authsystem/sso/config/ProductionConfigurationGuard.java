package com.authsystem.sso.config;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class ProductionConfigurationGuard implements EnvironmentAware {
    private Environment environment;
    @Override public void setEnvironment(Environment environment) { this.environment = environment; }

    @Bean
    ApplicationRunner validateProductionSettings(SsoProperties properties) {
        return (ApplicationArguments args) -> {
            if (properties.getSessionTtlSeconds() < 60 || properties.getLoginMaxAttempts() < 1 || properties.getLoginWindowSeconds() < 1
                    || properties.getAuthorizationCodeTtlSeconds() < 30 || properties.getAuthorizationCodeTtlSeconds() > 120
                    || properties.getPendingAuthorizationTtlSeconds() < 60 || properties.getPendingAuthorizationTtlSeconds() > 900
                    || properties.getAccessTokenTtlSeconds() < 60 || properties.getRefreshTokenTtlSeconds() < properties.getAccessTokenTtlSeconds()) {
                throw new IllegalStateException("Session TTL and login throttling configuration must be positive and session TTL must be at least 60 seconds");
            }
            if (properties.getIdTokenTtlSeconds() < 60 || properties.getIdTokenTtlSeconds() > 3600) {
                throw new IllegalStateException("ID Token TTL must be between 60 and 3600 seconds");
            }
            if (properties.getRefreshFamilyHistoryRetentionSeconds() < 86400) {
                throw new IllegalStateException("Refresh family history retention must be at least one day");
            }
            if (properties.getSessionCookie() == null || properties.getSessionCookie().isBlank() || properties.getCookiePath() == null || !properties.getCookiePath().startsWith("/")) {
                throw new IllegalStateException("SSO session cookie name and absolute cookie path are required");
            }
            String[] activeProfiles = environment.getActiveProfiles();
            ProductionProfiles.validate(activeProfiles, environment.getDefaultProfiles());
            boolean production = ProductionProfiles.isProduction(activeProfiles);
            String credentialMode = environment.getProperty("sso.identity.credential-mode", "database");
            if (!"database".equals(credentialMode) && !"directory".equals(credentialMode)) {
                throw new IllegalStateException("SSO_IDENTITY_CREDENTIAL_MODE must be database or directory");
            }
            if ("directory".equals(credentialMode) && !production) {
                throw new IllegalStateException("Directory credential mode requires the prod/production profile so Dubbo mTLS is enabled");
            }
            if (!production) return;
            if (properties.getSessionHmacKey() == null || properties.getSessionHmacKey().getBytes(StandardCharsets.UTF_8).length < 32
                    || properties.getSessionHmacKey().startsWith("local-development-only")) {
                throw new IllegalStateException("Production requires SSO_SESSION_HMAC_KEY with at least 32 bytes from a secret manager");
            }
            if (properties.getRateLimitHmacKey() == null || properties.getRateLimitHmacKey().getBytes(StandardCharsets.UTF_8).length < 32
                    || properties.getRateLimitHmacKey().startsWith("local-development-only")) {
                throw new IllegalStateException("Production requires SSO_RATE_LIMIT_HMAC_KEY with at least 32 bytes from a secret manager");
            }
            if (properties.getOauthStateHmacKey() == null || properties.getOauthStateHmacKey().getBytes(StandardCharsets.UTF_8).length < 32
                    || properties.getOauthStateHmacKey().startsWith("local-development-only")) {
                throw new IllegalStateException("Production requires SSO_OAUTH_STATE_HMAC_KEY with at least 32 bytes from a secret manager");
            }
            if (properties.getTokenStorageHmacKey() == null || properties.getTokenStorageHmacKey().getBytes(StandardCharsets.UTF_8).length < 32
                    || properties.getTokenStorageHmacKey().startsWith("local-development-only")) {
                throw new IllegalStateException("Production requires SSO_TOKEN_STORAGE_HMAC_KEY with at least 32 bytes from a secret manager");
            }
            Set<String> tokenKeys = new HashSet<>();
            tokenKeys.add(properties.getTokenStorageHmacKey());
            for (String previousKey : properties.getTokenStorageHmacPreviousKeys()) {
                if (previousKey == null || previousKey.getBytes(StandardCharsets.UTF_8).length < 32
                        || previousKey.startsWith("local-development-only") || !tokenKeys.add(previousKey)) {
                    throw new IllegalStateException("Previous token-storage HMAC keys must be unique secrets with at least 32 bytes");
                }
            }
            if (!properties.isCookieSecure() || properties.getIssuer() == null || !properties.getIssuer().startsWith("https://")) {
                throw new IllegalStateException("Production requires an HTTPS issuer and Secure session cookie");
            }
            if (properties.getOidcKeystorePath() == null || properties.getOidcKeystorePath().isBlank()
                    || properties.getOidcKeystorePassword() == null || properties.getOidcKeystorePassword().isBlank()) {
                throw new IllegalStateException("Production requires an external PKCS#12 OIDC signing keystore and password");
            }
            if (properties.getOidcKeyAlias() == null || properties.getOidcKeyAlias().isBlank()) {
                throw new IllegalStateException("Production requires a non-empty active OIDC signing key alias");
            }
            Set<String> signingAliases = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            signingAliases.add(properties.getOidcKeyAlias());
            for (String previousAlias : properties.getOidcPreviousKeyAliases()) {
                if (previousAlias == null || previousAlias.isBlank() || !signingAliases.add(previousAlias)) {
                    throw new IllegalStateException("Previous OIDC signing aliases must be non-empty and unique from the active alias");
                }
            }
            if (!properties.isAuthorizationStorageEncrypted()) {
                throw new IllegalStateException("Production requires encrypted authorization database storage and encrypted backups");
            }
            String jdbcUrl = environment.getProperty("spring.datasource.url", "");
            if (!java.util.regex.Pattern.compile("(?i)(?:[?&])sslMode=VERIFY_IDENTITY(?:&|$)").matcher(jdbcUrl).find()) {
                throw new IllegalStateException("Production MySQL URL must require sslMode=VERIFY_IDENTITY");
            }
            if (!Boolean.parseBoolean(environment.getProperty("spring.data.redis.ssl.enabled", "false"))) {
                throw new IllegalStateException("Production requires TLS for Redis connections");
            }
            if (!Boolean.getBoolean("nacos.remote.client.rpc.tls.enable")
                    || Boolean.getBoolean("nacos.remote.client.rpc.tls.trustAll")
                    || System.getProperty("nacos.remote.client.rpc.tls.trustCollectionChainPath") == null
                    || System.getProperty("nacos.remote.client.rpc.tls.trustCollectionChainPath").isBlank()) {
                throw new IllegalStateException("Production requires Nacos RPC TLS with certificate validation and an explicit CA trust file");
            }
        };
    }
}
