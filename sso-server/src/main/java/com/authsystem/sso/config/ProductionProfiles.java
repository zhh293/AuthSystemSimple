package com.authsystem.sso.config;

/** Canonical production profile recognition shared by bootstrap and security configuration. */
public final class ProductionProfiles {
    private ProductionProfiles() { }

    public static boolean isProduction(String[] activeProfiles) {
        return java.util.Arrays.stream(activeProfiles).anyMatch(profile -> profile.equals("prod") || profile.equals("production"));
    }

    public static void validate(String[] activeProfiles, String[] defaultProfiles) {
        boolean invalidProductionName = java.util.Arrays.stream(activeProfiles)
                .anyMatch(ProductionProfiles::isMalformedProductionName);
        if (invalidProductionName) {
            throw new IllegalStateException("Production profile names must be exactly prod or production with lowercase spelling and no surrounding whitespace");
        }
        if (java.util.Arrays.stream(defaultProfiles).anyMatch(ProductionProfiles::isProductionLike)) {
            throw new IllegalStateException("Production profiles must be explicitly active and cannot be configured as default profiles");
        }
    }

    public static void validateEnvironment(org.springframework.core.env.Environment environment) {
        String[] activeProfiles = environment.getActiveProfiles();
        validate(activeProfiles, environment.getDefaultProfiles());
        if (!isProduction(activeProfiles)) return;

        requireSecret(environment, "sso.session-hmac-key", 32);
        requireSecret(environment, "sso.rate-limit-hmac-key", 32);
        requireSecret(environment, "sso.oauth-state-hmac-key", 32);
        String tokenHmacKey = required(environment, "sso.token-storage-hmac-key");
        requireSecret(environment, "sso.token-storage-hmac-key", 32);
        java.util.Set<String> tokenHmacKeys = new java.util.HashSet<>();
        tokenHmacKeys.add(tokenHmacKey);
        for (String previousKey : commaSeparated(environment.getProperty("sso.token-storage-hmac-previous-keys", ""))) {
            if (previousKey.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < 32
                    || previousKey.startsWith("local-development-only") || !tokenHmacKeys.add(previousKey)) {
                throw new IllegalStateException("Production previous token-storage HMAC keys must be unique secrets with at least 32 bytes");
            }
        }
        String credentialMode = required(environment, "sso.identity.credential-mode");
        if (!credentialMode.equals("database") && !credentialMode.equals("directory")) {
            throw new IllegalStateException("SSO_IDENTITY_CREDENTIAL_MODE must be database or directory");
        }
        if (credentialMode.equals("directory")) {
            long syncInterval = positiveLong(environment, "sso.identity.directory-sync-interval-ms", 30_000);
            long maxStaleness = positiveLong(environment, "sso.identity.directory-sync-max-staleness-seconds", 120);
            if (syncInterval > 86_400_000 || maxStaleness > 604_800
                    || maxStaleness * 1_000L < syncInterval * 2L) {
                throw new IllegalStateException("Directory sync maximum staleness must allow at least two sync intervals");
            }
        }

        String jdbcUrl = required(environment, "spring.datasource.url");
        if (!java.util.regex.Pattern.compile("(?i)(?:[?&])sslMode=VERIFY_IDENTITY(?:&|$)").matcher(jdbcUrl).find()) {
            throw new IllegalStateException("Production MySQL URL must require sslMode=VERIFY_IDENTITY");
        }
        required(environment, "spring.datasource.username");
        required(environment, "spring.datasource.password");
        if (!Boolean.parseBoolean(environment.getProperty("spring.data.redis.ssl.enabled", "false"))) {
            throw new IllegalStateException("Production requires TLS for Redis connections");
        }
        required(environment, "spring.data.redis.host");
        required(environment, "spring.data.redis.password");
        if (!Boolean.parseBoolean(required(environment, "sso.cookie-secure"))
                || !required(environment, "sso.issuer").startsWith("https://")) {
            throw new IllegalStateException("Production requires an HTTPS issuer and Secure session cookie");
        }
        if (!Boolean.parseBoolean(required(environment, "sso.authorization-storage-encrypted"))) {
            throw new IllegalStateException("Production requires encrypted authorization database storage and encrypted backups");
        }
        required(environment, "dubbo.registry.address");
        required(environment, "dubbo.registry.parameters.namespace");
        required(environment, "dubbo.registry.parameters.username");
        required(environment, "dubbo.registry.parameters.password");
        readableSecretFile(required(environment, "sso.oidc-keystore-path"), "OIDC signing keystore");
        required(environment, "sso.oidc-keystore-password");
        String activeAlias = required(environment, "sso.oidc-key-alias");
        java.util.Set<String> aliases = new java.util.HashSet<>();
        aliases.add(activeAlias.toLowerCase(java.util.Locale.ROOT));
        for (String alias : commaSeparated(environment.getProperty("sso.oidc-previous-key-aliases", ""))) {
            if (alias.isBlank() || !aliases.add(alias.toLowerCase(java.util.Locale.ROOT))) {
                throw new IllegalStateException("Production OIDC signing aliases must be non-empty and unique");
            }
        }

        for (String variable : new String[] {"SSO_DUBBO_SERVER_CERT", "SSO_DUBBO_SERVER_KEY", "SSO_DUBBO_CLIENT_CA",
                "SSO_DUBBO_CLIENT_CERT", "SSO_DUBBO_CLIENT_KEY", "SSO_DUBBO_SERVER_CA"}) {
            readableSecretFile(System.getenv(variable), variable);
        }
        if (!"true".equalsIgnoreCase(System.getProperty("nacos.remote.client.rpc.tls.enable"))
                || "true".equalsIgnoreCase(System.getProperty("nacos.remote.client.rpc.tls.trustAll"))) {
            throw new IllegalStateException("Production requires Nacos RPC TLS with certificate validation");
        }
        readableSecretFile(System.getProperty("nacos.remote.client.rpc.tls.trustCollectionChainPath"), "Nacos RPC TLS CA");
    }

    private static String required(org.springframework.core.env.Environment environment, String name) {
        String value = environment.getProperty(name);
        if (value == null || value.isBlank() || value.startsWith("local-development-only")) {
            throw new IllegalStateException("Production requires configured " + name);
        }
        return value;
    }

    private static long positiveLong(org.springframework.core.env.Environment environment, String name, long defaultValue) {
        String configured = environment.getProperty(name);
        if (configured == null || configured.isBlank()) return defaultValue;
        try {
            long value = Long.parseLong(configured);
            if (value <= 0) throw new NumberFormatException();
            return value;
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Production requires a positive integer for " + name);
        }
    }

    private static void requireSecret(org.springframework.core.env.Environment environment, String name, int minimumBytes) {
        String value = required(environment, name);
        if (value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < minimumBytes) {
            throw new IllegalStateException("Production secret " + name + " must contain at least " + minimumBytes + " bytes");
        }
    }

    private static void readableSecretFile(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalStateException("Production requires " + name);
        try {
            java.nio.file.Path path = java.nio.file.Path.of(value);
            if (!java.nio.file.Files.isRegularFile(path) || !java.nio.file.Files.isReadable(path)) {
                throw new IllegalStateException("Production requires a readable " + name);
            }
        } catch (RuntimeException e) {
            if (e instanceof IllegalStateException illegalState) throw illegalState;
            throw new IllegalStateException("Production requires a readable " + name);
        }
    }

    private static java.util.List<String> commaSeparated(String value) {
        if (value == null || value.isBlank()) return java.util.List.of();
        return java.util.Arrays.stream(value.split(",", -1)).map(String::trim).toList();
    }

    private static boolean isMalformedProductionName(String profile) {
        String normalized = profile.trim();
        boolean productionLike = isProductionLike(normalized);
        return productionLike && (!profile.equals(normalized)
                || !normalized.equals("prod") && !normalized.equals("production"));
    }

    private static boolean isProductionLike(String profile) {
        String normalized = profile.trim();
        return normalized.equalsIgnoreCase("prod") || normalized.equalsIgnoreCase("production");
    }
}
