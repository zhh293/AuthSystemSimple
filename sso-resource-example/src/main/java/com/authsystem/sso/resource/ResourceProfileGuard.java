package com.authsystem.sso.resource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

/** Prevents a production resource consumer from silently using a non-mTLS profile. */
public final class ResourceProfileGuard implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Override public void initialize(ConfigurableApplicationContext context) {
        String[] active = context.getEnvironment().getActiveProfiles();
        String[] defaults = context.getEnvironment().getDefaultProfiles();
        boolean malformedActive = Arrays.stream(active).anyMatch(profile -> {
            String normalized = profile.trim();
            boolean productionLike = normalized.equalsIgnoreCase("prod") || normalized.equalsIgnoreCase("production");
            return productionLike && (!profile.equals(normalized)
                    || !normalized.equals("prod") && !normalized.equals("production"));
        });
        boolean productionDefault = Arrays.stream(defaults).anyMatch(profile -> {
            String normalized = profile.trim();
            return normalized.equalsIgnoreCase("prod") || normalized.equalsIgnoreCase("production");
        });
        if (malformedActive || productionDefault) {
            throw new IllegalStateException("Use lowercase active profile prod or production; production cannot be a default profile");
        }
        boolean production = Arrays.stream(active).anyMatch(profile -> profile.equals("prod") || profile.equals("production"));
        if (!production) return;
        if (!"true".equalsIgnoreCase(System.getProperty("nacos.remote.client.rpc.tls.enable"))
                || "true".equalsIgnoreCase(System.getProperty("nacos.remote.client.rpc.tls.trustAll"))
                || !readableFile(System.getProperty("nacos.remote.client.rpc.tls.trustCollectionChainPath"))) {
            throw new IllegalStateException("Production resource service requires Nacos RPC TLS with certificate validation and a readable CA file");
        }
        requireReadableFile("SSO_DUBBO_CLIENT_CERT");
        requireReadableFile("SSO_DUBBO_CLIENT_KEY");
        requireReadableFile("SSO_DUBBO_SERVER_CA");
    }

    private static void requireReadableFile(String name) {
        if (!readableFile(System.getenv(name))) {
            throw new IllegalStateException("Production resource service requires a readable file from " + name);
        }
    }

    private static boolean readableFile(String value) {
        if (value == null || value.isBlank()) return false;
        try {
            Path path = Path.of(value);
            return Files.isRegularFile(path) && Files.isReadable(path);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
