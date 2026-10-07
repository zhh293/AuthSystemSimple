package com.authsystem.sso.client.config;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Immutable runtime configuration. Secrets should be injected from a secret manager. */
public record SsoClientProperties(
    String issuer, String clientId, String clientSecret, String callbackUri,
    String cookieName, String cookiePath, String cookieSameSite,
    Duration transactionTtl, Duration connectTimeout, Duration responseTimeout,
    Duration refreshSkew, Duration familyLifetime, List<String> scopes, List<String> protectedPaths,
    boolean secureCookie, boolean localStore, String lookupHmacKey, String refreshEncryptionKey, String redisKeyPrefix) {

    public SsoClientProperties {
        issuer = normalizeIssuer(issuer);
        requireText(clientId, "clientId");
        if (!clientId.matches("[A-Za-z0-9._-]{1,64}"))
            throw new IllegalArgumentException("clientId must be a safe registered identifier");
        requireText(clientSecret, "clientSecret");
        URI callback = URI.create(Objects.requireNonNull(callbackUri, "callbackUri"));
        if (!callback.isAbsolute() || callback.getHost() == null || callback.getFragment() != null ||
            callback.getQuery() != null || callback.getUserInfo() != null) {
            throw new IllegalArgumentException("callbackUri must be an absolute HTTP(S) URI without user info or fragment");
        }
        if (!("https".equalsIgnoreCase(callback.getScheme()) || "http".equalsIgnoreCase(callback.getScheme()))) {
            throw new IllegalArgumentException("callbackUri must use HTTP or HTTPS");
        }
        URI issuerUri = URI.create(issuer);
        if ("http".equalsIgnoreCase(issuerUri.getScheme()) && (!localStore || !isLocalhost(issuerUri)))
            throw new IllegalArgumentException("HTTP issuer is permitted only for localhost single-instance development");
        if ("http".equalsIgnoreCase(callback.getScheme()) && (!localStore || !isLocalhost(callback)))
            throw new IllegalArgumentException("HTTP callback is permitted only for localhost single-instance development");
        if (!secureCookie && (!localStore || !isLocalhost(issuerUri) || !isLocalhost(callback)))
            throw new IllegalArgumentException("Insecure cookies are permitted only for localhost single-instance development");
        requireText(cookieName, "cookieName");
        if (!cookieName.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}"))
            throw new IllegalArgumentException("Invalid cookieName");
        if (cookiePath == null || !cookiePath.matches("/[A-Za-z0-9/._~-]*") || cookiePath.contains(".."))
            throw new IllegalArgumentException("cookiePath must be a safe absolute cookie path");
        if (!List.of("Lax", "Strict", "None").contains(cookieSameSite))
            throw new IllegalArgumentException("cookieSameSite must be Lax, Strict, or None");
        if ("None".equals(cookieSameSite) && !secureCookie)
            throw new IllegalArgumentException("SameSite=None requires Secure cookies");
        positive(transactionTtl, "transactionTtl");
        positive(connectTimeout, "connectTimeout");
        positive(responseTimeout, "responseTimeout");
        positive(familyLifetime, "familyLifetime");
        if (refreshSkew == null || refreshSkew.isNegative())
            throw new IllegalArgumentException("refreshSkew cannot be negative");
        if (scopes == null || scopes.size()>64 || !scopes.contains("openid") || scopes.stream().anyMatch(s -> s == null ||
                !s.matches("[!#$%&'()*+.^_`|~0-9A-Za-z:-]{1,128}"))
|| scopes.stream().distinct().count() != scopes.size())
            throw new IllegalArgumentException("scopes must include openid and contain at most 64 unique valid scope tokens");
        scopes = List.copyOf(scopes);
        if (protectedPaths == null)
            protectedPaths = List.of();
        else protectedPaths = List.copyOf(protectedPaths);
        requireText(lookupHmacKey, "lookupHmacKey");
        requireText(refreshEncryptionKey, "refreshEncryptionKey");
        if (redisKeyPrefix == null || !redisKeyPrefix.matches("[A-Za-z0-9:_-]{1,64}") || redisKeyPrefix.contains("{" ) ||
            redisKeyPrefix.contains("}"))
            throw new IllegalArgumentException("redisKeyPrefix must be a safe namespace prefix");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank())
            throw new IllegalArgumentException(name + " must not be blank");
    }
    private static void positive(Duration value, String name) {
        if (value == null || value.isZero() || value.isNegative())
            throw new IllegalArgumentException(name + " must be positive");
    }
    private static boolean isLocalhost(URI uri) {
        return "localhost".equalsIgnoreCase(uri.getHost());
    }
    private static String normalizeIssuer(String value) {
        requireText(value, "issuer");
        URI uri = URI.create(value);
        if (!uri.isAbsolute() || uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null ||
            uri.getFragment() != null)
            throw new IllegalArgumentException("issuer must be an absolute trusted HTTP(S) URI without query or fragment");
        if (!("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme())))
            throw new IllegalArgumentException("issuer must use HTTP or HTTPS");
        return uri.normalize().toString();
    }
}
