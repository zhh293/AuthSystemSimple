package com.authsystem.sso.client.protocol;

import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/** Loads metadata only from the statically configured issuer and caches it for a bounded interval. */
public final class OidcMetadataClient {
    private final String issuer;
    private final RestClient http;
    private final Clock clock;
    private final Duration cacheTtl;
    private volatile Cached cached;

    public OidcMetadataClient(String issuer, RestClient http, Clock clock, Duration cacheTtl) {
        this.issuer = issuer;
        this.http = http;
        this.clock = clock;
        this.cacheTtl = cacheTtl;
    }

    public OidcProviderMetadata get() {
        Cached value = cached;
        if (value != null && value.expiresAt().isAfter(clock.instant()))
            return value.metadata();
        synchronized (this) {
            value = cached;
            if (value != null && value.expiresAt().isAfter(clock.instant()))
                return value.metadata();
            Map<?, ?> body;
            String discoveryUri = issuer.endsWith("/")?issuer+".well-known/openid-configuration":issuer+"/.well-known/openid-configuration";
            try {
                body = http.get().uri(discoveryUri).retrieve().body(Map.class);
            } catch (RestClientException unavailable) {
                throw new SsoClientDependencyException("OIDC discovery is unavailable", unavailable);
            }
            if (body == null || !issuer.equals(body.get("issuer")))
                throw new IllegalStateException("OIDC issuer metadata mismatch");
            URI authorization = trustedEndpoint(body, "authorization_endpoint");
            URI token = trustedEndpoint(body, "token_endpoint");
            URI jwks = trustedEndpoint(body, "jwks_uri");
            URI userInfo = optionalEndpoint(body, "userinfo_endpoint");
            URI revoke = optionalEndpoint(body, "revocation_endpoint");
            URI logout = optionalEndpoint(body, "end_session_endpoint");
            if (userInfo != null)
                userInfo = validateOrigin(userInfo, "userinfo_endpoint");
            if (revoke != null)
                revoke = validateOrigin(revoke, "revocation_endpoint");
            if (logout != null)
                logout = validateOrigin(logout, "end_session_endpoint");
            OidcProviderMetadata metadata = new OidcProviderMetadata(issuer, authorization, token, jwks,
                userInfo, revoke, logout);
            cached = new Cached(metadata, clock.instant().plus(cacheTtl));
            return metadata;
        }
    }

    private URI trustedEndpoint(Map<?, ?> body, String name) {
        URI endpoint = optionalEndpoint(body, name);
        if (endpoint == null)
            throw new IllegalStateException("Required OIDC endpoint is missing: " + name);
        return validateOrigin(endpoint, name);
    }
    private URI validateOrigin(URI endpoint, String name) {
        URI issuerUri = URI.create(issuer);
        if (!issuerUri.getScheme().equalsIgnoreCase(endpoint.getScheme())
|| !issuerUri.getHost().equalsIgnoreCase(endpoint.getHost())
|| effectivePort(issuerUri) != effectivePort(endpoint)
|| endpoint.getUserInfo() != null || endpoint.getFragment() != null) {
            throw new IllegalStateException("OIDC endpoint is outside the trusted issuer origin: " + name);
        }
        return endpoint;
    }
    private URI optionalEndpoint(Map<?, ?> body, String name) {
        Object value = body.get(name);
        if (value == null)
            return null;
        if (!(value instanceof String text))
            throw new IllegalStateException("Invalid OIDC endpoint metadata");
        URI uri = URI.create(text);
        if (!uri.isAbsolute() || uri.getHost() == null)
            throw new IllegalStateException("Invalid OIDC endpoint metadata");
        return uri;
    }
    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0)
            return uri.getPort();
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }
    private record Cached(OidcProviderMetadata metadata, Instant expiresAt) {
    }
}
