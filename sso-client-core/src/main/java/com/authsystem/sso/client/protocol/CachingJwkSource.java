package com.authsystem.sso.client.protocol;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.JWKSelector;
import org.springframework.web.client.RestClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Bounded trusted-key cache with a stale-if-error window and rate-limited unknown-kid refresh. */
public final class CachingJwkSource implements JWKSource<SecurityContext> {
    private static final Duration UNKNOWN_KID_COOLDOWN = Duration.ofSeconds(5);
    private final RestClient http;
    private final String jwksUri;
    private final Clock clock;
    private final Duration refreshInterval, staleIfError;
    private volatile Cached cached;
    private Instant lastAttempt;
    public CachingJwkSource(RestClient http, String jwksUri, Clock clock, Duration refreshInterval, Duration staleIfError) {
        this.http = http;
        this.jwksUri = jwksUri;
        this.clock = clock;
        this.refreshInterval = refreshInterval;
        this.staleIfError = staleIfError;
    }
    @Override public List<JWK> get(JWKSelector selector, SecurityContext context) throws KeySourceException {
        synchronized (this) {
            Instant now = clock.instant();
            Cached current = cached;
            if (current == null) {
                refreshRequired();
                current = cached;
            } else if (!now.isBefore(current.refreshAt())) {
                try {
                    refreshRequired();
                    current = cached;
                } catch (KeySourceException failure) {
                    if (!now.isBefore(current.staleUntil()))
                        throw failure;
                }
            }
            List<JWK> matches = selector.select(current.keys());
            if (matches.isEmpty() && refreshDueForUnknownKid(now)) {
                try {
                    refreshRequired();
                    current = cached;
                    matches = selector.select(current.keys());
                } catch (KeySourceException failure) {
                    if (!now.isBefore(current.staleUntil()))
                        throw failure;
                }
            }
            return matches;
        }
    }
    private boolean refreshDueForUnknownKid(Instant now) {
        return lastAttempt == null || !lastAttempt.plus(UNKNOWN_KID_COOLDOWN).isAfter(now);
    }
    private void refreshRequired() throws KeySourceException {
        Instant now = clock.instant();
        if (lastAttempt != null && lastAttempt.plus(UNKNOWN_KID_COOLDOWN).isAfter(now))
            throw new KeySourceException("Trusted signing key is not available");
        lastAttempt = now;
        try {
            String json = http.get().uri(jwksUri).retrieve().body(String.class);
            if (json == null || json.length()>1_048_576)
                throw new IllegalArgumentException("JWKS response is invalid");
            JWKSet parsed = JWKSet.parse(json);
            if (parsed.getKeys().size()>100)
                throw new IllegalArgumentException("JWKS contains too many key entries");
            List<JWK> publicKeys = parsed.getKeys().stream().filter(CachingJwkSource::isTrustedSigningKey).toList();
            if (publicKeys.isEmpty())
                throw new IllegalArgumentException("JWKS has no supported signing keys");
            Set<String> kids = new HashSet<>();
            for (JWK key:publicKeys)
                if (key.getKeyID() == null || !kids.add(key.getKeyID()))
                    throw new IllegalArgumentException("JWKS key identifiers are invalid");
            cached = new Cached(new JWKSet(publicKeys), now, now.plus(refreshInterval), now.plus(refreshInterval).plus(staleIfError));
        } catch (Exception e) {
            throw new KeySourceException("Trusted signing keys are unavailable", e);
        }
    }
    private static boolean isTrustedSigningKey(JWK key) {
        if (!(key instanceof RSAKey rsa) || rsa.isPrivate())
            return false;
        try {
            return rsa.toRSAPublicKey().getModulus().bitLength() >= 2048
&& (key.getKeyUse() == null || KeyUse.SIGNATURE.equals(key.getKeyUse()))
&& (key.getAlgorithm() == null || JWSAlgorithm.RS256.equals(key.getAlgorithm()));
        } catch (Exception malformed) {
            return false;
        }
    }
    public synchronized void ensureAvailable() throws KeySourceException {
        Instant now = clock.instant();
        Cached current = cached;
        if (current == null) {
            refreshRequired();
            return;
        }
        if (!now.isBefore(current.refreshAt()))
            try {
            refreshRequired();
        } catch (KeySourceException failure) {
            if (!now.isBefore(current.staleUntil()))
                throw failure;
        }
    }
    public Duration cacheAge() {
        Cached current = cached;
        return current == null?null:Duration.between(current.fetchedAt(), clock.instant());
    }
    private record Cached(JWKSet keys, Instant fetchedAt, Instant refreshAt, Instant staleUntil) {
    }
}
