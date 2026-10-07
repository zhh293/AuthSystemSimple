package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.crypto.TokenDigests;
import com.authsystem.sso.client.session.SsoAuthorizationTransaction;
import com.authsystem.sso.client.session.SsoTokenRecord;
import com.authsystem.sso.client.store.SsoAuthorizationRequestStore;
import com.authsystem.sso.client.store.SsoTokenStore;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Volatile, single-instance development stores. Selection must be explicit. */
final class LocalAuthorizationRequestStore implements SsoAuthorizationRequestStore {
    private final ConcurrentHashMap<String, SsoAuthorizationTransaction> values = new ConcurrentHashMap<>();
    private final byte[] key;
    LocalAuthorizationRequestStore(byte[] key) {
        this.key = key;
    }
    @Override public synchronized void save(String state, SsoAuthorizationTransaction tx) {
        String stateKey = TokenDigests.hmacSha256(state, key);
        if (values.size() >= 10000 && !values.containsKey(stateKey)) {
            values.entrySet().removeIf(e -> !e.getValue().expiresAt().isAfter(Instant.now()));
            if (values.size() >= 10000)
                throw new IllegalStateException("Local authorization transaction store is full");
        }
        if (values.putIfAbsent(stateKey, tx) != null)
            throw new IllegalStateException("Authorization state collision");
    }
    @Override public synchronized Optional<SsoAuthorizationTransaction> consume(String state) {
        if (values.size()>10000) {
            values.entrySet().removeIf(e -> !e.getValue().expiresAt().isAfter(Instant.now()));
            if (values.size() >= 10000)
                throw new IllegalStateException("Local authorization transaction store is full");
        }
        SsoAuthorizationTransaction tx = values.remove(TokenDigests.hmacSha256(state, key));
        return tx != null && tx.expiresAt().isAfter(Instant.now())?Optional.of(tx):Optional.empty();
    }
}
final class LocalSsoTokenStore implements SsoTokenStore {
    private final ConcurrentHashMap<String, SsoTokenRecord> values = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Overlap> overlaps = new ConcurrentHashMap<>();
    private final byte[] key;
    private final ConcurrentHashMap<String, Instant> refreshAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> currentByUser = new ConcurrentHashMap<>();
    LocalSsoTokenStore(byte[] key) {
        this.key = key;
    }
    private String key(String token) {
        return TokenDigests.hmacSha256(token, key);
    }
    @Override public synchronized Optional<SsoTokenRecord> findByAccessToken(String token) {
        SsoTokenRecord value = values.get(key(token));
        if (value != null && !value.refreshFamilyExpiresAt().plus(java.time.Duration.ofMinutes(5)).isAfter(java.time.Instant.now())) {
            values.remove(key(token), value);
            currentByUser.remove(key(value.clientId()+":"+value.principal().subject()), key(token));
            return Optional.empty();
        }
        return Optional.ofNullable(value);
    }
    @Override public synchronized void saveCurrent(String oldToken, String newToken, SsoTokenRecord value,
        String encryptedOverlap, java.time.Duration overlapTtl) {
        SsoTokenRecord record = new SsoTokenRecord(value.issuer(), value.clientId(), key(newToken), value.encryptedRefreshToken(),
            value.encryptionKeyId(), value.principal(), value.accessTokenExpiresAt(), value.refreshFamilyExpiresAt(),
            value.idTokenNonceDigest(), value.grantedScopes());
        String newKey = key(newToken), userKey = key(record.clientId()+":"+record.principal().subject());
        String oldKey = oldToken == null || oldToken.isBlank()?null:key(oldToken);
        if (oldKey != null && (!oldKey.equals(currentByUser.get(userKey)) || !values.containsKey(oldKey)))
            throw new IllegalStateException("Token mapping changed during refresh");
        if (values.size() >= 100000) {
            values.entrySet().removeIf(e -> !e.getValue().refreshFamilyExpiresAt().plus(java.time.Duration.ofMinutes(5)).isAfter(java.time.Instant.now()));
            currentByUser.entrySet().removeIf(e -> !values.containsKey(e.getValue()));
            if (values.size() >= 100000)
                throw new IllegalStateException("Local token store is full");
        }
        if (overlaps.size() >= 100000) {
            overlaps.entrySet().removeIf(e -> !e.getValue().expiresAt().isAfter(java.time.Instant.now()));
            if (overlaps.size() >= 100000)
                throw new IllegalStateException("Local token overlap store is full");
        }
        String previous = currentByUser.put(userKey, newKey);
        values.put(newKey, record);
        if (previous != null && !previous.equals(newKey))
            values.remove(previous);
        if (oldKey != null) {
            if (encryptedOverlap != null)
                overlaps.put(oldKey, new Overlap(encryptedOverlap, java.time.Instant.now().plus(overlapTtl)));
            values.remove(oldKey);
        }
    }
    @Override public synchronized Optional<String> findOverlapAccessToken(String oldToken) {
        Overlap overlap = overlaps.get(key(oldToken));
        if (overlap == null)
            return Optional.empty();
        if (!overlap.expiresAt().isAfter(java.time.Instant.now())) {
            overlaps.remove(key(oldToken), overlap);
            return Optional.empty();
        }
        return Optional.of(overlap.encryptedAccessToken());
    }
    @Override public synchronized boolean claimRefreshAttempt(String refreshTokenFingerprint, Instant retainUntil) {
        Instant now = Instant.now();
        String digest = key(refreshTokenFingerprint);
        Instant existing = refreshAttempts.get(digest);
        if (existing != null && existing.isAfter(now))
            return false;
        if (refreshAttempts.size() >= 100000) {
            refreshAttempts.entrySet().removeIf(e -> !e.getValue().isAfter(now));
            if (refreshAttempts.size() >= 100000)
                throw new IllegalStateException("Local refresh attempt store is full");
        }
        refreshAttempts.put(digest, retainUntil.isAfter(now)?retainUntil:now.plusSeconds(1));
        return true;
    }
    @Override public synchronized void deleteByAccessToken(String token) {
        SsoTokenRecord removed = values.remove(key(token));
        overlaps.remove(key(token));
        if (removed != null)
            currentByUser.remove(key(removed.clientId()+":"+removed.principal().subject()),
                key(token));
    }
    @Override public synchronized Optional<SsoTokenRecord> removeCurrentBySubjectAndClient(String subject,
        String clientId) {
        String userKey = key(clientId+":"+subject), current = currentByUser.remove(userKey);
        if (current == null)
            return Optional.empty();
        overlaps.remove(current);
        return Optional.ofNullable(values.remove(current));
    }
    private record Overlap(String encryptedAccessToken, java.time.Instant expiresAt) {
    }
}
final class LocalSsoRefreshLock implements com.authsystem.sso.client.store.SsoRefreshLock {
    private final java.util.concurrent.ConcurrentHashMap<String, LockEntry> locks = new java.util.concurrent.ConcurrentHashMap<>();
    @Override public java.util.Optional<Lease> acquire(String digest, java.time.Duration wait, java.time.Duration lease) {
        LockEntry entry = locks.compute(digest, (key, current) -> {
                LockEntry selected = current == null?new LockEntry():current;
                selected.references++;
                return selected;
            });
        try {
            if (!entry.permit.tryAcquire(wait.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS)) {
                releaseReference(digest, entry);
                return java.util.Optional.empty();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            releaseReference(digest, entry);
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(() -> {
                entry.permit.release();
                releaseReference(digest, entry);
            });
    }
    private void releaseReference(String digest, LockEntry entry) {
        locks.computeIfPresent(digest, (key, current) -> {
                if (current != entry)
                    return current;
                current.references--;
                return current.references == 0?null:current;
            });
    }
    private static final class LockEntry {
        private final java.util.concurrent.Semaphore permit = new java.util.concurrent.Semaphore(1);
        private int references;
    }
}
