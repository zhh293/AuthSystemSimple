package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.crypto.TokenDigests;
import com.authsystem.sso.client.session.SsoAuthorizationTransaction;
import com.authsystem.sso.client.session.SsoTokenRecord;
import com.authsystem.sso.client.store.SsoAuthorizationRequestStore;
import com.authsystem.sso.client.store.SsoTokenStore;
import com.authsystem.sso.client.protocol.SsoClientDependencyException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Optional;

final class RedisAuthorizationRequestStore implements SsoAuthorizationRequestStore {
    private static final DefaultRedisScript<String> CONSUME = new DefaultRedisScript<>("local v=redis.call('GET',KEYS[1]); if v then redis.call('DEL',KEYS[1]); end; return v",
        String.class);
    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final byte[] key, encryptionKey;
    private final Duration ttl;
    private final String prefix, client;
    RedisAuthorizationRequestStore(StringRedisTemplate redis, ObjectMapper mapper, byte[] key, byte[] encryptionKey,
        Duration ttl, String prefix, String client) {
        this.redis = redis;
        this.mapper = mapper;
        this.key = key;
        this.encryptionKey = encryptionKey;
        this.ttl = ttl;
        this.prefix = prefix;
        this.client = client;
    }
    private String transactionKey(String state) {
        return prefix+":tx:{"+TokenDigests.hmacSha256(client, key)+"}:"+TokenDigests.hmacSha256(state,
            key);
    }
    @Override public void save(String state, SsoAuthorizationTransaction tx) {
        try {
            long seconds = Math.max(1, Duration.between(Instant.now(), tx.expiresAt()).toSeconds());
            Boolean saved = redis.opsForValue().setIfAbsent(transactionKey(state), com.authsystem.sso.client.crypto.RefreshTokenCipher.encrypt(mapper.writeValueAsString(tx),
                    encryptionKey, transactionAad(client, key, state)), Duration.ofSeconds(Math.max(1,
                        Math.min(seconds,
                            ttl.toSeconds()))));
            if (!Boolean.TRUE.equals(saved))
                throw new IllegalStateException("Unable to store authorization transaction");
        } catch (Exception e) {
            throw new SsoClientDependencyException("Authorization transaction store is unavailable", e);
        }
    }
    @Override public Optional<SsoAuthorizationTransaction> consume(String state) {
        try {
            String raw = redis.execute(CONSUME, Collections.singletonList(transactionKey(state)));
            if (raw == null)
                return Optional.empty();
            SsoAuthorizationTransaction tx = mapper.readValue(com.authsystem.sso.client.crypto.RefreshTokenCipher.decrypt(raw,
                    encryptionKey, transactionAad(client, key, state)), SsoAuthorizationTransaction.class);
            return tx.expiresAt().isAfter(Instant.now())?Optional.of(tx):Optional.empty();
        } catch (Exception e) {
            throw new SsoClientDependencyException("Authorization transaction store is unavailable", e);
        }
    }
    static byte[] transactionAad(String client, byte[] key, String state) {
        return (client+"\n"+TokenDigests.hmacSha256(state, key)+"\nauthorization-transaction").getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
}

final class RedisSsoTokenStore implements SsoTokenStore {
    private static final DefaultRedisScript<Long> SAVE_NEW = new DefaultRedisScript<>("local old=redis.call('GET',KEYS[2]); redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[2]); if old and old ~= KEYS[1] then redis.call('DEL',old); end; redis.call('SET',KEYS[2],KEYS[1],'EX',ARGV[2]); return 1",
        Long.class);
    private static final DefaultRedisScript<Long> REPLACE = new DefaultRedisScript<>("local current=redis.call('GET',KEYS[4]); if not current or current ~= KEYS[2] or redis.call('EXISTS',KEYS[2]) == 0 then return 0 end; redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[2]); if KEYS[2] ~= KEYS[1] then redis.call('DEL',KEYS[2]); end; if ARGV[3] ~= '' then redis.call('SET',KEYS[3],ARGV[3],'EX',ARGV[4]); end; redis.call('SET',KEYS[4],KEYS[1],'EX',ARGV[2]); return 1",
        Long.class);
    private static final DefaultRedisScript<Long> DELETE = new DefaultRedisScript<>("local current=redis.call('GET',KEYS[2]); if current==KEYS[1] then redis.call('DEL',KEYS[2]); end; redis.call('DEL',KEYS[1],KEYS[3]); return 1",
        Long.class);
    private static final DefaultRedisScript<String> REMOVE_CURRENT = new DefaultRedisScript<>("local current=redis.call('GET',KEYS[1]); if not current then return nil end; local record=redis.call('GET',current); redis.call('DEL',current,KEYS[1]); return record",
        String.class);
    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final byte[] key;
    private final String client, prefix;
    private final Cache<String, SsoTokenRecord> tokenCache;
    RedisSsoTokenStore(StringRedisTemplate redis, ObjectMapper mapper, byte[] key, String client, String prefix,
        Duration userMappingCacheTtl) {
        this.redis = redis;
        this.mapper = mapper;
        this.key = key;
        this.client = client;
        this.prefix = prefix;
        Caffeine<Object, Object> builder = Caffeine.newBuilder().maximumSize(userMappingCacheTtl.isZero()?0:100_000);
        if (!userMappingCacheTtl.isZero())
            builder.expireAfterWrite(userMappingCacheTtl);
        this.tokenCache = builder.build();
    }
    private String tag() {
        return "{"+TokenDigests.hmacSha256(client, key)+"}";
    }
    private String redisKey(String token) {
        return prefix+":token:"+tag()+":"+TokenDigests.hmacSha256(token, key);
    }
    private String overlapKey(String token) {
        return prefix+":overlap:"+tag()+":"+TokenDigests.hmacSha256(token, key);
    }
    private String refreshAttemptKey(String refreshTokenFingerprint) {
        return prefix+":refresh-attempt:"+tag()+":"+TokenDigests.hmacSha256(refreshTokenFingerprint, key);
    }
    private String userKey(String subject) {
        return prefix+":user:"+tag()+":"+TokenDigests.hmacSha256(subject, key);
    }
    @Override public Optional<SsoTokenRecord> findByAccessToken(String token) {
        String cacheKey = redisKey(token);
        SsoTokenRecord cached = tokenCache.getIfPresent(cacheKey);
        if (cached != null)
            return Optional.of(cached);
        return findByAccessTokenFresh(token);
    }
    @Override public Optional<SsoTokenRecord> findByAccessTokenFresh(String token) {
        String cacheKey = redisKey(token);
        try {
            String value = redis.opsForValue().get(cacheKey);
            if (value == null)
                return Optional.empty();
            SsoTokenRecord record = mapper.readValue(value, SsoTokenRecord.class);
            tokenCache.put(cacheKey, record);
            return Optional.of(record);
        } catch (Exception e) {
            throw new SsoClientDependencyException("Token store is unavailable", e);
        }
    }
    @Override public void saveCurrent(String oldToken, String newToken, SsoTokenRecord record, String encryptedOverlap,
        Duration overlapTtl) {
        tokenCache.invalidateAll();
        try {
            long ttl = Math.max(1, Duration.between(Instant.now(), record.refreshFamilyExpiresAt().plus(Duration.ofMinutes(5))).toSeconds());
            SsoTokenRecord stored = new SsoTokenRecord(record.issuer(), record.clientId(), TokenDigests.hmacSha256(newToken,
                    key), record.encryptedRefreshToken(), record.encryptionKeyId(), record.principal(),
                record.accessTokenExpiresAt(),
                record.refreshFamilyExpiresAt(), record.idTokenNonceDigest(), record.grantedScopes());
            String serialized = mapper.writeValueAsString(stored);
            if (oldToken == null || oldToken.isBlank()) {
                Long result = redis.execute(SAVE_NEW, java.util.List.of(redisKey(newToken), userKey(record.principal().subject())),
                    serialized, Long.toString(ttl));
                if (!Long.valueOf(1).equals(result))
                    throw new IllegalStateException("Token mapping write was not confirmed");
                return;
            }
            String oldKey = oldToken == null || oldToken.isBlank()?"":redisKey(oldToken);
            String oldOverlap = oldKey.isEmpty()?"":overlapKey(oldToken);
            Long result = redis.execute(REPLACE, java.util.List.of(redisKey(newToken), oldKey, oldOverlap,
                    userKey(record.principal().subject())), serialized, Long.toString(ttl), encryptedOverlap == null?"":encryptedOverlap,
                Long.toString(Math.max(1, overlapTtl.toSeconds())));
            if (!Long.valueOf(1).equals(result))
                throw new IllegalStateException("Token mapping write was not confirmed");
        } catch (Exception e) {
            tokenCache.invalidateAll();
            throw new SsoClientDependencyException("Token store is unavailable", e);
        }
    }
    @Override public Optional<String> findOverlapAccessToken(String oldToken) {
        try {
            return Optional.ofNullable(redis.opsForValue().get(overlapKey(oldToken)));
        } catch (Exception e) {
            throw new SsoClientDependencyException("Token store is unavailable", e);
        }
    }
    @Override public boolean claimRefreshAttempt(String refreshTokenFingerprint, Instant retainUntil) {
        try {
            long ttl = Math.max(1, Duration.between(Instant.now(), retainUntil).toSeconds());
            return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(refreshAttemptKey(refreshTokenFingerprint),
                    "1", Duration.ofSeconds(ttl)));
        } catch (Exception e) {
            throw new SsoClientDependencyException("Refresh attempt store is unavailable", e);
        }
    }
    @Override public void deleteByAccessToken(String token) {
        tokenCache.invalidate(redisKey(token));
        try {
            String mapping = redis.opsForValue().get(redisKey(token));
            if (mapping == null) {
                redis.delete(overlapKey(token));
                return;
            }
            SsoTokenRecord record = mapper.readValue(mapping, SsoTokenRecord.class);
            redis.execute(DELETE, java.util.List.of(redisKey(token), userKey(record.principal().subject()),
                    overlapKey(token)));
        } catch (Exception e) {
            tokenCache.invalidateAll();
            throw new SsoClientDependencyException("Token store is unavailable", e);
        }
    }
    @Override public Optional<SsoTokenRecord> removeCurrentBySubjectAndClient(String subject, String clientId) {
        if (!client.equals(clientId))
            throw new IllegalArgumentException("Token store client namespace mismatch");
        tokenCache.invalidateAll();
        try {
            String raw = redis.execute(REMOVE_CURRENT, java.util.List.of(userKey(subject)));
            if (raw == null)
                return Optional.empty();
            SsoTokenRecord removed = mapper.readValue(raw, SsoTokenRecord.class);
            tokenCache.invalidate(prefix+":token:"+tag()+":"+removed.accessTokenDigest());
            return Optional.of(removed);
        } catch (Exception e) {
            tokenCache.invalidateAll();
            throw new SsoClientDependencyException("Token store is unavailable", e);
        }
    }
}

final class RedisSsoRefreshLock implements com.authsystem.sso.client.store.SsoRefreshLock {
    private static final DefaultRedisScript<Long> RELEASE = new DefaultRedisScript<>("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end",
        Long.class);
    private final StringRedisTemplate redis;
    private final byte[] key;
    private final String client, prefix;
    RedisSsoRefreshLock(StringRedisTemplate redis, byte[] key, String client, String prefix) {
        this.redis = redis;
        this.key = key;
        this.client = client;
        this.prefix = prefix;
    }
    @Override public Optional<Lease> acquire(String digest, Duration wait, Duration lease) {
        String slot = TokenDigests.hmacSha256(client, key), lockKey = prefix+":lock:{"+slot+"}:"+TokenDigests.hmacSha256(digest,
            key);
        String owner = com.authsystem.sso.client.security.Pkce.randomUrlSafe(32);
        long end = System.nanoTime()+wait.toNanos();
        do {
            try {
                if (Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(lockKey, owner, lease)))
                    return Optional.of(() -> redis.execute(RELEASE,
                            Collections.singletonList(lockKey), owner));
            } catch (Exception unavailable) {
                throw new SsoClientDependencyException("Refresh coordination is unavailable", unavailable);
            }
            try {
                Thread.sleep(25L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            }
        } while (System.nanoTime()<end);
        return Optional.empty();
    }
}
