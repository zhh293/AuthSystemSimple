package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.session.SsoAuthorizationTransaction;
import com.authsystem.sso.client.session.SsoPrincipal;
import com.authsystem.sso.client.session.SsoTokenRecord;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class LocalSsoStoresTest {
    private final byte[] key = new byte[32];
    private SsoTokenRecord record(String digest) {
        Instant now = Instant.now();
        return new SsoTokenRecord("https://issuer.test", "portal", digest, "encrypted-refresh", "primary",
            new SsoPrincipal("subject-1", "User", null, java.util.Map.of()), now.plusSeconds(120), now.plusSeconds(3600),
            "login-nonce-digest", java.util.List.of("openid", "profile"));
    }

    @Test void authorizationTransactionsAreConsumedOnce() {
        var store = new LocalAuthorizationRequestStore(key);
        var tx = new SsoAuthorizationTransaction("nonce", "verifier", "binding", "/home", Instant.now(),
            Instant.now().plusSeconds(60));
        store.save("one-time-state", tx);
        assertEquals(tx, store.consume("one-time-state").orElseThrow());
        assertTrue(store.consume("one-time-state").isEmpty());
    }

    @Test void keepsOnlyOneCurrentMappingPerUserAndClient() {
        var store = new LocalSsoTokenStore(key);
        store.saveCurrent(null, "token-one", record(""), null, Duration.ZERO);
        store.saveCurrent(null, "token-two", record(""), null, Duration.ZERO);
        assertTrue(store.findByAccessToken("token-one").isEmpty());
        assertTrue(store.findByAccessToken("token-two").isPresent());
        assertEquals("login-nonce-digest", store.findByAccessToken("token-two").orElseThrow().idTokenNonceDigest());
        assertEquals(java.util.List.of("openid", "profile"), store.findByAccessToken("token-two").orElseThrow().grantedScopes());
    }

    @Test void refreshAttemptCanOnlyBeClaimedOnce() {
        var store = new LocalSsoTokenStore(key);
        Instant retainUntil = Instant.now().plusSeconds(60);
        assertTrue(store.claimRefreshAttempt("refresh-generation-one", retainUntil));
        store.deleteByAccessToken("one-time-access");
        assertFalse(store.claimRefreshAttempt("refresh-generation-one", retainUntil));
        assertTrue(store.claimRefreshAttempt("refresh-generation-two", retainUntil));
    }

    @Test void logoutBySubjectRemovesTheCurrentRotatedMapping() {
        var store = new LocalSsoTokenStore(key);
        store.saveCurrent(null, "access-one", record(""), null, Duration.ZERO);
        store.saveCurrent("access-one", "access-two", record(""), "overlap-ciphertext", Duration.ofSeconds(5));

        assertThat(store.removeCurrentBySubjectAndClient("subject-1", "portal")).isPresent();
        store.deleteByAccessToken("access-one");

        assertTrue(store.findByAccessToken("access-two").isEmpty());
        assertTrue(store.findByAccessToken("access-one").isEmpty());
        assertTrue(store.findOverlapAccessToken("access-one").isEmpty());
    }

    @Test void rejectsLateRefreshAfterLogoutOrReplacementLogin() {
        var store = new LocalSsoTokenStore(key);
        store.saveCurrent(null, "token-old", record(""), null, Duration.ZERO);
        store.saveCurrent(null, "token-new-login", record(""), null, Duration.ZERO);

        assertThrows(IllegalStateException.class, () -> store.saveCurrent("token-old", "late-refresh",
                record(""),
                "encrypted-overlap", Duration.ofSeconds(5)));
        assertTrue(store.findByAccessToken("token-old").isEmpty());
        assertTrue(store.findByAccessToken("token-new-login").isPresent());
        assertTrue(store.findByAccessToken("late-refresh").isEmpty());
        assertTrue(store.findOverlapAccessToken("token-old").isEmpty());
    }

    @Test void concurrentLoginsLeaveExactlyOneCurrentUserMapping() throws Exception {
        var store = new LocalSsoTokenStore(key);
        int writers = 24;
        var ready = new CountDownLatch(writers);
        var start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(writers);
        var futures = new ArrayList<Future<?>>();
        for (int i = 0;i<writers;i++) {
            final String token = "parallel-token-"+i;
            futures.add(pool.submit(() -> {
                        ready.countDown();
                        start.await();
                        store.saveCurrent(null, token, record(""), null, Duration.ZERO);
                        return null;
                    }));
        }
        ready.await();
        start.countDown();
        for (Future<?> future:futures)
            future.get();
        pool.shutdown();
        long current = 0;
        for (int i = 0;i<writers;i++)
            if (store.findByAccessToken("parallel-token-"+i).isPresent())
                current++;
        assertEquals(1, current);
    }

    @Test void refreshLockPreventsConcurrentLeaseForSameFamily() {
        var lock = new LocalSsoRefreshLock();
        var first = lock.acquire("family", Duration.ZERO, Duration.ofSeconds(2)).orElseThrow();
        assertTrue(lock.acquire("family", Duration.ofMillis(10), Duration.ofSeconds(2)).isEmpty());
        first.close();
        try(var second = lock.acquire("family", Duration.ZERO, Duration.ofSeconds(2)).orElseThrow()) {
            assertNotNull(second);
        }
    }

    @Test void refreshLockNeverAllowsTwoConcurrentOwnersDuringContention() throws Exception {
        var lock = new LocalSsoRefreshLock();
        int workers = 12;
        var ready = new CountDownLatch(workers);
        var start = new CountDownLatch(1);
        var active = new AtomicInteger();
        var maximum = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        var futures = new ArrayList<Future<?>>();
        for (int i = 0;i<workers;i++)
            futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    for (int n = 0;n<20;n++) {
                        try(var lease = lock.acquire("same-family", Duration.ofSeconds(3), Duration.ofSeconds(4)).orElseThrow()) {
                            int owners = active.incrementAndGet();
                            maximum.accumulateAndGet(owners, Math::max);
                            Thread.sleep(1);
                            active.decrementAndGet();
                        }
                    }
                    return null;
                }));
        ready.await();
        start.countDown();
        for (Future<?> future:futures)
            future.get();
        pool.shutdown();
        assertEquals(1, maximum.get());
    }
}
