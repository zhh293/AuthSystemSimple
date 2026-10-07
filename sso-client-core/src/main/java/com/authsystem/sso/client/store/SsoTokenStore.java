package com.authsystem.sso.client.store;

import com.authsystem.sso.client.session.SsoTokenRecord;
import java.util.Optional;
import java.time.Duration;

public interface SsoTokenStore {
    Optional<SsoTokenRecord> findByAccessToken(String rawAccessToken);
    /** Reads authoritative storage directly when a short-lived L1 cache could hide a concurrent rotation. */
    default Optional<SsoTokenRecord> findByAccessTokenFresh(String rawAccessToken) {
        return findByAccessToken(rawAccessToken);
    }
    void saveCurrent(String oldAccessToken, String newAccessToken, SsoTokenRecord record, String encryptedOverlapAccessToken,
        Duration overlapTtl);
    Optional<String> findOverlapAccessToken(String previousAccessToken);
    /** Atomically claims the one permitted attempt for this refresh-token generation. */
    boolean claimRefreshAttempt(String refreshTokenFingerprint, java.time.Instant retainUntil);
    void deleteByAccessToken(String rawAccessToken);
    /** Atomically returns and removes whichever mapping is current for this RP user, including a token rotated concurrently. */
    Optional<SsoTokenRecord> removeCurrentBySubjectAndClient(String subject, String clientId);
}
