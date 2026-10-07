package com.authsystem.sso.client.store;

import java.time.Duration;
import java.util.Optional;

/** Cross-instance refresh serialization; implementations release only leases they own. */
public interface SsoRefreshLock {
    Optional<Lease> acquire(String familyDigest, Duration wait, Duration lease);
    interface Lease extends AutoCloseable {
        @Override void close();
    }
}
