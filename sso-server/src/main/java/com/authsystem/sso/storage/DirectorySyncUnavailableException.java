package com.authsystem.sso.storage;

/** Indicates that directory-backed account status cannot be trusted until synchronization recovers. */
public final class DirectorySyncUnavailableException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public DirectorySyncUnavailableException() {
        super("Directory account synchronization is stale or unavailable");
    }
}
