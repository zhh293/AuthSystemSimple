package com.authsystem.sso.client.session;

import java.time.Instant;

/** Receives a credential-free event after the RP has attempted local logout cleanup. */
@FunctionalInterface
public interface SsoLogoutListener {
    void onLogout(SsoLogoutEvent event);
    record SsoLogoutEvent(String clientId, Instant occurredAt, boolean remoteRevocationConfirmed) {
    }
}
