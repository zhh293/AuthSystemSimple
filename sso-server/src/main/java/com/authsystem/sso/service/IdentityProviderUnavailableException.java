package com.authsystem.sso.service;

/** Safe failure signal for credential-provider outages; contains no submitted credential data. */
public final class IdentityProviderUnavailableException extends RuntimeException {
    public IdentityProviderUnavailableException() {
        super("Identity provider is unavailable");
    }
}
