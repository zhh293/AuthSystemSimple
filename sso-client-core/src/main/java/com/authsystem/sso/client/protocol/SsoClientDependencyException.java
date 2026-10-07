package com.authsystem.sso.client.protocol;

/** Signals an unavailable SSO dependency or application store without carrying credential data. */
public final class SsoClientDependencyException extends RuntimeException {
    public SsoClientDependencyException(String message, Throwable cause) {
        super(message, cause);
    }
    public SsoClientDependencyException(String message) {
        super(message);
    }
}
