package com.authsystem.sso.crypto;

public final class LoginCryptoRateLimitException extends RuntimeException {
    public LoginCryptoRateLimitException() { super("rate limited"); }
}
