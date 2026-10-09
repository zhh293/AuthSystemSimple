package com.authsystem.sso.crypto;

public final class LoginCryptoException extends RuntimeException {
    public LoginCryptoException(String message) { super(message); }
    public LoginCryptoException(String message, Throwable cause) { super(message, cause); }
}
