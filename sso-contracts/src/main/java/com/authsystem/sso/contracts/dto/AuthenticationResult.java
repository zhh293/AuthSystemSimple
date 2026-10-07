package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

public class AuthenticationResult implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private boolean authenticated;
    private String sessionCookieValue;
    private String subject;
    private long expiresInSeconds;
    public AuthenticationResult() { }
    public AuthenticationResult(boolean authenticated, String sessionCookieValue, String subject, long expiresInSeconds) { this.authenticated = authenticated; this.sessionCookieValue = sessionCookieValue; this.subject = subject; this.expiresInSeconds = expiresInSeconds; }
    public boolean isAuthenticated() { return authenticated; }
    public void setAuthenticated(boolean authenticated) { this.authenticated = authenticated; }
    public String getSessionCookieValue() { return sessionCookieValue; }
    public void setSessionCookieValue(String sessionCookieValue) { this.sessionCookieValue = sessionCookieValue; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public long getExpiresInSeconds() { return expiresInSeconds; }
    public void setExpiresInSeconds(long expiresInSeconds) { this.expiresInSeconds = expiresInSeconds; }
}
