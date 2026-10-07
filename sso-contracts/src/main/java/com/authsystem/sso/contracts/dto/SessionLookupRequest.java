package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

public class SessionLookupRequest implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private String sessionCookieValue;
    public SessionLookupRequest() { }
    public SessionLookupRequest(String sessionCookieValue) { this.sessionCookieValue = sessionCookieValue; }
    public String getSessionCookieValue() { return sessionCookieValue; }
    public void setSessionCookieValue(String sessionCookieValue) { this.sessionCookieValue = sessionCookieValue; }
}
