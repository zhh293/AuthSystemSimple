package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** Minimal authorization context for an internal resource server. */
public class TokenIntrospectionResult implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private boolean active;
    private String subject;
    private String clientId;
    private List<String> scopes = new ArrayList<>();
    private long expiresAtEpochSecond;

    public TokenIntrospectionResult() { }

    public TokenIntrospectionResult(boolean active, String subject, String clientId,
            List<String> scopes, long expiresAtEpochSecond) {
        this.active = active;
        this.subject = subject;
        this.clientId = clientId;
        this.scopes = scopes == null ? new ArrayList<>() : new ArrayList<>(scopes);
        this.expiresAtEpochSecond = expiresAtEpochSecond;
    }

    public static TokenIntrospectionResult inactive() {
        return new TokenIntrospectionResult(false, null, null, List.of(), 0);
    }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public List<String> getScopes() { return scopes; }
    public void setScopes(List<String> scopes) { this.scopes = scopes == null ? new ArrayList<>() : new ArrayList<>(scopes); }
    public long getExpiresAtEpochSecond() { return expiresAtEpochSecond; }
    public void setExpiresAtEpochSecond(long expiresAtEpochSecond) { this.expiresAtEpochSecond = expiresAtEpochSecond; }
}
