package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

public class SessionView implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private boolean active;
    private String subject;
    private long expiresInSeconds;
    public SessionView() { }
    public SessionView(boolean active, String subject, long expiresInSeconds) { this.active = active; this.subject = subject; this.expiresInSeconds = expiresInSeconds; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public long getExpiresInSeconds() { return expiresInSeconds; }
    public void setExpiresInSeconds(long expiresInSeconds) { this.expiresInSeconds = expiresInSeconds; }
}
