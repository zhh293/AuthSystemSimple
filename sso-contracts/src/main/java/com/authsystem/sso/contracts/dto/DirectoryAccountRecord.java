package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

/** Directory-owned account mapping data; credential fields are intentionally absent. */
public class DirectoryAccountRecord implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private String subject;
    private String usernameNormalized;
    private boolean enabled;
    private String displayName;
    private String email;
    private boolean emailVerified;

    public DirectoryAccountRecord() { }
    public DirectoryAccountRecord(String subject, String usernameNormalized, boolean enabled,
            String displayName, String email, boolean emailVerified) {
        this.subject = subject;
        this.usernameNormalized = usernameNormalized;
        this.enabled = enabled;
        this.displayName = displayName;
        this.email = email;
        this.emailVerified = emailVerified;
    }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getUsernameNormalized() { return usernameNormalized; }
    public void setUsernameNormalized(String usernameNormalized) { this.usernameNormalized = usernameNormalized; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public boolean isEmailVerified() { return emailVerified; }
    public void setEmailVerified(boolean emailVerified) { this.emailVerified = emailVerified; }

    @Override public String toString() { return "DirectoryAccountRecord{account=[REDACTED]}"; }
}
