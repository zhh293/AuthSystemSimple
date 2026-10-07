package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

/** Credential material is transient and must travel only over the trusted internal RPC channel. */
public class DirectoryAuthenticationRequest implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private String username;
    private String password;

    public DirectoryAuthenticationRequest() { }
    public DirectoryAuthenticationRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    @Override public String toString() {
        return "DirectoryAuthenticationRequest{username=[REDACTED], password=[REDACTED]}";
    }
}
