package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

public class AuthenticationRequest implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private String username;
    private String password;
    private String remoteAddress;
    public AuthenticationRequest() { }
    public AuthenticationRequest(String username, String password, String remoteAddress) { this.username = username; this.password = password; this.remoteAddress = remoteAddress; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getRemoteAddress() { return remoteAddress; }
    public void setRemoteAddress(String remoteAddress) { this.remoteAddress = remoteAddress; }
}
