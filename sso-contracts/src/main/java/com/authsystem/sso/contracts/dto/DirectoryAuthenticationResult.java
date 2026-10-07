package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

public class DirectoryAuthenticationResult implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private boolean authenticated;

    public DirectoryAuthenticationResult() { }
    public DirectoryAuthenticationResult(boolean authenticated) { this.authenticated = authenticated; }
    public boolean isAuthenticated() { return authenticated; }
    public void setAuthenticated(boolean authenticated) { this.authenticated = authenticated; }
}
