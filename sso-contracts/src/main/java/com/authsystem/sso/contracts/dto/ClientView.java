package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class ClientView implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private String clientId;
    private String displayName;
    private String clientType;
    private boolean enabled;
    private List<String> redirectUris = new ArrayList<>();
    private List<String> allowedScopes = new ArrayList<>();
    public ClientView() { }
    public ClientView(String clientId, String displayName, boolean enabled, List<String> redirectUris) { this.clientId = clientId; this.displayName = displayName; this.enabled = enabled; this.redirectUris = redirectUris; }
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public String getClientType() { return clientType; }
    public void setClientType(String clientType) { this.clientType = clientType; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public List<String> getRedirectUris() { return redirectUris; }
    public void setRedirectUris(List<String> redirectUris) { this.redirectUris = redirectUris; }
    public List<String> getAllowedScopes() { return allowedScopes; }
    public void setAllowedScopes(List<String> allowedScopes) { this.allowedScopes = allowedScopes; }
}
