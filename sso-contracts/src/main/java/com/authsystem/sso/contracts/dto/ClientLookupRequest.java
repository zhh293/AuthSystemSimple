package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

public class ClientLookupRequest implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private String clientId;
    public ClientLookupRequest() { }
    public ClientLookupRequest(String clientId) { this.clientId = clientId; }
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
}
