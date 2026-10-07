package com.authsystem.sso.contracts.dto;

import java.io.Serial;
import java.io.Serializable;

/** Carries a bearer value only across the protected internal RPC boundary. */
public class TokenIntrospectionRequest implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private String token;

    public TokenIntrospectionRequest() { }
    public TokenIntrospectionRequest(String token) { this.token = token; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    @Override public String toString() { return "TokenIntrospectionRequest{token=[REDACTED]}"; }
}
