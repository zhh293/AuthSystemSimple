package com.authsystem.sso.contracts;

import com.authsystem.sso.contracts.dto.AuthenticationRequest;
import com.authsystem.sso.contracts.dto.AuthenticationResult;
import com.authsystem.sso.contracts.dto.SessionLookupRequest;
import com.authsystem.sso.contracts.dto.SessionView;

/** Internal authentication and TGC session RPC contract. Version changes require compatibility review. */
public interface IdentityService {
    AuthenticationResult authenticate(AuthenticationRequest request);
    SessionView findSession(SessionLookupRequest request);
    void revokeSession(SessionLookupRequest request);
}
