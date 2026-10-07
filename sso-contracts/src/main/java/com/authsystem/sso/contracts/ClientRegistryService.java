package com.authsystem.sso.contracts;

import com.authsystem.sso.contracts.dto.ClientLookupRequest;
import com.authsystem.sso.contracts.dto.ClientView;

/** Internal read contract for registered OAuth clients. */
public interface ClientRegistryService {
    ClientView findEnabledClient(ClientLookupRequest request);
    boolean isRedirectUriAllowed(ClientLookupRequest request, String redirectUri);
}
