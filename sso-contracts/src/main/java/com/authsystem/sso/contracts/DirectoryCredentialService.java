package com.authsystem.sso.contracts;

import com.authsystem.sso.contracts.dto.DirectoryAuthenticationRequest;
import com.authsystem.sso.contracts.dto.DirectoryAuthenticationResult;

/** Internal credential verification contract implemented by the corporate identity provider. */
public interface DirectoryCredentialService {
    DirectoryAuthenticationResult authenticate(DirectoryAuthenticationRequest request);
}
