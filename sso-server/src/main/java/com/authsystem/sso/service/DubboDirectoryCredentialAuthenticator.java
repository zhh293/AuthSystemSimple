package com.authsystem.sso.service;

import com.authsystem.sso.contracts.DirectoryCredentialService;
import com.authsystem.sso.contracts.dto.DirectoryAuthenticationRequest;
import com.authsystem.sso.domain.UserAccount;
import org.apache.dubbo.config.annotation.DubboReference;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "sso.identity", name = "credential-mode", havingValue = "directory")
public class DubboDirectoryCredentialAuthenticator implements CredentialAuthenticator {
    @DubboReference(interfaceClass = DirectoryCredentialService.class, version = "1.0.0", check = true)
    private DirectoryCredentialService directory;

    @Override public boolean verify(String username, String rawPassword, UserAccount mappedAccount) {
        var result = directory.authenticate(new DirectoryAuthenticationRequest(username, rawPassword));
        return result != null && result.isAuthenticated();
    }
}
