package com.authsystem.sso.service;

import com.authsystem.sso.domain.UserAccount;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "sso.identity", name = "credential-mode", havingValue = "database", matchIfMissing = true)
public class JdbcCredentialAuthenticator implements CredentialAuthenticator {
    private final Argon2PasswordEncoder encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    private final String dummyPasswordHash = encoder.encode("constant-time-dummy-password");

    @Override public boolean verify(String username, String rawPassword, UserAccount mappedAccount) {
        String candidateHash = mappedAccount == null ? null : mappedAccount.passwordHash();
        return candidateHash == null
                ? encoder.matches(rawPassword, dummyPasswordHash)
                : encoder.matches(rawPassword, candidateHash);
    }
}
