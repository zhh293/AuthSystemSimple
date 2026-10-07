package com.authsystem.sso.storage;

import com.authsystem.sso.domain.UserAccount;
import java.util.Optional;

public interface UserAccountRepository {
    Optional<UserAccount> findByUsername(String username);
    boolean isEnabledBySubject(String subject);
}
