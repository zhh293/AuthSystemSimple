package com.authsystem.sso.service;

import com.authsystem.sso.domain.UserAccount;

/** Selectable credential source behind the stable identity/session use case. */
public interface CredentialAuthenticator {
    boolean verify(String username, String rawPassword, UserAccount mappedAccount);
}
