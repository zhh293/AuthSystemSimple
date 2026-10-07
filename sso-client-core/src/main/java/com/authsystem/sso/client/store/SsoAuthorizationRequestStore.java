package com.authsystem.sso.client.store;

import com.authsystem.sso.client.session.SsoAuthorizationTransaction;
import java.util.Optional;

public interface SsoAuthorizationRequestStore {
    void save(String state, SsoAuthorizationTransaction transaction);
    Optional<SsoAuthorizationTransaction> consume(String state);
}
