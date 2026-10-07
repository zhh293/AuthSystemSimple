package com.authsystem.sso.client.session;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import java.util.Optional;

public final class SsoCurrentUser {
    private SsoCurrentUser() {
    }
    public static Optional<SsoPrincipal> get() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth instanceof SsoAuthentication sso?Optional.of(sso.getPrincipal()):Optional.empty();
    }
}
