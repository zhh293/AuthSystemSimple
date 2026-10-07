package com.authsystem.sso.client.session;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

public final class SsoAuthentication extends AbstractAuthenticationToken {
    private final SsoPrincipal principal;
    public SsoAuthentication(SsoPrincipal principal) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.principal = principal;
        setAuthenticated(true);
    }
    @Override public Object getCredentials() {
        return "";
    }
    @Override public SsoPrincipal getPrincipal() {
        return principal;
    }
    @Override public String getName() {
        return principal.subject();
    }
}
