package com.authsystem.sso.client.session;

@FunctionalInterface
public interface SsoPrincipalMapper {
    SsoPrincipal map(VerifiedIdTokenClaims verifiedClaims);
}
