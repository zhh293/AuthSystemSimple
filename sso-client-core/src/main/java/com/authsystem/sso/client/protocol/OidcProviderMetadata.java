package com.authsystem.sso.client.protocol;

import java.net.URI;

public record OidcProviderMetadata(String issuer, URI authorizationEndpoint, URI tokenEndpoint,
    URI jwksUri, URI userInfoEndpoint, URI revocationEndpoint,
    URI endSessionEndpoint) {
}
