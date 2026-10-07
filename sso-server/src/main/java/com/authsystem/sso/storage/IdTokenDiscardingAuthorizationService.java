package com.authsystem.sso.storage;

import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/** Persists authorization state without retaining ID Token values or claims. */
public final class IdTokenDiscardingAuthorizationService implements OAuth2AuthorizationService {
    private final OAuth2AuthorizationService delegate;
    private final RegisteredClientRepository clients;

    public IdTokenDiscardingAuthorizationService(OAuth2AuthorizationService delegate, RegisteredClientRepository clients) {
        this.delegate = delegate;
        this.clients = clients;
    }

    @Override public void save(OAuth2Authorization authorization) {
        delegate.save(withoutIdToken(authorization));
    }

    @Override public void remove(OAuth2Authorization authorization) { delegate.remove(authorization); }

    @Override public OAuth2Authorization findById(String id) { return delegate.findById(id); }

    @Override public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        OAuth2Authorization authorization = delegate.findByToken(token, tokenType);
        if (authorization == null || !OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)
                || !authorization.getAuthorizedScopes().contains("openid")
                || authorization.getToken(OidcIdToken.class) != null) {
            return authorization;
        }

        // Spring Authorization Server's JwtGenerator expects an OIDC authorization
        // loaded for a refresh grant to contain the previous ID Token. The real token
        // is intentionally not persisted, so provide only the subject-bearing,
        // in-memory value it needs to inspect for optional sid/auth_time claims.
        // The generated refresh ID Token is persisted through save(), which strips it.
        OidcIdToken transientIdToken = new OidcIdToken(
                "transient-id-token-for-refresh", null, null,
                Map.of("sub", authorization.getPrincipalName()));
        return OAuth2Authorization.from(authorization).token(transientIdToken).build();
    }

    private OAuth2Authorization withoutIdToken(OAuth2Authorization source) {
        RegisteredClient client = clients.findById(source.getRegisteredClientId());
        if (client == null) throw new IllegalStateException("Cannot persist authorization for an unavailable client");
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .id(source.getId())
                .principalName(source.getPrincipalName())
                .authorizationGrantType(source.getAuthorizationGrantType())
                .authorizedScopes(source.getAuthorizedScopes())
                .attributes(attributes -> attributes.putAll(source.getAttributes()));
        copyToken(builder, source, OAuth2AuthorizationCode.class);
        copyToken(builder, source, OAuth2AccessToken.class);
        copyToken(builder, source, OAuth2RefreshToken.class);
        copyToken(builder, source, OAuth2DeviceCode.class);
        copyToken(builder, source, OAuth2UserCode.class);
        // OidcIdToken deliberately is not copied into the authorization store.
        return builder.build();
    }

    private static <T extends OAuth2Token> void copyToken(OAuth2Authorization.Builder builder,
            OAuth2Authorization source, Class<T> tokenType) {
        OAuth2Authorization.Token<T> token = source.getToken(tokenType);
        if (token != null) builder.token(token.getToken(), metadata -> metadata.putAll(token.getMetadata()));
    }
}
