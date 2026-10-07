package com.authsystem.sso.service;

import com.authsystem.sso.contracts.TokenIntrospectionService;
import com.authsystem.sso.contracts.dto.TokenIntrospectionRequest;
import com.authsystem.sso.contracts.dto.TokenIntrospectionResult;
import com.authsystem.sso.observability.SsoMetrics;
import com.authsystem.sso.storage.UserAccountRepository;
import java.time.Instant;
import org.apache.dubbo.config.annotation.DubboService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;

@DubboService(interfaceClass = TokenIntrospectionService.class, version = "1.0.0")
public class TokenIntrospectionServiceProvider implements TokenIntrospectionService {
    private static final int MAX_TOKEN_LENGTH = 4096;
    private final OAuth2AuthorizationService authorizations;
    private final RegisteredClientRepository clients;
    private final UserAccountRepository users;
    private final SsoMetrics metrics;

    public TokenIntrospectionServiceProvider(OAuth2AuthorizationService authorizations,
            RegisteredClientRepository clients, UserAccountRepository users, SsoMetrics metrics) {
        this.authorizations = authorizations;
        this.clients = clients;
        this.users = users;
        this.metrics = metrics;
    }

    @Override public TokenIntrospectionResult introspect(TokenIntrospectionRequest request) {
        try {
            return introspectRequest(request);
        } catch (RuntimeException e) {
            metrics.tokenValidation(SsoMetrics.TokenOutcome.DEPENDENCY_ERROR);
            throw e;
        }
    }

    private TokenIntrospectionResult introspectRequest(TokenIntrospectionRequest request) {
        if (request == null || !StringUtils.hasText(request.getToken())
                || request.getToken().length() > MAX_TOKEN_LENGTH
                || request.getToken().chars().anyMatch(Character::isWhitespace)) {
            return inactive();
        }
        OAuth2Authorization authorization = authorizations.findByToken(
                request.getToken(), OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) return inactive();

        OAuth2Authorization.Token<OAuth2AccessToken> access = authorization.getAccessToken();
        if (access == null || !access.isActive()) return inactive();
        Instant expiresAt = access.getToken().getExpiresAt();
        if (expiresAt == null || !expiresAt.isAfter(Instant.now())) return inactive();
        if (!users.isEnabledBySubject(authorization.getPrincipalName())) return inactive();
        RegisteredClient storedClient = clients.findById(authorization.getRegisteredClientId());
        if (storedClient == null) return inactive();
        RegisteredClient client = clients.findByClientId(storedClient.getClientId());
        if (client == null) return inactive();

        metrics.tokenValidation(SsoMetrics.TokenOutcome.ACTIVE);
        return new TokenIntrospectionResult(true, authorization.getPrincipalName(), client.getClientId(),
                access.getToken().getScopes().stream().sorted().toList(), expiresAt.getEpochSecond());
    }

    private TokenIntrospectionResult inactive() {
        metrics.tokenValidation(SsoMetrics.TokenOutcome.INACTIVE);
        return TokenIntrospectionResult.inactive();
    }
}
