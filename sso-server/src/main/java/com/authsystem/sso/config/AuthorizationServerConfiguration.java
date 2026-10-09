package com.authsystem.sso.config;

import com.authsystem.sso.storage.IdTokenDiscardingAuthorizationService;
import com.authsystem.sso.storage.DigestingJdbcOAuth2AuthorizationService;
import com.authsystem.sso.storage.AuditRepository;
import java.util.List;
import java.util.function.Consumer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import com.authsystem.sso.security.TgcAuthenticationFilter;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.authsystem.sso.security.FamilyAwareRefreshTokenGenerator;
import com.authsystem.sso.security.OpaqueUserInfoFilter;
import com.authsystem.sso.observability.SsoMetrics;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@Configuration
public class AuthorizationServerConfiguration {
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, TgcAuthenticationFilter tgcFilter,
            OpaqueUserInfoFilter opaqueUserInfoFilter, SecurityContextRepository securityContextRepository,
            OAuth2TokenGenerator<?> tokenGenerator, AuthorizationServerSettings authorizationServerSettings) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServer = OAuth2AuthorizationServerConfigurer.authorizationServer();
        http.securityMatcher(authorizationServer.getEndpointsMatcher())
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServer.getEndpointsMatcher()))
                .with(authorizationServer, server -> server
                        .tokenGenerator(tokenGenerator)
                        .oidc(Customizer.withDefaults())
                        .authorizationEndpoint(endpoint -> endpoint.authenticationProviders(requireStateNonceAndS256())))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, authorizationServerSettings.getTokenEndpoint()).permitAll()
                        .anyRequest().authenticated())
                .securityContext(context -> context.securityContextRepository(securityContextRepository))
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .addFilterBefore(opaqueUserInfoFilter, BearerTokenAuthenticationFilter.class)
                .addFilterBefore(tgcFilter, AnonymousAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository clients,
            SsoProperties properties, AuditRepository audit, SsoMetrics metrics) {
        return new IdTokenDiscardingAuthorizationService(
                new DigestingJdbcOAuth2AuthorizationService(jdbc, clients, properties, audit, metrics), clients);
    }

    @Bean
    OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    @Bean
    OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> oidcTokenCustomizer, JdbcTemplate jdbc,
            PlatformTransactionManager transactionManager, SsoProperties properties, AuditRepository audit,
            SsoMetrics metrics) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(oidcTokenCustomizer);
        return new org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator(
                jwtGenerator, new OAuth2AccessTokenGenerator(),
                new FamilyAwareRefreshTokenGenerator(new OAuth2RefreshTokenGenerator(), jdbc,
                        new TransactionTemplate(transactionManager), properties, audit, metrics));
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(SsoProperties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.getIssuer()).build();
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private Consumer<List<AuthenticationProvider>> requireStateNonceAndS256() {
        return providers -> providers.stream()
                .filter(OAuth2AuthorizationCodeRequestAuthenticationProvider.class::isInstance)
                .map(OAuth2AuthorizationCodeRequestAuthenticationProvider.class::cast)
                .forEach(provider -> provider.setAuthenticationValidator(context -> validateAuthorizationRequest(context)));
    }

    private void validateAuthorizationRequest(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken request =
            (OAuth2AuthorizationCodeRequestAuthenticationToken) context.getAuthentication();
        org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context);
        org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR.accept(context);
        if (request.getRedirectUri() == null || !context.getRegisteredClient().getRedirectUris().contains(request.getRedirectUri())) {
            var rejected = new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getAuthorizationUri(),
                    request.getClientId(), (org.springframework.security.core.Authentication) request.getPrincipal(),
                    null, request.getState(), request.getScopes(), request.getAdditionalParameters());
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), rejected);
        }
        OAuth2Error error = null;
        Object nonce = request.getAdditionalParameters().get(OidcParameterNames.NONCE);
        Object method = request.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
        Object challenge = request.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
        if (request.getState() == null || request.getState().isBlank() || request.getState().length() > 512
                || !(nonce instanceof String nonceValue) || nonceValue.isBlank() || nonceValue.length() > 512
                || !request.getScopes().contains("openid") || !"S256".equals(method)
                || !(challenge instanceof String challengeValue) || !challengeValue.matches("[A-Za-z0-9_-]{43}")) {
            error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        if (error != null) throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, request);
    }
}
