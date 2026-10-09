package com.authsystem.sso.client.protocol;

import com.authsystem.sso.client.config.SsoClientProperties;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Uses Spring Security's OAuth2 token response clients. POST grants are never retried. */
public final class OAuthTokenClient {
    private static final int MAX_TOKEN_CHARS = 8192;
    private static final int MAX_ID_TOKEN_CHARS = 16384;
    private static final int MAX_SCOPE_CHARS = 4096;
    private static final long MAX_ACCESS_TOKEN_SECONDS = 86400;
    private static final String ID_TOKEN_PARAMETER = "id_token";

    private final RestClient http;
    private final SsoClientProperties properties;
    private final OidcMetadataClient metadata;
    private final RestClientAuthorizationCodeTokenResponseClient authorizationCodeClient;
    private final RestClientRefreshTokenTokenResponseClient refreshTokenClient;

    public OAuthTokenClient(RestClient http, SsoClientProperties properties, OidcMetadataClient metadata) {
        this.http = http;
        this.properties = properties;
        this.metadata = metadata;
        OAuth2AccessTokenResponseHttpMessageConverter tokenResponseConverter =
        new OAuth2AccessTokenResponseHttpMessageConverter();
        DefaultMapOAuth2AccessTokenResponseConverter defaultResponseConverter =
        new DefaultMapOAuth2AccessTokenResponseConverter();
        tokenResponseConverter.setAccessTokenResponseConverter(parameters -> {
                validateRawTokenResponse(parameters);
                return defaultResponseConverter.convert(parameters);
            });
        RestClient tokenHttp = http.mutate()
        .messageConverters(converters -> {
                converters.clear();
                converters.add(new FormHttpMessageConverter());
                converters.add(tokenResponseConverter);
            })
        .defaultStatusHandler(org.springframework.http.HttpStatusCode::is5xxServerError,
                (request, response) -> {
                throw new SsoClientDependencyException("Token endpoint is unavailable");
            })
        .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
        .build();
        this.authorizationCodeClient = new RestClientAuthorizationCodeTokenResponseClient();
        this.authorizationCodeClient.setRestClient(tokenHttp);
        this.refreshTokenClient = new RestClientRefreshTokenTokenResponseClient();
        this.refreshTokenClient.setRestClient(tokenHttp);
    }

    public TokenResponse exchangeCode(String code, String verifier) {
        var provider = metadata.get();
        ClientRegistration registration = registration(provider.tokenEndpoint().toString(), properties.scopes());
        String internalState = UUID.randomUUID().toString();
        OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.authorizationCode()
        .authorizationUri(provider.authorizationEndpoint().toString())
        .clientId(properties.clientId())
        .redirectUri(properties.callbackUri())
        .scopes(new HashSet<>(properties.scopes()))
        .state(internalState)
        .attributes(attributes -> attributes.put(PkceParameterNames.CODE_VERIFIER, verifier))
        .build();
        OAuth2AuthorizationResponse response = OAuth2AuthorizationResponse.success(code)
        .redirectUri(properties.callbackUri())
        .state(internalState)
        .build();
        OAuth2AuthorizationCodeGrantRequest grant = new OAuth2AuthorizationCodeGrantRequest(
            registration, new OAuth2AuthorizationExchange(request, response));

        var tokenResponse = callAuthorizationCodeClient(grant);
        return validatedResponse(tokenResponse, properties.scopes(), properties.scopes());
    }

    /** Compatibility overload; session refresh should pass the persisted effective grant. */
    public TokenResponse refresh(String refreshToken) {
        return refresh(refreshToken, properties.scopes());
    }

    public TokenResponse refresh(String refreshToken, List<String> previouslyGrantedScopes) {
        if (previouslyGrantedScopes == null || previouslyGrantedScopes.isEmpty()) {
            throw new IllegalArgumentException("Previously granted scopes are required");
        }
        var provider = metadata.get();
        ClientRegistration registration = registration(provider.tokenEndpoint().toString(), previouslyGrantedScopes);
        Instant now = Instant.now();
        OAuth2AccessToken currentAccessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "sso-refresh-context",
            now.minusSeconds(1),
            now,
            Set.copyOf(previouslyGrantedScopes));
        OAuth2RefreshToken currentRefreshToken = new OAuth2RefreshToken(refreshToken, now.minusSeconds(1));
        OAuth2RefreshTokenGrantRequest grant = new OAuth2RefreshTokenGrantRequest(
            registration, currentAccessToken, currentRefreshToken);

        var tokenResponse = callRefreshTokenClient(grant);
        return validatedResponse(tokenResponse, previouslyGrantedScopes, previouslyGrantedScopes);
    }

    private org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse callAuthorizationCodeClient(
        OAuth2AuthorizationCodeGrantRequest grant) {
        try {
            return authorizationCodeClient.getTokenResponse(grant);
        } catch (SsoClientDependencyException unavailable) {
            throw unavailable;
        } catch (OAuth2AuthorizationException rejected) {
            rethrowTokenFailure(rejected);
            throw new IllegalStateException("Unreachable");
        } catch (HttpMessageNotReadableException invalidResponse) {
            throw new IllegalStateException("Authorization server returned an invalid token response",
                invalidResponse);
        } catch (ResourceAccessException | HttpServerErrorException unavailable) {
            throw new SsoClientDependencyException("Token endpoint is unavailable", unavailable);
        } catch (RestClientException unavailable) {
            throw new SsoClientDependencyException("Token endpoint response could not be read", unavailable);
        }
    }

    private org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse callRefreshTokenClient(
        OAuth2RefreshTokenGrantRequest grant) {
        try {
            return refreshTokenClient.getTokenResponse(grant);
        } catch (SsoClientDependencyException unavailable) {
            throw unavailable;
        } catch (OAuth2AuthorizationException rejected) {
            rethrowTokenFailure(rejected);
            throw new IllegalStateException("Unreachable");
        } catch (HttpMessageNotReadableException invalidResponse) {
            throw new IllegalStateException("Authorization server returned an invalid token response",
                invalidResponse);
        } catch (ResourceAccessException | HttpServerErrorException unavailable) {
            throw new SsoClientDependencyException("Token endpoint is unavailable", unavailable);
        } catch (RestClientException unavailable) {
            throw new SsoClientDependencyException("Token endpoint response could not be read", unavailable);
        }
    }

    private static void rethrowTokenFailure(OAuth2AuthorizationException failure) {
        if (hasCause(failure, ResourceAccessException.class)
|| hasCause(failure, HttpServerErrorException.class)
|| hasCause(failure, SsoClientDependencyException.class)) {
            throw new SsoClientDependencyException("Token endpoint is unavailable", failure);
        }
        throw new IllegalStateException("Token request was rejected: " + failure.getError().getErrorCode(), failure);
    }

    private static boolean hasCause(Throwable failure, Class<? extends Throwable> type) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause))
                return true;
        }
        return false;
    }

    private ClientRegistration registration(String tokenEndpoint, List<String> scopes) {
        var provider = metadata.get();
        return ClientRegistration.withRegistrationId(properties.clientId())
        .clientId(properties.clientId())
        .clientSecret(properties.clientSecret())
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(properties.callbackUri())
        .scope(scopes)
        .authorizationUri(provider.authorizationEndpoint().toString())
        .tokenUri(tokenEndpoint)
        .clientName(properties.clientId())
        .build();
    }

    private static void validateRawTokenResponse(Map<String, Object> body) {
        Object accessToken = body.get("access_token");
        Object refreshToken = body.get("refresh_token");
        Object tokenType = body.get("token_type");
        Object expiresIn = body.get("expires_in");
        Object idToken = body.get(ID_TOKEN_PARAMETER);
        if (!(accessToken instanceof String access) || access.isBlank() || access.length() > MAX_TOKEN_CHARS
|| !(refreshToken instanceof String refresh) || refresh.isBlank() || refresh.length() > MAX_TOKEN_CHARS
|| !(tokenType instanceof String type) || type.isBlank()
|| !(expiresIn instanceof Number expires) || !Double.isFinite(expires.doubleValue())
|| expires.doubleValue() != expires.longValue() || expires.longValue() <= 0
|| expires.longValue() > MAX_ACCESS_TOKEN_SECONDS
|| idToken != null && (!(idToken instanceof String value) || value.isBlank() || value.length() > MAX_ID_TOKEN_CHARS)) {
            throw new IllegalStateException("Authorization server returned an invalid token response");
        }
        Object rawScope = body.get("scope");
        if (rawScope == null)
            return;
        if (!(rawScope instanceof String scope) || scope.isBlank() || scope.length() > MAX_SCOPE_CHARS
|| scope.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalStateException("Authorization server returned an invalid token response");
        }
        Set<String> seen = new HashSet<>();
        for (String item : scope.split(" ", -1)) {
            if (!item.matches("[!#$%&'()*+.^_`|~0-9A-Za-z:-]{1,128}") || !seen.add(item)) {
                throw new IllegalStateException("Authorization server returned an invalid token response");
            }
        }
    }

    private TokenResponse validatedResponse(
        org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse response,
        List<String> allowedScopes,
        List<String> fallbackScopes) {
        if (response == null || response.getAccessToken() == null) {
            throw new IllegalStateException("Authorization server returned an invalid token response");
        }
        OAuth2AccessToken accessToken = response.getAccessToken();
        OAuth2RefreshToken refreshToken = response.getRefreshToken();
        String tokenValue = accessToken.getTokenValue();
        String refreshTokenValue = refreshToken == null ? null : refreshToken.getTokenValue();
        Instant issuedAt = accessToken.getIssuedAt();
        Instant expiresAt = accessToken.getExpiresAt();
        long expiresIn = issuedAt == null || expiresAt == null ? -1 : Duration.between(issuedAt, expiresAt).getSeconds();
        Map<String, Object> additionalParameters = response.getAdditionalParameters();
        Object rawIdToken = additionalParameters == null ? null : additionalParameters.get(ID_TOKEN_PARAMETER);
        if (tokenValue == null || tokenValue.isBlank() || tokenValue.length() > MAX_TOKEN_CHARS
|| refreshTokenValue == null || refreshTokenValue.isBlank() || refreshTokenValue.length() > MAX_TOKEN_CHARS
|| !OAuth2AccessToken.TokenType.BEARER.equals(accessToken.getTokenType())
|| expiresIn <= 0 || expiresIn > MAX_ACCESS_TOKEN_SECONDS
|| rawIdToken != null && (!(rawIdToken instanceof String idToken)
|| idToken.isBlank() || idToken.length() > MAX_ID_TOKEN_CHARS)) {
            throw new IllegalStateException("Authorization server returned an invalid token response");
        }

        String scope = validatedScope(accessToken.getScopes(), allowedScopes, fallbackScopes);
        return new TokenResponse(tokenValue, refreshTokenValue,
            rawIdToken == null ? null : (String) rawIdToken, expiresIn, scope);
    }

    private String validatedScope(Set<String> tokenScopes, List<String> allowedScopes, List<String> fallbackScopes) {
        if (tokenScopes == null || tokenScopes.isEmpty())
            return String.join(" ", fallbackScopes);
        if (tokenScopes.size() > MAX_SCOPE_CHARS) {
            throw new IllegalStateException("Authorization server returned an invalid token response");
        }
        Set<String> returned = new HashSet<>();
        for (String scope : tokenScopes) {
            if (scope == null || !scope.matches("[!#$%&'()*+.^_`|~0-9A-Za-z:-]{1,128}")
|| !returned.add(scope) || !allowedScopes.contains(scope)) {
                throw new IllegalStateException("Authorization server returned an invalid token response");
            }
        }
        String value = String.join(" ", returned.stream().sorted().toList());
        if (value.length() > MAX_SCOPE_CHARS) {
            throw new IllegalStateException("Authorization server returned an invalid token response");
        }
        return value;
    }

    /** RFC 7009 has no Spring Security OAuth2 Client token-response client, so this stays a bounded form POST. */
    public boolean revokeRefreshToken(String token) {
        var endpoint = metadata.get().revocationEndpoint();
        if (endpoint == null)
            return false;
        String basic = basicAuthorization();
        org.springframework.util.MultiValueMap<String, String> form = new org.springframework.util.LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("token_type_hint", "refresh_token");
        http.post().uri(endpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .header("Authorization", basic).body(form).retrieve().toBodilessEntity();
        return true;
    }

    private String basicAuthorization() {
        String clientId = URLEncoder.encode(properties.clientId(), StandardCharsets.UTF_8);
        String clientSecret = URLEncoder.encode(properties.clientSecret(), StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }

    public record TokenResponse(String accessToken, String refreshToken, String idToken, long expiresIn,
        String scope) {
    }
}
