package com.authsystem.sso.client.protocol;

import com.authsystem.sso.client.config.SsoClientProperties;
import com.authsystem.sso.client.security.Pkce;
import com.authsystem.sso.client.session.SsoAuthorizationTransaction;
import com.authsystem.sso.client.store.SsoAuthorizationRequestStore;
import com.authsystem.sso.client.crypto.TokenDigests;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.HashSet;

public final class AuthorizationRequestFactory {
    private final SsoClientProperties properties;
    private final OidcMetadataClient metadata;
    private final SsoAuthorizationRequestStore store;
    private final Clock clock;
    private final byte[] bindingKey;

    public AuthorizationRequestFactory(SsoClientProperties properties, OidcMetadataClient metadata,
        SsoAuthorizationRequestStore store, Clock clock, byte[] bindingKey) {
        this.properties = properties;
        this.metadata = metadata;
        this.store = store;
        this.clock = clock;
        this.bindingKey = bindingKey;
    }

    public LoginRequest create(String returnPath) {
        String normalizedReturn = safeReturnPath(returnPath);
        String state = Pkce.randomUrlSafe(32), nonce = Pkce.randomUrlSafe(32);
        String binding = Pkce.randomUrlSafe(32);
        Instant now = clock.instant();
        OAuth2AuthorizationRequest.Builder requestBuilder = OAuth2AuthorizationRequest.authorizationCode()
        .authorizationUri(metadata.get().authorizationEndpoint().toString())
        .clientId(properties.clientId())
        .redirectUri(properties.callbackUri())
        .scopes(new HashSet<>(properties.scopes()))
        .state(state);
        OAuth2AuthorizationRequestCustomizers.withPkce().accept(requestBuilder);
        requestBuilder.additionalParameters(parameters -> parameters.put("nonce", nonce));
        OAuth2AuthorizationRequest authorizationRequest = requestBuilder.build();
        String verifier = authorizationRequest.getAttribute(PkceParameterNames.CODE_VERIFIER);
        if (verifier == null || verifier.isBlank()
|| !"S256".equals(authorizationRequest.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD))
|| authorizationRequest.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE) == null
|| !nonce.equals(authorizationRequest.getAdditionalParameters().get("nonce"))) {
            throw new IllegalStateException("Spring Security produced an incomplete authorization request");
        }
        SsoAuthorizationTransaction tx = new SsoAuthorizationTransaction(nonce, verifier,
            TokenDigests.hmacSha256(binding, bindingKey), normalizedReturn, now, now.plus(properties.transactionTtl()));
        store.save(state, tx);
        return new LoginRequest(binding, browserBindingCookieName(properties.clientId(), state, bindingKey),
            authorizationRequest.getAuthorizationRequestUri(), tx.expiresAt());
    }

    public static String browserBindingCookieName(String clientId, String state, byte[] bindingKey) {
        return clientId+"_sso_tx_"+TokenDigests.hmacSha256(state, bindingKey).substring(0, 22);
    }

    public static String safeReturnPath(String candidate) {
        if (candidate == null || candidate.isBlank() || candidate.length()>4096)
            return "/";
        if (!candidate.startsWith("/") || candidate.startsWith("//") || candidate.contains("\\") || candidate.contains("\r") ||
            candidate.contains("\n"))
            return "/";
        try {
            java.net.URI uri = java.net.URI.create(candidate);
            String decoded = candidate;
            boolean fullyDecoded = false;
            for (int i = 0;i<4;i++) {
                String next = java.net.URLDecoder.decode(decoded.replace("+", "%2B"), StandardCharsets.UTF_8);
                if (next.equals(decoded)) {
                    fullyDecoded = true;
                    break;
                }
                decoded = next;
            }
            if (!fullyDecoded)
                return "/";
            String decodedPath = decoded.split("\\?", 2)[0];
            boolean traversal = java.util.Arrays.stream(decodedPath.split("/", -1)).anyMatch(segment -> segment.equals(".") ||
                segment.equals(".."));
            if (uri.isAbsolute() || uri.getRawAuthority() != null || uri.getPath() == null || uri.getPath().startsWith("//")
|| decoded.startsWith("//") || decoded.indexOf('\\') >= 0 || decoded.chars().anyMatch(Character::isISOControl) ||
                traversal)
                return "/";
            return uri.toASCIIString();
        } catch (RuntimeException ex) {
            return "/";
        }
    }
    public record LoginRequest(String browserBinding, String browserBindingCookieName, String authorizationUri,
        Instant expiresAt) {
    }
}
