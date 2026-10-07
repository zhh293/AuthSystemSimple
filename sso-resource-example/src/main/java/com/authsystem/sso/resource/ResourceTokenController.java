package com.authsystem.sso.resource;

import com.authsystem.sso.contracts.TokenIntrospectionService;
import com.authsystem.sso.contracts.dto.TokenIntrospectionRequest;
import com.authsystem.sso.contracts.dto.TokenIntrospectionResult;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import org.apache.dubbo.config.annotation.DubboReference;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/** Demonstrates a resource server that treats authorization-center RPC as mandatory. */
@RestController
public class ResourceTokenController {
    private static final int MAX_TOKEN_LENGTH = 4096;
    private static final String REQUIRED_SCOPE = "resource.read";
    private final Set<String> allowedClientIds;

    @DubboReference(interfaceClass = TokenIntrospectionService.class, version = "1.0.0",
            check = false, timeout = 1500, retries = 0)
    private TokenIntrospectionService introspection;

    public ResourceTokenController(@Value("${sso.resource.allowed-client-ids}") String allowedClientIds) {
        String[] configured = allowedClientIds.split(",", -1);
        if (configured.length == 0 || Arrays.stream(configured).anyMatch(value ->
                !value.trim().matches("[A-Za-z0-9._-]{1,128}"))) {
            throw new IllegalArgumentException("SSO_RESOURCE_ALLOWED_CLIENT_IDS must be a comma-separated list of client IDs");
        }
        this.allowedClientIds = Arrays.stream(configured).map(String::trim).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    @GetMapping("/api/whoami")
    public ResponseEntity<?> whoami(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        String token = bearerToken(authorization);
        if (token == null) return unauthorized();

        TokenIntrospectionResult result;
        try {
            result = introspection.introspect(new TokenIntrospectionRequest(token));
        } catch (RuntimeException e) {
            return ResponseEntity.status(503).cacheControl(CacheControl.noStore())
                    .header(HttpHeaders.RETRY_AFTER, "1").body(Map.of("error", "authorization_service_unavailable"));
        }
        if (result == null || !result.isActive() || result.getSubject() == null || result.getSubject().isBlank()
                || result.getClientId() == null || result.getClientId().isBlank()
                || result.getExpiresAtEpochSecond() <= Instant.now().getEpochSecond()) return unauthorized();
        if (!allowedClientIds.contains(result.getClientId())) {
            return ResponseEntity.status(403).cacheControl(CacheControl.noStore()).body(Map.of("error", "client_not_allowed"));
        }
        if (result.getScopes() == null || !result.getScopes().contains(REQUIRED_SCOPE)) {
            return ResponseEntity.status(403).cacheControl(CacheControl.noStore()).body(Map.of("error", "insufficient_scope"));
        }
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(Map.of("subject", result.getSubject(), "client_id", result.getClientId(),
                        "scopes", result.getScopes(), "expires_at", result.getExpiresAtEpochSecond()));
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || authorization.length() <= 7 || authorization.length() > MAX_TOKEN_LENGTH + 7
                || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        String token = authorization.substring(7);
        if (token.isBlank() || token.chars().anyMatch(Character::isWhitespace)) return null;
        return token;
    }

    private static ResponseEntity<Map<String, String>> unauthorized() {
        return ResponseEntity.status(401).cacheControl(CacheControl.noStore())
                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .body(Map.of("error", "invalid_token"));
    }
}
