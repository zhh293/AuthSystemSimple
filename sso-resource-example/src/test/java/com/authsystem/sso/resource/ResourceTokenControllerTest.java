package com.authsystem.sso.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authsystem.sso.contracts.TokenIntrospectionService;
import com.authsystem.sso.contracts.dto.TokenIntrospectionRequest;
import com.authsystem.sso.contracts.dto.TokenIntrospectionResult;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.util.ReflectionTestUtils;

class ResourceTokenControllerTest {
    private final TokenIntrospectionService introspection = mock(TokenIntrospectionService.class);
    private ResourceTokenController controller;

    @BeforeEach
    void setUp() {
        controller = new ResourceTokenController("allowed-client");
        ReflectionTestUtils.setField(controller, "introspection", introspection);
    }

    @Test
    void rejectsMissingMalformedWhitespaceAndOversizedBearerTokensWithoutRpc() {
        assertThat(controller.whoami(null).getStatusCode().value()).isEqualTo(401);
        assertThat(controller.whoami("Basic abc").getStatusCode().value()).isEqualTo(401);
        assertThat(controller.whoami("Bearer ").getStatusCode().value()).isEqualTo(401);
        assertThat(controller.whoami("Bearer a b").getStatusCode().value()).isEqualTo(401);
        assertThat(controller.whoami("Bearer " + "a".repeat(4097)).getStatusCode().value()).isEqualTo(401);
        assertThat(controller.whoami(null).getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo("Bearer");
    }

    @Test
    void introspectsValidOpaqueTokenAndReturnsOnlyMinimalAuthorizationContext() {
        when(introspection.introspect(any(TokenIntrospectionRequest.class))).thenReturn(active("allowed-client", List.of("openid", "resource.read")));

        var response = controller.whoami("Bearer opaque-access-token");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        assertThat(response.getBody()).isInstanceOf(java.util.Map.class);
        java.util.Map<?, ?> body = (java.util.Map<?, ?>) response.getBody();
        assertThat(body.get("subject")).isEqualTo("subject-1");
        assertThat(body.get("client_id")).isEqualTo("allowed-client");
        verify(introspection).introspect(any(TokenIntrospectionRequest.class));
    }

    @Test
    void rejectsInactiveAndExpiredTokens() {
        when(introspection.introspect(any(TokenIntrospectionRequest.class)))
                .thenReturn(TokenIntrospectionResult.inactive())
                .thenReturn(new TokenIntrospectionResult(true, "subject-1", "allowed-client", List.of("resource.read"),
                        Instant.now().getEpochSecond() - 1));

        assertThat(controller.whoami("Bearer inactive").getStatusCode().value()).isEqualTo(401);
        assertThat(controller.whoami("Bearer expired").getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void rejectsClientsOutsideTheIndependentResourceAllowlist() {
        when(introspection.introspect(any(TokenIntrospectionRequest.class)))
                .thenReturn(active("other-client", List.of("resource.read")));

        var response = controller.whoami("Bearer valid-for-other-client");

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getBody()).asString().contains("client_not_allowed");
    }

    @Test
    void requiresResourceReadScopeEvenForAllowedClient() {
        when(introspection.introspect(any(TokenIntrospectionRequest.class)))
                .thenReturn(active("allowed-client", List.of("openid", "profile")));

        var response = controller.whoami("Bearer insufficient-scope");

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getBody()).asString().contains("insufficient_scope");
    }

    @Test
    void failsClosedWithRetryHintWhenAuthorizationRpcIsUnavailable() {
        when(introspection.introspect(any(TokenIntrospectionRequest.class))).thenThrow(new IllegalStateException("offline"));

        var response = controller.whoami("Bearer opaque-access-token");

        assertThat(response.getStatusCode().value()).isEqualTo(503);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("1");
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        assertThat(response.getBody()).asString().contains("authorization_service_unavailable");
    }

    private static TokenIntrospectionResult active(String clientId, List<String> scopes) {
        return new TokenIntrospectionResult(true, "subject-1", clientId, scopes, Instant.now().getEpochSecond() + 60);
    }
}
