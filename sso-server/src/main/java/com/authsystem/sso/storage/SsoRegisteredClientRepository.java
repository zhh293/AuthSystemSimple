package com.authsystem.sso.storage;

import com.authsystem.sso.config.SsoProperties;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;

@Repository
public class SsoRegisteredClientRepository implements RegisteredClientRepository {
    private static final Set<String> SUPPORTED_SCOPES = Set.of("openid", "profile", "email", "resource.read");
    private final JdbcTemplate jdbc;
    private final SsoProperties properties;

    public SsoRegisteredClientRepository(JdbcTemplate jdbc, SsoProperties properties) {
        this.jdbc = jdbc;
        this.properties = properties;
    }

    @Override public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("OAuth client registration is managed by the controlled provisioning workflow");
    }

    @Override public RegisteredClient findById(String id) { return load(id, false); }

    @Override public RegisteredClient findByClientId(String clientId) {
        return load(clientId, true);
    }

    private RegisteredClient load(String clientId, boolean enabledOnly) {
        if (clientId == null || clientId.isBlank() || clientId.length() > 128) return null;
        String query = "select client_id, display_name, client_type, client_secret_hash from oauth_client where client_id = ?"
                + (enabledOnly ? " and enabled = true" : "");
        List<ClientRow> rows = jdbc.query(query,
                (rs, row) -> new ClientRow(rs.getString("client_id"), rs.getString("display_name"), rs.getString("client_type"), rs.getString("client_secret_hash")), clientId);
        if (rows.isEmpty()) return null;
        ClientRow row = rows.get(0);
        boolean publicClient = "PUBLIC".equalsIgnoreCase(row.clientType());
        if (!publicClient && (!"CONFIDENTIAL".equalsIgnoreCase(row.clientType()) || row.secretHash() == null || row.secretHash().isBlank())) return null;

        List<String> redirectUris = jdbc.query("select redirect_uri from oauth_client_redirect_uri where client_id = ? order by redirect_uri",
                (rs, index) -> rs.getString(1), clientId).stream().filter(SsoRegisteredClientRepository::safeRedirectUri).toList();
        if (redirectUris.isEmpty()) return null;
        List<String> scopes = jdbc.query("select scope_name from oauth_client_scope where client_id = ? order by scope_name",
                (rs, index) -> rs.getString(1), clientId);
        if (scopes.isEmpty() || !SUPPORTED_SCOPES.containsAll(scopes) || !scopes.contains("openid")) return null;

        RegisteredClient.Builder builder = RegisteredClient.withId(row.clientId())
                .clientId(row.clientId())
                .clientName(row.displayName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientAuthenticationMethod(publicClient ? ClientAuthenticationMethod.NONE : ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofSeconds(properties.getAccessTokenTtlSeconds()))
                        .refreshTokenTimeToLive(Duration.ofSeconds(properties.getRefreshTokenTtlSeconds()))
                        .authorizationCodeTimeToLive(Duration.ofSeconds(properties.getAuthorizationCodeTtlSeconds()))
                        .reuseRefreshTokens(false)
                        .build());
        if (!publicClient) builder.clientSecret(row.secretHash());
        redirectUris.forEach(builder::redirectUri);
        scopes.forEach(builder::scope);
        return builder.build();
    }

    private static boolean safeRedirectUri(String value) {
        try {
            URI uri = new URI(value);
            if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null || value.contains("*")) return false;
            if ("https".equalsIgnoreCase(uri.getScheme())) return true;
            if (!"http".equalsIgnoreCase(uri.getScheme())) return false;
            String host = uri.getHost();
            return host.equalsIgnoreCase("localhost") || host.equals("127.0.0.1") || host.equals("[::1]") || host.equals("::1");
        } catch (Exception ignored) { return false; }
    }

    private record ClientRow(String clientId, String displayName, String clientType, String secretHash) { }
}
