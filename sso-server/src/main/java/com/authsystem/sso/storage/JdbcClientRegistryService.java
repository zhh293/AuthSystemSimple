package com.authsystem.sso.storage;

import com.authsystem.sso.contracts.ClientRegistryService;
import com.authsystem.sso.contracts.dto.ClientLookupRequest;
import com.authsystem.sso.contracts.dto.ClientView;
import java.net.URI;
import java.util.List;
import java.util.Set;
import org.apache.dubbo.config.annotation.DubboService;
import org.springframework.jdbc.core.JdbcTemplate;

@DubboService(interfaceClass = ClientRegistryService.class, version = "1.0.0")
public class JdbcClientRegistryService implements ClientRegistryService {
    private static final Set<String> SUPPORTED_SCOPES = Set.of("openid", "profile", "email", "resource.read");
    private final JdbcTemplate jdbc;
    public JdbcClientRegistryService(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    @Override public ClientView findEnabledClient(ClientLookupRequest request) {
        if (request == null || request.getClientId() == null || request.getClientId().isBlank()
                || request.getClientId().length() > 128) return null;
        List<ClientView> clients = jdbc.query("select client_id, display_name, client_type, enabled from oauth_client where client_id = ? and enabled = true",
                (rs, row) -> {
                    ClientView view = new ClientView(rs.getString("client_id"), rs.getString("display_name"), rs.getBoolean("enabled"), List.of());
                    view.setClientType(rs.getString("client_type"));
                    return view;
                }, request.getClientId());
        if (clients.isEmpty()) return null;
        ClientView client = clients.get(0);
        if (!"PUBLIC".equalsIgnoreCase(client.getClientType())
                && !"CONFIDENTIAL".equalsIgnoreCase(client.getClientType())) return null;
        List<String> redirectUris = jdbc.query("select redirect_uri from oauth_client_redirect_uri where client_id = ? order by redirect_uri", (rs, row) -> rs.getString(1), client.getClientId());
        List<String> scopes = jdbc.query("select scope_name from oauth_client_scope where client_id = ? order by scope_name", (rs, row) -> rs.getString(1), client.getClientId());
        if (redirectUris.isEmpty() || redirectUris.size() > 20 || redirectUris.stream().anyMatch(uri -> !safeRedirectUri(uri))
                || scopes.isEmpty() || !scopes.contains("openid") || !SUPPORTED_SCOPES.containsAll(scopes)) return null;
        client.setRedirectUris(redirectUris);
        client.setAllowedScopes(scopes);
        return client;
    }
    @Override public boolean isRedirectUriAllowed(ClientLookupRequest request, String redirectUri) {
        if (redirectUri == null || !safeRedirectUri(redirectUri)) return false;
        ClientView client = findEnabledClient(request);
        return client != null && client.getRedirectUris().stream().anyMatch(redirectUri::equals);
    }

    private static boolean safeRedirectUri(String value) {
        if (value == null || value.length() > 2048 || value.contains("*")) return false;
        try {
            URI uri = new URI(value);
            if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null) return false;
            if ("https".equalsIgnoreCase(uri.getScheme())) return true;
            if (!"http".equalsIgnoreCase(uri.getScheme())) return false;
            String host = uri.getHost();
            return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                    || "::1".equals(host) || "[::1]".equalsIgnoreCase(host);
        } catch (java.net.URISyntaxException e) {
            return false;
        }
    }
}
