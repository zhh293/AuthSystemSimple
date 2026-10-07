package com.authsystem.sso.config;

import java.util.List;
import java.time.Instant;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class OidcTokenConfiguration {
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> oidcTokenCustomizer(JdbcTemplate jdbc, SsoProperties properties) {
        return context -> {
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                context.getJwsHeader().keyId(properties.getOidcKeyAlias());
                context.getClaims().expiresAt(Instant.now().plusSeconds(properties.getIdTokenTtlSeconds()));
                boolean profileAllowed = context.getAuthorizedScopes().contains("profile");
                boolean emailAllowed = context.getAuthorizedScopes().contains("email");
                if (!profileAllowed && !emailAllowed) return;
                String subject = context.getPrincipal().getName();
                List<UserClaims> rows = jdbc.query(
                        "select display_name, email, email_verified from sso_user where subject_id = ? and enabled = true",
                        (rs, row) -> new UserClaims(rs.getString("display_name"), rs.getString("email"), rs.getBoolean("email_verified")),
                        subject);
                if (!rows.isEmpty()) {
                    UserClaims user = rows.get(0);
                    if (profileAllowed && user.name() != null && !user.name().isBlank()) context.getClaims().claim("name", user.name());
                    if (emailAllowed && user.email() != null && !user.email().isBlank()) {
                        context.getClaims().claim("email", user.email());
                        context.getClaims().claim("email_verified", user.emailVerified());
                    }
                }
            }
        };
    }

    private record UserClaims(String name, String email, boolean emailVerified) { }
}
