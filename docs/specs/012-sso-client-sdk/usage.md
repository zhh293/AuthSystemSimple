# SSO Client SDK setup and migration

## Artifacts

The reactor publishes `com.authsystem:sso-client-core` and `com.authsystem:sso-client-spring-boot-starter` at the parent version. A normal Spring Boot application adds only the starter. The supported line is Java 17, Spring Boot 3.5.x, and its managed Spring Security 6.5.x (the SDK uses Spring Security's `RestClient` OAuth2 token response clients, available since 6.4). The starter is opt-in; without `sso.client.enabled=true` it contributes no SSO routes or security filter.

## Authorization server registration

Register a confidential client with the exact callback URI, for example:

```powershell
java -jar sso-admin/target/sso-admin-0.1.0-SNAPSHOT.jar client create --id portal --name "Portal" --type CONFIDENTIAL --redirect-uri https://portal.example.com/sso/callback --scope openid --scope profile
```

Store the generated secret in the deployment secret manager. Add `email` only after the application has approval to request that scope. The issuer and registered callback must exactly match the deployed authorization server configuration.

## Production configuration

```yaml
sso:
  client:
    enabled: true
    issuer: https://sso.example.com
    client-id: portal
    client-secret: ${SSO_CLIENT_SECRET}
    redirect-uri: https://portal.example.com/sso/callback
    scopes: [openid, profile]
    family-lifetime: 30d # Must match the authorization server's refresh-token-ttl-seconds.
    user-mapping-cache-ttl: 250ms # Optional Caffeine L1; 0 disables it, max 1s.
    redis-key-prefix: sso:rp:production
    protected-paths: [/app/**, /api/**]
    public-paths: [/, /error, /assets/**]
    local-store: false
    lookup-hmac-key: ${SSO_CLIENT_LOOKUP_HMAC_KEY}
    refresh-encryption-key: ${SSO_CLIENT_REFRESH_AES_KEY}
    secure-cookie: true
    cookie-same-site: Lax
```

Both store keys are Base64-encoded 32-byte values injected from a secret manager. Set a Redis key prefix unique to the deployment environment. Configure Spring Data Redis with TLS, authentication, a private network path, persistence/availability appropriate to the application, and bounded connection timeouts. The SDK does not fall back to local storage when Redis fails. Keep secrets out of source control and startup logs.

## Compose with the application's security chain

The application keeps ownership of its existing `SecurityFilterChain`, CSRF policy, public paths, and authorization rules. Add the SDK configurer before the final `anyRequest` rule:

```java
@Bean
SecurityFilterChain applicationSecurity(HttpSecurity http, SsoHttpSecurityConfigurer sso) throws Exception {
    http.with(sso, Customizer.withDefaults())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/", "/error", "/assets/**").permitAll()
            .anyRequest().authenticated());
    return http.build();
}
```

The application must permit the SDK login, callback, and logout routes in its own authorization rules before the final `anyRequest` rule. The configurer installs the authentication filter and leaves authorization ownership to the application. Spring Security CSRF remains enabled; applications should render the normal CSRF token in their POST logout form. Protected route patterns must match the application's authorization policy. JSON/API requests receive 401; browser page requests redirect to the SDK login route. `/sso/status` is disabled by default and should be enabled only if the application needs it.

The logout controller also requires the `CsrfToken` request attribute supplied by Spring Security. If CSRF is disabled in the host chain, logout returns 403 without clearing the user's cookie or local session.

The SDK installs an `SsoAuthentication` in the request security context. `SsoCurrentUser.get()` returns the verified minimal `SsoPrincipal`. The browser receives only `{client-id}_access_token`; it never receives the refresh token or ID token.

## Local SDK example

The existing standard OAuth2 Client example remains the default. Run its SDK profile with:

```powershell
$env:SPRING_PROFILES_ACTIVE = 'sso-sdk'
$env:SSO_CLIENT_ID = 'portal'
$env:SSO_CLIENT_SECRET = '<secret from local secret store>'
mvn -pl sso-example-rp -am spring-boot:run
```

The profile listens on `http://localhost:8082`, uses explicit in-memory single-instance stores, and disables Secure cookies only for localhost HTTP development. In-memory state and token records disappear on restart. Do not use this mode with multiple instances or in production. Visit `/profile` to exercise the protected route.

## Migration from the existing example

The default `sso-example-rp` continues to demonstrate Spring Security `oauth2Login`, JSESSIONID, and its existing logout path. The `sso-sdk` profile demonstrates the application AT-cookie model and SDK APIs. Migrate one RP at a time: register the callback, deploy secrets and Redis, compose the SDK configurer into the existing security chain, move application principal mapping to `SsoPrincipalMapper` if needed, and verify local logout, refresh-family expiry, API 401 behavior, Redis outage behavior, CSRF, cookie flags, and logs before removing the old OAuth client configuration.

## Operational constraints

- The starter does not pull Actuator into consuming applications. If the application adds Actuator itself, the SDK contributes a readiness health indicator; the application remains responsible for endpoint exposure and security.
- Token, revoke, discovery, JWKS and store failures fail closed. Code exchange, refresh and revoke POSTs are not retried.
- Redis transaction values are encrypted; state and access tokens are not stored as Redis key text. Access-token lookup uses HMAC-SHA-256 digests.
- Local logout revokes the refresh token best effort and clears the RP mapping and cookie. It does not clear the SSO TGC or promise global logout.
- Reverse proxies must preserve the configured public HTTPS callback URI. The SDK does not infer redirect URIs from untrusted forwarded headers.
- Logs and access logs must redact callback query parameters (`code`, `state`, `error_description`) and authorization headers. Do not attach token or user values to metrics labels.
