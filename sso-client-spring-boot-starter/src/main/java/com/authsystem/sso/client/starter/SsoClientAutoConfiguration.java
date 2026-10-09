package com.authsystem.sso.client.starter;

import com.authsystem.sso.client.config.SsoClientProperties;
import com.authsystem.sso.client.protocol.IdTokenValidator;
import com.authsystem.sso.client.protocol.OAuthTokenClient;
import com.authsystem.sso.client.protocol.OidcMetadataClient;
import com.authsystem.sso.client.protocol.CachingJwkSource;
import com.authsystem.sso.client.session.SsoPrincipal;
import com.authsystem.sso.client.session.SsoPrincipalMapper;
import com.authsystem.sso.client.session.SsoSessionService;
import com.authsystem.sso.client.session.SsoLogoutListener;
import com.authsystem.sso.client.observability.SsoClientMetrics;
import com.authsystem.sso.client.store.SsoAuthorizationRequestStore;
import com.authsystem.sso.client.store.SsoRefreshLock;
import com.authsystem.sso.client.store.SsoTokenStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestClient;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.time.Duration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

@AutoConfiguration
@EnableConfigurationProperties(SsoClientSettings.class)
@ConditionalOnProperty(prefix = "sso.client", name = "enabled", havingValue = "true")
public class SsoClientAutoConfiguration {
    @Bean SsoClientProperties ssoClientProperties(SsoClientSettings s, org.springframework.core.env.Environment environment) {
        String cookie = s.getCookieName() == null || s.getCookieName().isBlank()?s.getClientId()+"_access_token":s.getCookieName();
        String hmac = resolveKey(s.getLookupHmacKey(), s.isLocalStore()), enc = resolveKey(s.getRefreshEncryptionKey(),
            s.isLocalStore());
        SsoClientProperties p = new SsoClientProperties(s.getIssuer(), s.getClientId(), s.getClientSecret(),
            s.getRedirectUri(), cookie, s.getCookiePath(), s.getCookieSameSite(), s.getTransactionTtl(),
            s.getConnectTimeout(),
            s.getResponseTimeout(), s.getRefreshSkew(), s.getFamilyLifetime(), s.getScopes(), s.getProtectedPaths(),
            s.isSecureCookie(), s.isLocalStore(), hmac, enc, s.getRedisKeyPrefix());
        if (p.issuer().startsWith("http://") && !java.net.URI.create(p.issuer()).getHost().equalsIgnoreCase("localhost"))
            throw new IllegalArgumentException("HTTP issuer is permitted only for localhost development");
        if (p.localStore() && environment.acceptsProfiles(org.springframework.core.env.Profiles.of("prod",
                    "production")))
            throw new IllegalArgumentException("Local token stores are forbidden in production profiles");
        if (!p.secureCookie() && (!p.localStore() || !java.net.URI.create(p.issuer()).getHost().equalsIgnoreCase("localhost")))
            throw new IllegalArgumentException("Insecure cookies are permitted only for explicit localhost development");
        java.net.URI callback = java.net.URI.create(p.callbackUri());
        if (!java.util.Objects.equals(callback.getPath(), s.getCallbackPath()))
            throw new IllegalArgumentException("redirect-uri path must exactly match callback-path");
        if (!p.secureCookie() && !"localhost".equalsIgnoreCase(callback.getHost()))
            throw new IllegalArgumentException("Insecure development callback must use localhost");
        if (s.getLoginPath().equals(s.getCallbackPath()) || s.getLoginPath().equals(s.getLogoutPath()) ||
            s.getCallbackPath().equals(s.getLogoutPath()))
            throw new IllegalArgumentException("SDK login, callback and logout routes must be distinct");
        if ("http".equalsIgnoreCase(callback.getScheme()) && (!p.localStore() || !"localhost".equalsIgnoreCase(callback.getHost())))
            throw new IllegalArgumentException("HTTP callbacks are permitted only for localhost single-instance development");
        for (String path:List.of(s.getLoginPath(), s.getCallbackPath(), s.getLogoutPath(), s.getStatusPath()))
            if (path == null ||
                !path.startsWith("/") || path.contains("?") || path.contains("#") || path.contains("\\"))
                throw new IllegalArgumentException("SDK routes must be absolute application paths");
        if (List.of(s.getLoginPath(), s.getCallbackPath(), s.getLogoutPath(), s.getStatusPath()).stream().distinct().count() != 4)
            throw new IllegalArgumentException("SDK routes must be distinct");
        if (s.getProtectedPaths() == null || s.getProtectedPaths().size()>256 || s.getPublicPaths() == null ||
            s.getPublicPaths().size()>256)
            throw new IllegalArgumentException("At most 256 route patterns may be configured in each list");
        if (s.getReturnToParameter() == null || !s.getReturnToParameter().matches("[A-Za-z][A-Za-z0-9._-]{0,63}"))
            throw new IllegalArgumentException("return-to-parameter must be a valid query parameter name");
        if (s.getTransactionTtl().compareTo(Duration.ofMinutes(10))>0 || s.getConnectTimeout().compareTo(Duration.ofSeconds(60))>0 ||
            s.getResponseTimeout().compareTo(Duration.ofSeconds(60))>0 || s.getFamilyLifetime().compareTo(Duration.ofDays(30))>0 ||
            s.getRefreshSkew().compareTo(s.getFamilyLifetime()) >= 0 || s.getUserMappingCacheTtl() == null ||
            s.getUserMappingCacheTtl().isNegative() || s.getUserMappingCacheTtl().compareTo(Duration.ofSeconds(1))>0 ||
            s.getMetadataCacheTtl() == null || s.getMetadataCacheTtl().isZero() || s.getMetadataCacheTtl().isNegative() ||
            s.getMetadataCacheTtl().compareTo(Duration.ofDays(1))>0 || s.getJwksRefreshInterval() == null ||
            s.getJwksRefreshInterval().isZero() || s.getJwksRefreshInterval().isNegative() || s.getJwksRefreshInterval().compareTo(Duration.ofDays(1))>0 ||
            s.getJwksStaleIfError() == null || s.getJwksStaleIfError().isNegative() || s.getJwksStaleIfError().compareTo(Duration.ofDays(1))>0)
            throw new IllegalArgumentException("SSO transaction, network, cache, refresh and family lifetimes are outside supported bounds");
        return p;
    }
    @Bean(name = "ssoClientClock") Clock ssoClientClock() {
        return Clock.systemUTC();
    }
    @Bean @ConditionalOnMissingBean SsoHttpClientCustomizer ssoHttpClientCustomizer() {
        return () -> null;
    }
    @Bean @ConditionalOnMissingBean SsoCookieCustomizer ssoCookieCustomizer() {
        return (kind, maximum) -> maximum;
    }
    @Bean @ConditionalOnMissingBean SsoFailureHandler ssoFailureHandler() {
        return new DefaultSsoFailureHandler();
    }
    @Bean SsoHttpClients ssoHttpClients(SsoClientProperties p, SsoHttpClientCustomizer customizer) {
        return new SsoHttpClients(buildRestClient(p, customizer, 32*1024), buildRestClient(p, customizer,
                1_048_576));
    }
    private static RestClient buildRestClient(SsoClientProperties p, SsoHttpClientCustomizer customizer,
        int maxResponseBytes) {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(p.connectTimeout()).followRedirects(HttpClient.Redirect.NEVER);
        if (customizer.proxySelector() != null)
            builder.proxy(customizer.proxySelector());
        HttpClient client = builder.build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(p.responseTimeout());
        return RestClient.builder().requestFactory(factory).requestInterceptor((request, body, execution) -> bounded(execution.execute(request,
                    body), maxResponseBytes)).build();
    }
    @Bean OidcMetadataClient oidcMetadataClient(SsoClientProperties p, SsoHttpClients clients, @Qualifier("ssoClientClock") Clock clock,
        SsoClientSettings settings) {
        return new OidcMetadataClient(p.issuer(), clients.protocol(), clock, settings.getMetadataCacheTtl());
    }
    @Bean @ConditionalOnMissingBean SsoPrincipalMapper ssoPrincipalMapper() {
        return claims -> new SsoPrincipal(claims.subject(), (String) claims.claims().get("name"), (String) claims.claims().get("email"),
            claims.claims());
    }
    @Bean @ConditionalOnMissingBean SsoAuthorizationRequestStore authorizationRequestStore(SsoClientProperties p,
        ObjectProvider<StringRedisTemplate> redis, ObjectMapper mapper) {
        byte[] key = Base64.getDecoder().decode(p.lookupHmacKey()), enc = deriveKey(Base64.getDecoder().decode(p.refreshEncryptionKey()),
            "authorization-transaction");
        return p.localStore()?new LocalAuthorizationRequestStore(key):new RedisAuthorizationRequestStore(redis.getObject(),
            mapper, key, enc, p.transactionTtl(), p.redisKeyPrefix(), p.clientId());
    }
    @Bean @ConditionalOnMissingBean SsoTokenStore ssoTokenStore(SsoClientProperties p, SsoClientSettings settings,
        ObjectProvider<StringRedisTemplate> redis, ObjectMapper mapper) {
        byte[] key = Base64.getDecoder().decode(p.lookupHmacKey());
        return p.localStore()?new LocalSsoTokenStore(key):new RedisSsoTokenStore(redis.getObject(), mapper,
            key, p.clientId(), p.redisKeyPrefix(), settings.getUserMappingCacheTtl());
    }
    @Bean @ConditionalOnMissingBean SsoRefreshLock ssoRefreshLock(SsoClientProperties p, ObjectProvider<StringRedisTemplate> redis) {
        return p.localStore()?new LocalSsoRefreshLock():new RedisSsoRefreshLock(redis.getObject(), Base64.getDecoder().decode(p.lookupHmacKey()),
            p.clientId(), p.redisKeyPrefix());
    }
    @Bean CachingJwkSource ssoJwkSource(OidcMetadataClient metadata, SsoHttpClients clients, @Qualifier("ssoClientClock") Clock clock,
        SsoClientSettings settings) {
        return new CachingJwkSource(clients.jwks(), metadata.get().jwksUri().toString(), clock, settings.getJwksRefreshInterval(),
            settings.getJwksStaleIfError());
    }
    @Bean(name = "ssoIdTokenDecoder") JwtDecoder ssoIdTokenDecoder(CachingJwkSource source, SsoClientProperties properties) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, source));
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer()));
        return decoder;
    }
    @Bean IdTokenValidator idTokenValidator(@Qualifier("ssoIdTokenDecoder") JwtDecoder decoder, SsoClientProperties p,
        @Qualifier("ssoClientClock") Clock clock) {
        return new IdTokenValidator(decoder, p.issuer(), p.clientId(), clock, Duration.ofSeconds(60));
    }
    @Bean OAuthTokenClient oauthTokenClient(SsoHttpClients clients, SsoClientProperties p, OidcMetadataClient metadata) {
        return new OAuthTokenClient(clients.protocol(), p, metadata);
    }
    @Bean SsoClientMetrics ssoClientMetrics(ObjectProvider<MeterRegistry> registries) {
        return new SsoClientMetrics(registries.getIfAvailable(SimpleMeterRegistry::new));
    }
    @Bean SsoSessionService ssoSessionService(SsoClientProperties p, SsoAuthorizationRequestStore tx,
        SsoTokenStore store,
        OAuthTokenClient client, IdTokenValidator validator, SsoPrincipalMapper mapper, OidcMetadataClient metadata,
        @Qualifier("ssoClientClock") Clock clock, SsoRefreshLock lock, SsoClientMetrics metrics, ObjectProvider<SsoLogoutListener> listeners) {
        return new SsoSessionService(p, tx, store, client, validator, mapper, metadata, clock, lock, metrics,
            listeners.orderedStream().toList());
    }
    @Bean SsoAuthenticationFilter ssoAuthenticationFilter(SsoClientSettings s, SsoClientProperties p,
        SsoSessionService sessions,
        SsoCookieCustomizer cookies, SsoFailureHandler failures, @Qualifier("ssoClientClock") Clock clock) {
        return new SsoAuthenticationFilter(s, p.cookieName(), sessions, cookies, failures, clock);
    }
    @Bean FilterRegistrationBean<SsoAuthenticationFilter> disableContainerRegistration(SsoAuthenticationFilter filter) {
        FilterRegistrationBean<SsoAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
    @Bean SsoHttpSecurityConfigurer ssoHttpSecurityConfigurer(SsoAuthenticationFilter filter) {
        return new SsoHttpSecurityConfigurer(filter);
    }
    @Bean SsoClientController ssoClientController(SsoClientSettings s, SsoClientProperties p, SsoSessionService sessions,
        SsoCookieCustomizer cookies, SsoFailureHandler failures, @Qualifier("ssoClientClock") Clock clock) {
        return new SsoClientController(s, p.cookieName(), sessions, cookies, failures, clock);
    }

    private static String resolveKey(String value, boolean local) {
        if (value != null && !value.isBlank())
            return value;
        if (!local)
            throw new IllegalArgumentException("Production SSO token-store keys must be supplied as base64-encoded secret-manager values");
        byte[] random = new byte[32];
        new java.security.SecureRandom().nextBytes(random);
        return Base64.getEncoder().encodeToString(random);
    }
    private static byte[] deriveKey(byte[] key, String purpose) {
        try {
            return java.util.Arrays.copyOf(java.security.MessageDigest.getInstance("SHA-256").digest((Base64.getEncoder().encodeToString(key)+":"+purpose).getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                32);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
    private static ClientHttpResponse bounded(ClientHttpResponse response, int maxResponseBytes) throws IOException {
        if (response.getHeaders().getContentLength()>maxResponseBytes) {
            response.close();
            throw new IOException("SSO endpoint response exceeds size limit");
        }
        byte[] bytes;
        try {
            bytes = response.getBody().readNBytes(maxResponseBytes+1);
        } catch (IOException failure) {
            response.close();
            throw failure;
        }
        if (bytes.length>maxResponseBytes) {
            response.close();
            throw new IOException("SSO endpoint response exceeds size limit");
        }
        return new ClientHttpResponse() {
            public org.springframework.http.HttpStatusCode getStatusCode() throws IOException {
                return response.getStatusCode();
            }
            public String getStatusText() throws IOException {
                return response.getStatusText();
            }
            public org.springframework.http.HttpHeaders getHeaders() {
                return response.getHeaders();
            }
            public java.io.InputStream getBody() {
                return new ByteArrayInputStream(bytes);
            }
            public void close() {
                response.close();
            }
        };
    }
}
