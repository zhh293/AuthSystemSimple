package com.authsystem.sso.client.session;

import com.authsystem.sso.client.config.SsoClientProperties;
import com.authsystem.sso.client.crypto.RefreshTokenCipher;
import com.authsystem.sso.client.crypto.TokenDigests;
import com.authsystem.sso.client.observability.SsoClientMetrics;
import com.authsystem.sso.client.protocol.IdTokenValidator;
import com.authsystem.sso.client.protocol.OAuthTokenClient;
import com.authsystem.sso.client.protocol.OidcMetadataClient;
import com.authsystem.sso.client.store.SsoAuthorizationRequestStore;
import com.authsystem.sso.client.store.SsoRefreshLock;
import com.authsystem.sso.client.store.SsoTokenStore;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.http.HttpMethod.POST;

class SsoSessionServiceTest {
    private static final String ISSUER = "https://issuer.example.test";
    private static final String ACCESS = "expired-access-token";
    private static final String REFRESH = "refresh-secret-value";
    private static final Instant NOW = Instant.parse("2026-05-01T12:00:00Z");
    private static final byte[] KEY = new byte[32];

    @Test
    void familyExpiryAndAccessExpiryAreEnforcedForDirectAndOverlapLookups() {
        MutableClock clock = new MutableClock(NOW);
        InMemoryTokenStore store = new InMemoryTokenStore();
        SsoPrincipal principal = new SsoPrincipal("subject-1", "User", null, Map.of());
        store.records.put("family-expired", sessionRecord("family-expired", principal, NOW.plusSeconds(3600),
                NOW.minusSeconds(1)));

        SsoSessionService service = serviceFor(store, clock);
        assertThat(service.resolve("family-expired")).isEmpty();
        assertThat(store.records).doesNotContainKey("family-expired");

        Instant familyExpiry = NOW.plusSeconds(3600);
        store.records.put("current-family-expired", sessionRecord("current-family-expired", principal,
                NOW.plusSeconds(600),
                NOW.minusSeconds(1)));
        store.overlaps.put("old-family-expired", overlap("old-family-expired", "current-family-expired",
                NOW.minusSeconds(1)));
        assertThat(service.resolve("old-family-expired")).isEmpty();

        store.records.put("current-access-expired", sessionRecord("current-access-expired", principal,
                NOW.minusSeconds(1),
                familyExpiry));
        store.overlaps.put("old-access-expired", overlap("old-access-expired", "current-access-expired",
                familyExpiry));
        assertThat(service.resolve("old-access-expired")).isEmpty();
    }

    private static SsoSessionService serviceFor(InMemoryTokenStore store, MutableClock clock) {
        String hmac = Base64.getEncoder().encodeToString(KEY);
        SsoClientProperties properties = new SsoClientProperties(ISSUER, "portal", "client-secret", ISSUER+"/callback",
            "portal_access_token", "/", "Lax",
            Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30),
            Duration.ofHours(12),
            List.of("openid"), List.of("/**"), true, false, hmac, hmac, "sso:rp");
        RestClient http = RestClient.builder().build();
        OidcMetadataClient metadata = new OidcMetadataClient(ISSUER, http, clock, Duration.ofMinutes(10));
        SsoAuthorizationRequestStore transactions = new SsoAuthorizationRequestStore() {
            public void save(String state, SsoAuthorizationTransaction transaction) {
            }
            public Optional<SsoAuthorizationTransaction> consume(String state) {
                return Optional.empty();
            }
        };
        SsoPrincipal principal = new SsoPrincipal("subject-1", "User", null, Map.of());
        return new SsoSessionService(properties, transactions, store, new OAuthTokenClient(http, properties,
                metadata),
            new IdTokenValidator((JwtDecoder) token -> {
                    throw new IllegalStateException("unused");
                }, ISSUER, "portal", clock, Duration.ofSeconds(60)),
            claims -> principal, metadata, clock, (family, wait, lease) -> Optional.empty(), new SsoClientMetrics(new SimpleMeterRegistry()),
            List.of());
    }

    private static SsoTokenRecord sessionRecord(String token, SsoPrincipal principal, Instant accessExpiry,
        Instant familyExpiry) {
        return new SsoTokenRecord(ISSUER, "portal", TokenDigests.hmacSha256(token, KEY), "encrypted-refresh",
            "primary", principal,
            accessExpiry, familyExpiry, "nonce-digest", List.of("openid"));
    }

    private static String overlap(String oldAccess, String currentAccess, Instant familyExpiry) {
        String oldDigest = TokenDigests.hmacSha256(oldAccess, KEY);
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(currentAccess.getBytes(StandardCharsets.UTF_8))+":"+familyExpiry;
        String aad = ISSUER+"\nportal\n"+oldDigest+"\nrotation-overlap";
        return RefreshTokenCipher.encrypt(payload, KEY, aad.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void expiredAccessTokenIsRejectedAndMappingRemovedWhenRefreshFails() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("grant_type=refresh_token")))
        .andRespond(withBadRequest());

        String hmac = Base64.getEncoder().encodeToString(KEY);
        SsoClientProperties properties = new SsoClientProperties(ISSUER, "portal", "client-secret", ISSUER+"/callback",
            "portal_access_token", "/", "Lax",
            Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30),
            Duration.ofHours(12),
            List.of("openid"), List.of("/**"), true, false, hmac, hmac, "sso:rp");
        MutableClock clock = new MutableClock(NOW);
        RestClient http = builder.build();
        OidcMetadataClient metadata = new OidcMetadataClient(ISSUER, http, clock, Duration.ofMinutes(10));
        OAuthTokenClient tokenClient = new OAuthTokenClient(http, properties, metadata);
        InMemoryTokenStore store = new InMemoryTokenStore();
        Instant familyExpiry = NOW.plus(Duration.ofHours(2));
        String digest = TokenDigests.hmacSha256(ACCESS, KEY);
        String aad = ISSUER+"\nportal\n"+digest+"\n"+familyExpiry.toEpochMilli();
        String encrypted = RefreshTokenCipher.encrypt(REFRESH, KEY, aad.getBytes(StandardCharsets.UTF_8));
        SsoPrincipal principal = new SsoPrincipal("subject-1", "User", null, Map.of());
        SsoTokenRecord staleRecord = new SsoTokenRecord(ISSUER, "portal", digest, encrypted, "primary",
            principal,
            NOW.minusSeconds(1), familyExpiry);
        store.records.put(ACCESS, staleRecord);
        SsoAuthorizationRequestStore transactions = new SsoAuthorizationRequestStore() {
            public void save(String state, SsoAuthorizationTransaction transaction) {
            }
            public Optional<SsoAuthorizationTransaction> consume(String state) {
                return Optional.empty();
            }
        };
        AtomicReference<Duration> refreshLease = new AtomicReference<>();
        SsoRefreshLock lock = (family, wait, lease) -> {
            refreshLease.set(lease);
            return Optional.of(() -> {
                });
        };
        IdTokenValidator idTokens = new IdTokenValidator((JwtDecoder) token -> {
                throw new IllegalStateException("unused");
            }, ISSUER, "portal", clock, Duration.ofSeconds(60));
        SsoSessionService service = new SsoSessionService(properties, transactions, store, tokenClient,
            idTokens,
            claims -> principal, metadata, clock, lock,
            new SsoClientMetrics(new SimpleMeterRegistry()), List.of());

        assertThat(service.resolve(ACCESS)).isEmpty();
        assertThat(store.findByAccessToken(ACCESS)).isEmpty();
        assertThat(refreshLease.get()).isEqualTo(Duration.ofSeconds(17));
        // Simulate a process crash after the refresh endpoint may have consumed the RT but
        // before local cleanup: the mapping reappears while the durable claim survives.
        store.records.put(ACCESS, staleRecord);
        assertThat(service.resolve(ACCESS)).isEmpty();
        assertThat(store.findByAccessToken(ACCESS)).isEmpty();
        server.verify();
    }

    @Test
    void refreshIdTokenUpdatesPrincipalUsingOnlyGrantedClaims() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("grant_type=refresh_token")))
        .andRespond(withSuccess("{\"access_token\":\"new-access-token\",\"refresh_token\":\"new-refresh-token\",\"token_type\":\"Bearer\",\"expires_in\":300,\"id_token\":\"refreshed-id-token\",\"scope\":\"openid profile\"}",
                MediaType.APPLICATION_JSON));
        SsoClientProperties properties = new SsoClientProperties(ISSUER, "portal", "client-secret", ISSUER+"/callback",
            "portal_access_token", "/", "Lax",
            Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30),
            Duration.ofHours(12),
            List.of("openid", "profile", "email"), List.of("/**"), true, false, Base64.getEncoder().encodeToString(KEY),
            Base64.getEncoder().encodeToString(KEY), "sso:rp");
        MutableClock clock = new MutableClock(NOW);
        RestClient http = builder.build();
        OidcMetadataClient metadata = new OidcMetadataClient(ISSUER, http, clock, Duration.ofMinutes(10));
        InMemoryTokenStore store = new InMemoryTokenStore();
        Instant familyExpiry = NOW.plus(Duration.ofHours(2));
        String nonce = "initial-login-nonce";
        String digest = TokenDigests.hmacSha256(ACCESS, KEY), aad = ISSUER+"\nportal\n"+digest+"\n"+familyExpiry.toEpochMilli();
        String encrypted = RefreshTokenCipher.encrypt(REFRESH, KEY, aad.getBytes(StandardCharsets.UTF_8));
        SsoPrincipal original = new SsoPrincipal("subject-1", "Old Name", "old@example.test", Map.of("name",
                "Old Name", "email", "old@example.test"));
        store.records.put(ACCESS, new SsoTokenRecord(ISSUER, "portal", digest, encrypted, "primary", original,
                NOW.minusSeconds(1), familyExpiry, TokenDigests.sha256(nonce), List.of("openid", "profile",
                    "email")));
        SsoAuthorizationRequestStore transactions = new SsoAuthorizationRequestStore() {
            public void save(String state, SsoAuthorizationTransaction transaction) {
            }
            public Optional<SsoAuthorizationTransaction> consume(String state) {
                return Optional.empty();
            }
        };
        JwtDecoder decoder = compact -> Jwt.withTokenValue(compact).header("alg", "RS256").issuer(ISSUER).subject("subject-1").audience(List.of("portal"))
        .issuedAt(NOW.minusSeconds(5)).expiresAt(NOW.plusSeconds(300)).claim("nonce", nonce)
        .claim("name", "Updated Name").claim("email", "new@example.test").build();
        SsoPrincipalMapper mapper = claims -> new SsoPrincipal(claims.subject(), (String) claims.claims().get("name"),
                (String) claims.claims().get("email"), claims.claims());
        SsoSessionService service = new SsoSessionService(properties, transactions, store, new OAuthTokenClient(http,
                properties, metadata),
            new IdTokenValidator(decoder, ISSUER, "portal", clock, Duration.ofSeconds(60)), mapper, metadata,
            clock,
                (family, wait, lease) -> Optional.of(() -> {
                }), new SsoClientMetrics(new SimpleMeterRegistry()), List.of());

        SsoSessionService.Session session = service.resolve(ACCESS).orElseThrow();

        assertThat(session.refreshed()).isTrue();
        assertThat(session.record().principal().name()).isEqualTo("Updated Name");
        assertThat(session.record().principal().email()).isNull();
        assertThat(store.lastOverlapTtl).isEqualTo(Duration.ofSeconds(10));
        assertThat(store.findByAccessToken(ACCESS)).isEmpty();
        assertThat(store.findByAccessToken("new-access-token")).isPresent();
        assertThat(store.findByAccessToken("new-access-token").orElseThrow().idTokenNonceDigest()).isEqualTo(TokenDigests.sha256(nonce));
        server.verify();
    }

    @Test
    void uncertainRefreshStoreWriteRemovesOldAndNewMappingsAndRevokesRotatedRefreshToken() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\",\"revocation_endpoint\":\""+ISSUER+"/oauth2/revoke\"}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST))
        .andRespond(withSuccess("{\"access_token\":\"new-access-token\",\"refresh_token\":\"new-refresh-token\",\"token_type\":\"Bearer\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/revoke"))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("token=new-refresh-token")))
        .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        SsoClientProperties properties = new SsoClientProperties(ISSUER, "portal", "client-secret", ISSUER+"/callback",
            "portal_access_token", "/", "Lax",
            Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30),
            Duration.ofHours(12),
            List.of("openid"), List.of("/**"), true, false, Base64.getEncoder().encodeToString(KEY), Base64.getEncoder().encodeToString(KEY),
            "sso:rp");
        MutableClock clock = new MutableClock(NOW);
        RestClient http = builder.build();
        OidcMetadataClient metadata = new OidcMetadataClient(ISSUER, http, clock, Duration.ofMinutes(10));
        InMemoryTokenStore store = new InMemoryTokenStore();
        store.failAfterSave = true;
        Instant familyExpiry = NOW.plus(Duration.ofHours(2));
        String digest = TokenDigests.hmacSha256(ACCESS, KEY), aad = ISSUER+"\nportal\n"+digest+"\n"+familyExpiry.toEpochMilli();
        store.records.put(ACCESS, new SsoTokenRecord(ISSUER, "portal", digest, RefreshTokenCipher.encrypt(REFRESH,
                    KEY, aad.getBytes(StandardCharsets.UTF_8)), "primary",
                new SsoPrincipal("subject-1", "User", null, Map.of()), NOW.minusSeconds(1), familyExpiry));
        SsoAuthorizationRequestStore transactions = new SsoAuthorizationRequestStore() {
            public void save(String state, SsoAuthorizationTransaction transaction) {
            }
            public Optional<SsoAuthorizationTransaction> consume(String state) {
                return Optional.empty();
            }
        };
        SsoSessionService service = new SsoSessionService(properties, transactions, store, new OAuthTokenClient(http,
                properties, metadata),
            new IdTokenValidator((JwtDecoder) token -> {
                    throw new IllegalStateException("unused");
                }, ISSUER, "portal", clock, Duration.ofSeconds(60)),
            claims -> new SsoPrincipal(claims.subject(), "User", null, claims.claims()), metadata, clock,
                (family,
                wait, lease) -> Optional.of(() -> {
                }),
            new SsoClientMetrics(new SimpleMeterRegistry()), List.of());

        assertThat(service.resolve(ACCESS)).isEmpty();
        assertThat(store.findByAccessToken(ACCESS)).isEmpty();
        assertThat(store.findByAccessToken("new-access-token")).isEmpty();
        server.verify();
    }

    @Test
    void refreshResponseAfterFamilyExpiryIsDiscardedAndRevoked() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\",\"revocation_endpoint\":\""+ISSUER+"/oauth2/revoke\"}",
                MediaType.APPLICATION_JSON));
        MutableClock clock = new MutableClock(NOW);
        server.expect(requestTo(ISSUER+"/oauth2/token")).andExpect(method(POST)).andExpect(request -> {
                clock.advance(Duration.ofSeconds(2));
            })
        .andRespond(withSuccess("{\"access_token\":\"late-access-token\",\"refresh_token\":\"late-refresh-token\",\"token_type\":\"Bearer\",\"expires_in\":300}",
                MediaType.APPLICATION_JSON));
        server.expect(requestTo(ISSUER+"/oauth2/revoke"))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("token=late-refresh-token")))
        .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        SsoClientProperties properties = new SsoClientProperties(ISSUER, "portal", "client-secret", ISSUER+"/callback",
            "portal_access_token", "/", "Lax",
            Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30),
            Duration.ofHours(12),
            List.of("openid"), List.of("/**"), true, false, Base64.getEncoder().encodeToString(KEY), Base64.getEncoder().encodeToString(KEY),
            "sso:rp");
        RestClient http = builder.build();
        OidcMetadataClient metadata = new OidcMetadataClient(ISSUER, http, clock, Duration.ofMinutes(10));
        InMemoryTokenStore store = new InMemoryTokenStore();
        Instant familyExpiry = NOW.plusSeconds(1);
        String digest = TokenDigests.hmacSha256(ACCESS, KEY), aad = ISSUER+"\nportal\n"+digest+"\n"+familyExpiry.toEpochMilli();
        store.records.put(ACCESS, new SsoTokenRecord(ISSUER, "portal", digest, RefreshTokenCipher.encrypt(REFRESH,
                    KEY, aad.getBytes(StandardCharsets.UTF_8)), "primary",
                new SsoPrincipal("subject-1", "User", null, Map.of()), NOW.minusSeconds(1), familyExpiry));
        SsoAuthorizationRequestStore transactions = new SsoAuthorizationRequestStore() {
            public void save(String state, SsoAuthorizationTransaction transaction) {
            }
            public Optional<SsoAuthorizationTransaction> consume(String state) {
                return Optional.empty();
            }
        };
        SsoSessionService service = new SsoSessionService(properties, transactions, store, new OAuthTokenClient(http,
                properties, metadata),
            new IdTokenValidator((JwtDecoder) token -> {
                    throw new IllegalStateException("unused");
                }, ISSUER, "portal", clock, Duration.ofSeconds(60)),
            claims -> new SsoPrincipal(claims.subject(), "User", null, claims.claims()), metadata, clock,
                (family,
                wait, lease) -> Optional.of(() -> {
                }),
            new SsoClientMetrics(new SimpleMeterRegistry()), List.of());

        assertThat(service.resolve(ACCESS)).isEmpty();
        assertThat(store.findByAccessToken(ACCESS)).isEmpty();
        assertThat(store.findByAccessToken("late-access-token")).isEmpty();
        server.verify();
    }

    @Test
    void logoutRemovesCurrentMappingBeforeAttemptingRemoteRevoke() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ISSUER+"/.well-known/openid-configuration"))
        .andRespond(withSuccess("{\"issuer\":\""+ISSUER+"\",\"authorization_endpoint\":\""+ISSUER+"/authorize\",\"token_endpoint\":\""+ISSUER+"/oauth2/token\",\"jwks_uri\":\""+ISSUER+"/jwks\",\"revocation_endpoint\":\""+ISSUER+"/oauth2/revoke\"}",
                MediaType.APPLICATION_JSON));
        SsoClientProperties properties = new SsoClientProperties(ISSUER, "portal", "client-secret", ISSUER+"/callback",
            "portal_access_token", "/", "Lax",
            Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(30),
            Duration.ofHours(12),
            List.of("openid"), List.of("/**"), true, false, Base64.getEncoder().encodeToString(KEY), Base64.getEncoder().encodeToString(KEY),
            "sso:rp");
        MutableClock clock = new MutableClock(NOW);
        RestClient http = builder.build();
        OidcMetadataClient metadata = new OidcMetadataClient(ISSUER, http, clock, Duration.ofMinutes(10));
        InMemoryTokenStore store = new InMemoryTokenStore();
        Instant familyExpiry = NOW.plus(Duration.ofHours(2));
        String currentAccess = "rotated-access-token", currentRefresh = "rotated-refresh-secret";
        String digest = TokenDigests.hmacSha256(currentAccess, KEY), aad = ISSUER+"\nportal\n"+digest+"\n"+familyExpiry.toEpochMilli();
        String encrypted = RefreshTokenCipher.encrypt(currentRefresh, KEY, aad.getBytes(StandardCharsets.UTF_8));
        store.records.put(currentAccess, new SsoTokenRecord(ISSUER, "portal", digest, encrypted, "primary",
                new SsoPrincipal("subject-1", "User", null, Map.of()), NOW.plusSeconds(120), familyExpiry));
        String overlapAad = ISSUER+"\nportal\n"+TokenDigests.hmacSha256(ACCESS, KEY)+"\nrotation-overlap";
        String overlapPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(currentAccess.getBytes(StandardCharsets.UTF_8))+":"+familyExpiry;
        store.overlaps.put(ACCESS, RefreshTokenCipher.encrypt(overlapPayload, KEY, overlapAad.getBytes(StandardCharsets.UTF_8)));
        String racedAccess = "refresh-won-before-logout-access", racedRefresh = "latest-refresh-secret";
        String racedDigest = TokenDigests.hmacSha256(racedAccess, KEY), racedAad = ISSUER+"\nportal\n"+racedDigest+"\n"+familyExpiry.toEpochMilli();
        store.recordPublishedImmediatelyBeforeRemoval(racedAccess, new SsoTokenRecord(ISSUER, "portal",
                racedDigest,
                RefreshTokenCipher.encrypt(racedRefresh, KEY, racedAad.getBytes(StandardCharsets.UTF_8)),
                "primary",
                new SsoPrincipal("subject-1", "User", null, Map.of()), NOW.plusSeconds(120), familyExpiry));
        server.expect(requestTo(ISSUER+"/oauth2/revoke"))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("token="+java.net.URLEncoder.encode(racedRefresh,
                        StandardCharsets.UTF_8))))
        .andExpect(request -> {
                assertThat(store.findByAccessToken(racedAccess)).isEmpty();
            })
        .andRespond(withServerError());
        SsoAuthorizationRequestStore transactions = new SsoAuthorizationRequestStore() {
            public void save(String state, SsoAuthorizationTransaction transaction) {
            }
            public Optional<SsoAuthorizationTransaction> consume(String state) {
                return Optional.empty();
            }
        };
        SsoSessionService service = new SsoSessionService(properties, transactions, store, new OAuthTokenClient(http,
                properties, metadata),
            new IdTokenValidator((JwtDecoder) token -> {
                    throw new IllegalStateException("unused");
                }, ISSUER, "portal", clock, Duration.ofSeconds(60)),
            claims -> new SsoPrincipal(claims.subject(), "User", null, claims.claims()), metadata, clock,
                (family,
                wait, lease) -> Optional.empty(),
            new SsoClientMetrics(new SimpleMeterRegistry()), List.of());

        service.logout(ACCESS);

        assertThat(store.findByAccessToken(currentAccess)).isEmpty();
        assertThat(store.findByAccessToken(racedAccess)).isEmpty();
        assertThat(store.findOverlapAccessToken(ACCESS)).isEmpty();
        server.verify();
    }

    private static final class InMemoryTokenStore implements SsoTokenStore {
        private final Map<String, SsoTokenRecord> records = new ConcurrentHashMap<>();
        private final Map<String, String> overlaps = new ConcurrentHashMap<>();
        private final java.util.Set<String> refreshAttempts = ConcurrentHashMap.newKeySet();
        private String publishedToken;
        private SsoTokenRecord publishedRecord;
        private boolean failAfterSave;
        private Duration lastOverlapTtl;
        private void recordPublishedImmediatelyBeforeRemoval(String token, SsoTokenRecord record) {
            publishedToken = token;
            publishedRecord = record;
        }
        public Optional<SsoTokenRecord> findByAccessToken(String token) {
            return Optional.ofNullable(records.get(token));
        }
        public void saveCurrent(String oldToken, String newToken, SsoTokenRecord record, String overlap,
            Duration overlapTtl) {
            lastOverlapTtl = overlapTtl;
            if (oldToken != null)
                records.remove(oldToken);
            records.put(newToken, record);
            if (oldToken != null && overlap != null)
                overlaps.put(oldToken, overlap);
            if (failAfterSave)
                throw new IllegalStateException("simulated lost write acknowledgement");
        }
        public Optional<String> findOverlapAccessToken(String token) {
            return Optional.ofNullable(overlaps.get(token));
        }
        public boolean claimRefreshAttempt(String fingerprint, Instant retainUntil) {
            return refreshAttempts.add(fingerprint);
        }
        public void deleteByAccessToken(String token) {
            records.remove(token);
            overlaps.remove(token);
        }
        public Optional<SsoTokenRecord> removeCurrentBySubjectAndClient(String subject, String clientId) {
            if (publishedRecord != null) {
                records.clear();
                records.put(publishedToken, publishedRecord);
                publishedRecord = null;
            }
            return records.entrySet().stream().filter(entry -> entry.getValue().principal().subject().equals(subject) &&
                entry.getValue().clientId().equals(clientId)).findFirst().map(entry -> records.remove(entry.getKey()));
        }
    }

    private static final class MutableClock extends Clock {
        private Instant instant;
        private MutableClock(Instant instant) {
            this.instant = instant;
        }
        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }
        @Override public ZoneId getZone() {
            return ZoneOffset.UTC;
        }
        @Override public Clock withZone(ZoneId zone) {
            return this;
        }
        @Override public Instant instant() {
            return instant;
        }
    }
}
