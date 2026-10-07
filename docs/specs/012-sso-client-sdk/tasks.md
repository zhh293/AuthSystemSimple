# SDD Tasks: SSO Relying Party Client SDK

## Contracts and core protocol

- [x] Add core and starter Maven modules and dependency/version metadata.
- [x] Add validated typed configuration and stable public API types.
- [x] Implement bounded OIDC discovery/JWKS cache from fixed trusted issuer, including stale-key policy and key-refresh acceptance.
- [x] Implement state/nonce/PKCE S256, per-transaction browser binding and atomic transaction consume.
- [x] Implement bounded token/revoke HTTP client and confidential client authentication; require Bearer token responses, bound token field sizes/access-token lifetime, and reject scopes outside the requested set.
- [x] Validate ID token signature, issuer, audience/azp, exp, iat, nonce and subject; validate refresh response ID tokens against the existing subject and original nonce digest.
- [x] Filter profile and email claims by granted scopes before invoking the application principal mapper.
- [x] Implement safe return paths and generic credential-safe callback failures.

## Session and persistence

- [x] Implement HMAC access-token lookup, AEAD encrypted refresh-token records, and persistence of the effective granted-scope set across refreshes.
- [x] Implement Redis token/transaction stores, atomic replacement/consume, user/client current mapping and absolute family TTL.
- [x] Implement explicitly opt-in bounded local stores for single-instance development.
- [x] Implement refresh single-flight, fail-closed behavior and refresh failure cleanup.
- [x] Persist a one-time refresh-attempt marker keyed by the old RT HMAC fingerprint before refresh POST; Redis retains its HMAC key through family expiry plus cleanup grace and across process restarts, while explicit local development mode keeps it for the process lifetime. Fail closed when the claim is already held or its acknowledgement is uncertain.
- [x] Implement cookie writing/clearing and local logout without implying global logout.

## Spring integration and delivery

- [x] Add opt-in Boot auto-configuration that composes with, but never replaces, host security chains.
- [x] Add login/callback/logout/status routes, protected-route integration and safe page/API failures; logout rejects requests unless Spring Security supplied its CSRF token request attribute.
- [x] Add extension beans, route validation, bounded metrics and health/readiness integration.
- [x] Add SDK example profile, application configuration and migration guide.
- [ ] Complete protocol, security, concurrency and auto-configuration acceptance tests; unit coverage now includes authorization-code/PKCE callback with server-only verifier persistence, nonce-digest persistence, single-attempt code/refresh failures on HTTP 5xx, refresh ID Token remapping under effective scopes, callback and refresh-cookie rollback, successful callback issuing only the app AT cookie with a clean redirect, uncertain refresh-write cleanup/revoke, refresh response past family-expiry rejection, Redis refresh-attempt SET-NX digest/TTL/failure behavior, simulated stale mapping after a refresh attempt, local marker retention after mapping deletion, direct and overlap session rejection at family expiry or AT refresh-skew expiry, browser binding name agreement, scope-subset response validation and scope-filtered claims, multi-encoded/path-traversal return-path rejection, context-path-aware API handling and configurable return parameter, issuer and endpoint trust, bounded JWKS rotation/stale behavior including refresh-failure rate limiting before the first successful fetch, refresh overlap longer than the lock wait, Bearer token response limits, client authentication, ID Token/refresh ID Token validation, bounded callback cancellation, fail-closed refresh, CSRF-disabled logout rejection, late-refresh rejection, logout using the latest atomically removed record after a racing rotation, enabled/disabled auto-configuration and optional Actuator behavior; local-store and refresh-lock concurrency are covered. The suite and Java 17 reactor build remain unverified.
- [ ] Verify authorization requests and authorization-code/refresh exchanges through Spring Security OAuth2 Client protocol components, including builder-generated PKCE, the custom bounded `RestClient`, client authentication, response validation, scope ceiling, and no-retry behavior. RFC 7009 revocation remains an explicit bounded form POST because Spring Security OAuth2 Client does not provide a revocation response client.
- [ ] Complete code/dependency review and update architecture document with implemented behavior and limitations.

## Verification environment

The required Java 17 Maven reactor build and acceptance suite have not run in the current workspace. Java 17 and Maven 3.9.12 are available, but the configured Maven Central connection is denied and the local Maven caches do not contain the parent POM's required Spring Boot 3.5.16 or Dubbo 3.3.6 BOM POM files. Do not treat existing `target/manual-javac` class files as verification of the current source tree. Once dependency access is restored, run the Java 17 reactor build and the acceptance suite before release.
