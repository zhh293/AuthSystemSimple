# SDD 012: SSO Relying Party Client SDK

**Status:** In progress
**Parent:** `docs/sso-client-sdk-architecture.md`

## Problem

Company Spring Boot applications currently have to assemble OAuth/OIDC login, callback validation, token storage, application cookies, refresh, and local logout themselves. The existing `sso-example-rp` demonstrates Spring Security's session-based OAuth client and is not the application-token-cookie plus application-Redis SDK described in the architecture.

## Requirements

- Publish an opt-in `sso-client-spring-boot-starter` backed by a reusable `sso-client-core` module, aligned with Java 17 and the parent Spring Boot dependency line.
- When disabled or absent from configuration, leave application `SecurityFilterChain` behavior unchanged. Never replace the application's filter chain; provide composable filters/configurers and overridable beans.
- Use a statically configured issuer and OIDC Discovery/JWKS. Never derive endpoints from untrusted token claims. Bound HTTP timeouts and response sizes; do not retry one-time code exchange, refresh rotation, or revoke POSTs.
- Implement authorization code flow with server-side, short-lived, one-time state/nonce/PKCE S256 transaction storage, browser transaction binding, fixed registered callback URI, and same-origin relative return paths.
- Exchange codes server-side with confidential client authentication; validate ID token signature and issuer, audience/azp, exp, iat, nonce and subject using trusted Discovery/JWKS. Retain only the minimum mapped principal claims; never persist/log ID tokens.
- Expose only the application access token in a Secure, HttpOnly, configurable SameSite cookie. Keep refresh tokens encrypted at rest in the application token store; never expose them to browsers.
- Store opaque access-token lookup keys as HMAC digests, retain a single current mapping per user/client, preserve refresh-family absolute expiry, atomically consume authorization state and replace token mappings, and set bounded TTLs.
- On expired application access token, refresh server-side with single-flight coordination; fail closed if refresh or storage writes fail. Do not pass expired tokens downstream. Do not silently fall back from a failed Redis deployment to local state.
- Support local application logout with CSRF-protected POST, best-effort standards-compliant token revocation, local mapping removal and cookie clearing. Do not claim real-time global logout; it remains out of scope until the authorization server provides a supported RP global-logout contract.
- Provide documented extension points for principal mapping, token/transaction stores, bounded cookie lifetime customization, enterprise proxy selection, credential-free failure handling and logout listeners; enforce non-weakenable security defaults.
- Provide protected-route matching, SDK login/callback/logout/status endpoints, page/API unauthenticated behaviors, readiness/metrics hooks, bounded-cardinality telemetry, and credential-safe logs.
- Include an SDK-specific example profile and migration/configuration documentation while retaining the existing standard OAuth client example.

## Acceptance criteria

- A consuming Boot application can enable the starter with issuer, client credentials, callback, protected routes and stores, then complete authorization-code + PKCE login without implementing protocol plumbing.
- Callback replay, bad browser binding, wrong issuer/audience/nonce, bad signature, expired token, unsafe return path, and Redis failure are rejected without issuing an application token cookie.
- The browser receives no refresh token, ID token, verifier, authorization code after callback, or client secret.
- Access-token expiry never grants access; refresh rotation updates the mapping and cookie once under concurrent requests and never extends the refresh-family absolute expiry.
- Local logout is POST/CSRF protected, clears local state and cookie even when remote revoke is unavailable, and does not claim global logout.
- Disabled starter configuration has no effect on existing security chains. User-provided extension beans override defaults without weakening mandatory protocol checks.
- SDK module dependency metadata, minimal configuration, migration steps, operational behavior and supported version line are documented.

## Out of scope

Implementing an authorization server, corporate login UI, resource-server validation of opaque access tokens, automatic account provisioning, back-channel logout before its protocol requirements are independently specified, and publishing artifacts to an external Maven repository.
