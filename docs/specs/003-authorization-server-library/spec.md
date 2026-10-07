# Spring Authorization Server Integration

**Status:** In progress  
**Supersedes:** the transitional protocol provider described by spec 002 for protocol endpoints.

## Requirements

- Protocol endpoints are provided by Spring Authorization Server 1.5.8, matching the Spring Boot 3.5 / Spring Security 6 baseline.
- Client metadata is resolved from the existing client registry; disabled clients and unsafe/non-exact callbacks are rejected. Registered clients require PKCE S256; OpenID requests require nonce; state is mandatory.
- The authorization server issues OAuth authorization codes, opaque access tokens, rotating refresh tokens, OIDC ID Tokens and standard discovery/JWKS/revocation endpoints through the library.
- Browser authentication remains the SSO account service over Dubbo and an opaque TGC cookie. A TGC-backed security filter restores the authenticated principal for the protocol engine.
- Signing private keys are loaded from a PKCS#12 keystore mounted/provided by the secret manager in production. Development may use an ephemeral signing key only.
- ID Token values and claim sets are returned to the relying party but discarded before authorization state is persisted.
- Authorization codes, opaque access tokens, refresh tokens, user codes and device codes are stored as HMAC-SHA-256 digests using a dedicated secret key; production also requires encrypted database storage/backups for identity and authorization metadata.
- ID Token and UserInfo profile/email claims are emitted only when the corresponding `profile` or `email` scope was authorized.
- The custom `/oauth2/authorize` controller, Redis code state machine, and internal one-off code redemption RPC are removed to prevent parallel protocol implementations.

## Acceptance evidence

- Library endpoint filters own authorize, token, discovery, JWK, and revoke routes.
- The persisted client repository enforces enabled state, exact callback allowlists, allowed scopes, client type, and PKCE.
- The identity provider authenticates the authorization request from a validated TGC or the login form, and Spring Security saves the principal.
- Production startup rejects missing keys and does not use generated signing keys.
