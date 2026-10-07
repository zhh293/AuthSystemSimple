# SDD Tasks — Authorization Server Library

- [x] Add Spring Authorization Server dependency and its MySQL persistence schema.
- [x] Map the existing client registry to `RegisteredClientRepository` with enabled/client-type/scope/redirect policy.
- [x] Add library protocol chain for OAuth/OIDC endpoints and settings.
- [x] Add TGC-to-Spring-Security context filter and secure custom login success handling.
- [x] Add configured RSA JWK source, discovery/JWKS, OIDC claims, opaque access tokens, and refresh rotation policy.
- [x] Discard ID Token values and claims before authorization state is persisted.
- [x] Adapt UserInfo for opaque access tokens without persisting ID Token claims.
- [x] Remove the transitional handwritten authorize/code endpoint and RPC contracts.
- [x] Store authorization codes and access/refresh tokens as keyed HMAC digests; discard ID Token values before persistence.
- [x] Revoke a refresh-token family after detecting replay and enforce a family absolute expiration.
- [x] Update endpoint docs and parent SDD task ledger.
- [x] Support OIDC signing-key overlap and active-key selection; see SDD 006.
- [x] Limit ID Token profile/email claims to their authorized scopes.
- [ ] Runtime-validate JWKS overlap and active-key rollover with a relying-party verifier.

Build/runtime acceptance remains pending until dependencies are available and the service is run with infrastructure.
