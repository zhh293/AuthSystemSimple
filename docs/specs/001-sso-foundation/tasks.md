# SDD Tasks: SSO Foundation

## Stage 0: Project baseline

- [x] Record requirements, architecture decisions, security invariants, and phased acceptance criteria.
- [x] Create Maven reactor with `sso-contracts`, `sso-server`, and isolated `sso-admin` modules.
- [x] Wire Dubbo 3 providers/consumers and Nacos registry configuration.
- [x] Add local dependency topology and operational configuration examples.
- [x] Add schema migrations and health endpoints.

## Stage 1: Authentication foundation

- [x] Client registration schema and exact redirect URI comparison.
- [x] Bound internal client-registry RPC input and reject unsafe redirects or unsupported stored scopes.
- [x] Whitelist the `resource.read` permission scope separately from OIDC profile scopes.
- [x] User account/password verification with Argon2id and account status checks.
- [x] Opaque TGC creation, HMAC-digest-only storage, lookup, expiry, revocation, live account-status validation, per-request servlet-context revalidation, and security-chain-only filter registration.
- [x] Login CSRF, secure cookie policy, IP/account throttling, and credential-safe audit.
- [x] Minimal login UI and HTTP/Dubbo integration.
- [x] Add the pluggable corporate-directory credential RPC contract/consumer and local mapping mode; see [`SDD 010`](../010-directory-authentication-rpc/spec.md).
- [x] Add a generic directory account-sync Dubbo consumer with transactional cursors and freshness fail-closed checks; see [`SDD 011`](../011-directory-account-sync-rpc/spec.md).
- [ ] Integrate the organization's directory provider and field mapping, then capture production acceptance; see [`SDD 010`](../010-directory-authentication-rpc/spec.md).
- [x] Add a separate operator-run user/client provisioning CLI; see [`SDD 005`](../005-provisioning-cli/spec.md).
- [x] Enforce TLS and certificate validation for production MySQL, Redis, Dubbo, and Nacos client connections.
- [x] Require canonical production profiles to be explicitly active; reject malformed or default-only names before bean creation.
- [x] Validate production TLS, secret, issuer, cookie, encryption, and signing-store configuration before bean creation.

## Stage 2: Authorization Code + PKCE

- [x] Complete standard authorization-code/PKCE flow through Spring Authorization Server; see [`SDD 002`](../002-auth-code-pkce/spec.md) and [`SDD 003`](../003-authorization-server-library/spec.md).
- [x] Validate authorize request and exact client/redirect/scope policy through Spring Authorization Server and registered-client policy.
- [x] Persist authorization transaction and one-time code through Spring Authorization Server JDBC services.
- [x] Redeem codes through the standard token endpoint with PKCE and registered-client authentication policy.
- [x] Replace transitional custom protocol endpoint/state handling with Spring Authorization Server 1.5.x.

## Stage 3: OIDC and tokens

- [x] Opaque Access Token, keyed-digest token storage, and rotating Refresh Token families with replay revocation and absolute lifetime.
- [x] ID Token signing and verification metadata, JWKS, Discovery.
- [x] Client authentication and standard token endpoint response handling.
- [x] Global logout revokes the TGC and all subject refresh-token families; opaque access-token lookup rejects revoked families. Details: [`SDD 004`](../004-refresh-token-family/spec.md).

## Stage 4+: Integration and operations

- [x] Add a separately deployable example RP using framework-managed callback, state/nonce/verifier, and OIDC validation; see [`SDD 008`](../008-example-relying-party/spec.md).
- [ ] Run the example RP callback flow against a live SSO deployment and record runtime acceptance.
- [x] Add internal Dubbo validation for opaque Access Tokens so family/TGC logout revocation is visible to resource services; see [`SDD 009`](../009-resource-token-rpc/spec.md).
- [x] Add a separately deployable Dubbo/Nacos resource-service consumer example; see [`SDD 009`](../009-resource-token-rpc/usage.md).
- [x] Add CSRF-protected example-RP logout that revokes its server-held token before local cleanup; see [`SDD 008`](../008-example-relying-party/spec.md).
- [ ] Verify token revocation and resource-service fail-closed behavior on RPC errors in a deployed integration.
- [x] Add credential-safe authentication/TGC/refresh metrics and a loopback-bound Prometheus management endpoint; see [`SDD 007`](../007-operational-metrics/spec.md).
- [x] Add Prometheus scrape/alert and Grafana dashboard templates; deployment target, network policy, and alert calibration remain open in SDD 007.
- [ ] Complete backup/recovery drills and security review.
- [x] Implement staged OIDC signing-key rotation; see [`SDD 006`](../006-oidc-signing-key-rotation/spec.md).
- [ ] Validate OIDC signing-key rollover at runtime with a relying-party verifier.
- [x] Token-storage HMAC key ring and staged rotation procedure; runtime rotation acceptance remains open in SDD 004.

## Verification evidence

For each stage, attach build output and acceptance evidence for the corresponding requirements. Static checks on 2026-10-07: all six Maven POM files parsed as XML, the Grafana dashboard parsed as JSON, and the source/document scan found no UTF-8 replacement or known mojibake markers. Prometheus YAML parsing remains unverified because no YAML parser is available. Compilation/runtime behavior remains unverified: Maven is not available on PATH and the installed Java runtime is 11 while this project requires Java 17. Production acceptance remains open pending build/runtime verification, token-key rotation acceptance, and Stage 4+ operational work.


