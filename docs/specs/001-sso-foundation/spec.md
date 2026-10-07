# SSO Authentication Center — Foundation Specification

**Status:** In progress  
**Source:** `docs/sso-development-design.md`  
**Scope:** Development baseline and Stage 1 (authentication-center foundation)

## Objective

Create the Java foundation for the company SSO authentication center. Internal business capabilities are exposed as versioned Dubbo contracts and discovered through Nacos. HTTP controllers are protocol adapters for browser/OAuth/OIDC traffic; they delegate business operations to the internal services.

## Requirements

### R1 — Service architecture

- The repository is a Maven multi-module Java project with a separate operator provisioning CLI.
- `sso-contracts` contains serializable, versioned Dubbo service contracts and transport DTOs only; it must not depend on the server implementation.
- `sso-server` is the deployable Spring Boot service and exposes HTTP protocol endpoints as well as Dubbo providers.
- Dubbo uses Nacos service discovery. Registry address, namespace, group, credentials, service port, issuer, and all secrets are external configuration.
- Production security configuration is activated only by the explicitly active canonical lowercase `prod` or `production` profile; case-mismatched, whitespace-padded, or default-only production profile names fail startup instead of falling back to development keys or transport settings.
- Critical production secret, TLS, cookie, issuer, encryption, and key-store settings are validated before Spring creates database or Dubbo provider beans.
- Local development has a documented way to start Nacos, Redis, and MySQL.

### R2 — Authentication foundation

- User credential verification uses a mature password-hashing library (Argon2id); plaintext passwords are never persisted or logged.
- Client registration and exact redirect-URI allowlists are persisted; wildcard and prefix matching are forbidden.
- Client scopes are restricted to `openid`, `profile`, `email`, and `resource.read`; every OIDC client includes `openid`, while resource APIs enforce `resource.read` independently.
- Internal Dubbo client-registry lookups bound client IDs, reject unsafe or oversized redirect URIs, and fail closed on unsupported scopes or inconsistent registry records.
- TGC is an opaque, cryptographically random browser cookie value. Only a one-way digest is stored server-side. Cookie policy is HttpOnly, Secure by default, SameSite=Lax, and configurable path; local insecure HTTP is an explicit development-only override.
- Authentication sessions and authorization/token state fail closed when storage is unavailable.
- Every TGC validation checks that its subject account still exists and is enabled; disabled or deleted accounts cannot continue existing sessions.
- Disabling an account revokes its outstanding refresh-token families; re-enabling the account cannot reactivate credentials issued before disablement.
- If the internal TGC validation RPC is unavailable or returns a malformed result, the request clears any previously persisted authentication context and returns HTTP 503 without treating the session as invalid or expiring its cookie.
- The POST global-logout handler is not blocked by the TGC validation filter; it always clears the local servlet context and TGC cookie even when remote revocation is unavailable, and reports that remote failure with HTTP 503.
- The persisted servlet security context cannot outlive the authoritative TGC: each request revalidates the TGC, replaces the context from its current subject, or clears the context and expires the stale cookie.
- Authentication and protocol filters execute only inside their intended Spring Security chains, not as duplicate servlet-container filters.
- User and OAuth client records can be created through a controlled operator workflow; no public HTTP provisioning endpoint is exposed.
- Login and logout state-changing requests require CSRF protection. Login attempts are throttled and security outcomes are auditable without credentials.

### R3 — OAuth/OIDC progression

The foundation must provide seams for later stages without claiming those stages complete:

1. Stage 1: configuration, client lookup/policy, login UI/account verification, TGC, CSRF, throttling, audit, health checks, key-management abstraction.
2. Stage 2: authorize validation, exact redirect URI, state/nonce, S256 PKCE, one-time authorization code and atomic redemption.
3. Stage 3: opaque Access Token and rotating Refresh Token, OIDC ID Token, JWKS/Discovery, revoke and client authentication.
4. Later stages: application integration, logout propagation, hardening and operations.

### R4 — Standards implementation

- Production OAuth 2.0/OIDC protocol machinery must use a mature authorization-server library. Application code may supply client policy, identity, storage, key management, and lifecycle integration, but must not independently implement the standards state machines or JWT/JOSE primitives.
- Password hashing uses a mature library (currently Spring Security Argon2id). Custom cryptographic primitives are forbidden.

## Acceptance criteria

- Maven reactor contains independent contracts and deployable server modules.
- Server configuration shows Dubbo/Nacos wiring, data sources, Redis, token/session policies, and secure cookie defaults.
- The server has distinct application, client, session, credential, and audit boundaries; HTTP adapters invoke application services rather than embedding domain rules.
- No credentials, tokens, cookies, authorization codes, or PKCE verifier are logged.
- Internal client-registry RPC never returns redirect or scope policy that is broader than the authorization server accepts.
- Disabling or deleting a user prevents every existing TGC from restoring an authenticated context.
- Revoking a TGC prevents an already-created servlet session from remaining authenticated on later requests.
- Stage 2/3 requirements are explicitly marked incomplete until implemented and verified.
- Production protocol endpoints are owned by the standards library; custom code stays at integration boundaries.
- Starting with a case-mismatched production profile fails before Spring creates service beans or accepts traffic.

## Out of scope for this change

Authorization code issuance/redemption, token signing/rotation, OIDC discovery/JWKS, production user-directory integration, cross-application logout propagation, and production deployment secrets. These are tracked in `tasks.md`.
