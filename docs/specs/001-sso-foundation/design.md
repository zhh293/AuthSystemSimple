# Design — SSO Foundation

## Decisions

- Java 17 and Spring Boot 3.5.x: supported LTS baseline with Dubbo's Spring Boot 3 starter family. The build currently pins Spring Boot 3.5.16 and Dubbo 3.3.6.
- Apache Dubbo 3.x with Nacos 2.x+ registry. Contracts are a separate artifact so callers need not depend on the web/server module.
- Trusted internal resource services validate opaque Access Tokens through a versioned Dubbo contract; production calls use the configured Triple mTLS channel and fail closed on RPC errors.
- MySQL is the system of record for clients, users, credentials, and audit records. Redis stores short-lived TGC sessions and later OAuth state. All repository interfaces keep domain services independent of storage details.
- Access/refresh tokens will be opaque in the initial design so revocation is centrally enforceable. Signing keys are abstracted for the OIDC ID Token stage and must never be source-controlled.
- The external protocol uses standard HTTP endpoints. Internal capability calls use Dubbo; the public OAuth protocol itself is not replaced with proprietary RPC.
- Production Dubbo Triple links use mutual TLS; local development can run without certificates. Registry authentication is configured independently. Production Nacos client RPC TLS is enabled with CA validation, Redis uses TLS, and MySQL Connector/J requires `sslMode=VERIFY_IDENTITY`.
- Spring Authorization Server 1.5.x is the selected OAuth/OIDC protocol engine. The current Stage 2 code-provider implementation is transitional; it must be replaced by library-backed endpoint and persistence integration before protocol acceptance or production exposure.
- Configuration has safe local defaults for developer convenience but production requires HTTPS, explicit secrets, and managed credentials.

## Module and call flow

```text
Browser / Relying Party
        | HTTPS (OAuth/OIDC and login UI)
        v
HTTP protocol adapters (sso-server)
        | application service calls
        +------> domain services ------> MySQL / Redis / key provider
        |
        +------> Dubbo providers <----> internal consumers
                         |
                       Nacos
```

The protocol adapter validates and translates HTTP input. Application services own use cases. Domain policies own exact redirect matching, password verification, session lifecycle, and credential-safe audit semantics. Infrastructure implements repositories and RPC providers.

The internal Dubbo client-registry provider applies the same redirect URI and scope constraints as the Spring Authorization Server repository. It bounds incoming client IDs and fails closed when stored registry data is malformed, so downstream internal consumers cannot observe a more permissive client policy.

The TGC request filter revalidates the opaque cookie over `IdentityService` on every request. If that RPC fails or returns a malformed result, the filter clears the request's persisted security context, records a bounded dependency-error metric, and returns HTTP 503 without deleting the cookie; a transient control-plane outage therefore cannot preserve stale authentication or force a user to discard a potentially valid session. The `/session` endpoint reports this request's already-validated security context instead of making a second session RPC. The browser login adapter similarly validates successful RPC responses before setting a TGC cookie.

POST `/logout` skips this pre-validation so a TGC RPC outage cannot short-circuit local logout cleanup. The identity provider reads the session subject from Redis without applying account freshness, then attempts refresh-family revocation and TGC deletion independently so one failed store does not prevent the other action from being attempted. The controller always clears the local servlet context and expires the browser cookie in its `finally` block, and returns HTTP 503 if remote revocation could not be confirmed.

Production profiles must be explicitly active and canonical lowercase (`prod` or `production`) without surrounding whitespace because Spring profile activation controls both external configuration files and Dubbo mTLS beans. A context initializer rejects malformed or default-only production names before bean creation instead of allowing different components to choose different key or transport modes.

The same initializer validates production TLS endpoints, key material locations, cookie/issuer policy, and storage encryption settings before Spring can initialize Flyway or export Dubbo services. The later configuration runner retains its bound-property validation as a second check.

## Security invariants

- Persist only a password hash and a keyed/one-way digest of opaque session and token values.
- Use constant-time digest comparisons where applicable; use atomic Redis create/consume operations for one-time state.
- Redirect URI matching is exact after no normalization beyond the protocol's defined parsing; no wildcard or prefix rules.
- Any required database/Redis/key dependency failure rejects authentication or token operations.
- Never log request bodies or credential-bearing headers/cookies; audit only identifiers, event type, outcome, timestamp, and correlation ID.
- Production cookie `Secure` cannot be disabled by an HTTP request; a local-only profile may override it.

## Configuration boundary

`application.yml` contains non-secret local defaults and environment-variable references. Deployment must supply Nacos address/namespace, MySQL credentials and TLS URL, Redis credentials/TLS, issuer URL, cookie domain/path, and cryptographic keys via a secret manager. There are no embedded production secrets.

## Risks / open choices

- Corporate user directory and internal subject mapping need a product decision before production login enablement.
- Nacos deployment version and authentication mode are deployment-specific; Dubbo 3 requires Nacos 2 or later.
- HTTPS termination and trusted proxy configuration must be defined before production cookie/issuer behavior is enabled.
- The in-progress custom authorization-code RPC is not the final production protocol engine; Stage 3 must integrate the maintained Spring authorization-server library and remove overlapping custom HTTP protocol handling.
