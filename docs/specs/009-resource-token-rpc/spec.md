# SDD 009: Internal Resource-Token Validation RPC

## Problem

Access Tokens are opaque so the authorization center can revoke them immediately, but internal resource services need a server-to-server way to ask whether a presented token is still active.

## Requirements

- Add a versioned Dubbo contract for an internal resource server to validate an opaque Access Token.
- Resolve token state through the same authorization service used by OAuth/OIDC; revoked, expired, unknown, or family-revoked tokens must be inactive.
- A disabled or missing subject account makes the token inactive.
- A disabled or missing OAuth client makes the token inactive.
- Return only active status and the minimum authorization context needed by a resource server: subject, client ID, granted scopes, and expiry.
- Do not include raw token values in results, logs, metrics, or audit events. Limit input length and reject malformed requests as inactive.
- Production relies on the existing Dubbo Triple mTLS configuration; callers must be internal resource services and network access must remain restricted.
- Provide a separate resource-service consumer example that calls the contract for Bearer requests and fails closed on inactive results, expired contexts, or RPC failures.
- The consumer must enforce its configured client allowlist and `resource.read` scope; a valid token for an unrelated client or without this API permission is not sufficient authorization.

## Acceptance criteria

- A valid live token returns active with its subject/client/scope/expiry context.
- Unknown, expired, revoked, replay-revoked-family, disabled-account, and disabled-client tokens return inactive with no identity or scope fields.
- Global logout makes tokens from the subject's refresh families inactive on subsequent RPC calls.
- Invalid input never reaches an unbounded lookup and no token string is recorded.
- The example resource endpoint returns no protected data when the token is inactive, lacks the required scope, is expired, or the RPC is unavailable.
- The example rejects a token whose client ID is not explicitly allowed by resource-service configuration.
