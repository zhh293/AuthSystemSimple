# Authorization Code + PKCE Specification

**Status:** In progress  
**Source:** `docs/sso-development-design.md`, sections 4, 9, 11, 12, and 17.

## Requirements

- `GET /oauth2/authorize` accepts only `response_type=code`, an enabled client, a byte-for-byte registered `redirect_uri`, a supported scope set containing `openid`, non-empty bounded `state` and `nonce`, and `code_challenge_method=S256` with a valid challenge.
- When no active TGC exists, save the already-validated request server-side for a short time and use a random opaque continuation handle through login. Do not put verifier or secrets in the browser. Resuming a continuation uses only server-stored values.
- Authorization codes are high-entropy, short-lived, single-use, and stored by keyed digest. Bind each code to client, redirect URI, subject, scope, nonce, and S256 challenge.
- Code redemption must atomically validate client, exact redirect URI, expiry, and `BASE64URL(SHA256(code_verifier))`, then consume the code so concurrent redemption has at most one success.
- OAuth errors are redirected only to a callback already checked against the enabled client's exact allowlist. Invalid/untrusted callbacks receive a local 400 response and never control `Location`.
- Stage 3 token issuance and client authentication are not implied complete by authorization-code issuance/redemption.

## Acceptance evidence

- Request validation and exact callback lookup live in the application service.
- Redis transactions have bounded TTLs and use opaque random keys/digests.
- Redemption is a single Redis atomic operation and returns one grant at most.
- Endpoint responses use no-store/no-cache and do not leak internal storage errors.
