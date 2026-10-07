# SDD 008: Example OIDC Relying Party

## Problem

The authorization center needs a separately deployable example client to exercise the real browser callback flow and document correct server-side OIDC client behavior.

## Requirements

- Use Spring Security OAuth2 Client and the configured SSO issuer; do not implement OAuth/OIDC protocol parsing or ID Token verification by hand.
- Use Authorization Code with PKCE S256. Keep state, nonce, and verifier in the RP server session; only the authorization code and state cross the browser callback.
- Use a confidential client secret from environment/secret management and the exact registered callback `http://localhost:8090/login/oauth2/code/sso` for local development.
- Send the revocation request only to an HTTP(S) URI on the configured issuer origin; reject cross-origin configuration at startup to prevent bearer-token disclosure.
- Keep OAuth authorized-client tokens in the server-side session; never render or return bearer/refresh/ID Token values.
- Configure the RP session cookie as HttpOnly, SameSite=Lax, and Secure by default; insecure transport is an explicit local-development override only.
- Demonstrate scope-filtered user information and CSRF-protected RP logout. Before local cleanup, submit the server-held Refresh Token to the SSO revocation endpoint with client authentication; fall back to the Access Token when no Refresh Token exists.
- If remote revocation cannot be confirmed, still clear local session and authorized-client state, show an explicit unconfirmed status, and never claim remote tokens were revoked. RP logout does not clear the global SSO TGC or other applications' sessions.
- Do not add this RP's session, cookie, or Redis behavior to `sso-server`.

## Acceptance criteria

- The example starts independently on port 8090 and discovers the provider from `SSO_ISSUER`.
- Login returns through the exact callback, and Spring Security validates state, nonce, PKCE, issuer, audience, signature, and token lifetime before creating the RP session.
- `/api/me` returns only the verified subject and available name/email claims with `Cache-Control: no-store`; it does not expose OAuth tokens.
- RP logout is a CSRF-protected POST, attempts remote revocation before local cleanup, and reports whether revocation was confirmed. It never clears the global SSO TGC.
- The RP session cookie has the Secure attribute by default.
