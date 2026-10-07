# SDD Tasks: Example OIDC Relying Party

- [x] Add a standalone Spring Boot OAuth2 Client module.
- [x] Require PKCE S256 and rely on framework-managed state, nonce, callback, and ID Token validation.
- [x] Add a no-store profile endpoint that does not expose tokens.
- [x] Add CSRF-protected logout that revokes the stored token before local cleanup and reports remote failures.
- [x] Restrict the revocation destination to the configured issuer origin.
- [x] Default the RP session cookie to Secure, HttpOnly, and SameSite=Lax.
- [ ] Run the registered-client browser flow against a live SSO deployment and capture acceptance evidence.
