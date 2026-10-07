# SDD Tasks: OIDC Signing Key Rotation

- [x] Bind previous signing aliases and expose rotation configuration.
- [x] Publish previous public keys without private material in the JWK source.
- [x] Pin ID Token signing to the active alias through `kid` selection.
- [x] Validate production RSA key size, alias uniqueness, and active key-pair correspondence.
- [x] Make ID Token TTL configurable and bounded.
- [x] Document staged rollover and client-cache retention.
- [ ] Build and run overlap/rotation/JWKS acceptance with a relying-party verifier.
