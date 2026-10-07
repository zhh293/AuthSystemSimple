# SDD 006: OIDC Signing Key Rotation

**Status:** In progress; build, runtime rollover, and verifier acceptance pending  
**Parent:** `docs/specs/001-sso-foundation`  
**Related:** `docs/specs/003-authorization-server-library`

## Problem

The authorization server currently loads one RSA key pair. It cannot publish old and new public keys together during client JWKS cache rollover, and it has no configured active key selection across deployments.

## Requirements

- Load one active RSA private key and zero or more previous RSA public keys from the externally managed PKCS#12 keystore.
- Publish active and previous public keys in JWKS; never expose any private key.
- Sign every new ID Token with the configured active key and put its key ID in the JWS `kid` header.
- Never use a previous key to sign a new token.
- Reject duplicate/blank aliases, an active alias also listed as previous, non-RSA keys, weak RSA keys below 2048 bits, and mismatched active private/public material.
- Support staged deployment: publish the new public key before promoting it, retain the old public key after promotion, and remove it only after all ID Tokens signed by it have expired plus the maximum supported client JWKS cache age.
- Make ID Token lifetime configurable and bound it so key-retention calculations have a known maximum.
- Keep production keystore material external; development may continue to use one ephemeral key.

## Acceptance criteria

- With active alias `new` and previous alias `old`, discovery/JWKS exposes both public keys and no private key fields.
- Newly issued ID Tokens contain `kid=new` and validate with the published `new` key.
- Tokens issued before promotion still validate with the published `old` key during the overlap window.
- Invalid alias/key configuration prevents production startup.

## Out of scope

- Automated KMS integration, dynamic in-process keystore reload, and client cache-control policy beyond documented rollover retention.
