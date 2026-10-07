# Design: OIDC Signing Key Rotation

The PKCS#12 file contains the active alias and any public keys still required by relying parties. `sso.oidc-key-alias` selects the only active private key. `sso.oidc-previous-key-aliases` lists overlap keys; their certificate public keys are added to the server `JWKSet` without private material. Every RSA JWK carries its alias as `kid`, `use=sig`, and `alg=RS256`. `sso.id-token-ttl-seconds` sets the ID Token expiration and is bounded from 60 to 3600 seconds, overriding the authorization library's default lifetime.

The OIDC `OAuth2TokenCustomizer<JwtEncodingContext>` sets the ID Token JWS header `kid` to the active alias. `NimbusJwtEncoder` therefore selects exactly that active JWK even though the source contains the overlap keys. The opaque Access Token generator does not sign access tokens.

Rollover procedure:

1. Add the new RSA key pair/certificate to the PKCS#12 keystore. Deploy all nodes with the old key active and both old and new aliases in the previous-key list. Confirm `/oauth2/jwks` publishes the new public key.
2. Promote the new alias to active on all nodes and keep the old alias in the previous-key list. Confirm newly issued ID Tokens use the new `kid` and old tokens still validate.
3. After the configured maximum ID Token lifetime and the maximum supported client JWKS cache age have both elapsed from promotion, remove the old alias from the previous list. The old public key may then be removed from the keystore.

Do not remove a previous public key during an overlap window. Configuration is restart-bound and must be identical across all server nodes in each rollout phase.
