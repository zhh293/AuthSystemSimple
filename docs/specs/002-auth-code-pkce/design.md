# Design — Authorization Code + PKCE

The HTTP controller translates OAuth parameters and browser cookies into a versioned Dubbo contract. The provider validates client and callback policy via the client registry, validates/looks up TGC sessions through the identity service, and writes short-lived state to Redis.

Pending login requests are stored as JSON under an HMAC digest of an unguessable continuation handle. Login only transports that opaque handle in a hidden form input and redirects to the fixed local authorize-resume path. The resume request ignores caller-supplied OAuth parameters and consumes the server-stored request after a valid TGC is present.

Codes are 256-bit random Base64URL strings. Redis keys use HMAC-SHA-256 digests. Redemption uses a Lua script to compare client, redirect URI, PKCE challenge, and expiry before deleting and returning the stored grant atomically. PKCE is fixed to S256.

This stage's initial handwritten endpoint and `AuthorizationCodeService` RPC were transitional. They have been removed in favor of Spring Authorization Server; protocol handling and token exchange are now provided by the standard `/oauth2/authorize` and `/oauth2/token` endpoints. See SDD 003 for the current implementation.
