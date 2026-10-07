# SDD Tasks — Authorization Code + PKCE

- [x] Add versioned Dubbo request/result contracts.
- [x] Validate authorize request, enabled client, exact redirect URI, supported scope, state, nonce, and S256.
- [x] Persist pending login transaction and safely resume after TGC creation.
- [x] Issue random one-time code bound to user and request metadata.
- [x] Atomically redeem code with client/redirect/PKCE checks through the internal RPC contract.
- [x] Add `/oauth2/authorize` protocol adapter with safe OAuth error redirects and no-store headers.
- [x] Replace transitional custom protocol endpoint/state handling with Spring Authorization Server 1.5.x before accepting this stage or exposing it in production.
- [x] Record implementation evidence and link this SDD from the parent task ledger.

Source work is present. POM XML parses, but Java compilation/runtime verification remains pending because dependencies are absent from the local cache and Maven Central access was denied. The public `/oauth2/token` endpoint and actual access/ID/refresh token issuance are intentionally Stage 3 work.
