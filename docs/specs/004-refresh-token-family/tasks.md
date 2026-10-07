# SDD Tasks: Refresh Token Family Lifecycle

- [x] Add family/current digest and consumed-token history tables.
- [x] Hash family token references with the dedicated token-storage HMAC key.
- [x] Enforce one-time rotation and absolute family expiry in the SAS refresh-token generator.
- [x] Revoke families on replay and expose the revocation through opaque-token lookup.
- [x] Revoke all subject families during global SSO logout.
- [x] Audit refresh-token replay without writing token values.
- [ ] Build and run concurrency/replay/expiry/logout acceptance scenarios.
- [x] Add bounded cleanup for expired family/history and authorization rows, with authorization expiry indexes.
- [x] Define the active/previous HMAC-key rotation procedure and bind previous keys.
- [ ] Validate rotation across old/new authorization and family digests with runtime acceptance.
