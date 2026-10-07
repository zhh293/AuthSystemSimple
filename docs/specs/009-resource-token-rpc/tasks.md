# SDD Tasks: Resource-Token Validation RPC

- [x] Add a versioned Dubbo contract with a credential-safe DTO.
- [x] Reuse authorization-service token lookup and family revocation checks.
- [x] Reject disabled-account, expired, invalidated, missing, and oversized-token requests.
- [x] Return only active authorization context and record bounded outcome metrics.
- [x] Add a standalone resource-service consumer example using Dubbo/Nacos and fail-closed bearer enforcement.
- [x] Enforce the dedicated `resource.read` scope and configured client allowlist in the consumer example.
- [ ] Verify RPC authorization/mTLS and revocation behavior in a deployed resource-service integration.
