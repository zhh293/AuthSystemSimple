# SDD Tasks: Directory Authentication RPC

- [x] Add a credential-verifier application port and retain local Argon2id mode.
- [x] Add versioned Dubbo directory request/result contracts with redacted credentials.
- [x] Add configurable Dubbo consumer mode and fail-closed authentication handling.
- [x] Require local subject mapping and enabled account in both modes.
- [x] Configure production credential mode explicitly and document provider registration/mTLS requirements.
- [x] Add operator provisioning for directory-linked accounts without a local password hash.
- [ ] Integrate the organization's provider and account synchronization, then capture live acceptance evidence.
