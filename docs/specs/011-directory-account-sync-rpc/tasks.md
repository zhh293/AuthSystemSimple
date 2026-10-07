# SDD Tasks: Directory Account Synchronization RPC

- [x] Define serializable versioned page, cursor, and account-record contracts without credential fields.
- [x] Add the directory-only Dubbo consumer and bounded polling schedule.
- [x] Add cursor/freshness persistence migration and atomic optimistic page application.
- [x] Enforce stable subject/username conflict rejection and account-field validation.
- [x] Revoke refresh-token families atomically when the directory disables an account.
- [x] Make login, TGC, UserInfo, and token introspection fail closed when directory sync is stale.
- [x] Add bounded synchronization outcome metrics and credential-safe batch audit events.
- [x] Document provider responsibilities, cursor semantics, and deployment configuration.
- [ ] Integrate the organization's provider and capture mTLS/freshness acceptance evidence.
