# Directory account sync provider guide

The corporate directory owns the Dubbo provider for `DirectoryAccountSyncService` (`version=1.0.0`) and registers it in the same Nacos namespace/group as the SSO service. In production, provider traffic uses the configured Dubbo Triple mTLS trust and identity material. The SSO side activates the consumer only when `SSO_IDENTITY_CREDENTIAL_MODE=directory`.

## Page protocol

The first `fetchChanges` request has a null cursor and requests up to 500 records. Later requests pass the exact opaque `nextCursor` returned by the previous committed page. Each response contains `accounts`, a non-empty `nextCursor` of at most 1024 characters, and `hasMore`. When `hasMore` is true, the cursor must advance. A page with account changes must also advance its cursor. An empty terminal page may repeat the cursor. The consumer reads at most ten pages per 30-second polling run by default; excess changes continue in the next run.

Each account record contains a stable immutable `subject`, a normalized lowercase `usernameNormalized`, `enabled`, and optional `displayName`, `email`, and `emailVerified`. Subjects must be 1–128 characters without control characters. Usernames must match `[a-z0-9._@+-]{1,128}`. The provider must not include passwords, password hashes, secrets, or other credential material. The source cursor must represent a consistent change-feed position so retries return the same changes until the cursor is advanced.

The consumer rejects malformed pages, duplicate subjects/usernames, or attempts to reassign a subject or username. Account updates and cursor advancement are committed atomically; the provider must therefore treat each request as retryable and idempotent. Do not log cursors or raw request/response payloads. SSO emits only bounded sync outcome metrics and a credential-free batch audit event.

## Freshness and operations

Set `SSO_DIRECTORY_SYNC_INTERVAL_MS` (default `30000`) and `SSO_DIRECTORY_SYNC_MAX_STALENESS_SECONDS` (default `120`). Production validates positive values, caps them at one day/seven days respectively, and requires the freshness window to allow at least two polling intervals. With no successful initial sync, or after the freshness window expires, directory-mode login, TGC validation, OIDC UserInfo, and opaque-token introspection fail closed as dependency-unavailable responses; an uncertain freshness state does not delete an otherwise valid TGC record. Database credential mode does not poll the provider and does not use this freshness gate.

Before production rollout, verify provider discovery, certificate identity and CA validation, initial null-cursor behavior, retry stability, cursor advancement, malformed/conflicting change rejection, and the observed stale-source fail-closed behavior. The alert `SSODirectorySyncUnavailable` in `ops/monitoring/sso-alerts.yml` fires on sync failures or rejected conflicts; production routing and thresholds must be reviewed against the deployment SLO.
