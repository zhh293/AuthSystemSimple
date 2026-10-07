# SDD 004: Refresh Token Family Lifecycle

**Status:** Implemented; build and runtime acceptance pending  
**Parent:** `docs/specs/001-sso-foundation`  
**Related:** `docs/specs/003-authorization-server-library`

## Problem

Refresh token rotation must prevent concurrent reuse and detect replay after a successful rotation. A new refresh token must not extend the original family's absolute lifetime. Logging out of the SSO session must revoke all token families issued to that subject.

## Requirements

- Store refresh token history as keyed HMAC digests, never raw values.
- Create one family for a successful authorization-code grant that receives a refresh token.
- Set the family expiry once, from the initial refresh token, and cap every rotated token at that expiry.
- Consume the current refresh digest and register its replacement atomically under a database row lock.
- Reject an expired/revoked family. Detect a used token replay, revoke the family, and audit the event without recording token material.
- Reject introspection/UserInfo lookups for opaque access tokens whose family was revoked.
- Global logout revokes the TGC and all refresh families associated with the authenticated subject.
- Disabling a directory-backed subject revokes all of that subject's refresh families atomically with the account-sync page.
- Revocation through the standard token revocation endpoint must revoke the associated family when the refresh token is revoked.
- During key rotation, credentials and family history created with the previous active key remain resolvable while that key is configured as previous; all new digests use the active key.

## Acceptance criteria

- Two requests attempting to rotate the same refresh token cannot both advance the family; stale reuse revokes the family.
- A rotated token retains the original family's expiry.
- Reusing an old refresh token returns `invalid_grant`, creates an audit event, and makes family access tokens inactive.
- Refresh token raw values are absent from MySQL family tables and audit data.
- Logging out with a valid TGC makes all subject families inactive and revokes the TGC.
- Disabling a directory account makes existing TGC sessions and access tokens unusable and permanently revokes its current refresh families, even if the account is later re-enabled.
- After promotion, a credential stored under the prior key remains usable while that key remains in the configured previous-key ring.

## Out of scope

- Per-client logout UX/API.
- Per-token family migration to unrelated HMAC keys; rotation uses a bounded active/previous key ring.
