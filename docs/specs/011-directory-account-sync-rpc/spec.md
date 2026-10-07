# SDD 011: Directory Account Synchronization over Dubbo

**Status:** In progress; organization provider and runtime acceptance pending  
**Parent:** `docs/specs/010-directory-authentication-rpc`  
**Related:** `docs/specs/001-sso-foundation`, `docs/specs/009-resource-token-rpc`

## Problem

Directory-mode authentication depends on a local stable-subject/profile mapping. Manual CLI linking does not keep account names, profile data, or enabled state synchronized with the authoritative corporate directory.

## Requirements

- Define a versioned Dubbo contract for the directory provider to return changed account pages using an opaque cursor. Records contain stable subject, normalized username, enabled state, and optional profile fields; they never contain passwords.
- Consume the contract only in directory credential mode, through the existing production Dubbo Triple mTLS and Nacos boundary.
- Validate each page's size, cursor, stable subject and normalized username, field lengths, duplicate subjects/usernames, and email shape before applying it.
- Apply each page and its cursor advancement atomically. Concurrent SSO instances must use compare-and-set cursor advancement so a stale worker cannot skip changes.
- Never reassign a subject to a different username mapping or a username to a different subject. Reject conflicts and leave the cursor unchanged.
- When an account is marked disabled, revoke its outstanding refresh-token families in the same page transaction as the account update and cursor advancement.
- Track the last successful synchronization time. When directory data exceeds the configured maximum staleness, login, TGC session validation, OIDC UserInfo, and resource-token validation must fail closed.
- Do not store or log credentials or raw RPC payloads/cursors. Record bounded sync outcomes and credential-safe batch audit events.
- Keep the corporate directory implementation and field mapping deployment-owned; the SSO repository supplies only the consumer contract and adapter.

## Acceptance criteria

- A valid page updates/inserts local account mappings and advances the cursor in one transaction.
- A disabled-account change and revocation of that subject's refresh-token families commit atomically with the page cursor.
- A failed, malformed, conflicting, oversized, or concurrent stale page does not advance the cursor.
- When no successful sync has occurred or the sync is stale, account authentication, TGC validation, OIDC UserInfo, and token introspection reject access.
- Database credential mode does not invoke the sync provider or depend on sync freshness.

## Out of scope

Implementing a specific LDAP/HR/identity-platform provider, deletion/retention policy for departed identities, production schema mapping, and deployed mTLS acceptance.
