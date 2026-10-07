# SDD 010: Pluggable Directory Credential Verification

## Problem

Production identity-source selection is open in the base design. The SSO service currently verifies passwords against its local user table; production deployments need an internal service boundary for an existing corporate directory without moving the browser-facing OAuth/OIDC protocol onto RPC.

## Requirements

- Keep local Argon2id password verification for development and standalone deployments.
- Add a versioned Dubbo contract that forwards credentials only over the trusted internal service channel to a corporate identity provider.
- Make credential verification a replaceable application port so account/session, audit, throttling, and OAuth/OIDC behavior do not depend on the selected credential source.
- Require a local SSO account mapping and enabled state even when the external directory authenticates the credential; the mapping supplies the stable SSO subject and user profile.
- Never persist, log, metric-label, or return the submitted password. Redact request DTO string representation.
- Production deployments that select directory mode must provide a directory service implementation registered in Nacos and use the existing Dubbo Triple mTLS configuration.

## Acceptance criteria

- Database mode uses Argon2id and preserves constant-time dummy verification for unknown usernames.
- Directory mode calls the versioned Dubbo provider and accepts only when the external credential is valid and the local SSO mapping is enabled.
- Directory RPC failures fail authentication closed and propagate as dependency errors for monitoring; passwords are not included in diagnostics.
- Both modes produce the same TGC and audit behavior after credential verification.
- The actual enterprise provider and account mapping lifecycle remain deployment integration acceptance items.

