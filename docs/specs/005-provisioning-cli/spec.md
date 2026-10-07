# SDD 005: Operator Provisioning CLI

**Status:** In progress; build and database acceptance pending  
**Parent:** `docs/specs/001-sso-foundation`

## Problem

The authentication service intentionally has no public account or client administration API, but production still needs a repeatable way to provision users and OAuth clients without hand-generating password hashes or storing client secrets in SQL files.

## Requirements

- Provide a separate command-line application; it must not add an HTTP or Dubbo provisioning endpoint.
- Provision users with Argon2id password hashes compatible with the identity provider; read passwords interactively and never echo or log them.
- Provision public and confidential authorization-code clients, exact redirect URI allowlists, and supported scopes.
- Generate confidential client secrets using a cryptographically secure random generator, hash them with a password encoder accepted by the authorization server, and display the raw secret only once.
- Use prepared SQL statements and one database transaction per user/client operation.
- Require an operator identity and write a credential-safe audit event in the same transaction as each provisioning change.
- Require database connection settings from external environment variables and provide no default production credentials.
- Reject wildcard, unsafe, and non-local HTTP redirect URIs; require `openid` and limit scopes to `openid`, `profile`, `email`, and `resource.read`.

## Acceptance criteria

- A user password is never accepted as a command-line argument and the database stores only an Argon2id hash.
- A created confidential client can authenticate at the OAuth token endpoint with the one-time-displayed secret; only its encoded hash is stored.
- Invalid input or SQL failure cannot leave a partially provisioned client, redirects, or scopes.
- Successful operations record the operator, resource type, and resource ID; audit records contain no password or client secret.
- Missing or oversized operator identity prevents provisioning before any database mutation.
- The CLI runs separately from the SSO HTTP/Dubbo server.

## Out of scope

- Editing or deleting existing records, administrative authorization UI, bulk import, and production directory synchronization.
