# Operator use: SSO provisioning CLI

Build the standalone operator artifact from the repository root:

```powershell
mvn -pl sso-admin -am package
```

Set `SSO_DB_URL`, `SSO_DB_USERNAME`, `SSO_DB_PASSWORD`, and `SSO_ADMIN_ACTOR` in the operator's secret-managed environment. `SSO_ADMIN_ACTOR` is the operator identity recorded in the audit log. The database must already have Flyway migrations applied through V7. The `user create` command requires an interactive terminal for password input; do not pipe it through a logger or CI job that captures secrets.

Create a user (the password is prompted twice and is not accepted as an argument):

```powershell
java -jar sso-admin/target/sso-admin-0.1.0-SNAPSHOT.jar user create --username alice --subject user-123 --display-name "Alice Chen" --email alice@example.com
```

For a corporate-directory account, create only the local stable-subject/profile mapping and do not store a local password hash:

```powershell
java -jar sso-admin/target/sso-admin-0.1.0-SNAPSHOT.jar user link-directory --username alice --subject user-123 --display-name "Alice Chen" --email alice@example.com
```

Use that mapping only when the server is configured with `SSO_IDENTITY_CREDENTIAL_MODE=directory` and the version `1.0.0` `DirectoryCredentialService` provider is registered in Nacos. The user mapping must remain enabled and synchronized with the corporate directory.

Create a confidential authorization-code client (each redirect and scope is a repeated option). The generated secret is shown once in the operator terminal; save it directly in the application's secret manager:

```powershell
java -jar sso-admin/target/sso-admin-0.1.0-SNAPSHOT.jar client create --id portal --name "Internal Portal" --type CONFIDENTIAL --redirect-uri https://portal.example.com/login/callback --scope openid --scope profile
```

Public clients use the same command with `--type PUBLIC`; they do not receive a client secret and must use PKCE. HTTP redirect URIs are accepted only for localhost development. Creation is insert-only; duplicates fail without modifying existing rows. Revoke/disable existing accounts or clients through the approved database operations procedure.

For a client whose Access Token will call the sample resource service, include `--scope resource.read` when provisioning; the resource service still applies its client allowlist independently.

The CLI is an administrative database client, not a server mode: it starts no HTTP listener, Dubbo provider, or Nacos connection.
