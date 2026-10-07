# Resource-service consumer example

The `sso-resource-example` module demonstrates the resource-server side of the opaque-token Dubbo contract. It is separate from the OAuth client example and does not hold an RP session.

## Local development

Start the local MySQL/Redis/Nacos dependencies and the SSO server, then set the allowed OAuth client IDs and run:

```powershell
$env:SSO_RESOURCE_ALLOWED_CLIENT_IDS = "example-rp"
mvn -pl sso-resource-example -am spring-boot:run
```

Call the protected endpoint with an Access Token issued to an allowed client and containing the `resource.read` scope:

```powershell
$headers = @{ Authorization = "Bearer $env:SSO_ACCESS_TOKEN" }
Invoke-RestMethod -Uri http://localhost:8082/api/whoami -Headers $headers
```

The endpoint returns `401` for invalid/inactive/expired tokens, `403` for a client outside the allowlist or a missing `resource.read` scope, and `503` when the authorization service RPC cannot be confirmed. Responses use `Cache-Control: no-store` and never include the presented token. The root README's `example-rp` client registration includes `resource.read` for this integration.

## Production requirements

Activate exactly `prod` or `production`. Set `SSO_RESOURCE_ALLOWED_CLIENT_IDS` to an explicit comma-separated allowlist. Provide readable `SSO_DUBBO_CLIENT_CERT`, `SSO_DUBBO_CLIENT_KEY`, and `SSO_DUBBO_SERVER_CA` files. Enable Nacos RPC TLS with CA validation through `JAVA_TOOL_OPTIONS` as documented in the repository README, and configure the Nacos server to accept TLS. The resource service's HTTP ingress must use TLS and must redact the `Authorization` header from access logs. Local Compose has Nacos TLS disabled and is not a production topology.
