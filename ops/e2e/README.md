# Isolated SSO integration test stack

Install Python dependencies and run from a Linux host with Docker Engine and Docker Compose v2:

```bash
python3 -m pip install -r ops/e2e/requirements.txt
bash ops/e2e/run-e2e.sh
```

The runner first executes Maven unit suites for the server, SDK, and resource service. It then creates a unique Compose project with disposable MySQL, Redis, SSO, SDK relying-party, resource-service, and Python test-runner containers. The stack uses the external Nacos registry at `101.201.153.254:8848` and registers test-only Dubbo services under a unique `SSO_E2E_*` group in the `public` namespace. The registry's HTTP readiness endpoint and the actual Dubbo calls are both checked. Test ports bind to loopback; the RP and Python runner use Linux host networking so the SDK sees the required localhost issuer and callback. The script removes its containers, networks, and local volumes on success or failure. Test reports and service logs remain in `ops/e2e/artifacts/`.

The Python HTTP client simulates the browser and WebCrypto login request, follows the authorization-code + PKCE redirects through the SDK callback, verifies the principal and HttpOnly access cookie, tests resource introspection over Dubbo, races protected requests across refresh rotation, and submits the CSRF-protected logout form. It also checks that a wrong password never creates an RP session. No real browser is downloaded or launched.

All accounts, credentials, keys, and tokens in this stack are test-only. It does not connect to the production SSO database or Redis. Nacos settings can be overridden with `SSO_E2E_NACOS_ADDRESS`, `SSO_E2E_NACOS_NAMESPACE`, `SSO_E2E_NACOS_GROUP`, `SSO_E2E_NACOS_USERNAME`, and `SSO_E2E_NACOS_PASSWORD`. The disposable database/cache images can be selected with `SSO_E2E_MYSQL_IMAGE` and `SSO_E2E_REDIS_IMAGE` when the corresponding tags are already available on the host.
