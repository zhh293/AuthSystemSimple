#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

task_compose_project="sso-e2e-$(date +%s)-$$"
export SSO_E2E_NACOS_GROUP="SSO_E2E_$(date +%Y%m%d%H%M%S)_$$"
task_maven_repository="${MAVEN_REPO:-$repo_root/.maven-cache/repository}"
mkdir -p "$task_maven_repository" ops/e2e/artifacts
compose=(docker compose --project-name "$task_compose_project" -f ops/e2e/compose.yaml)

cleanup() {
    status=$?
    set +e
    "${compose[@]}" logs --no-color sso-server rp resource mysql redis oidc-keygen \
        > ops/e2e/artifacts/compose.log 2>&1
    "${compose[@]}" down --volumes --remove-orphans --rmi local
    exit "$status"
}
trap cleanup EXIT

docker run --rm \
    -v "$repo_root:/workspace" \
    -v "$task_maven_repository:/root/.m2/repository" \
    -w /workspace \
    maven:3.9.9-eclipse-temurin-17 \
    mvn -B -pl sso-server,sso-example-rp,sso-resource-example -am verify

"${compose[@]}" up -d --build --wait --wait-timeout 180 mysql redis
"${compose[@]}" up -d --build sso-server
python3 - <<'PY'
import time
import urllib.request

url = "http://127.0.0.1:28080/.well-known/openid-configuration"
deadline = time.monotonic() + 180
while time.monotonic() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            if response.status == 200:
                break
    except Exception:
        time.sleep(2)
else:
    raise SystemExit("SSO server did not become ready before starting relying parties")
PY
"${compose[@]}" up -d --build --wait --wait-timeout 180 rp resource
python3 -m pytest -q --junitxml=ops/e2e/artifacts/junit.xml ops/e2e/test_full_flow.py
