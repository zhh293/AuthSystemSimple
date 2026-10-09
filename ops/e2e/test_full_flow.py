import base64
import concurrent.futures
import hashlib
import json
import os
import re
import secrets
import time
import warnings

import pymysql
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SSO_URL = os.environ.get("E2E_SSO_URL", "http://localhost:28080")
RP_URL = os.environ.get("E2E_RP_URL", "http://localhost:28082")
RESOURCE_URL = os.environ.get("E2E_RESOURCE_URL", "http://localhost:28083")
NACOS_HEALTH_URL = os.environ.get(
    "E2E_NACOS_HEALTH_URL",
    "http://101.201.153.254:8848/nacos/v1/console/health/readiness",
)
CLIENT_ID = "e2e-portal"
CLIENT_SECRET = "e2e-only-client-secret"
USERNAME = "e2e.user"
PASSWORD = "E2E-only-password-2026!"
SUBJECT = "e2e-subject-001"
CALLBACK = RP_URL + "/sso/callback"
TIMEOUT = (3, 20)
PASSWORD_HASH = "$argon2id$v=19$m=16384,t=2,p=1$yHnhrQLVUUMR0E/QLLzMfA$nN2+lua/qR8pv6CAaOTZXM4Dmsut1LN6+GZ3q3ZpQkQ"
CLIENT_SECRET_HASH = "{bcrypt}$2b$10$i0x91zn1XMTQmKQyc0ZgMuJmzUBD9f0aHa7kLURv7PvANZ5zofpIC"


def database():
    return pymysql.connect(
        host=os.environ.get("E2E_MYSQL_HOST", "127.0.0.1"),
        port=int(os.environ.get("E2E_MYSQL_PORT", "23306")),
        user=os.environ.get("E2E_SSO_DB_USER", "sso"),
        password=os.environ.get("E2E_SSO_DB_PASSWORD", "e2e-db-password"),
        database=os.environ.get("E2E_SSO_DB", "sso"),
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=3,
    )


def b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unb64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def wait_for(url, expected_status, timeout=180, request_timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    last_status = None
    while time.monotonic() < deadline:
        try:
            response = requests.get(url, timeout=request_timeout, allow_redirects=False)
            last_status = response.status_code
            if last_status == expected_status:
                return response
        except requests.RequestException:
            pass
        time.sleep(2)
    raise AssertionError(f"Service did not reach expected HTTP {expected_status}; last status={last_status}")


def wait_for_migrations(timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with database() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) AS n, MIN(version) AS vmin, MAX(version) AS vmax, "
                    "SUM(success) AS ok FROM flyway_schema_history"
                )
                state = cursor.fetchone()
                if state and state["n"] == 7 and state["vmin"] == "1" and state["vmax"] == "7" and state["ok"] == 7:
                    return
        except Exception:
            pass
        time.sleep(2)
    raise AssertionError("Test database did not reach Flyway version 7")


def provision_test_principal():
    with database() as connection, connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO sso_user
                   (subject_id, username_normalized, password_hash, enabled, display_name, email, email_verified)
               VALUES (%s, %s, %s, TRUE, %s, %s, TRUE)
               ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), enabled=TRUE,
                   display_name=VALUES(display_name), email=VALUES(email), email_verified=TRUE""",
            (SUBJECT, USERNAME, PASSWORD_HASH, "E2E Test User", "e2e.user@example.test"),
        )
        cursor.execute(
            """INSERT INTO oauth_client (client_id, display_name, client_type, enabled, client_secret_hash)
               VALUES (%s, %s, 'CONFIDENTIAL', TRUE, %s)
               ON DUPLICATE KEY UPDATE enabled=TRUE, client_secret_hash=VALUES(client_secret_hash)""",
            (CLIENT_ID, "E2E SDK Client", CLIENT_SECRET_HASH),
        )
        cursor.execute(
            """INSERT INTO oauth_client_redirect_uri (client_id, redirect_uri) VALUES (%s, %s)
               ON DUPLICATE KEY UPDATE redirect_uri=VALUES(redirect_uri)""",
            (CLIENT_ID, CALLBACK),
        )
        for scope in ("openid", "profile", "email", "resource.read"):
            cursor.execute(
                """INSERT INTO oauth_client_scope (client_id, scope_name) VALUES (%s, %s)
                   ON DUPLICATE KEY UPDATE scope_name=VALUES(scope_name)""",
                (CLIENT_ID, scope),
            )


def wait_for_stack_and_seed():
    wait_for_migrations()
    try:
        nacos_health = requests.get(NACOS_HEALTH_URL, timeout=(2, 5))
        if nacos_health.status_code != 200 or nacos_health.text.strip() != "OK":
            raise AssertionError("Nacos health endpoint did not report ready")
    except (requests.RequestException, AssertionError):
        warnings.warn(
            "Nacos HTTP health is unavailable; continuing only if the resource service can invoke Dubbo",
            RuntimeWarning,
        )
    discovery = wait_for(SSO_URL + "/.well-known/openid-configuration", 200).json()
    assert discovery["issuer"] == SSO_URL
    assert discovery["jwks_uri"].startswith(SSO_URL + "/")
    wait_for(RP_URL + "/", 200)
    wait_for(RESOURCE_URL + "/api/whoami", 401)
    provision_test_principal()
    deadline = time.monotonic() + 60
    rpc_status = None
    while time.monotonic() < deadline:
        try:
            response = requests.get(
                RESOURCE_URL + "/api/whoami",
                headers={"Authorization": "Bearer invalid-e2e-probe"},
                timeout=TIMEOUT,
            )
            rpc_status = response.status_code
            if rpc_status == 401:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise AssertionError(f"Dubbo introspection provider did not become available; HTTP status={rpc_status}")


def simulate_frontend_encryption(session, csrf_token, username, password):
    crypto_session = session.get(SSO_URL + "/login/crypto/session", timeout=TIMEOUT)
    assert crypto_session.status_code == 200
    server = crypto_session.json()
    server_jwk = server["serverPublicKey"]
    server_public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(unb64url(server_jwk["x"]), "big"),
        int.from_bytes(unb64url(server_jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    client_private = ec.generate_private_key(ec.SECP256R1())
    numbers = client_private.public_key().public_numbers()
    client_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(numbers.x.to_bytes(32, "big")),
        "y": b64url(numbers.y.to_bytes(32, "big")),
    }
    shared_secret = client_private.exchange(ec.ECDH(), server_public)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(("sso-login-v1|" + server["sessionId"]).encode()).digest(),
        info=("sso-login-aes-256-gcm|" + server["keyId"]).encode(),
    ).derive(shared_secret)
    timestamp = int(time.time())
    request_id = b64url(secrets.token_bytes(16))
    nonce = secrets.token_bytes(12)
    canonical_jwk = ":".join((client_jwk["crv"], client_jwk["kty"], client_jwk["x"], client_jwk["y"]))
    aad = (
        f"v1|{server['sessionId']}|{server['keyId']}|{request_id}|{timestamp}|{canonical_jwk}"
    ).encode()
    plaintext = json.dumps({"username": username, "password": password}, separators=(",", ":")).encode()
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    encrypted = {
        "version": "v1",
        "sessionId": server["sessionId"],
        "keyId": server["keyId"],
        "clientPublicKey": client_jwk,
        "requestId": request_id,
        "timestamp": timestamp,
        "nonce": b64url(nonce),
        "ciphertext": b64url(ciphertext_and_tag[:-16]),
        "tag": b64url(ciphertext_and_tag[-16:]),
    }
    encoded_body = json.dumps(encrypted, separators=(",", ":"))
    assert username not in encoded_body and password not in encoded_body
    response = session.post(
        SSO_URL + "/login/submit",
        data=encoded_body,
        headers={"Content-Type": "application/json", "X-CSRF-TOKEN": csrf_token},
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    submit_response = next((r for r in response.history if r.request.url.endswith("/login/submit")), None)
    assert submit_response is not None
    assert submit_response.headers.get("Cache-Control", "").lower().find("no-store") >= 0
    assert response.status_code == 200, "simulated frontend login callback failed"
    return response


def start_authorization(session):
    response = session.get(RP_URL + "/profile", timeout=TIMEOUT, allow_redirects=True)
    assert response.status_code == 200
    assert response.url.startswith(SSO_URL + "/login"), response.url
    assert any(cookie.name.startswith(CLIENT_ID + "_sso_tx_") for cookie in session.cookies), (
        "RP did not retain its browser transaction cookie"
    )
    csrf = re.search(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]+)"', response.text)
    assert csrf, "SSO login form CSRF field was not rendered"
    return csrf.group(2)


def refresh_state():
    with database() as connection, connection.cursor() as cursor:
        cursor.execute(
            """SELECT COUNT(*) AS tokens FROM oauth_refresh_token_history h
               JOIN oauth_refresh_token_family f ON f.family_id = h.family_id
               WHERE f.subject_id = %s AND f.client_id = %s""",
            (SUBJECT, CLIENT_ID),
        )
        token_count = cursor.fetchone()["tokens"]
        cursor.execute(
            "SELECT COUNT(*) AS revoked FROM oauth_refresh_token_family "
            "WHERE subject_id=%s AND client_id=%s AND revoked=TRUE",
            (SUBJECT, CLIENT_ID),
        )
        revoked = cursor.fetchone()["revoked"]
        return token_count, revoked


def clone_client_session(source):
    clone = requests.Session()
    clone.headers.update(source.headers)
    for cookie in source.cookies:
        clone.cookies.set_cookie(cookie)
    return clone


def test_wrong_password_is_rejected_without_sdk_session():
    wait_for_stack_and_seed()
    session = requests.Session()
    csrf = start_authorization(session)
    response = simulate_frontend_encryption(session, csrf, USERNAME, "incorrect-test-password")
    assert response.url.startswith(SSO_URL + "/login?error=true")
    assert "incorrect-test-password" not in response.text
    assert not any(cookie.name == CLIENT_ID + "_access_token" for cookie in session.cookies)


def test_simulated_frontend_pkce_resource_dubbo_refresh_and_csrf_logout():
    wait_for_stack_and_seed()
    client = requests.Session()
    csrf = start_authorization(client)
    profile = simulate_frontend_encryption(client, csrf, USERNAME, PASSWORD)
    assert profile.url == RP_URL + "/profile"
    principal = profile.json()
    assert principal["subject"] == SUBJECT
    assert principal["name"] == "E2E Test User"
    assert principal["email"] == "e2e.user@example.test"

    status = client.get(RP_URL + "/sso/status", timeout=TIMEOUT)
    assert status.status_code == 200 and status.json()["authenticated"] is True
    access_cookie = next((cookie for cookie in client.cookies if cookie.name == CLIENT_ID + "_access_token"), None)
    assert access_cookie is not None and access_cookie.value
    assert "HttpOnly" in access_cookie._rest
    assert not any("refresh" in cookie.name.lower() or "id_token" in cookie.name.lower()
                   for cookie in client.cookies)
    first_access_token = access_cookie.value

    resource = requests.Session()
    assert resource.get(RESOURCE_URL + "/api/whoami", timeout=TIMEOUT).status_code == 401
    result = resource.get(
        RESOURCE_URL + "/api/whoami",
        headers={"Authorization": "Bearer " + first_access_token},
        timeout=TIMEOUT,
    )
    assert result.status_code == 200, result.text
    assert result.headers.get("Cache-Control", "").lower().find("no-store") >= 0
    assert result.json()["subject"] == SUBJECT
    assert result.json()["client_id"] == CLIENT_ID
    assert "resource.read" in result.json()["scopes"]

    token_exp = result.json()["expires_at"]
    # expires_at is integer-second precision; enter the SDK's five-second refresh window safely.
    time.sleep(max(0, token_exp - time.time() - 3))
    request_sessions = [clone_client_session(client) for _ in range(5)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        responses = list(pool.map(lambda s: s.get(RP_URL + "/profile", timeout=TIMEOUT), request_sessions))
    assert all(response.status_code == 200 and response.json()["subject"] == SUBJECT for response in responses)
    for session in request_sessions:
        for cookie in session.cookies:
            if cookie.name == CLIENT_ID + "_access_token":
                client.cookies.set_cookie(cookie)
    second_access_cookie = next(cookie for cookie in client.cookies if cookie.name == CLIENT_ID + "_access_token")
    second_access_token = second_access_cookie.value
    assert second_access_token and second_access_token != first_access_token
    token_count, _ = refresh_state()
    assert token_count >= 2

    refreshed = resource.get(
        RESOURCE_URL + "/api/whoami",
        headers={"Authorization": "Bearer " + second_access_token},
        timeout=TIMEOUT,
    )
    assert refreshed.status_code == 200, refreshed.text

    logout_form = client.get(RP_URL + "/logout-form", timeout=TIMEOUT)
    csrf_field = re.search(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]+)"', logout_form.text)
    assert csrf_field and logout_form.status_code == 200
    missing_csrf = client.post(
        RP_URL + "/sso/logout",
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    assert missing_csrf.status_code == 403
    logout = client.post(
        RP_URL + "/sso/logout",
        data={csrf_field.group(1): csrf_field.group(2)},
        headers={"X-CSRF-TOKEN": csrf_field.group(2)},
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    assert logout.status_code == 204
    assert not any(cookie.name == CLIENT_ID + "_access_token" and cookie.value for cookie in client.cookies)
    _, revoked_count = refresh_state()
    assert revoked_count >= 1
    revoked = resource.get(
        RESOURCE_URL + "/api/whoami",
        headers={"Authorization": "Bearer " + second_access_token},
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 401
