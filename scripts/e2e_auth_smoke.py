"""End-to-end smoke test for the auth slice.

Runs inside a container on the same Docker network as Keycloak. Starts the
compiled control plane, obtains a real token, and exercises /v1/me.

Environment:
    KC_BASE  Base URL of Keycloak as seen from this container.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC_BASE = os.environ["KC_BASE"].rstrip("/")
ISSUER = f"{KC_BASE}/realms/agentic-platform"
JWKS = f"{ISSUER}/protocol/openid-connect/certs"
BASE = "http://127.0.0.1:8081"

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"{status} {name}{(': ' + detail) if detail and not condition else ''}")
    if not condition:
        failures.append(name)


def wait_for_health(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE}/health/live", timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.5)
    raise SystemExit("control plane did not become healthy")


def fetch_token() -> str:
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "rust-control-plane",
            "client_secret": "REDACTED-IN-PUBLIC-HISTORY",
            "username": "dev-user",
            "password": "REDACTED-IN-PUBLIC-HISTORY",
            "scope": "openid",
        }
    ).encode()
    request = urllib.request.Request(
        f"{ISSUER}/protocol/openid-connect/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)["access_token"]


def get_me(token: str | None) -> tuple[int, dict | None, dict]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(f"{BASE}/v1/me", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.load(response), dict(response.headers)
    except urllib.error.HTTPError as error:
        body = error.read()
        return error.code, json.loads(body) if body else None, dict(error.headers)


env = dict(
    os.environ,
    BIND_ADDR="127.0.0.1:8081",
    OIDC_ISSUER=ISSUER,
    OIDC_AUDIENCE="rust-control-plane",
    OIDC_JWKS_URI=JWKS,
    OIDC_TENANT_CLAIM="tenant_id",
    RUST_LOG="warn",
)

server = subprocess.Popen(["./target/debug/rust-control-plane"], env=env)
try:
    wait_for_health()

    status, body, _ = get_me(None)
    check("unauthenticated request is 401", status == 401, f"got {status}")
    check(
        "unauthenticated response carries a challenge",
        "www-authenticate" in {key.lower() for key in _},
    )

    token = fetch_token()
    status, principal, headers = get_me(token)
    check("authenticated request is 200", status == 200, f"got {status}")

    principal = principal or {}
    check("tenant comes from the token claim", principal.get("tenant_id") == "tenant-acme",
          str(principal.get("tenant_id")))
    check("subject is present", bool(principal.get("subject")))
    check("issuer is preserved", principal.get("issuer") == ISSUER, str(principal.get("issuer")))
    check(
        "audience includes the control plane",
        "rust-control-plane" in principal.get("audiences", []),
        str(principal.get("audiences")),
    )
    check("scopes are split", "openid" in principal.get("scopes", []),
          str(principal.get("scopes")))

    # A syntactically valid token with a broken signature must be rejected.
    header, payload, _ = token.split(".")
    forged = f"{header}.{payload}.{'A' * 342}"
    status, body, _ = get_me(forged)
    check("tampered token is 401", status == 401, f"got {status}")
finally:
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()

if failures:
    print(f"\n{len(failures)} check(s) failed: {', '.join(failures)}")
    sys.exit(1)

print("\nAll end-to-end checks passed.")
