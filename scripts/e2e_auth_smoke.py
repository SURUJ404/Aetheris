"""End-to-end smoke test for the identity and principal-resolution slice.

Runs inside a container on the same Docker network as Keycloak and PostgreSQL.
Starts the compiled control plane, obtains a real token, and exercises
/v1/me, /v1/session, /v1/authorize and /health/ready.

Environment:
    KC_BASE           Base URL of Keycloak as seen from this container.
    DATABASE_URL      PostgreSQL URL as seen from this container.
    KC_CLIENT_SECRET  Throwaway client secret for the local dev realm.
    KC_DEV_USERNAME   Local dev username.
    KC_DEV_PASSWORD   Password for KC_DEV_USERNAME.

All URLs are operator-supplied loopback or Docker service names; no untrusted
input reaches urllib. The ``nosemgrep`` annotations below document that review.

Prerequisite: seed a membership with an issuer that matches KC_BASE, e.g.
    ./scripts/seed-dev.ps1 -KeycloakUrl http://keycloak:8080 `
        -Issuer http://keycloak:8080/realms/agentic-platform
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
DATABASE_URL = os.environ["DATABASE_URL"]
KC_CLIENT_SECRET = os.environ["KC_CLIENT_SECRET"]
KC_DEV_USERNAME = os.environ["KC_DEV_USERNAME"]
KC_DEV_PASSWORD = os.environ["KC_DEV_PASSWORD"]

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"{status} {name}{(': ' + detail) if detail and not condition else ''}")
    if not condition:
        failures.append(name)


def wait_for_ready(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE}/health/ready", timeout=1) as response:  # nosemgrep
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.5)
    raise SystemExit("control plane did not become ready (is PostgreSQL seeded and reachable?)")


def fetch_token() -> str:
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "rust-control-plane",
            "client_secret": KC_CLIENT_SECRET,
            "username": KC_DEV_USERNAME,
            "password": KC_DEV_PASSWORD,
            "scope": "openid",
        }
    ).encode()
    request = urllib.request.Request(
        f"{ISSUER}/protocol/openid-connect/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:  # nosemgrep
        return json.load(response)["access_token"]


def get_json(path: str, token: str | None) -> tuple[int, dict | None, dict]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(f"{BASE}{path}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosemgrep
            return response.status, json.load(response), dict(response.headers)
    except urllib.error.HTTPError as error:
        body = error.read()
        return error.code, json.loads(body) if body else None, dict(error.headers)


def post_json(path: str, token: str | None, payload: dict) -> tuple[int, dict | None, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosemgrep
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
    DATABASE_URL=DATABASE_URL,
    DATABASE_MIGRATE="true",
    # The binary runs with /work as its cwd. The approved workload registry lives
    # inside the Rust crate, not at the repository root. An absolute path keeps
    # startup independent of the caller's working directory.
    EXECUTION_WORKLOAD_DIR="/work/services/rust-control-plane/workloads",
    RUST_LOG="warn",
)

server = subprocess.Popen(["./target/debug/rust-control-plane"], env=env)
try:
    wait_for_ready()

    status, body, headers = get_json("/v1/me", None)
    check("unauthenticated /v1/me is 401", status == 401, f"got {status}")
    check(
        "unauthenticated response carries a challenge",
        "www-authenticate" in {key.lower() for key in headers},
    )
    check("unauthenticated /v1/session is 401", get_json("/v1/session", None)[0] == 401)

    token = fetch_token()

    status, identity, _ = get_json("/v1/me", token)
    check("authenticated /v1/me is 200", status == 200, f"got {status}")
    identity = identity or {}
    check("subject is present", bool(identity.get("subject")))
    check("issuer is preserved", identity.get("issuer") == ISSUER, str(identity.get("issuer")))
    check(
        "audience includes the control plane",
        "rust-control-plane" in identity.get("audiences", []),
        str(identity.get("audiences")),
    )
    check("scopes are split", "openid" in identity.get("scopes", []), str(identity.get("scopes")))
    check(
        "tenant is not part of the identity response",
        "tenant_id" not in identity,
        str(identity.get("tenant_id")),
    )

    status, session, _ = get_json("/v1/session", token)
    check("authenticated /v1/session is 200", status == 200, f"got {status}")
    session = session or {}
    check("tenant comes from resolved membership", session.get("tenant_id") == "tenant-acme",
          str(session.get("tenant_id")))
    check("role comes from PostgreSQL", session.get("role") == "owner", str(session.get("role")))
    check(
        "permissions come from the role",
        "tool:invoke" in session.get("permissions", []),
        str(session.get("permissions")),
    )
    check("principal id is a UUID", len(str(session.get("principal_id", ""))) == 36)

    check(
        "unauthenticated /v1/authorize is 401",
        post_json("/v1/authorize", None, {"action": "tool.invoke"})[0] == 401,
    )

    status, decision, _ = post_json("/v1/authorize", token, {"action": "tool.invoke"})
    check("allowed action is 200", status == 200, f"got {status}")
    decision = decision or {}
    check("allowed action reports the grant", decision.get("allowed") is True, str(decision))
    check(
        "decision names the required permission",
        decision.get("permission") == "tool:invoke",
        str(decision.get("permission")),
    )

    status, body, _ = post_json("/v1/authorize", token, {"action": "tool.delete"})
    check("unknown action is 400", status == 400, f"got {status}")
    check(
        "unknown action is not a policy denial",
        (body or {}).get("error") == "unsupported_action",
        str((body or {}).get("error")),
    )

    # A syntactically valid token with a broken signature must be rejected.
    header, payload, _ = token.split(".")
    forged = f"{header}.{payload}.{'A' * 342}"
    check("tampered token is 401", get_json("/v1/me", forged)[0] == 401)
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
