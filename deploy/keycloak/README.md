# Keycloak — local development

Development-only Keycloak for the agentic platform. Identity decisions are
recorded in `migration/adr/0001-identity-provider.md`.

> `start-dev` uses embedded H2, no TLS, and a container-local datastore.
> Removing the container deletes the realm. This is never a production setup.

## Start

```powershell
docker run -d --name keycloak `
  -p 127.0.0.1:8080:8080 `
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin `
  -e 'KC_BOOTSTRAP_ADMIN_PASSWORD=REDACTED-IN-PUBLIC-HISTORY' `
  quay.io/keycloak/keycloak:26.8.2 start-dev
```

Admin console: <http://127.0.0.1:8080/admin/>

## Configure the realm

Idempotent. Creates the client, audience mapper, `tenant_id` claim mapper, and a
development user.

```powershell
./deploy/keycloak/bootstrap.ps1
```

Result:

| Item | Value |
| --- | --- |
| Realm | `agentic-platform` |
| Issuer | `http://127.0.0.1:8080/realms/agentic-platform` |
| Client | `rust-control-plane` (confidential, PKCE S256) |
| Audience | `rust-control-plane` |
| Tenant claim | `tenant_id` (user attribute) |
| Dev user | `dev-user` / `REDACTED-IN-PUBLIC-HISTORY` with `tenant_id=tenant-acme` |
| Redirect URIs | `http://127.0.0.1:8081/*`, `http://localhost:8081/*` |

Overrides: `-KeycloakUrl`, `-Realm`, `-ClientId`, `-ClientSecret`,
`-DevUsername`, `-DevPassword`, `-DevTenantId`. Admin credentials come from
`KC_ADMIN_USER` / `KC_ADMIN_PASSWORD` when set.

## Verify a token

```powershell
./deploy/keycloak/verify-token.ps1
```

Decodes the access token and fails unless `alg=RS256`, `aud` contains
`rust-control-plane`, and `tenant_id` matches.

## End-to-end auth and resolution check

Requires `cargo build` first, because the server runs from the workspace
`target/` directory, and the local PostgreSQL container from `compose.yaml`.

```powershell
# One-time: let Keycloak and the e2e container share the compose network.
docker network connect agentic-platform_default keycloak 2>$null

# Seed a membership whose issuer matches the name the container will use.
./scripts/seed-dev.ps1 -Issuer http://keycloak:8080/realms/agentic-platform

.\rust.ps1 cargo build --manifest-path /work/agentic-platform-structure-v1/Cargo.toml

docker run --rm --network agentic-platform_default `
  -v "${PWD}/agentic-platform-structure-v1:/work" -w /work `
  -e "KC_BASE=http://keycloak:8080" `
  python:3.12-slim python scripts/e2e_auth_smoke.py
```

The server and the client share the Docker network, so the issuer Keycloak mints
matches `OIDC_ISSUER`. The check covers 401 without a token, identity shape from
`/v1/me`, role and permission resolution from `/v1/session`, a policy decision
from `/v1/authorize`, readiness, and rejection of a tampered token. `DATABASE_URL` defaults to
`postgresql://agentic:REDACTED-IN-PUBLIC-HISTORY@postgres:5432/agentic`; override it when the
container is named differently.

Seed with the loopback issuer (`./scripts/seed-dev.ps1` with no `-Issuer`) when
running the control plane on the host instead. Principals are keyed by
`(issuer, subject)`, so the issuer must match exactly.

## Loopback caveat

`.env.example` uses `127.0.0.1:8080`, which is correct when the control plane
runs on the host. `rust.ps1` runs cargo inside a container, where `127.0.0.1` is
the container, not your machine. Keycloak also mints `iss` from the request
host, so issuer, JWKS URI and token requests must all use the same name.

Two supported options:

1. **Run the server on the host** (production-style) and keep the
   `.env.example` loopback values.
2. **Run server and client in containers on Keycloak's network**, using
   Keycloak's container IP for both issuance and verification. This is what
   `scripts/e2e_auth_smoke.py` does automatically.

Avoid mixing names (for example, fetching a token via `127.0.0.1` while
configuring `host.docker.internal`); the `iss` check will reject it.

## Why 8081

Keycloak owns `127.0.0.1:8080`. The control plane binds `BIND_ADDR`, default
`127.0.0.1:8081`, so both can run locally. Session cookies and redirect URIs are
localhost-scoped, so changing ports later means updating the client redirect URIs.

## Gotchas

- **Declarative user profile:** Keycloak 24+ silently discards attributes that are
  not declared in the realm user profile. `tenant_id` is declared by the bootstrap
  script; a new claim needs the same treatment.
- **Token audience:** without the audience mapper, `aud` is only `account` and the
  control plane will reject the token.
- **Direct access grants:** enabled for local tests only. Disable it in any shared
  environment and use the authorization code flow with PKCE.
- **Secrets:** the client secret here is a throwaway dev value. Production must
  inject it from a secret manager.

## Reset

```powershell
docker rm -f keycloak
# then start again and re-run bootstrap.ps1
```

## Not covered yet

- External Postgres and a persistent volume
- TLS and a non-localhost hostname
- Realm export/import for reproducible environments
- SCIM provisioning
