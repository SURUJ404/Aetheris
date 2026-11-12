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
