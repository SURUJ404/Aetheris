# ADR 0001 — Identity provider and token contract

- Status: Accepted
- Date: 2026-11-12
- Deciders: platform owner
- Related: `migration/ARCHITECTURE_GAP_ANALYSIS.md`, `proto/agentic/v1/cognitive.proto`

## Context

The platform needs authentication for end users and service-to-service calls, and
multi-tenant isolation. Rust is the authorization authority: identity claims are
input, never authority. Free-tier operation is a hard constraint, so per-connection
SaaS pricing is unacceptable while there is no revenue.

The identity provider must speak OIDC and expose:

- a discovery document (`issuer`, `jwks_uri`)
- RS256-signed access tokens
- a tenant claim suitable for mapping to the Rust tenant context
- domain/enterprise federation without per-customer billing

## Decision

Use **Keycloak**, self-hosted, as the identity provider in development and early
production.

- Single realm: `agentic-platform`
- OIDC client: `rust-control-plane` (confidential, PKCE S256, service accounts on)
- Audience: `rust-control-plane` added by an audience mapper
- Tenant claim: `tenant_id`, sourced from the declarative user profile attribute
  `tenant_id`
- Signature: RS256, validated against the realm JWKS
- Access token lifespan: 300 seconds

The control plane validates `iss`, `aud`, `exp`, `nbf`, and `alg` and reads the
tenant from a configurable claim. No vendor-specific code is allowed in
`src/auth/`.

## Consequences

Positive:

- Zero licence cost; enterprise SSO/SAML/LDAP available without per-connection fees.
- Identity data stays inside the deployment boundary.
- Standard OIDC keeps WorkOS/Auth0/Zitadel a configuration swap, not a rewrite.

Negative:

- We operate a stateful Java service: database, upgrades, backups, HA, patching.
- Keycloak's declarative user profile silently drops undeclared attributes; new
  claims require a profile update (see `deploy/keycloak/bootstrap.ps1`).
- SCIM provisioning is extension-dependent and is not part of this decision.

## Alternatives considered

| Option | Why not now |
| --- | --- |
| WorkOS | AuthKit free to 1M MAU, but SSO and Directory Sync are $125/connection/month each. Fails the free-tier constraint for B2B. |
| Auth0 | Free tier is small and enterprise federation is paid. |
| Zitadel | Viable OSS alternative; smaller ecosystem and less operational familiarity. |
| Ory | Strong primitives, more assembly required for a complete IdP. |

## Provider-agnostic contract

The control plane is configured with:

| Setting | Keycloak value (dev) |
| --- | --- |
| `OIDC_ISSUER` | `http://127.0.0.1:8080/realms/agentic-platform` |
| `OIDC_AUDIENCE` | `rust-control-plane` |
| `OIDC_JWKS_URI` | `{issuer}/protocol/openid-connect/certs` |
| `OIDC_TENANT_CLAIM` | `tenant_id` |

Switching providers means changing these four values, not the auth code. For
WorkOS the tenant claim would be `org_id`.

## Non-goals

- Roles and permissions are **not** derived from IdP claims. Rust owns the
  authorization model; IdP claims are identity input only.
- This ADR does not cover internal Rust↔Python service identity. That will use
  mTLS or short-lived signed service tokens and is a separate decision.
- Production deployment topology (TLS, external Postgres, HA) is out of scope.

## Revisit triggers

- On-prem/air-gapped requirement disappears **and** enterprise customers demand
  self-service SCIM with no ops capacity → re-evaluate WorkOS.
- More than roughly 20 tenant connections where Keycloak operational cost exceeds
  $125/connection/month.
- A compliance requirement that the IdP must be vendor-managed.
