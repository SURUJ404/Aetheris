# ADR 0002 — Authorization state lives in PostgreSQL, not in IdP claims

Status: accepted
Date: 2026-11-12

## Context

ADR 0001 established Keycloak as the identity provider and restricted Rust to
reading `sub`, `iss`, `aud`, and `tenant_id` from validated access tokens. The
next question is where roles and permissions come from.

Options considered:

1. **Roles in the IdP token.** Keycloak could mint `realm_access.roles` or a
   custom `roles` claim, and Rust could trust it.
2. **Roles in an in-process configuration file.** Fast, but changes require a
   deploy and cannot be scoped per tenant.
3. **Memberships and permissions in PostgreSQL.** Rust is the only reader and
   writer; the IdP only proves identity.

## Decision

Authorization state lives in PostgreSQL and is owned exclusively by the Rust
control plane.

- A `principal` is the pair `(issuer, subject)` from a validated token. The
  internal UUID is stable across sessions, provider subject reuse, and renaming.
- A `membership` attaches a principal to a tenant with exactly one role and a
  status (`active` / `suspended`).
- A `role_permissions` table maps each role to its permissions. Permissions are
  the atomic unit policy evaluation will consume (`tool:invoke`,
  `tool:approve`, `task:write`, ...).
- Resolution requires an active membership in an active tenant. Anything else
  is a denial, never an anonymous or downgraded principal.
- Claims never carry roles. Adding a role to a token must not grant access
  unless the corresponding membership exists in PostgreSQL.

## Consequences

- Compromising the IdP or a token mapper cannot escalate privileges in this
  platform; it can only impersonate an existing identity.
- Tenant isolation is enforced by the `(tenant_id, principal_id)` membership key
  and by resolving only the tenant carried in the validated token.
- Role changes take effect on the next request without token reissuance.
- The control plane now has a hard dependency on PostgreSQL. Startup fails if it
  cannot connect, and `/health/ready` returns 503 if it cannot be probed.
- Membership administration, invitations, and audit writes are not implemented
  yet. Until they exist, rows are seeded by `scripts/seed-dev.ps1`.
- Per-resource and per-action policy rules are a later slice; this ADR only
  fixes the data model and resolution semantics.

## Alternatives rejected

- **IdP roles**: couples authorization to provider configuration, makes tenant
  scoping awkward, and lets any client with mapper rights grant permissions.
- **Redis as source of truth**: violates the invariant that Redis is ephemeral.
- **Config file**: cannot support per-tenant membership or runtime updates.

## Follow-ups

1. Policy evaluation over permissions and resource context.
2. Tenant-scoped membership management endpoints with audit records.
3. Approval records bound to action, arguments, tenant, actor, expiry and nonce.
