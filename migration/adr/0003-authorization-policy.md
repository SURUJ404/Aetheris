# ADR 0003 — Deny-by-default RBAC in-process; no external policy engine yet

Status: accepted
Date: 2026-11-13

## Context

ADR 0002 moved roles and permissions into PostgreSQL. The next decision is how a
request becomes an allow or deny: which engine evaluates the rules, where it
runs, and how much context it sees.

The platform must be able to state, for every privileged action, why it was
allowed or denied. That record must be deterministic and reproducible from the
request identity, the membership data, and the action.

## Decision

Use a small in-process policy engine (`src/policy/`) with deny-by-default RBAC.

- **Actions are a closed vocabulary.** Callers name an action (`tool.invoke`);
  unknown actions are rejected as a client error, not evaluated as denials.
- **Each action maps to exactly one required permission** (`tool:invoke`).
  Permissions are an enum so unseeded strings cannot enter the code path.
- **Allow requires an exact permission grant** from the resolved membership
  role. There are no wildcards, implicit roles, or token-claim fallbacks.
- **Anything else is a deny.** The decision also cross-checks that the resolved
  membership tenant equals the token tenant, as defense in depth.
- **The engine has no I/O and no cache.** It reads the permissions already
  resolved for the request, so a suspended membership cannot keep working from
  stale state.
- **Decisions are advisory to clients.** `/v1/authorize` lets a UI or the Python
  planner ask whether an action is available, but the broker must re-evaluate
  the same engine at dispatch time. A prior allow is not an execution token.

## Consequences

- The decision path is auditable by construction: action, required permission,
  granted role, and denial reason are explicit values.
- Policy changes ship with code and migrations, which keeps review and rollback
  simple at this stage. Membership changes still take effect immediately.
- Resource-scoped rules (for example "this member may invoke only tools in
  project X") are not expressible yet. Adding them will extend the request
  context, not loosen the default.
- The service must not duplicate this logic in Python. Python may predict the
  decision for planning, but only Rust's evaluation is authoritative.

## Alternatives rejected

- **OPA / Cedar now.** A separate policy service or language adds deployment,
  latency, and a second source of truth before there is policy complexity to
  justify it. The engine's call site is isolated so it can be replaced later.
- **Wildcard permissions.** Makes least-privilege review and audit harder, and
  hides which concrete capability was granted.
- **Allow-list in configuration files.** Cannot be tenant-scoped or changed
  without a deploy.

## Follow-ups

1. Resource-scoped authorization (project/tool/resource identifiers).
2. Budget and rate checks before the broker dispatches.
3. Approval binding for high-risk actions.
4. Persist authorization decisions to the audit trail.
