# Security Policy

## Supported versions

This project is an early-stage reference implementation. Security fixes are
applied to the latest published release and the default branch only.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Earlier releases | No |
| Default branch | Yes (best effort) |

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). If that is unavailable, contact the
maintainer privately through the contact information on their GitHub profile.

Include:

- affected version or commit;
- reproduction steps or a minimal proof of concept;
- impact and any suggested mitigation;
- whether the issue is already known publicly.

You should receive an acknowledgement within 7 days. We will work with you on
a fix and coordinated disclosure. Please allow at least 90 days before public
disclosure.

## Scope notes

- The sandbox boundary is enforced in the Rust control plane. Only the broker
  is an entry point to execution; adding a sibling container with a Docker
  socket mount is explicitly out of scope and voids the isolation model.
- The local Keycloak setup in `deploy/keycloak/` is development-only. It must
  never be exposed outside localhost.
- This project does not include smart contracts; blockchain contract auditing
  is not applicable.
