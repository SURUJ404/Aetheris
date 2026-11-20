# Release and repository settings checklist

This file lists the **manual** GitHub actions that cannot be expressed in the
repository. Complete each item before making the repository public or issuing
a release. Nothing in this file performs a push, history rewrite, or visibility
change.

## 1. Repository visibility and branch protection

- [ ] Review the full tree for internal material. `docs/QA_STEPS_1_TO_4.md`,
      `migration/ARCHITECTURE_GAP_ANALYSIS.md`, `migration/PHASE_*.md`,
      `migration/REPOSITORY_MAP.md`, and `.opencode/skills/` are intentionally
      excluded and listed in `.gitignore`.
- [ ] Settings → Branches → Branch protection rules for the default branch:
  - [ ] Require a pull request before merging (at least 1 approval).
  - [ ] Dismiss stale approvals when new commits are pushed.
  - [ ] Require review from Code Owners.
  - [ ] Require status checks to pass: `lint-and-test`, `dependency-and-secret-scan`.
  - [ ] Require branches to be up to date before merging.
  - [ ] Do not allow bypassing the above settings.
- [ ] Settings → Environments → create `ci` with no protection rules, and
      `first-time-contributors` with at least one required reviewer. PRs from
      first-time contributors are held at the protected environment; all other
      runs use `ci`.
- [ ] Settings → Actions → General → Workflow permissions: choose
      **Read repository contents and packages permissions** as the default.
- [ ] Settings → Actions → General → Fork pull request workflows: do not send
      secrets to workflows from forks. The workflows use only `GITHUB_TOKEN`
      on tag pushes.

## 2. Security features

- [ ] Settings → Code security and analysis: enable Dependency graph.
- [ ] Enable Dependabot alerts and Dependabot security updates.
- [ ] Enable Secret scanning and **Push protection**.
- [ ] Enable Private vulnerability reporting (used by `SECURITY.md`).
- [ ] Confirm `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`,
      `LICENSE`, and `.github/CODEOWNERS` are present in the public tree.

## 3. Pre-release verification

Run locally (on this Windows host, Rust commands must go through `rust.ps1`
because Smart App Control blocks unsigned binaries):

```powershell
..\rust.ps1 cargo fmt --all -- --check
..\rust.ps1 --% cargo clippy --all --workspace --all-targets -- -D warnings
..\rust.ps1 cargo test --all-targets
..\rust.ps1 cargo audit
..\rust.ps1 cargo build --release
```

Confirm:

- [ ] `cargo audit` reports zero vulnerabilities (the unmaintained `chrono`
      advisory with no fixed release is an acknowledged warning).
- [ ] Python `ruff check .` and `pytest -q` pass in
      `services/python-cognitive`.
- [ ] `mypy app tests` is **not** currently clean; if you choose to gate on it,
      fix the outstanding type errors first.
- [ ] `docker compose config --quiet` passes with a local `.env` in place.
- [ ] Release binary contains no embedded dev credentials or internal IPs.

## 4. Tagging and release workflow

- [ ] Create and sign an annotated tag locally, e.g. `git tag -s v0.1.0 -m "v0.1.0"`.
- [ ] Push only that tag after the tag is signed and CI is green.
- [ ] The `release.yml` workflow produces:
  - the release binary;
  - `sbom.spdx.json` (Syft);
  - `provenance.json` (SLSA-style predicate);
  - `*.sig` (cosign keyless signature);
  - `*.attestation` (cosign SLSA provenance attestation).
- [ ] Verify the signature and attestation with cosign before publishing the
      release notes.
- [ ] Confirm the release contains no internal QA/phase-report documents or
      generated tool skills.

## 5. History purge reminder (Phase 3)

This checklist does **not** rewrite history. Before any purge:

1. Make a backup mirror clone outside the repository:
   `git clone --mirror <repo> <backup-path>`.
2. Show the exact `git-filter-repo`/BFG command and affected paths/strings.
3. Obtain explicit written approval.
4. Run on a fresh clone, rescan full history, and rotate/revoke any credential
   that was ever committed, even if the commit is removed.

## 6. Known limitations at release time

- Firecracker requires KVM, a firecracker binary, kernel image, and guest-agent
  rootfs; it fails closed when absent.
- Python `Plan` is still `NotImplementedError`; orchestration wiring remains
  future work.
- RLS, Redis/NATS/object storage, signed URLs, artifact lifecycle, live OIDC
  rotation testing, production TLS, durable Keycloak DB, and service
  Dockerfiles remain out of scope for this release.
- No smart contracts exist in this repository; Slither/Foundry checks are N/A.
