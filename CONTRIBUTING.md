# Contributing

Thanks for your interest in improving this project.

## Ground rules

- Do not open a public issue for security vulnerabilities. See `SECURITY.md`.
- Do not include real credentials, internal hostnames, private IP addresses,
  or internal-only documents in issues, pull requests, or commits.
- Keep changes scoped. Do not weaken authentication, authorization, tenant
  isolation, or the sandbox boundary in order to make a test pass.
- Do not add obfuscators, packers, or anti-debugging. The source is public by
  design; release hardening only covers stripping and compiler options.

## Development environment

Rust commands must run inside the provided container wrapper because unsigned
Windows binaries are blocked by Smart App Control:

```powershell
..\rust.ps1 cargo fmt --all -- --check
..\rust.ps1 --% cargo clippy --all --workspace --all-targets -- -D warnings
..\rust.ps1 cargo test --all-targets
..\rust.ps1 cargo audit
```

Python checks:

```powershell
cd services/python-cognitive
python -m pip install -e '.[dev]'
python -m ruff check .
python -m pytest -q
```

`mypy` is not yet a clean gate; see `docs/RELEASE_CHECKLIST.md`.

## Pull requests

1. Fork the repository and create a topic branch.
2. Add or update tests for behaviour changes.
3. Run the checks above.
4. Open a pull request describing the change and its security impact.

First-time contributors may be held for manual approval by a maintainer. This
is a repository setting documented in `docs/RELEASE_CHECKLIST.md`.

## Commit hygiene

- Use conventional, descriptive commit messages.
- Never commit `.env`, credentials, or generated `target/` output.
- Signing off commits is optional; signing release tags is required for
  maintainers and is handled by the release workflow.
