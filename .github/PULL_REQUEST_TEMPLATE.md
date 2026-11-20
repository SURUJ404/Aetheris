## Summary

<!-- What changed and why? -->

## Security impact

<!-- Does this touch auth, authorization, tenant isolation, secrets, or the sandbox? -->

- [ ] No credentials, internal hosts, or private IPs are included.
- [ ] Authentication/authorization/tenant isolation behaviour is unchanged or strengthened.
- [ ] The sandbox entry point remains the broker only.

## Verification

<!-- List the commands you ran and their outcome. -->

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all --workspace --all-targets -- -D warnings`
- [ ] `cargo test --all-targets`
- [ ] `cargo audit`
- [ ] Python `ruff` and `pytest` (if Python code changed)

## Checklist

- [ ] Tests added or updated for behaviour changes.
- [ ] Documentation updated where needed.
- [ ] No internal QA/phase-report docs or generated tool skills are included.
