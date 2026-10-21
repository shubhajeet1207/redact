## What and why

## Checklist

- [ ] All values in tests and fixtures are synthetic.
- [ ] Commits are signed off (`git commit -s`).
- [ ] `cargo fmt`, `cargo clippy -D warnings`, and `cargo test --workspace` pass locally.
- [ ] Any new dependency is justified below and passes `cargo deny check`.

### Rule changes only (CONTRIBUTING.md § Changing detection rules)

- [ ] Positive, near-miss, overlap, and regression fixtures added.
- [ ] Vendor `source` link included for any credential format.
- [ ] Manifest `ruleVersion` bumped, `CHANGELOG.md` updated, and `docs/rules.md` regenerated.
- [ ] Benign-corpus changes reviewed and justified.
