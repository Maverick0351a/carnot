# Changelog

## 0.5.0

First crate version. Not published to crates.io.

### Command line

- `carnot` with no arguments prints help. `carnot demo` is the offline walkthrough.
- `carnot generate` requires a `carnot.manifest.json` from `carnot init`.
- A workspace whose manifest, ledger, dataset, or proposals file is unreadable fails the command. The in-memory demo machine is not substituted for that directory.
- Binding a workspace does not write seeded demo proposals, golden dataset rows, or scout fixtures into `.carnot/`.

### License firewall and writes

- A manifest or package license field that names both a permissive id and AGPL, GPL, LGPL, SSPL, or BSL is classified as the restrictive license.
- Project materialization, worktree organ writes, staged promotion, and quarantine purge refuse `..` and symlinks that leave the workspace directory.
- Zone detection still reads `LICENSE` / `COPYING` and manifest fields, not per-file SPDX headers.

### Release

- GitHub Actions runs fmt, clippy, and tests on Linux, macOS, and Windows.
- `.github/workflows/release.yml` builds binaries when a `v*` tag is pushed. Publishing to crates.io remains a manual decision.
