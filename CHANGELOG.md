# Changelog

## 0.5.0

First crate version. Not published to crates.io.

### Command line

- `carnot` with no arguments prints help. `carnot demo` is the offline walkthrough.
- `carnot verify` runs `cargo test`, pytest or `python3 -m unittest discover -s tests`, `npm test`, or `go test ./...` when that project file is present. `checks_executed` stays false when no runner is detected. `--timeout` defaults to 120 seconds.
- Live evolve writes `.carnot/worktrees` and `.carnot/staged` under the point state directory. `--in-tree` and an existing Carnot workspace keep those directories in the tree.
- `carnot spec` writes a Python public-API spec (signatures, docstrings, literal examples) and does not copy function bodies. Other languages are not supported.
- `carnot generate <dir> --spec <file>` rebuilds from that spec alone and records `spec_only` plus the spec sha256 in `carnot.rebuild.json`. The generator is an example lookup.
- `carnot spec --holdout` (default 0.3) withholds examples from generation. `verify --against` grades those held-out examples, and `--all` grades every example. The generator is a prototype example lookup and does not synthesize logic.
- `carnot verify` exits 1 when the runner times out, exits non-zero, or any graded example fails. The JSON report stays on stdout.
- `carnot verify <dir> --against <spec>` replays the spec's examples and flags a shared token 12-gram with the original tree.
- `carnot generate` without `--spec` still requires a `carnot.manifest.json` from `carnot init`.
- A workspace whose manifest, ledger, dataset, or proposals file is unreadable fails the command. The in-memory demo machine is not substituted for that directory.
- Binding a workspace does not write seeded demo proposals, golden dataset rows, or scout fixtures into `.carnot/`.

### License firewall and writes

- A manifest or package license field that names both a permissive id and AGPL, GPL, LGPL, SSPL, or BSL is classified as the restrictive license.
- Project materialization, worktree organ writes, staged promotion, and quarantine purge refuse `..` and symlinks that leave the workspace directory.
- Zone detection still reads `LICENSE` / `COPYING` and manifest fields, not per-file SPDX headers.

### Release

- GitHub Actions runs fmt, clippy, and tests on Linux, macOS, and Windows.
- `.github/workflows/release.yml` builds binaries when a `v*` tag is pushed. Publishing to crates.io remains a manual decision.
