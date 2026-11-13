# CarnotEngine (`carnot` v0.5)

**Agent-First App Refinery, Clean-Room License Firewall, Polyglot Project Emitter, Worktree Organ Evolver & Strangler-Fig Canary Proxy**

`carnot` is a single-binary Rust engine (`serde` + `serde_json` + Rust `std` only; release profile strips symbols) for turning a local tree into a clean-room, conformance-tested, feature-flagged build (`init -> scout -> intake-scan -> generate -> evolve -> verify -> proxy`).

It ships with three synchronized interfaces over the same deterministic state machine:
1. **CLI (`carnot ...`):** Workspace initializer, disk SPDX license scanner, polyglot project materializer, evolution & verification runners, and live TCP/HTTP/1.1 strangler-fig reverse proxy.
2. **Local workbench (`carnot app` / `carnot serve`):** Browser UI served on localhost (`Home` + 6-pane `Workbench` + `ProposalCard` column). `carnot app` opens that URL in a browser; it is not a native desktop shell.
3. **Bounded-Context MCP Server (`carnot mcp`):** JSON-RPC 2.0 stdio server with automatic 12 KB receipt paging (`ev_...`) so coding agents can inspect and drive every stage without blowing context windows.

---

## Architecture & Production Honesty Matrix (`v0.5` vs. Roadmap)

Reviewers can inspect every claim directly against the source modules and `tests/full_machine_tests.rs`. See [`ROADMAP.md`](./ROADMAP.md) for `v0.6`–`v1.0` milestones.

| Subsystem | `v0.5` Verified Production Execution (Today) | Seeded Demo Convenience / `v0.6–v1.0` Roadmap |
| :--- | :--- | :--- |
| **Feature Flags & Sticky Canary Math** (`src/rollout.rs`) | **Real & Conformance-Verified:** Exact 32-bit `MurmurHash3` (`STRATEGY_SEED=0`, `VARIANT_SEED=86028157`), 21 constraint operators, segments, & parent dependencies passing **127/127** Feature Toggle v2 spec vectors. | Offline Ed25519 signed toggle bundles (`v1.0`). |
| **Evidence Ledger & IP Attestation** (`src/evidence.rs`, `src/intake.rs`) | **Real Disk Scan & FIPS SHA-256:** Zero-dependency FIPS 180-4 SHA-256 `ev_...` receipts appended to `.carnot/ledger.jsonl`; `carnot intake-scan <dir>` scans real directory trees on disk for SPDX licenses while reading **0 bytes** of quarantined (`AGPL`/`GPL`/`BSL`/`UNKNOWN`) source files. | Remote GitHub/`deps.dev` sparse license scout without full clone (`v0.7`); Ed25519 third-party audit signatures (`v1.0`). |
| **Polyglot Project Generation** (`src/recipe.rs`, `src/workspace.rs`) | **Real Compilable Disk Output:** `carnot generate <dir> [lang]` materializes complete, runnable `Rust`, `Python`, `TypeScript` (Node ESM), and `Go` repositories on disk with `EVOLVE_START`..`EVOLVE_END` organs, frozen `solve_bench` JSON harnesses, unit tests, and `git init`. | `Scala 3` and `Zig` currently emit starter organ scaffolds rather than full benchmark harnesses. |
| **Coding Agents & Organ Evolution** (`src/agents.rs`, `src/worktree.rs`, `src/evolve.rs`, `src/daemon.rs`, `src/bridge.rs`) | **Live worktree evolve** when a workspace is pointed **and** an `explicit_candidate` (EVOLVE block body) is supplied through the library or MCP: real `git worktree` trial → StageOnly staging + Accept gate (`require_human_accept`) or AutoRatchet with `--apply`. Pending `PromoteStagedOrgan` cards persist to `.carnot/proposals.json` so `carnot proposal accept` works across processes. The CLI `carnot daemon` does not take a candidate, so its tick reports a skip. Offline 3-island ring is **`carnot demo` / `evolve --demo` only**. Binding a workspace does not copy those seeded proposals, golden rows, or scout fixtures onto disk. | Headless agent auto-candidate for live ticks without an explicit body is **deferred** (`v0.6`); multi-agent parallel worktree island fan-out + SSE evolve stream also remain `v0.6`. A CLI flag for the candidate body is not shipped. Seeded island scores are never presented as live agent wins. |
| **Strangler-Fig Cutover & Kill-Switch** (`src/proxy.rs`, `src/bridge.rs`) | **Real Live TCP/HTTP/1.1 Reverse Proxy:** `carnot proxy` splits live HTTP requests between `--control` and `--canary` upstreams via `X-User-Id`, trips the `<0.1 ms` circuit breaker on real `5xx`/latency breaches, logs real failing payloads to `.carnot/regressions.jsonl`, and transparently fails over to `--control`. | Workbench UI also keeps a `Simulate Traffic` button for instant single-machine demos; async dark-traffic shadow mirroring arrives in `v0.9`. |
| **Anti-Creep Pruner (`EntropyBudget`)** (`src/prune.rs`) | **Manifest & Flag Telemetry Audit:** Detects overlapping organ I/O schemas, excess bridge indirection, and unexercised `organ.<id>.enabled` flags. | Source-level AST dead-export & cyclomatic complexity budgets (`v0.8`). |

---

## Install

Rust 1.88 or newer. From a git checkout:

```bash
cargo install --path .
carnot help
```

`carnot` with no arguments prints help. Release binaries are attached to a GitHub Release when a `v*` tag is pushed (Linux, macOS, and Windows). This repository does not publish to crates.io from CI.

Account tier defaults to Pro. Set `CARNOT_TIER=community` to lock Pro-gated commands. That variable is an operator switch, not a cryptographic license check.

## Quick Start

```bash
# 1. Test (feature-toggle vectors, SHA-256, SPDX scan, project generation, git worktree trials, proxy)
cargo test

# 2. Initialize a workspace, then materialize a project (rust | python | ts | go)
carnot init ./my-clean-service edge-gateway python
carnot generate ./my-clean-service python

# 3. Scan a local tree. A directory with no manifest is scanned in memory.
#    A present but unreadable carnot.manifest.json is an error.
carnot intake-scan ./my-clean-service

# 4. HTTP/1.1 reverse proxy (25% canary + failover to control)
carnot proxy 127.0.0.1:8080 127.0.0.1:8081 127.0.0.1:8082 25 ./my-clean-service

# 5. Local workbench (browser) or HTTP server
carnot app
carnot serve 127.0.0.1:4242 ./my-clean-service

# 6. MCP stdio server. Live ticks need explicit_candidate on carnot_daemon_tick.
carnot mcp ./my-clean-service

# 7. Offline walkthrough. This does not write a workspace and is not a live agent run.
carnot demo
```

Tracked files must not name upstream projects this repository studies. The checker and the gitignored denylist are described in [`CONTRIBUTING.md`](./CONTRIBUTING.md). The check skips when no denylist is configured.

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
