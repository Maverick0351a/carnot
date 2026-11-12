# CarnotEngine (`carnot` v0.5)

**Agent-First App Refinery, Clean-Room License Firewall, Polyglot Project Emitter, Worktree Organ Evolver & Strangler-Fig Canary Proxy**

`carnot` is a zero-bloat single-binary Rust engine (`~1.4 MB` release binary; `serde` + `serde_json` + Rust `std` only) for turning messy multi-repo inspirations or raw app ideas into clean-room, conformance-tested, feature-flagged builds (`init -> scout -> intake-scan -> generate -> evolve -> verify -> proxy`).

It ships with three synchronized interfaces over the same deterministic state machine:
1. **CLI (`carnot ...`):** Workspace initializer, disk SPDX license scanner, polyglot project materializer, evolution & verification runners, and live TCP/HTTP/1.1 strangler-fig reverse proxy.
2. **Desktop Workbench UI (`carnot app` / `carnot serve`):** Persistent `Home` + 6-pane `Workbench` + shared right-hand Agent & `ProposalCard` confirmation column (`Accept` / `Decline` / `Undo`).
3. **Bounded-Context MCP Server (`carnot mcp`):** JSON-RPC 2.0 stdio server with automatic 12 KB receipt paging (`ev_...`) so coding agents can inspect and drive every stage without blowing context windows.

---

## Architecture & Production Honesty Matrix (`v0.5` vs. Roadmap)

Reviewers can inspect every claim directly against the source modules and `tests/full_machine_tests.rs`. See [`ROADMAP.md`](./ROADMAP.md) for `v0.6`–`v1.0` milestones.

| Subsystem | `v0.5` Verified Production Execution (Today) | Seeded Demo Convenience / `v0.6–v1.0` Roadmap |
| :--- | :--- | :--- |
| **Feature Flags & Sticky Canary Math** (`src/rollout.rs`) | **Real & Conformance-Verified:** Exact 32-bit `MurmurHash3` (`STRATEGY_SEED=0`, `VARIANT_SEED=86028157`), 21 constraint operators, segments, & parent dependencies passing **127/127** Feature Toggle v2 spec vectors. | Offline Ed25519 signed toggle bundles (`v1.0`). |
| **Evidence Ledger & IP Attestation** (`src/evidence.rs`, `src/intake.rs`) | **Real Disk Scan & FIPS SHA-256:** Zero-dependency FIPS 180-4 SHA-256 `ev_...` receipts appended to `.carnot/ledger.jsonl`; `carnot intake-scan <dir>` scans real directory trees on disk for SPDX licenses while reading **0 bytes** of quarantined (`AGPL`/`GPL`/`BSL`/`UNKNOWN`) source files. | Remote GitHub/`deps.dev` sparse license scout without full clone (`v0.7`); Ed25519 third-party audit signatures (`v1.0`). |
| **Polyglot Project Generation** (`src/recipe.rs`, `src/workspace.rs`) | **Real Compilable Disk Output:** `carnot generate <dir> [lang]` materializes complete, runnable `Rust`, `Python`, `TypeScript` (Node ESM), and `Go` repositories on disk with `EVOLVE_START`..`EVOLVE_END` organs, frozen `solve_bench` JSON harnesses, unit tests, and `git init`. | `Scala 3` and `Zig` currently emit starter organ scaffolds rather than full benchmark harnesses. |
| **Coding Agents & Organ Evolution** (`src/agents.rs`, `src/worktree.rs`, `src/evolve.rs`, `src/daemon.rs`, `src/bridge.rs`) | **Live worktree evolve** when a workspace is pointed **and** an `explicit_candidate` (EVOLVE block body) is supplied: real `git worktree` trial → StageOnly staging + Accept gate (`require_human_accept`) or AutoRatchet with `--apply`. Pending `PromoteStagedOrgan` cards persist to `.carnot/proposals.json` so `carnot proposal accept` works across processes. `carnot daemon` / `daemon_tick` drive measured ticks the same way. Offline 3-island ring is **`--demo` only** (or no workspace / UI without a candidate). | Headless agent auto-candidate for live ticks without an explicit body is **deferred** (`v0.6`); multi-agent parallel worktree island fan-out + SSE evolve stream also remain `v0.6`. Seeded island scores are never presented as live agent wins. |
| **Strangler-Fig Cutover & Kill-Switch** (`src/proxy.rs`, `src/bridge.rs`) | **Real Live TCP/HTTP/1.1 Reverse Proxy:** `carnot proxy` splits live HTTP requests between `--control` and `--canary` upstreams via `X-User-Id`, trips the `<0.1 ms` circuit breaker on real `5xx`/latency breaches, logs real failing payloads to `.carnot/regressions.jsonl`, and transparently fails over to `--control`. | Workbench UI also keeps a `Simulate Traffic` button for instant single-machine demos; async dark-traffic shadow mirroring arrives in `v0.9`. |
| **Anti-Creep Pruner (`EntropyBudget`)** (`src/prune.rs`) | **Manifest & Flag Telemetry Audit:** Detects overlapping organ I/O schemas, excess bridge indirection, and unexercised `organ.<id>.enabled` flags. | Source-level AST dead-export & cyclomatic complexity budgets (`v0.8`). |

---

## Quick Start

```powershell
# 1. Run all 8 end-to-end integration test suites (127 v2 vectors + FIPS SHA-256 + real disk SPDX scan
#    + real Python project generation & git worktree evolution + real HTTP reverse proxy failover)
cargo test

# 2. Initialize a persistent disk workspace & materialize a runnable project (rust | python | ts | go)
cargo run --release -- init ./my-clean-service edge-gateway python
cargo run --release -- generate ./my-clean-service python

# 3. Scan any local directory tree on disk through the SPDX Clean-Room License Firewall
cargo run --release -- intake-scan ./my-clean-service

# 4. Run the live HTTP/1.1 Strangler-Fig Reverse Proxy (25% MurmurHash3 canary + auto failover)
cargo run --release -- proxy 127.0.0.1:8080 127.0.0.1:8081 127.0.0.1:8082 25 ./my-clean-service

# 5. Launch the frameless Desktop Workbench App Shell (or headless HTTP server on 127.0.0.1:4242)
cargo run --release -- app
cargo run --release -- serve 127.0.0.1:4242 ./my-clean-service

# 6. Run as a bounded-context MCP stdio server for local coding agents (Codex, Claude, Gemini, AGY)
cargo run --release -- mcp ./my-clean-service

# 7. Run the self-contained 5-stage terminal walkthrough
cargo run --release -- demo
```

Tracked files must not name upstream projects this repository studies. The checker and the gitignored denylist are described in [`CONTRIBUTING.md`](./CONTRIBUTING.md). The check skips when no denylist is configured.

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
