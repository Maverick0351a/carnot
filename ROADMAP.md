# CarnotEngine Technical Roadmap (`v0.5` → `v1.0`)

This document separates **what is production-real and test-verified in the repository today (`v0.5`)** from **what remains interactive orchestration or scheduled for `v0.6`–`v1.0`**. Reviewers should never have to guess where deterministic execution ends and roadmap items begin.

---

## Shipped in `v0.5` — Un-Staged Disk, Worktree & Live Proxy Execution

Earlier prototypes (`v0.1`–`v0.4`) proved the deterministic algorithms (`MurmurHash3` Feature Toggle v2, FIPS 180-4 SHA-256 `ev_...` receipts, `<0.1 ms` circuit breaker, `EVOLVE_START`..`EVOLVE_END` block splicer, and the 6-pane Workbench UI) around an in-memory demo loop. **`v0.5` replaces all four staged prototype boundaries with real OS/filesystem/network execution:**

1. **Persistent Disk Workspaces & Filesystem SPDX Firewall (`src/workspace.rs`, `src/intake.rs`):**
   - `carnot init <dir> [name] [lang]` creates durable workspaces (`carnot.manifest.json`, `Carnot.toml`, `.carnot/ledger.jsonl`, `.carnot/regressions.jsonl`).
   - `carnot intake-scan <dir>` executes `scan_directory_spdx_zones` against real directory trees on disk, classifying license files of any case (`LICENSE`, `LICENCE`, `COPYING`, …) including nested vendor licenses, plus `Cargo.toml` / `package.json` / `pyproject.toml` / `setup.cfg` fields, without reading source-code bodies inside quarantined (`AGPL`, `GPL`, `BSL`, `PROPRIETARY`, `UNKNOWN`) zones (`quarantined_source_bytes_read == 0`).
2. **Real Compilable & Runnable Project Materializer (`src/recipe.rs`, `src/workspace.rs`):**
   - `carnot generate <dir> [lang]` writes complete, compilable, runnable project trees (`Rust`, `Python`, `TypeScript`/Node ESM, `Go`) onto disk with real `EVOLVE_START`..`EVOLVE_END` organ modules, frozen `solve_bench` JSON CLI harnesses, conformance test suites, and an initialized `git` repository.
3. **Isolated `git worktree` Organ Trials & Live Headless Agent Runner (`src/worktree.rs`, `src/agents.rs`):**
   - `invoke_headless_agent` spawns real non-interactive CLI coding agents (`claude -p`, `gemini -p`, `codex exec`, `opencode run`, or custom `CARNOT_AGENT_BIN` overrides) under hard wall-clock timeouts and strips markdown fences while preserving block indentation.
   - `run_git_worktree_trial` spins up detached git worktrees (`git worktree add --detach`), splices only `EVOLVE_START`..`EVOLVE_END`, executes real test suites and `solve_bench` JSON harnesses via `evaluate_json_command_in_dir`, ratchets the primary file + `.carnot/ledger.jsonl` only on strict objective improvement, and removes/prunes temporary worktrees via an RAII `Drop` guard.
4. **Live TCP/HTTP/1.1 Strangler-Fig Reverse Proxy (`src/proxy.rs`):**
   - `carnot proxy <listen> <control> <canary> [pct] [workspace]` routes real live HTTP traffic between `--control` and `--canary` upstream servers via `MurmurHash3` (`X-User-Id`), feeds real latency/status telemetry into the `<0.1 ms` circuit breaker, captures real failing HTTP payloads into `.carnot/regressions.jsonl`, and transparently fails over `5xx` canary faults to `--control` so callers still receive a clean `200 OK`.

---

## Shipped in the tree at crate `0.5.0` — Clean-Room Reconstruction Spine, Black-Box Shield & Hybrid Search

The crate version is `0.5.0`. The items below are in this tree; they are not a `1.0` release. They are covered by `cargo test` and `cargo clippy --all-targets -- -D warnings`, still with only `serde` + `serde_json` dependencies.

1. **Black-Box Shield ON/OFF (`CarnotManifest.black_box_enforced`, default `true`):**
   - ON = strict Chinese-Wall quarantine for `AGPL`/`GPL`/`SSPL`/`BSL`/EULA zones. OFF = white-box inspection for permissive or owned code. Every toggle mints a fresh `CleanRoomCertificate` (with an honest `black_box_enforced` flag and attestation statement) plus a `black_box_shield_toggle` evidence receipt.
   - You can toggle it from the CLI (`carnot black-box <on|off|status> [ws]`), HTTP (`GET`/`POST /api/intake/black-box`), MCP (`carnot_toggle_black_box`) and the Workbench rail switch.
   - `InspectionFirewall` still blocks decompiler/white-box inspection-CLI subcommands for quarantined policies whatever the toggle says.
2. **Hybrid code search (`src/codesearch.rs`):** BM25, static subword embeddings, RRF fusion, reranking and a token-savings meter, in the shape of a local hybrid code-search engine. The shield gates it: quarantined prefixes and files with canonical copyleft/EULA headers are skipped while ON.
   - CLI: `carnot search`, `carnot related`. HTTP: `/api/codesearch`, `/api/codesearch/related`. MCP: `carnot_code_search`, `carnot_find_related`. UI: Home search card.
3. **Feature-flag client-specification conformance:** 22/22 suites (`specs/feature_toggle_v2/`) and `GET /api/client/delta` with SHA-256 `ETag` / `If-None-Match` → `304`.
4. **Trace-and-judge evaluation (`src/eval.rs`):**
   - `TraceIndex` cache
   - V2 evaluators that return Skipped rather than Fail when they can't score
   - `<trace>`-isolated judge prompts and `calibrate_judge`
   - Paired statistics: Wilson, MOVER, McNemar, bootstrap, Wilcoxon
5. **Evolutionary algorithm-design loop (`src/evolve.rs`, `src/worktree.rs`, `src/daemon.rs`):**
   - 3-tier hotspot scanner (`carnot hotspots`, `/api/evolve/hotspots`, `carnot_hotspots`)
   - Heuristic-search and reflective pairwise operators with an EMA bandit
   - Dominance-dissimilarity scoring, A-Res experience retrieval and hop-limited ring migration
   - Outer-harness byte verification, n-gram clean-room gate and quarantine purge for worktree trials
   - Function Foundry: `point` → live evolve / StageOnly daemon ticks; Experience Cards persist to `.carnot/experience_cards.jsonl`
6. **Agent workbench:**
   - `AcpSession` JSON-RPC client that denies quarantined permission requests
   - Reversible `ProposalCard` snapshots, so Accept → Undo is lossless
   - LCS diffs with intra-line spans
   - Workspace `.carnot/playbooks/<id>/SKILL.md` playbooks (runnable, with a `/id` composer shortcut)
   - XSS-escaped `ui.html` with Obligations and Language-Advisor inspectors
7. **Obligation spine:** `ObligationLedger` closure verdicts (`carnot obligations`, `/api/obligations`, `carnot_obligations`) and the Design-to-Language Fitness Matrix (`carnot advise`, `/api/advise/languages`, `carnot_advise_languages`).

**Still deferred:** shared `--mcp-bridge` IPC between `carnot mcp` and a live `carnot serve`, SSE streaming in the UI, and the Ed25519 signing items in `v1.0` below.

---

## Upcoming Milestones (`v0.6` – `v1.0`)

### Milestone `v0.6` — Multi-Agent Parallel Worktree Island Executor
- **Current state (`v0.5` + Function Foundry wire):** Single-trial `run_git_worktree_trial` runs real detached git worktrees + real headless CLI agents + real subprocess benchmarks. **Live evolve** on a pointed workspace requires an `explicit_candidate` (CLI: `carnot evolve --candidate <file>`; StageOnly Accept gate / AutoRatchet); headless auto-candidate wiring is deferred. Offline 3-island `run_island_evolution` is `--demo` (or no workspace / UI without a candidate). `carnot point` stores state outside a foreign tree (XDG data dir); an existing Carnot workspace or `--in-tree` keeps `.carnot/proposals.json` in the tree. Live trials write `.carnot/worktrees` and `.carnot/staged` in that same state directory. `carnot verify` runs a detected test runner (`checks_executed` only after it starts) and inventories the tree when none is found. `carnot spec` / `generate --spec` / `verify --against` rebuild a Python library from a public-API spec; other languages are not supported, and the generator is an example lookup. `carnot daemon` / `daemon_tick` + StageOnly Accept + Experience Card flush/retrieval are wired and covered by E1–E4 in `tests/daemon_experiment_tests.rs`. E4 asserts multi-tick cumulative staged wins ≥ one-shot control on the toy organ — not a general “continuous search advantage.”
- **Target (`v0.6`):**
  - Wire `run_island_evolution` to fan out `N` concurrent `git worktree` worker threads across heterogeneous local coding agents (`Exploitation` = `codex`, `Correction` = `claude`, `Exploration` = `gemini`).
  - Stream live generation-by-generation telemetry over Server-Sent Events (`/api/evolve/stream`) into the Workbench UI.
  - Headless agent auto-candidate for daemon ticks (no explicit block required); richer cross-session Experience Card retrieval beyond the current A-Res prompt path.

### Milestone `v0.7` — Live Remote Repository Scout & Dependency Graph Inspector
- **Current state (`v0.5`):** `inspect_local_directory_metrics` and `scan_directory_spdx_zones` inspect real local directories on disk; `new_seeded()` provides sample multi-repo comparison fixtures when no workspace is loaded.
- **Target (`v0.7`):**
  - Add `carnot scout-remote <repo_url_or_query>` querying public package/advisory metadata (`deps.dev` / GitHub REST metadata + shallow sparse-checkout of `LICENSE*` and `specs/` only) so quarantined repositories never even download restricted source blobs onto disk.
  - Exact lockfile transitive-dependency counting (`Cargo.lock`, `go.sum`, `package-lock.json`, `uv.lock`).

### Milestone `v0.8` — Structural AST Anti-Creep Analyzer (`EntropyBudget` v2)
- **Current state (`v0.5`):** `src/prune.rs` analyzes manifest organ I/O contract overlap, bridge hop depth, and runtime toggle exercise counts (`ToggleMetricsCounter`), plus token-Jaccard syntax diversity in `src/evolve.rs`.
- **Target (`v0.8`):**
  - Add lightweight lexical/structural symbol-graph extraction across `Rust`, `Go`, `TypeScript`, and `Python` workspaces to detect dead public exports, duplicate struct/interface shapes in real source files, and cyclomatic complexity growth inside `EVOLVE_START`..`EVOLVE_END` blocks.
  - Enforce hard `EntropyBudget` byte/branch ceilings inside `run_git_worktree_trial` before ratcheting.

### Milestone `v0.9` — Streaming HTTP/1.1 Chunked + TLS Termination & Shadow Mirroring
- **Current state (`v0.5`):** `src/proxy.rs` handles HTTP/1.1 `Content-Length` request forwarding, `X-User-Id` sticky routing, transparent `5xx` failover to control, `<0.1 ms` circuit-breaker trips, and `.carnot/regressions.jsonl` capture. `ProxyExtendedOptions::shadow_mirror_canary` can fork a background canary request from library callers. `carnot proxy` does not enable it.
- **Target (`v0.9`):**
  - Add asynchronous dark-traffic **shadow mirroring** (100% synchronous response from `control`, non-blocking clone to `canary` with response-body JSON structural diffing).
  - Support chunked transfer-encoding streaming and OpenTelemetry OTLP trace-header propagation (`traceparent`).

### Milestone `v1.0` — Offline Ed25519 Signed Clean-Room Certificates & Reproducible Release Builds
- **Current state (`v0.5`):** Clean-Room IP Certificates (`CleanRoomCertificate`) are content-addressed with zero-dependency FIPS 180-4 SHA-256 (`ev_...`) and persisted to `.carnot/ledger.jsonl`; `tier.rs` gates Community vs. Pro capabilities via environment/config state.
- **Target (`v1.0`):**
  - Sign Clean-Room IP Certificates and `.carnot/ledger.jsonl` checkpoints with offline Ed25519 keys (`carnot verify-cert <cert.json> --pubkey <pk>`) for third-party enterprise M&A / compliance audits.
  - Offline cryptographic license token verification for air-gapped Pro deployments.
  - Cross-platform release binaries are built by `.github/workflows/release.yml` when a `v*` tag is pushed (host triples for Linux, macOS, and Windows, with SHA-256 files). crates.io publish and Ed25519 provenance are not automated. `x86_64-unknown-linux-musl` is not in that matrix.
