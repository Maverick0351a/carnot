---
name: carnot-rust-organs
description: Use when adding or changing Carnot Rust modules, CLI/MCP/HTTP surfaces, worktree trials, daemon policy, serde types, or dependencies in this zero-extra-dep crate
---

# Carnot Rust Organs

## Overview

Carnot is a **single binary**, Rust 2021, deps = `serde` + `serde_json` + `std` only. New features stay inside that envelope unless the human explicitly expands deps.

## Module map (extend, don’t fork)

| Concern | Module |
|---------|--------|
| State machine / evolve / point / accept | `bridge.rs` (`CarnotMachine`) |
| Daemon policy, leases, targets | `daemon.rs` |
| Worktree trial + StageOnly staging | `worktree.rs` |
| Offline island demo | `evolve.rs` |
| Proposals / Accept cards | `proposals.rs` |
| SPDX intake / clean-room cert | `intake.rs`, `evidence.rs` |
| CLI | `main.rs` |
| MCP | `mcp.rs` |
| HTTP + UI | `server.rs`, `ui.html` |
| Gym / JSON command eval | `eval.rs`, `proc_util.rs` |
| Outside-in oracles | `oracle.rs` |

Wire new behavior through `CarnotMachine` so CLI, MCP, and UI stay synchronized.

## Hard constraints

- **No new crates** without an explicit human decision (not “for convenience”).
- Prefer `Result<T, String>` / structured JSON errors consistent with neighbors.
- Sanitize relative paths with `sanitize_workspace_rel_path` before joining to workspace root.
- Persist cross-process state under `.carnot/` (e.g. `proposals.json`, `ledger.jsonl`) — don’t assume in-memory alone.
- Quarantine / black-box counters stay honest; never decrement or spoof `quarantined_source_bytes_read`.

## Evolve surfaces checklist

When adding an evolve/daemon capability, update **all** that apply:

1. Types + logic (`daemon` / `worktree` / `bridge`)
2. CLI subcommand (`main.rs`)
3. MCP tool (`mcp.rs`) + version note if user-visible
4. HTTP API + UI honesty copy (`server.rs` / `ui.html`)
5. Integration test under `tests/` (prefer gym discrimination + write-gate proof)
6. README / ROADMAP honesty matrix if claims change

## Test posture

- Prefer deterministic tests (temp dirs, explicit candidates, JSON benches).
- Prove StageOnly does **not** write primary until Accept.
- Never assert seeded `--demo` scores as live worktree wins.

## Anti-patterns

- Pulling `tokio`, `reqwest`, `git2`, etc. for one call site when `std::process` / std HTTP already patterns exist
- Duplicating machine logic only in the UI
- Defaulting AutoRatchet in library constructors used by CLI/MCP
- Reading third-party evolution source while implementing (use `clean-room-reverse-engineering`)
