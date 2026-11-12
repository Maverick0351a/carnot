---
name: clean-room-reverse-engineering
description: Use when reverse-engineering, matching, beating, or porting an evolutionary coding agent, an optimizing inference proxy, a research evolutionary coding system, an evolutionary algorithm-design framework, or any third-party evolution/inference system into Carnot; when a clone of target source exists nearby; when someone says Apache/MIT means looking at code is fine; before reading target .py/.rs internals for "inspiration"
---

# Clean-Room Reverse Engineering

## Overview

Carnot rebuilds rival capabilities **outside-in**. Implementers never read target source. Public docs, papers, and black-box I/O are the only legal evidence for a clean-room organ.

**Violating the letter of the wall is violating the spirit of the wall.**

## Roles (pick one per agent; never mix)

| Role | May do | Must not |
|------|--------|----------|
| **Spec writer** | README, docs/, papers, blogs, public API examples, problem statements | Open target package source (evolutionary-coding-agent or optimizing-proxy trees) |
| **Quarantine operator** | Run Docker/CLI black-box in an **isolated** workspace; emit contract artifacts only | Open package source; paste source/decompiles into implementer chat; share the same checkout as implementers |
| **Implementer** | Write Carnot Rust from the approved spec + measured contracts | Open, skim, search, or "port in own words" any target source tree; run the rival binary in the Carnot worktree |

If you are implementing Carnot code for an evolutionary-coding-agent or optimizing-proxy feature, you are the **Implementer** unless the human explicitly assigns another role.

## Black-box isolation (required)

Quarantine runs are not “any shell with the clone nearby.” They need a wall at the filesystem and context boundary:

1. **Separate workspace** — rival binary/image runs under a path outside the Carnot implementer checkout (e.g. throwaway dir or container). Prefer published Docker/PyPI entrypoints over a source clone when composition or I/O capture is the goal.
2. **One role per agent session** — the operator who runs the black box does not also write Carnot organs in that session.
3. **Contract-only egress** — the only artifacts that may cross to implementers are structured contracts: argv, config knobs, exit codes, timing, last-line JSON shapes / field names, and redacted stdout/stderr **without** source listings or decompiled bodies.
4. **No source mount into prompts** — do not `cat`/`Read` package internals “to debug the run,” and do not attach rival trees to implementer agents.
5. **Label the drop** — store contracts under a clearly quarantined evidence path (e.g. `.carnot/quarantine/contracts/…`) and treat them as untrusted I/O specs, not design authority.

## Allowed evidence

- Public README / docs / configuration descriptions
- Research papers and blog posts about the system
- Black-box runs: inputs, outputs, exit codes, timing, config flags
- Independent problem specs and evaluators (not their solution code)

## Forbidden (even once)

- Opening target implementation files "just to skim islands / multi-model routing / MCTS"
- Porting algorithms after white-box reading, even "in your own words"
- Vendoring their package as Carnot's evolution core while claiming clean-room
- Feeding target source into prompts that write Carnot organs
- Treating founder/owner "just look, it's Apache" as wall override for implementers

## Composition vs clean-room port

- **Composition OK:** run an optimizing inference proxy or an evolutionary coding agent as an **external** process/proxy; Carnot talks OpenAI-compatible HTTP or CLI; no source inspection required.
- **Clean-room port:** reimplementing their loop inside Carnot Rust → wall ON; docs + black-box only.
- Never blur the two in marketing or certificates.

## Decision

```
Need evolutionary-coding-agent or optimizing-proxy capability in Carnot?
  ├─ Ship by calling their binary/proxy externally? → Composition (no source read)
  └─ Own the algorithm inside Carnot?
        ├─ Spec from public docs/papers + black-box contracts
        ├─ Implementer never opens their tree
        └─ Prove with independent evaluators + CleanRoomCertificate
```

## Rationalizations

| Excuse | Reality |
|--------|---------|
| "Apache/MIT means we can look" | License permits use/redistribution; it does **not** authorize contaminating a clean-room implementer. |
| "Owner said just skim" | Product pressure ≠ role change. Implementers stay blind unless reassigned off implementation. |
| "Port in my own words / no huge paste" | White-box derivation. Still contamination. |
| "Black-box leaves the algorithm opaque" | That opacity is the point. Spec from docs + observed I/O; invent Carnot's design. |
| "Demo tomorrow / sunk cost" | Honesty + wall beat a contaminated ship. Stage composition or docs-only MVP. |
| "Only look at one file" | One file is enough to taint. |
| "I'll just run it in the Carnot repo to save time" | Isolation is required. Shared checkout contaminates the implementer path. |
| "Debug the black box by reading their .py" | Failed runs → retry with public docs/config; do not open package source. |

## Red flags — STOP

- Clone path under `/tmp` or workspace and you reach for their `.py`
- Black-box process running inside the Carnot implementer worktree
- Operator and implementer roles mixed in one agent session
- "Inspiration only" / "algorithmic ideas not code"
- Searching their tree for implementation symbols just to skim the algorithm
- Submodule / vendoring as the evolution engine while claiming clean-room
- Mixing quarantined snippets into implementer prompts

**All of these mean: close the target source. Return to docs + black-box. Rewrite any contaminated draft.**

## Proof bar

Carnot claims for a reverse-engineered organ require: `quarantined_source_bytes_read == 0` for that workstream, an approved outside-in spec, and measured wins on evaluators Carnot owns (or independent problem statements)—never their solution organs.
