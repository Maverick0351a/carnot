---
name: carnot-function-foundry
description: Use when designing, implementing, documenting, or demoing Carnot daemon ticks, organ evolution, StageOnly vs AutoRatchet, evolutionary-coding-agent features, optimizing-proxy composition, proposals, solve_bench gyms, or product claims about continuous reverse-engineering
---

# Carnot Function Foundry

## Overview

Carnot’s product is **software metabolism**: observe outside-in → score with a gym → propose mutants → trial in quarantine → **ratchet only on measured win** → human Accept when required. Not a port of an upstream evolutionary coding agent. Not a fake live agent.

## North star

Build the best continuous reverse-engineering + evolution engine in Rust:

1. **Clean-room first** — REQUIRED: `clean-room-reverse-engineering` for rival systems.
2. **Evolutionary-coding-agent loop** — islands / diversity / artifact feedback as *Carnot* organs from public specs + black-box contracts.
3. **Optimizing-inference-proxy proposer** — prefer **composition** (external optimizing proxy) before clean-room-porting techniques.
4. **Honest surfaces** — CLI / MCP / UI never label `--demo` or seeded islands as live agent wins.

## Gym contract

Every evolve target needs:

- An `EVOLVE_START` / `EVOLVE_END` (or language twin) organ
- A frozen `solve_bench` (or equivalent) that prints **last-line JSON** with `objective` and `validity`
- Trials in git worktrees; primary writes gated by `PromoteMode`

## Write gate

| Mode | Primary organ write | When |
|------|---------------------|------|
| `StageOnly` (default product path) | Only after human `Accept` on `PromoteStagedOrgan` | `require_human_accept` |
| `AutoRatchet` | On measured win | Explicit `--apply` / opted-in policy — never silent demo bypass |

Default path: **primary files do not change without an Accept receipt** (or an explicit AutoRatchet opt-in the operator knows about).

## Live vs demo

| Path | Requires | Claim allowed |
|------|----------|---------------|
| Live evolve / `daemon_tick` | Pointed workspace + `explicit_candidate` (until v0.6 auto-candidate) | Measured worktree trial |
| `--demo` / offline islands | None | **Demo only** — seeded/offline tournament |

Headless auto-candidate is roadmap, not a UI lie.

## Product recipe (output shape)

When proposing the next foundry change, state in order:

1. **Capability** — one sentence (e.g. “MAP-Elites diversity archive for organ trials”)
2. **Evidence source** — public docs / black-box / composition (never target source for implementers)
3. **Gym proof** — which bench JSON fields prove a win
4. **Write gate** — StageOnly or explicit AutoRatchet
5. **Honesty** — what README/UI must not claim

## Common mistakes

- Calling seeded island scores “agent wins”
- Flipping Accept off “just for the demo”
- Treating an optimizing-proxy checkout as clean-room IP
- Evolving without a discriminating gym (E1)
- Skipping ExperienceCard / retrieval into the next propose prompt (E3)
