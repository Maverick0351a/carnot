# Agent instructions — CarnotEngine

## Product

Carnot is a clean-room **Function Foundry**: outside-in observation, scored gyms, worktree trials, StageOnly Accept gates, and honest live-vs-demo labeling. End goal: continuous reverse-engineering and evolution of pointed targets without contaminating IP.

## Required skills (read before related work)

| Skill | Path | When |
|-------|------|------|
| Clean-room RE | `.cursor/skills/clean-room-reverse-engineering/SKILL.md` | Evolutionary coding agent, optimizing inference proxy, research evolutionary coding system, evolutionary algorithm-design framework, or any rival port/match/beat |
| Function Foundry | `.cursor/skills/carnot-function-foundry/SKILL.md` | Daemon, evolve, proposals, gyms, product claims, demos |
| Rust organs | `.cursor/skills/carnot-rust-organs/SKILL.md` | Any `src/` / CLI / MCP / HTTP change in this crate |

Also use repo process skills when applicable: brainstorming before creative scope, writing-plans / executing-plans for multi-step work, TDD for behavior changes.

## Non-negotiables

1. **Chinese Wall for rival source** — implementers do not open target package internals. Composition (external proxy/CLI) is allowed; clean-room ports use docs + black-box only.
2. **Deps** — `serde` + `serde_json` + `std` only unless a human explicitly expands the set.
3. **Write gate** — default product path is StageOnly + human Accept before primary organ writes.
4. **Honesty** — never present `--demo` / seeded islands as live agent wins; document gaps instead of theater.

## Primary RE target (current)

- **Evolutionary coding agent** — clean-room reverse-engineer evolution-loop capabilities into Carnot organs.
- **Optimizing inference proxy** — prefer composition; clean-room only if implementing techniques inside Carnot.

## Verification

```bash
cargo test
```

Keep README / ROADMAP honesty matrix accurate when behavior changes.
