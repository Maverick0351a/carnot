//! Built-In & Workspace `.carnot/playbooks/<id>/SKILL.md` Playbooks.
//!
//! Each playbook carries structured metadata plus full `SKILL.md` Markdown instructions runnable
//! from the composer `/` slash palette, the left rail, CLI, or MCP (`carnot_playbook_run`).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub title: String,
    pub shortcut: String,
    pub stage: String,
    pub summary: String,
    #[serde(default)]
    pub skill_markdown: String,
}

pub fn builtin_playbooks() -> Vec<Playbook> {
    vec![
        Playbook {
            id: "blueprint-brainstorm".to_string(),
            title: "Brainstorm & Confirm Blueprint".to_string(),
            shortcut: "1".to_string(),
            stage: "Intake".to_string(),
            summary: "Turn a plain-language app idea into a module graph and emit an Accept/Decline confirmation card before building.".to_string(),
            skill_markdown: "# Blueprint Brainstorm\n1. Decompose user goal into <= 5 cohesive organs with explicit I/O contracts.\n2. Gate every new organ behind `organ.<id>.enabled`.\n3. Stage a reversible `ProposalCard` with LCS `Carnot.toml` diff for human confirmation.".to_string(),
        },
        Playbook {
            id: "discover-and-quarantine".to_string(),
            title: "Discover Organs & Quarantine Licenses".to_string(),
            shortcut: "2".to_string(),
            stage: "Discover + Dissect".to_string(),
            summary: "Rank candidate open-source organs, block copyleft/EULA source reads, and mint a SHA-256 Clean-Room receipt.".to_string(),
            skill_markdown: "# Discover & Quarantine\n1. Inspect candidate repositories and lockfiles for signal-to-bloat ratio.\n2. Enforce SPDX firewall (`AGPL`/`GPL`/`BSL`/EULA quarantined when Black-Box Shield is ON).\n3. Mint a SHA-256 `ev_...` Clean-Room Provenance Certificate.".to_string(),
        },
        Playbook {
            id: "evolve-hot-organ".to_string(),
            title: "Evolve Hot Organ (3-Island Ring)".to_string(),
            shortcut: "E".to_string(),
            stage: "Evolve (Pro)".to_string(),
            summary: "Mutate only EVOLVE_START..EVOLVE_END across 3 islands under blind prompts, keeping ratchet-only winners and Experience Cards.".to_string(),
            skill_markdown: "# Evolve Hot Organ\n1. Locate hotspots via `EVOLVE_START` markers and `HybridCodeIndex` RRF search.\n2. Run heuristic and reflective operators across `DiverseIslandGA` with dominance-dissimilarity scoring.\n3. Enforce outer-harness byte identity, 5-gram clean-room gate, and `SourceEntropyBudget`.".to_string(),
        },
        Playbook {
            id: "parallel-shootout".to_string(),
            title: "Run Parallel Sandbox Shootout".to_string(),
            shortcut: "3".to_string(),
            stage: "Verify".to_string(),
            summary: "Benchmark competing implementations and wiring topologies concurrently on the 3D Pareto frontier.".to_string(),
            skill_markdown: "# Parallel Pareto Shootout\n1. Evaluate variants across deterministic schemas, tool-call traces, and logprob G-Eval.\n2. Compute paired Wilson/MOVER confidence intervals and McNemar/Bootstrap p-values.\n3. Rank non-dominated winners on the 3D `(score, p95_latency_ms, cost)` Pareto frontier.".to_string(),
        },
        Playbook {
            id: "prune-feature-creep".to_string(),
            title: "Audit Feature Creep & Consolidate".to_string(),
            shortcut: "4".to_string(),
            stage: "Prune".to_string(),
            summary: "Flag overlapping modules, bloated dependencies, and unexercised flags; propose a consolidation patch.".to_string(),
            skill_markdown: "# Prune Feature Creep\n1. Audit `Carnot.toml` for overlapping organ I/O schemas, bridge chains > 4 hops, and stale 100%-rolled-out flags.\n2. Run `audit_source_entropy` against `SourceEntropyBudget`.\n3. Stage a reversible `ConsolidateOrgans` proposal with full snapshot Undo.".to_string(),
        },
        Playbook {
            id: "flagged-cutover".to_string(),
            title: "Stage Per-Organ Flagged Cutover".to_string(),
            shortcut: "5".to_string(),
            stage: "Cutover".to_string(),
            summary: "Gate each synthesized organ behind its own MurmurHash3 canary flag with <0.1 ms auto-rollback.".to_string(),
            skill_markdown: "# Flagged Canary Cutover\n1. Verify `ObligationLedger` has zero unresolved high-impact `UnknownRecord` blockers.\n2. Route canary percentage deterministically via feature-toggle v2 `MurmurHash3`.\n3. Auto-rollback in `< 0.1 ms` on error/latency breach and capture regression JSONL.".to_string(),
        },
    ]
}

/// Loads custom workspace playbooks from `<workspace_dir>/.carnot/playbooks/<id>/SKILL.md`.
pub fn load_workspace_playbooks(workspace_dir: &Path) -> Vec<Playbook> {
    let pb_root = workspace_dir.join(".carnot").join("playbooks");
    let Ok(entries) = fs::read_dir(&pb_root) else {
        return Vec::new();
    };
    let mut sorted: Vec<_> = entries.flatten().collect();
    sorted.sort_by_key(|e| e.file_name());

    let mut custom = Vec::new();
    for entry in sorted {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        let skill_file = path.join("SKILL.md");
        let Ok(raw_md) = fs::read_to_string(&skill_file) else {
            continue;
        };
        let (meta, body) = parse_skill_frontmatter(&raw_md);
        let title = meta
            .get("title")
            .or_else(|| meta.get("name"))
            .cloned()
            .unwrap_or_else(|| id.replace('-', " "));
        let shortcut = meta
            .get("shortcut")
            .cloned()
            .unwrap_or_else(|| "P".to_string());
        let stage = meta
            .get("stage")
            .cloned()
            .unwrap_or_else(|| "Custom".to_string());
        let summary = meta.get("description").cloned().unwrap_or_else(|| {
            body.lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with('#'))
                .unwrap_or("Custom workspace playbook")
                .chars()
                .take(140)
                .collect()
        });
        custom.push(Playbook {
            id,
            title,
            shortcut,
            stage,
            summary,
            skill_markdown: body,
        });
    }
    custom
}

fn parse_skill_frontmatter(raw: &str) -> (std::collections::HashMap<String, String>, String) {
    let mut map = std::collections::HashMap::new();
    let trimmed = raw.trim_start();
    if let Some(after_open) = trimmed
        .strip_prefix("---\n")
        .or_else(|| trimmed.strip_prefix("---\r\n"))
    {
        if let Some(end_idx) = after_open.find("\n---") {
            let fm_block = &after_open[..end_idx];
            for line in fm_block.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    map.insert(
                        k.trim().to_ascii_lowercase(),
                        v.trim().trim_matches(['"', '\'']).to_string(),
                    );
                }
            }
            let rest = &after_open[(end_idx + 4)..];
            let body = rest.trim_start_matches(['\r', '\n']).to_string();
            return (map, body);
        }
    }
    (map, raw.to_string())
}
