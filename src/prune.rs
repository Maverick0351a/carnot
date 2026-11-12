//! Thermodynamic Anti-Feature-Creep, Stale Flag Pruner & Source Complexity Analyzer (`EntropyBudget` & `carnot prune`).
//!
//! Flags capability overlap across modules, excess bridge hops, unexercised per-organ feature flags,
//! stale 100%-rolled-out cutover flags eligible for control inlining, and source-level complexity bloat.

use crate::recipe::CarnotManifest;
use crate::rollout::ToggleMetricsCounter;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreepKind {
    OverlappingOrganResponsibility,
    ExcessBridgeIndirection,
    UnexercisedFeatureFlag,
    StaleFullyRolledOutFlag,
    ExcessFunctionComplexity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreepFinding {
    pub id: String,
    pub kind: CreepKind,
    pub involved_organs: Vec<String>,
    pub headline: String,
    pub consolidation_action: String,
    pub estimated_surface_reduction_pct: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEntropyReport {
    pub total_loc: usize,
    pub function_count: usize,
    pub max_function_loc: usize,
    pub max_branch_depth: usize,
    pub within_budget: bool,
    pub violation_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SourceEntropyBudget {
    pub max_total_loc: usize,
    pub max_functions: usize,
    pub max_function_loc: usize,
    pub max_branch_depth: usize,
}

impl Default for SourceEntropyBudget {
    fn default() -> Self {
        Self {
            max_total_loc: 1_200,
            max_functions: 32,
            max_function_loc: 160,
            max_branch_depth: 8,
        }
    }
}

pub fn analyze_feature_creep(
    manifest: &CarnotManifest,
    sdk_metrics: &HashMap<String, ToggleMetricsCounter>,
) -> Vec<CreepFinding> {
    analyze_feature_creep_with_rollout(manifest, sdk_metrics, 0, None)
}

pub fn analyze_feature_creep_with_rollout(
    manifest: &CarnotManifest,
    sdk_metrics: &HashMap<String, ToggleMetricsCounter>,
    canary_rollout_pct: u32,
    canary_variant_id: Option<&str>,
) -> Vec<CreepFinding> {
    let mut findings = Vec::new();

    // 1. Check pairwise input/output type overlap across organs
    for i in 0..manifest.organs.len() {
        for j in (i + 1)..manifest.organs.len() {
            let a = &manifest.organs[i];
            let b = &manifest.organs[j];
            let a_types: HashSet<&str> = a
                .inputs
                .iter()
                .chain(a.outputs.iter())
                .map(|s| s.as_str())
                .collect();
            let b_types: HashSet<&str> = b
                .inputs
                .iter()
                .chain(b.outputs.iter())
                .map(|s| s.as_str())
                .collect();
            let shared = a_types.intersection(&b_types).count();
            if shared > 0 {
                findings.push(CreepFinding {
                    id: format!("creep-overlap-{}-{}", a.id, b.id),
                    kind: CreepKind::OverlappingOrganResponsibility,
                    involved_organs: vec![a.id.clone(), b.id.clone()],
                    headline: format!(
                        "Organs '{}' and '{}' share {} boundary schema type(s)",
                        a.id, b.id, shared
                    ),
                    consolidation_action: format!(
                        "Inline shared boundary adapter between '{}' and '{}' to eliminate duplicate serialization.",
                        a.id, b.id
                    ),
                    estimated_surface_reduction_pct: 18,
                });
            }
        }
    }

    // 2. Check excess bridge hops vs organ count
    if manifest.bridges.len() > manifest.organs.len() {
        findings.push(CreepFinding {
            id: "creep-bridge-chatter".to_string(),
            kind: CreepKind::ExcessBridgeIndirection,
            involved_organs: manifest.organs.iter().map(|o| o.id.clone()).collect(),
            headline: format!(
                "{} bridges connecting {} organs exceeds 1:1 linear pipeline budget",
                manifest.bridges.len(),
                manifest.organs.len()
            ),
            consolidation_action:
                "Collapse cyclic bridge callbacks into a single shared state struct.".to_string(),
            estimated_surface_reduction_pct: 24,
        });
    }

    // 3. Check per-organ feature flags with zero live hits when traffic exists
    let any_traffic = sdk_metrics.values().any(|m| m.yes + m.no > 0);
    if any_traffic {
        for org in &manifest.organs {
            let flag_key = format!("organ.{}.enabled", org.id);
            let hits = sdk_metrics
                .get(&flag_key)
                .map(|m| m.yes + m.no)
                .unwrap_or(0);
            if hits == 0 {
                findings.push(CreepFinding {
                    id: format!("creep-unused-{}", org.id),
                    kind: CreepKind::UnexercisedFeatureFlag,
                    involved_organs: vec![org.id.clone()],
                    headline: format!("Per-organ flag '{}' has 0 runtime evaluations", flag_key),
                    consolidation_action: format!(
                        "Keep '{}' gated off or prune before 1.0 release unless exercised by acceptance tests.",
                        org.id
                    ),
                    estimated_surface_reduction_pct: 15,
                });
            }
        }
    }

    // 4. Stale 100%-rolled-out cutover flag ready to inline as permanent control
    if canary_rollout_pct >= 100 {
        if let Some(cid) = canary_variant_id {
            let eval_count = sdk_metrics
                .get("carnot.cutover.v2")
                .map(|m| m.yes + m.no)
                .unwrap_or(0);
            if eval_count >= 10 {
                findings.push(CreepFinding {
                    id: format!("creep-stale-cutover-{}", cid),
                    kind: CreepKind::StaleFullyRolledOutFlag,
                    involved_organs: manifest.organs.iter().map(|o| o.id.clone()).collect(),
                    headline: format!(
                        "Canary '{}' has been at 100% rollout across {} evaluations without rollback",
                        cid, eval_count
                    ),
                    consolidation_action: format!(
                        "Promote '{}' to permanent control_variant_id and retire legacy fallback branch.",
                        cid
                    ),
                    estimated_surface_reduction_pct: 30,
                });
            }
        }
    }

    findings
}

/// Audits candidate/evolved source code against `SourceEntropyBudget` to prevent bloated LLM mutations.
pub fn audit_source_entropy(code: &str, budget: SourceEntropyBudget) -> SourceEntropyReport {
    let mut total_loc = 0usize;
    let mut function_count = 0usize;
    let mut max_function_loc = 0usize;
    let mut current_fn_loc = 0usize;
    let mut in_fn = false;
    let mut brace_depth = 0isize;
    let mut fn_entry_depth = 0isize;
    let mut max_branch_depth = 0usize;

    for raw_line in code.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        total_loc += 1;

        let starts_fn = trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("pub async fn ")
            || trimmed.starts_with("async fn ")
            || trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("func ")
            || trimmed.starts_with("function ")
            || trimmed.starts_with("export function ");

        if starts_fn {
            if in_fn && current_fn_loc > max_function_loc {
                max_function_loc = current_fn_loc;
            }
            function_count += 1;
            in_fn = true;
            current_fn_loc = 1;
            fn_entry_depth = brace_depth;
        } else if in_fn {
            current_fn_loc += 1;
        }

        let opens = trimmed.bytes().filter(|&b| b == b'{').count() as isize;
        let closes = trimmed.bytes().filter(|&b| b == b'}').count() as isize;
        brace_depth = (brace_depth + opens - closes).max(0);
        let rel_depth = (brace_depth - fn_entry_depth).max(0) as usize;
        if rel_depth > max_branch_depth {
            max_branch_depth = rel_depth;
        }
        if in_fn && closes > 0 && brace_depth <= fn_entry_depth && current_fn_loc > 1 {
            if current_fn_loc > max_function_loc {
                max_function_loc = current_fn_loc;
            }
            in_fn = false;
            current_fn_loc = 0;
        }
    }
    if in_fn && current_fn_loc > max_function_loc {
        max_function_loc = current_fn_loc;
    }

    let mut violations = Vec::new();
    if total_loc > budget.max_total_loc {
        violations.push(format!(
            "total_loc {} > budget {}",
            total_loc, budget.max_total_loc
        ));
    }
    if function_count > budget.max_functions {
        violations.push(format!(
            "function_count {} > budget {}",
            function_count, budget.max_functions
        ));
    }
    if max_function_loc > budget.max_function_loc {
        violations.push(format!(
            "max_function_loc {} > budget {}",
            max_function_loc, budget.max_function_loc
        ));
    }
    if max_branch_depth > budget.max_branch_depth {
        violations.push(format!(
            "max_branch_depth {} > budget {}",
            max_branch_depth, budget.max_branch_depth
        ));
    }

    SourceEntropyReport {
        total_loc,
        function_count,
        max_function_loc,
        max_branch_depth,
        within_budget: violations.is_empty(),
        violation_reason: if violations.is_empty() {
            None
        } else {
            Some(violations.join("; "))
        },
    }
}
