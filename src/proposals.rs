//! Shared App Shell State, Persistent Chat Thread, Accept/Decline Proposal Cards,
//! Lossless Snapshot Undo & LCS Intra-Line Diff Engine.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppScreen {
    Home,
    Workbench,
    Settings,
}

impl AppScreen {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "home" | "landing" => Self::Home,
            "settings" => Self::Settings,
            _ => Self::Workbench,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkbenchPane {
    WiringMap,
    Dossier,
    Shootout,
    Prune,
    Cutover,
    Receipts,
}

impl WorkbenchPane {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "wiring" | "wiring_map" | "graph" => Self::WiringMap,
            "dossier" | "code" => Self::Dossier,
            "shootout" | "verify" | "pareto" => Self::Shootout,
            "prune" | "creep" => Self::Prune,
            "cutover" | "canary" => Self::Cutover,
            "receipts" | "evidence" => Self::Receipts,
            _ => Self::WiringMap,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalState {
    Pending,
    Accepted,
    Declined,
    Undone,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalAction {
    ConfirmIdeaBlueprint {
        project_name: String,
        added_organ_id: String,
        added_capability: String,
    },
    ConsolidateOrgans {
        remove_organ_id: String,
        rationale: String,
    },
    PromoteWinnerToCanary {
        variant_id: String,
        rollout_pct: u32,
    },
    /// StageOnly worktree win awaiting human Accept → `promote_staged_trial`.
    PromoteStagedOrgan {
        trial_id: String,
        staged_rel_dir: String,
        organ_rel_path: String,
        baseline_objective: f64,
        achieved_objective: f64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffLineKind {
    Context,
    Removed,
    Added,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedSpan {
    pub start_col: usize,
    pub end_col: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffLine {
    pub kind: DiffLineKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_lineno: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_lineno: Option<usize>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_span: Option<ChangedSpan>,
}

/// Computes an exact Longest Common Subsequence (`LCS`) unified line diff between `before` and `after`,
/// annotating adjacent `Removed`/`Added` line pairs with intra-line `changed_span` column offsets.
pub fn compute_lcs_line_diff(before: &str, after: &str) -> Vec<DiffLine> {
    let old_lines: Vec<&str> = before.lines().collect();
    let new_lines: Vec<&str> = after.lines().collect();
    let n = old_lines.len();
    let m = new_lines.len();

    if n == 0 && m == 0 {
        return Vec::new();
    }

    // Guard against quadratic blowup on huge files (>600 lines) with prefix/suffix anchor + linear body
    let mut raw_ops: Vec<DiffLine> = if n.saturating_mul(m) > 360_000 {
        let mut fallback = Vec::with_capacity(n + m);
        for (i, &l) in old_lines.iter().enumerate() {
            fallback.push(DiffLine {
                kind: DiffLineKind::Removed,
                old_lineno: Some(i + 1),
                new_lineno: None,
                text: l.to_string(),
                changed_span: None,
            });
        }
        for (j, &l) in new_lines.iter().enumerate() {
            fallback.push(DiffLine {
                kind: DiffLineKind::Added,
                old_lineno: None,
                new_lineno: Some(j + 1),
                text: l.to_string(),
                changed_span: None,
            });
        }
        fallback
    } else {
        let cols = m + 1;
        let mut dp = vec![0u32; (n + 1) * cols];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                dp[i * cols + j] = if old_lines[i] == new_lines[j] {
                    dp[(i + 1) * cols + (j + 1)] + 1
                } else {
                    dp[(i + 1) * cols + j].max(dp[i * cols + (j + 1)])
                };
            }
        }

        let mut res = Vec::with_capacity(n + m);
        let (mut i, mut j) = (0usize, 0usize);
        while i < n && j < m {
            if old_lines[i] == new_lines[j] {
                res.push(DiffLine {
                    kind: DiffLineKind::Context,
                    old_lineno: Some(i + 1),
                    new_lineno: Some(j + 1),
                    text: old_lines[i].to_string(),
                    changed_span: None,
                });
                i += 1;
                j += 1;
            } else if dp[(i + 1) * cols + j] >= dp[i * cols + (j + 1)] {
                res.push(DiffLine {
                    kind: DiffLineKind::Removed,
                    old_lineno: Some(i + 1),
                    new_lineno: None,
                    text: old_lines[i].to_string(),
                    changed_span: None,
                });
                i += 1;
            } else {
                res.push(DiffLine {
                    kind: DiffLineKind::Added,
                    old_lineno: None,
                    new_lineno: Some(j + 1),
                    text: new_lines[j].to_string(),
                    changed_span: None,
                });
                j += 1;
            }
        }
        while i < n {
            res.push(DiffLine {
                kind: DiffLineKind::Removed,
                old_lineno: Some(i + 1),
                new_lineno: None,
                text: old_lines[i].to_string(),
                changed_span: None,
            });
            i += 1;
        }
        while j < m {
            res.push(DiffLine {
                kind: DiffLineKind::Added,
                old_lineno: None,
                new_lineno: Some(j + 1),
                text: new_lines[j].to_string(),
                changed_span: None,
            });
            j += 1;
        }
        res
    };

    // Annotate intra-line `changed_span` for adjacent (Removed, Added) pairs
    let mut idx = 0usize;
    while idx + 1 < raw_ops.len() {
        if raw_ops[idx].kind == DiffLineKind::Removed
            && raw_ops[idx + 1].kind == DiffLineKind::Added
        {
            let (old_span, new_span) =
                compute_intraline_spans(&raw_ops[idx].text, &raw_ops[idx + 1].text);
            raw_ops[idx].changed_span = old_span;
            raw_ops[idx + 1].changed_span = new_span;
            idx += 2;
        } else {
            idx += 1;
        }
    }

    raw_ops
}

fn compute_intraline_spans(
    old_line: &str,
    new_line: &str,
) -> (Option<ChangedSpan>, Option<ChangedSpan>) {
    let old_chars: Vec<char> = old_line.chars().collect();
    let new_chars: Vec<char> = new_line.chars().collect();
    let mut prefix = 0usize;
    while prefix < old_chars.len()
        && prefix < new_chars.len()
        && old_chars[prefix] == new_chars[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < (old_chars.len() - prefix)
        && suffix < (new_chars.len() - prefix)
        && old_chars[old_chars.len() - 1 - suffix] == new_chars[new_chars.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let old_end = old_chars.len() - suffix;
    let new_end = new_chars.len() - suffix;
    let old_span = (prefix < old_end).then_some(ChangedSpan {
        start_col: prefix,
        end_col: old_end,
    });
    let new_span = (prefix < new_end).then_some(ChangedSpan {
        start_col: prefix,
        end_col: new_end,
    });
    (old_span, new_span)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalCard {
    pub id: String,
    pub author_agent: String,
    pub title: String,
    pub summary: String,
    pub impact_badge: String,
    pub state: ProposalState,
    pub action: ProposalAction,
    #[serde(default)]
    pub can_undo: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff_lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatEntry {
    pub seq: u64,
    pub author: String,
    pub role: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppShellState {
    pub active_screen: AppScreen,
    pub active_pane: WorkbenchPane,
    pub selected_organ_id: String,
    pub active_agent_id: String,
    pub chat: Vec<ChatEntry>,
    pub proposals: Vec<ProposalCard>,
    next_msg_seq: u64,
}

impl AppShellState {
    pub fn new_seeded(default_agent: &str) -> Self {
        let mut s = Self {
            active_screen: AppScreen::Home,
            active_pane: WorkbenchPane::WiringMap,
            selected_organ_id: "verifier".to_string(),
            active_agent_id: default_agent.to_string(),
            chat: Vec::new(),
            proposals: Vec::new(),
            next_msg_seq: 1,
        };

        let prop_id = "prop-001".to_string();
        let diff_lines = compute_lcs_line_diff(
            "canary_variant = \"none\"\ncanary_rollout_pct = 0",
            "canary_variant = \"v2-carnot-consolidated\"\ncanary_rollout_pct = 25",
        );
        s.proposals.push(ProposalCard {
            id: prop_id.clone(),
            author_agent: default_agent.to_string(),
            title: "Confirm Consolidated 3-Organ Blueprint".to_string(),
            summary: "Lock verifier + MurmurHash3 router + SHA-256 provenance ledger into Carnot.toml and provision per-organ feature flags.".to_string(),
            impact_badge: "-406 restricted files quarantined".to_string(),
            state: ProposalState::Pending,
            action: ProposalAction::PromoteWinnerToCanary {
                variant_id: "v2-carnot-consolidated".to_string(),
                rollout_pct: 25,
            },
            can_undo: false,
            before_snapshot: None,
            after_snapshot: None,
            diff_lines,
        });

        s.push_message(
            default_agent,
            "agent",
            "Ready. Describe an app idea on Home to brainstorm a blueprint, type `/` for playbooks, toggle Black-Box Shield ON/OFF, or accept the staged shootout winner below.",
            Some(prop_id),
        );
        s
    }

    pub fn push_message(
        &mut self,
        author: &str,
        role: &str,
        text: impl Into<String>,
        proposal_id: Option<String>,
    ) {
        let seq = self.next_msg_seq;
        self.next_msg_seq += 1;
        self.chat.push(ChatEntry {
            seq,
            author: author.to_string(),
            role: role.to_string(),
            text: text.into(),
            proposal_id,
        });
        if self.chat.len() > 80 {
            self.chat.remove(0);
        }
    }
}
