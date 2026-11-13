//! Function Foundry daemon orchestration (point → gym → trial → stage/ratchet).

use crate::worktree::WorktreeTrialResult;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PromoteMode {
    StageOnly,
    #[default]
    AutoRatchet,
}

/// How a pointed target is addressed. v1 product surfaces only accept WorkspaceDir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// v1 required. Daemon + experiments ship against this first.
    WorkspaceDir,
    /// v1.1 adapters — types exist, product surfaces may stay unused until E1/E2 green.
    CliBinary {
        program: String,
        args_prefix: Vec<String>,
    },
    HttpBase {
        base_url: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointedTarget {
    pub kind: TargetKind,
    /// Workspace that owns `.carnot/`.
    pub root: PathBuf,
    pub black_box_enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonPolicy {
    pub max_concurrent_worktrees: usize,
    pub max_trials_per_hour: usize,
    pub require_human_accept: bool,
    pub allow_offline_demo_fallback: bool,
    pub tick_sleep_ms: u64,
}

impl Default for DaemonPolicy {
    fn default() -> Self {
        Self {
            max_concurrent_worktrees: 1,
            max_trials_per_hour: 12,
            require_human_accept: true,
            allow_offline_demo_fallback: false,
            tick_sleep_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonTickReport {
    pub organ_id: Option<String>,
    pub trial: Option<WorktreeTrialResult>,
    /// True only when primary organ bytes were updated this tick.
    pub ratcheted: bool,
    /// Set when a measured win was staged awaiting Accept.
    pub staged_trial_id: Option<String>,
    pub proposal_id: Option<String>,
    pub skipped_reason: Option<String>,
    pub receipt_ids: Vec<String>,
}

/// Process-local trial budget (inflight leases + rolling hourly timestamps).
#[derive(Debug, Clone, Default)]
pub struct TrialBudgetState {
    pub inflight: usize,
    pub trial_timestamps_ms: Vec<u64>,
}

/// Opaque lease held for a trial lifetime. Drop decrements `inflight`.
///
/// Uses a raw pointer so callers can re-borrow `&mut TrialBudgetState` while a
/// guard is still alive (e.g. to attempt a second acquire and observe the cap).
pub struct TrialLeaseGuard {
    budget: *mut TrialBudgetState,
}

// `TrialLeaseGuard` stays `!Send`. The raw pointer aliases caller-owned
// `TrialBudgetState` and is only dereferenced on the thread that acquired it.

impl Drop for TrialLeaseGuard {
    fn drop(&mut self) {
        if self.budget.is_null() {
            return;
        }
        // SAFETY: budget remains valid for the guard's lifetime; acquire only
        // hands out pointers to caller-owned TrialBudgetState.
        unsafe {
            (*self.budget).inflight = (*self.budget).inflight.saturating_sub(1);
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

const ONE_HOUR_MS: u64 = 60 * 60 * 1000;

/// Non-mutating check: returns `Some(reason)` when a lease would be denied.
pub fn trial_lease_denied_reason(
    policy: &DaemonPolicy,
    budget: &TrialBudgetState,
) -> Option<String> {
    if budget.inflight >= policy.max_concurrent_worktrees {
        return Some(format!(
            "trial lease denied: max_concurrent_worktrees={} already inflight={}",
            policy.max_concurrent_worktrees, budget.inflight
        ));
    }

    let now = now_ms();
    let recent = budget
        .trial_timestamps_ms
        .iter()
        .filter(|&&ts| now.saturating_sub(ts) < ONE_HOUR_MS)
        .count();
    if recent >= policy.max_trials_per_hour {
        return Some(format!(
            "trial lease denied: max_trials_per_hour={} already used in the last hour",
            policy.max_trials_per_hour
        ));
    }
    None
}

/// Acquire a trial lease before spawning a worktree. Fails closed when
/// concurrent or rolling hourly caps would be exceeded.
pub fn acquire_trial_lease(
    policy: &DaemonPolicy,
    budget: &mut TrialBudgetState,
) -> Result<TrialLeaseGuard, String> {
    let now = now_ms();
    budget
        .trial_timestamps_ms
        .retain(|&ts| now.saturating_sub(ts) < ONE_HOUR_MS);
    if let Some(reason) = trial_lease_denied_reason(policy, budget) {
        return Err(reason);
    }

    budget.inflight += 1;
    budget.trial_timestamps_ms.push(now);
    Ok(TrialLeaseGuard {
        budget: budget as *mut TrialBudgetState,
    })
}

fn looks_like_url(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let lower = s.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("file://")
}

/// Build a v1 WorkspaceDir pointed target. Rejects non-directories and URLs.
pub fn build_pointed_workspace(
    path: &Path,
    black_box_enforced: bool,
) -> Result<PointedTarget, String> {
    if looks_like_url(path) {
        return Err(format!(
            "point target rejects URLs in v1 (got '{}'); pass a workspace directory",
            path.display()
        ));
    }
    if !path.exists() {
        return Err(format!(
            "point target path does not exist: {}",
            path.display()
        ));
    }
    if !path.is_dir() {
        return Err(format!(
            "point target must be a directory (got '{}')",
            path.display()
        ));
    }
    Ok(PointedTarget {
        kind: TargetKind::WorkspaceDir,
        root: path.to_path_buf(),
        black_box_enforced,
    })
}

/// Prefer the first hotspot that appears in the manifest; else the first
/// manifest organ; else `None`.
pub fn select_next_organ_id(
    manifest_organ_ids: &[String],
    hotspot_ids: &[String],
) -> Option<String> {
    for hot in hotspot_ids {
        if manifest_organ_ids.iter().any(|id| id == hot) {
            return Some(hot.clone());
        }
    }
    manifest_organ_ids.first().cloned()
}
