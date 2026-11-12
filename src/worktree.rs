//! Isolated Airgapped `git worktree` Organ Mutation & Subprocess Verification Runner.
//!
//! Executes candidate organ mutations safely on disk without polluting the primary working tree:
//! 1. Measures baseline objective in `repo_dir` via `evaluate_json_command_in_dir`.
//! 2. Creates a temporary detached git worktree at `<repo_dir>/.carnot/worktrees/trial-<id>` and,
//!    when `black_box_enforced == true`, physically purges `.carnot/quarantine` and restricted
//!    directories from the worktree before any coding agent runs inside it.
//! 3. Supports BOTH stdout-emitting headless agents AND disk-editing coding agents (`claude`, `codex`,
//!    `gemini`, `opencode`), verifying byte-for-byte outer harness identity via
//!    `verify_outer_harness_and_extract_body` and running a 1-shot `<untrusted_evaluation_error>`
//!    `Repair` retry when tests fail.
//! 4. Enforces Clean-Room 5-gram similarity (`passes_clean_room_ngram_gate`) and `SourceEntropyBudget`.
//! 5. Applies ratchet-only promotion and always cleans up via an RAII `Drop` guard.

use crate::agents::invoke_headless_agent;
use crate::daemon::PromoteMode;
use crate::evidence::{EvidenceKind, EvidenceLedger};
use crate::evolve::{
    build_operator_prompt, evaluate_json_command_in_dir, extract_evolve_blocks,
    passes_clean_room_ngram_gate, splice_evolve_block, verify_outer_harness_and_extract_body,
    PromptOperator, SubprocessEvalOutcome,
};
use crate::prune::{audit_source_entropy, SourceEntropyBudget};
use crate::recipe::OrganSpec;
use crate::workspace::{append_jsonl, WorkspaceLayout};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TRIAL_SEQ: AtomicU64 = AtomicU64::new(1);

pub enum CandidateSource<'a> {
    ExplicitBlock(&'a str),
    HeadlessAgent {
        agent_id: &'a str,
        custom_program_and_args: Option<(&'a str, &'a [&'a str])>,
        timeout_ms: u64,
    },
}

pub struct WorktreeTrialRequest<'a> {
    pub repo_dir: &'a Path,
    pub organ: &'a OrganSpec,
    pub organ_rel_path: &'a str,
    pub block_index: usize,
    pub candidate_source: CandidateSource<'a>,
    pub test_program: &'a str,
    pub test_args: &'a [&'a str],
    pub bench_program: &'a str,
    pub bench_args: &'a [&'a str],
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorktreeSecurityOptions {
    pub black_box_enforced: bool,
    pub quarantined_rel_paths: Vec<String>,
    pub forbidden_ngram_corpora: Vec<String>,
    pub max_ngram_similarity: f64,
    pub entropy_budget: Option<SourceEntropyBudget>,
    pub allow_one_shot_repair: bool,
    pub promote_mode: PromoteMode,
}

impl Default for WorktreeSecurityOptions {
    fn default() -> Self {
        Self {
            black_box_enforced: true,
            quarantined_rel_paths: vec![".carnot/quarantine".to_string()],
            forbidden_ngram_corpora: Vec::new(),
            max_ngram_similarity: 0.35,
            entropy_budget: None,
            allow_one_shot_repair: true,
            promote_mode: PromoteMode::AutoRatchet,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorktreeTrialResult {
    pub trial_id: String,
    pub organ_id: String,
    pub organ_rel_path: String,
    pub tests_passed: bool,
    pub baseline_objective: f64,
    pub candidate_eval: SubprocessEvalOutcome,
    pub ratcheted_baseline: bool,
    pub worktree_cleaned_up: bool,
    pub receipt_id: Option<String>,
    pub diagnostic: String,
    pub staged_rel_dir: Option<String>,
}

/// Git invocations that check out trial files must not rewrite LF fixtures to CRLF.
fn git_lf() -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("core.autocrlf=false");
    cmd
}

struct WorktreeCleanupGuard {
    repo_dir: PathBuf,
    wt_dir: PathBuf,
}

impl Drop for WorktreeCleanupGuard {
    fn drop(&mut self) {
        let wt_str = self.wt_dir.to_string_lossy().into_owned();
        let _ = git_lf()
            .args(["worktree", "remove", "--force", &wt_str])
            .current_dir(&self.repo_dir)
            .output();
        if self.wt_dir.exists() {
            let _ = fs::remove_dir_all(&self.wt_dir);
        }
        let _ = git_lf()
            .args(["worktree", "prune"])
            .current_dir(&self.repo_dir)
            .output();
    }
}

pub fn run_git_worktree_trial(
    req: WorktreeTrialRequest<'_>,
) -> Result<WorktreeTrialResult, String> {
    run_git_worktree_trial_secured(req, &WorktreeSecurityOptions::default())
}

pub fn run_git_worktree_trial_secured(
    req: WorktreeTrialRequest<'_>,
    security: &WorktreeSecurityOptions,
) -> Result<WorktreeTrialResult, String> {
    if !req.repo_dir.join(".git").exists() {
        return Err(format!(
            "Target directory '{}' is not a git repository",
            req.repo_dir.display()
        ));
    }

    let baseline_eval = evaluate_json_command_in_dir(
        req.bench_program,
        req.bench_args,
        Some(req.repo_dir),
        req.timeout_ms,
    );
    if !baseline_eval.success {
        return Err(format!(
            "Baseline benchmark failed in '{}': {}",
            req.repo_dir.display(),
            baseline_eval
                .error_message
                .unwrap_or_else(|| "unknown error".to_string())
        ));
    }
    let baseline_objective = baseline_eval.raw_objective;

    let seq = TRIAL_SEQ.fetch_add(1, Ordering::Relaxed);
    let trial_id = format!("trial-{}-{}", std::process::id(), seq);
    let wt_parent = req.repo_dir.join(".carnot").join("worktrees");
    fs::create_dir_all(&wt_parent).map_err(|e| format!("Failed to create worktrees dir: {}", e))?;
    let wt_dir = wt_parent.join(&trial_id);
    let wt_str = wt_dir.to_string_lossy().into_owned();

    let add_out = git_lf()
        .args(["worktree", "add", "--detach", &wt_str, "HEAD"])
        .current_dir(req.repo_dir)
        .output()
        .map_err(|e| format!("Failed to invoke `git worktree add`: {}", e))?;
    if !add_out.status.success() {
        return Err(format!(
            "`git worktree add` failed: {}",
            String::from_utf8_lossy(&add_out.stderr).trim()
        ));
    }

    let guard = WorktreeCleanupGuard {
        repo_dir: req.repo_dir.to_path_buf(),
        wt_dir: wt_dir.clone(),
    };

    // Airgap worktree when Black-Box Clean-Room Shield is ON
    if security.black_box_enforced {
        purge_quarantined_paths(&wt_dir, &security.quarantined_rel_paths);
    }

    let wt_organ_path = wt_dir.join(req.organ_rel_path);
    let original_source = fs::read_to_string(&wt_organ_path).map_err(|e| {
        format!(
            "Failed to read organ file '{}' in worktree: {}",
            wt_organ_path.display(),
            e
        )
    })?;
    let orig_blocks = extract_evolve_blocks(&original_source, 4)?;
    let target_block = orig_blocks
        .get(req.block_index)
        .ok_or_else(|| format!("Block index {} out of range", req.block_index))?
        .clone();

    let mut candidate_code = match req.candidate_source {
        CandidateSource::ExplicitBlock(code) => code.to_string(),
        CandidateSource::HeadlessAgent {
            agent_id,
            custom_program_and_args,
            timeout_ms,
        } => {
            let op_prompt = build_operator_prompt(
                req.organ,
                PromptOperator::M1MutateStructural,
                &target_block,
                &[(&target_block.body, baseline_objective)],
                None,
                &[],
            );
            let agent_out = invoke_headless_agent(
                agent_id,
                &op_prompt.prompt_text,
                &wt_dir,
                timeout_ms,
                custom_program_and_args,
            );
            if !agent_out.exit_ok {
                drop(guard);
                return Ok(WorktreeTrialResult {
                    trial_id,
                    organ_id: req.organ.id.clone(),
                    organ_rel_path: req.organ_rel_path.to_string(),
                    tests_passed: false,
                    baseline_objective,
                    candidate_eval: SubprocessEvalOutcome {
                        success: false,
                        validity: 0.0,
                        raw_objective: 0.0,
                        duration_ms: agent_out.duration_ms,
                        error_message: agent_out.error_message.clone(),
                    },
                    ratcheted_baseline: false,
                    worktree_cleaned_up: !wt_dir.exists(),
                    receipt_id: None,
                    diagnostic: agent_out
                        .error_message
                        .unwrap_or_else(|| "Agent exited non-zero".to_string()),
                    staged_rel_dir: None,
                });
            }

            // Support BOTH disk-editing agents (verify outer harness byte identity!) AND stdout-emitting agents
            let post_agent_disk = fs::read_to_string(&wt_organ_path).unwrap_or_default();
            if post_agent_disk != original_source {
                match verify_outer_harness_and_extract_body(
                    &original_source,
                    &post_agent_disk,
                    req.block_index,
                ) {
                    Ok(extracted_inner) => {
                        // Reset any stray edits outside the organ file before re-splicing cleanly
                        let _ = git_lf()
                            .args(["checkout", "--", "."])
                            .current_dir(&wt_dir)
                            .output();
                        if security.black_box_enforced {
                            purge_quarantined_paths(&wt_dir, &security.quarantined_rel_paths);
                        }
                        extracted_inner
                    }
                    Err(harness_err) => {
                        drop(guard);
                        return Ok(WorktreeTrialResult {
                            trial_id,
                            organ_id: req.organ.id.clone(),
                            organ_rel_path: req.organ_rel_path.to_string(),
                            tests_passed: false,
                            baseline_objective,
                            candidate_eval: SubprocessEvalOutcome {
                                success: false,
                                validity: 0.0,
                                raw_objective: 0.0,
                                duration_ms: agent_out.duration_ms,
                                error_message: Some(harness_err.clone()),
                            },
                            ratcheted_baseline: false,
                            worktree_cleaned_up: !wt_dir.exists(),
                            receipt_id: None,
                            diagnostic: format!("Rejected candidate: {}", harness_err),
                            staged_rel_dir: None,
                        });
                    }
                }
            } else {
                agent_out.extracted_code
            }
        }
    };

    let mut spliced = splice_evolve_block(&original_source, req.block_index, &candidate_code)?;
    fs::write(&wt_organ_path, &spliced)
        .map_err(|e| format!("Failed to write spliced organ file in worktree: {}", e))?;

    let (mut tests_passed, mut test_diag) =
        run_command_in_dir_with_timeout(req.test_program, req.test_args, &wt_dir, req.timeout_ms);

    // 1-Shot `<untrusted_evaluation_error>` Repair retry for HeadlessAgent trials
    if !tests_passed && security.allow_one_shot_repair {
        if let CandidateSource::HeadlessAgent {
            agent_id,
            custom_program_and_args,
            timeout_ms,
        } = req.candidate_source
        {
            let repair_prompt = build_operator_prompt(
                req.organ,
                PromptOperator::Repair,
                &target_block,
                &[(&candidate_code, 0.0)],
                Some(&test_diag),
                &[],
            );
            fs::write(&wt_organ_path, &original_source).ok();
            let repair_out = invoke_headless_agent(
                agent_id,
                &repair_prompt.prompt_text,
                &wt_dir,
                timeout_ms,
                custom_program_and_args,
            );
            if repair_out.exit_ok {
                let post_disk = fs::read_to_string(&wt_organ_path).unwrap_or_default();
                let repaired_body = if post_disk != original_source {
                    verify_outer_harness_and_extract_body(
                        &original_source,
                        &post_disk,
                        req.block_index,
                    )
                    .ok()
                } else if !repair_out.extracted_code.trim().is_empty() {
                    Some(repair_out.extracted_code)
                } else {
                    None
                };
                if let Some(new_body) = repaired_body {
                    if let Ok(new_spliced) =
                        splice_evolve_block(&original_source, req.block_index, &new_body)
                    {
                        if fs::write(&wt_organ_path, &new_spliced).is_ok() {
                            let (re_ok, re_diag) = run_command_in_dir_with_timeout(
                                req.test_program,
                                req.test_args,
                                &wt_dir,
                                req.timeout_ms,
                            );
                            if re_ok {
                                candidate_code = new_body;
                                spliced = new_spliced;
                                tests_passed = true;
                                test_diag = re_diag;
                            }
                        }
                    }
                }
            }
        }
    }

    // Clean-Room n-gram non-copying gate & SourceEntropyBudget gate
    let ngram_ok = if security.black_box_enforced && !security.forbidden_ngram_corpora.is_empty() {
        passes_clean_room_ngram_gate(
            &candidate_code,
            &security.forbidden_ngram_corpora,
            security.max_ngram_similarity,
        )
    } else {
        true
    };
    let entropy_ok = if let Some(ref budget) = security.entropy_budget {
        audit_source_entropy(&candidate_code, *budget).within_budget
    } else {
        true
    };

    let candidate_eval = if !ngram_ok {
        SubprocessEvalOutcome {
            success: false,
            validity: 0.0,
            raw_objective: 0.0,
            duration_ms: 0,
            error_message: Some(
                "Clean-room 5-gram similarity exceeded maximum threshold".to_string(),
            ),
        }
    } else if !entropy_ok {
        SubprocessEvalOutcome {
            success: false,
            validity: 0.0,
            raw_objective: 0.0,
            duration_ms: 0,
            error_message: Some("Candidate exceeded SourceEntropyBudget".to_string()),
        }
    } else if tests_passed {
        evaluate_json_command_in_dir(
            req.bench_program,
            req.bench_args,
            Some(&wt_dir),
            req.timeout_ms,
        )
    } else {
        SubprocessEvalOutcome {
            success: false,
            validity: 0.0,
            raw_objective: 0.0,
            duration_ms: 0,
            error_message: Some(format!("Test suite failed: {}", test_diag)),
        }
    };

    let mut ratcheted_baseline = false;
    let mut receipt_id = None;
    let mut staged_rel_dir = None;
    let diagnostic = if ngram_ok
        && entropy_ok
        && tests_passed
        && candidate_eval.success
        && candidate_eval.raw_objective > baseline_objective
    {
        match security.promote_mode {
            PromoteMode::AutoRatchet => {
                let primary_organ_path = req.repo_dir.join(req.organ_rel_path);
                fs::write(&primary_organ_path, &spliced)
                    .map_err(|e| format!("Failed to ratchet primary organ file: {}", e))?;
                ratcheted_baseline = true;

                let layout = WorkspaceLayout::at(req.repo_dir);
                let mut ledger = EvidenceLedger::new();
                let rec = ledger.record(
                    EvidenceKind::Derived,
                    format!("worktree_ratchet_{}", req.organ.id),
                    format!(
                        "Ratcheted '{}' in '{}' ({:.4} -> {:.4})",
                        req.organ.id,
                        req.organ_rel_path,
                        baseline_objective,
                        candidate_eval.raw_objective
                    ),
                    None,
                    &json!({
                        "trial_id": trial_id,
                        "organ_id": req.organ.id,
                        "organ_rel_path": req.organ_rel_path,
                        "black_box_enforced": security.black_box_enforced,
                        "baseline_objective": baseline_objective,
                        "achieved_objective": candidate_eval.raw_objective,
                        "duration_ms": candidate_eval.duration_ms,
                        "spliced_code": candidate_code,
                    }),
                );
                receipt_id = Some(rec.id.clone());
                let rec_val = serde_json::to_value(&rec).unwrap_or_else(|_| json!({}));
                let _ = append_jsonl(&layout.ledger_jsonl, &rec_val);
                format!(
                    "Ratcheted baseline {:.4} -> {:.4} (tests PASS)",
                    baseline_objective, candidate_eval.raw_objective
                )
            }
            PromoteMode::StageOnly => {
                let staged_rel = format!(".carnot/staged/{}", trial_id);
                let staged_root = req.repo_dir.join(&staged_rel);
                if let Some(parent) = staged_root.join(req.organ_rel_path).parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create staged dir: {}", e))?;
                } else {
                    fs::create_dir_all(&staged_root)
                        .map_err(|e| format!("Failed to create staged dir: {}", e))?;
                }
                let staged_organ = staged_root.join(req.organ_rel_path);
                if let Some(parent) = staged_organ.parent() {
                    fs::create_dir_all(parent).ok();
                }
                fs::write(&staged_organ, &spliced)
                    .map_err(|e| format!("Failed to write staged organ: {}", e))?;
                let meta = json!({
                    "trial_id": trial_id,
                    "organ_id": req.organ.id,
                    "organ_rel_path": req.organ_rel_path,
                    "baseline_objective": baseline_objective,
                    "achieved_objective": candidate_eval.raw_objective,
                    "candidate_body": candidate_code,
                });
                fs::write(staged_root.join("meta.json"), meta.to_string())
                    .map_err(|e| format!("Failed to write staged meta: {}", e))?;
                staged_rel_dir = Some(staged_rel.clone());

                let layout = WorkspaceLayout::at(req.repo_dir);
                let mut ledger = EvidenceLedger::new();
                let rec = ledger.record(
                    EvidenceKind::Derived,
                    format!("worktree_staged_{}", req.organ.id),
                    format!(
                        "Staged '{}' under '.carnot/staged/{}' ({:.4} -> {:.4})",
                        req.organ.id, trial_id, baseline_objective, candidate_eval.raw_objective
                    ),
                    None,
                    &json!({
                        "trial_id": trial_id,
                        "organ_id": req.organ.id,
                        "organ_rel_path": req.organ_rel_path,
                        "black_box_enforced": security.black_box_enforced,
                        "baseline_objective": baseline_objective,
                        "achieved_objective": candidate_eval.raw_objective,
                        "duration_ms": candidate_eval.duration_ms,
                        "promote_mode": "stage_only",
                        "staged_rel_dir": staged_rel,
                        "candidate_body": candidate_code,
                    }),
                );
                receipt_id = Some(rec.id.clone());
                let rec_val = serde_json::to_value(&rec).unwrap_or_else(|_| json!({}));
                let _ = append_jsonl(&layout.ledger_jsonl, &rec_val);
                format!(
                    "Staged win {:.4} -> {:.4} under .carnot/staged/{} (primary unchanged)",
                    baseline_objective, candidate_eval.raw_objective, trial_id
                )
            }
        }
    } else if !ngram_ok {
        "Rejected candidate: clean-room 5-gram similarity gate triggered".to_string()
    } else if !entropy_ok {
        "Rejected candidate: exceeded SourceEntropyBudget".to_string()
    } else if !tests_passed {
        format!(
            "Rejected candidate: conformance tests failed ({})",
            test_diag
        )
    } else if !candidate_eval.success {
        format!(
            "Rejected candidate: benchmark invalid ({})",
            candidate_eval
                .error_message
                .clone()
                .unwrap_or_else(|| "invalid".to_string())
        )
    } else {
        format!(
            "Rejected candidate: objective {:.4} did not beat baseline {:.4}",
            candidate_eval.raw_objective, baseline_objective
        )
    };

    drop(guard);
    let worktree_cleaned_up = !wt_dir.exists();

    Ok(WorktreeTrialResult {
        trial_id,
        organ_id: req.organ.id.clone(),
        organ_rel_path: req.organ_rel_path.to_string(),
        tests_passed,
        baseline_objective,
        candidate_eval,
        ratcheted_baseline,
        worktree_cleaned_up,
        receipt_id,
        diagnostic,
        staged_rel_dir,
    })
}

fn purge_quarantined_paths(wt_dir: &Path, quarantined_rel_paths: &[String]) {
    let default_quarantine = wt_dir.join(".carnot").join("quarantine");
    if default_quarantine.exists() {
        let _ = fs::remove_dir_all(&default_quarantine);
    }
    for rel in quarantined_rel_paths {
        let clean = rel.trim_start_matches(['/', '\\']);
        if clean.is_empty() || clean.contains("..") {
            continue;
        }
        let target = wt_dir.join(clean);
        if target.is_dir() {
            let _ = fs::remove_dir_all(&target);
        } else if target.is_file() {
            let _ = fs::remove_file(&target);
        }
    }
}

fn run_command_in_dir_with_timeout(
    program: &str,
    args: &[&str],
    dir: &Path,
    timeout_ms: u64,
) -> (bool, String) {
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(dir);
    let out = crate::proc_util::run_command_bounded(
        cmd,
        None,
        timeout_ms.max(50),
        crate::proc_util::DEFAULT_MAX_STREAM_BYTES,
    );
    if !out.spawned {
        return (
            false,
            format!(
                "spawn error: {}",
                out.spawn_error.unwrap_or_else(|| "unknown".to_string())
            ),
        );
    }
    if out.timed_out {
        return (false, format!("timed out after {} ms", timeout_ms));
    }
    if out.success {
        (true, "ok".to_string())
    } else {
        (
            false,
            format!("exit {:?}: {}", out.exit_code, out.stderr.trim()),
        )
    }
}
