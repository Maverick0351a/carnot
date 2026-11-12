//! E1–E4 daemon experiments against `experiments/toy_cli`.

use carnot::bridge::{CarnotMachine, EvolveOpts};
use carnot::daemon::{acquire_trial_lease, DaemonPolicy, PromoteMode, TrialBudgetState};
use carnot::evidence::sha256_hex;
use carnot::evolve::{
    build_operator_prompt, evaluate_json_command_in_dir, extract_evolve_blocks,
    retrieve_experience_cards_ares, splice_evolve_block, ExperienceCard, ExperienceCardKind,
    IslandRole, PromptOperator,
};
use carnot::mcp::handle_jsonrpc_with_budget;
use carnot::proposals::ProposalAction;
use carnot::recipe::OrganSpec;
use carnot::tier::AccountTier;
use carnot::workspace::sanitize_workspace_rel_path;
use carnot::worktree::{
    run_git_worktree_trial_secured, CandidateSource, WorktreeSecurityOptions, WorktreeTrialRequest,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn toy_organ() -> OrganSpec {
    OrganSpec {
        id: "toy".to_string(),
        capability: "Sum of 1..n".to_string(),
        inputs: vec!["int".to_string()],
        outputs: vec!["int".to_string()],
        invariants: vec!["Correct closed or loop form".to_string()],
        conformance_suite: "test_organ.py".to_string(),
    }
}

fn sha256_file(path: impl AsRef<Path>) -> String {
    let bytes = fs::read(path.as_ref()).expect("read file for sha256");
    sha256_hex(&bytes)
}

fn run_git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("Failed to run `git {}`: {}", args.join(" "), e));
    assert!(
        out.status.success(),
        "`git {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn should_skip_copy_entry(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".pytest_cache" | "__pycache__" | ".mypy_cache" | ".ruff_cache"
    )
}

fn copy_dir_filtered(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dest dir");
    for entry in fs::read_dir(src).expect("read source dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if should_skip_copy_entry(&name_str) {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        let ft = entry.file_type().expect("file type");
        if ft.is_dir() {
            copy_dir_filtered(&from, &to);
        } else if ft.is_file() {
            fs::copy(&from, &to)
                .unwrap_or_else(|e| panic!("copy {} -> {}: {}", from.display(), to.display(), e));
        }
    }
}

/// Copy `experiments/toy_cli` into a fresh temp git repo (init + commit).
fn materialize_toy_cli_git() -> (PathBuf, TempDirGuard) {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("experiments/toy_cli");
    assert!(
        fixture.join("organ.py").is_file(),
        "toy_cli fixture missing at {}",
        fixture.display()
    );

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("carnot-toy-cli-{}-{}", std::process::id(), nanos));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create temp root");
    let guard = TempDirGuard(root.clone());

    copy_dir_filtered(&fixture, &root);

    run_git(&root, &["init"]);
    run_git(&root, &["config", "core.autocrlf", "false"]);
    run_git(&root, &["config", "user.name", "Carnot Experiment"]);
    run_git(&root, &["config", "user.email", "experiment@carnot.local"]);
    run_git(&root, &["add", "-A"]);
    run_git(&root, &["commit", "-m", "chore: toy_cli fixture baseline"]);

    (root, guard)
}

fn security(promote_mode: PromoteMode) -> WorktreeSecurityOptions {
    WorktreeSecurityOptions {
        promote_mode,
        black_box_enforced: false,
        ..Default::default()
    }
}

fn trial_request<'a>(
    root: &'a Path,
    organ: &'a OrganSpec,
    body: &'a str,
) -> WorktreeTrialRequest<'a> {
    WorktreeTrialRequest {
        repo_dir: root,
        organ,
        organ_rel_path: "organ.py",
        block_index: 0,
        candidate_source: CandidateSource::ExplicitBlock(body),
        test_program: "python",
        test_args: &["-m", "pytest", "test_organ.py", "-q"],
        bench_program: "python",
        bench_args: &["solve_bench.py"],
        timeout_ms: 30_000,
    }
}

#[test]
fn trial_lease_respects_max_concurrent() {
    let policy = DaemonPolicy {
        max_concurrent_worktrees: 1,
        max_trials_per_hour: 100,
        ..Default::default()
    };
    let mut budget = TrialBudgetState::default();
    let g1 = acquire_trial_lease(&policy, &mut budget).unwrap();
    assert!(acquire_trial_lease(&policy, &mut budget).is_err());
    drop(g1);
    assert!(acquire_trial_lease(&policy, &mut budget).is_ok());
}

#[test]
fn e1_gym_rejects_bad_organ_and_accepts_baseline() {
    let (root, _guard) = materialize_toy_cli_git();

    let base = evaluate_json_command_in_dir("python", &["solve_bench.py"], Some(&root), 10_000);
    assert!(base.success, "baseline must pass: {:?}", base.error_message);
    assert!(base.raw_objective > 0.0, "baseline objective must be > 0");

    let bad = "    return n\n";
    let organ = fs::read_to_string(root.join("organ.py")).unwrap();
    let spliced = splice_evolve_block(&organ, 0, bad).unwrap();
    fs::write(root.join("organ.py"), spliced).unwrap();

    let bad_eval = evaluate_json_command_in_dir("python", &["solve_bench.py"], Some(&root), 10_000);
    assert!(
        !bad_eval.success || bad_eval.raw_objective < base.raw_objective,
        "bad organ must fail or score worse than baseline (base={:?}, bad={:?})",
        base,
        bad_eval
    );
}

#[test]
fn e2_autoratchet_promotes_better_not_worse() {
    let organ = toy_organ();
    let better = "    return n * (n + 1) // 2\n";
    let worse_body = "    return n\n";

    let (root, _guard) = materialize_toy_cli_git();
    let before = sha256_file(root.join("organ.py"));
    let ok = run_git_worktree_trial_secured(
        trial_request(&root, &organ, better),
        &security(PromoteMode::AutoRatchet),
    )
    .expect("better AutoRatchet trial");
    assert!(
        ok.ratcheted_baseline,
        "better candidate must ratchet: {}",
        ok.diagnostic
    );
    assert!(ok.receipt_id.is_some(), "ratchet must emit receipt_id");
    assert_ne!(
        sha256_file(root.join("organ.py")),
        before,
        "primary organ must change after AutoRatchet win"
    );

    let (root2, _guard2) = materialize_toy_cli_git();
    let before2 = sha256_file(root2.join("organ.py"));
    let worse = run_git_worktree_trial_secured(
        trial_request(&root2, &organ, worse_body),
        &security(PromoteMode::AutoRatchet),
    )
    .expect("worse AutoRatchet trial");
    assert!(
        !worse.ratcheted_baseline,
        "worse candidate must not ratchet: {}",
        worse.diagnostic
    );
    assert_eq!(
        sha256_file(root2.join("organ.py")),
        before2,
        "primary organ must stay unchanged for non-win"
    );
}

#[test]
fn e2_stage_only_keeps_primary_until_accept_helper() {
    let organ = toy_organ();
    let better = "    return n * (n + 1) // 2\n";
    let (root, _guard) = materialize_toy_cli_git();
    let before = sha256_file(root.join("organ.py"));

    let res = run_git_worktree_trial_secured(
        trial_request(&root, &organ, better),
        &security(PromoteMode::StageOnly),
    )
    .expect("StageOnly trial");

    assert!(
        !res.ratcheted_baseline,
        "StageOnly must not ratchet primary: {}",
        res.diagnostic
    );
    assert!(
        res.staged_rel_dir.is_some(),
        "StageOnly win must set staged_rel_dir: {}",
        res.diagnostic
    );
    assert_eq!(
        sha256_file(root.join("organ.py")),
        before,
        "primary organ must be byte-identical until Accept"
    );

    let staged = root
        .join(res.staged_rel_dir.as_ref().unwrap())
        .join("organ.py");
    assert!(
        staged.exists(),
        "staged organ.py missing at {}",
        staged.display()
    );

    // Simulate Accept: copy staged -> primary
    fs::copy(&staged, root.join("organ.py")).unwrap();
    assert_ne!(
        sha256_file(root.join("organ.py")),
        before,
        "manual Accept must change primary organ"
    );
}

#[test]
fn e2_machine_accept_promotes_staged_organ() {
    let (root, _guard) = materialize_toy_cli_git();
    let before = sha256_file(root.join("organ.py"));
    let better = "    return n * (n + 1) // 2\n";

    let mut machine = CarnotMachine::new_seeded();
    machine.set_tier(AccountTier::Pro);
    machine.manifest.black_box_enforced = false;
    machine.daemon_policy.require_human_accept = true;
    machine.manifest.organs = vec![toy_organ()];
    machine.shell.selected_organ_id = "toy".to_string();
    machine.organ_flags.clear();
    machine.organ_flags.insert("toy".to_string(), true);

    machine
        .point_target(&root)
        .expect("point_target toy_cli workspace");

    machine
        .evolve_organ_with_opts(EvolveOpts {
            organ_id: Some("toy".to_string()),
            generations: None,
            demo: false,
            apply: false,
            explicit_candidate: Some(better.to_string()),
            organ_rel_path: Some("organ.py".to_string()),
        })
        .expect("StageOnly live evolve");

    assert_eq!(
        sha256_file(root.join("organ.py")),
        before,
        "primary organ must stay unchanged after StageOnly evolve"
    );

    let prop = machine
        .shell
        .proposals
        .iter()
        .find(|p| matches!(p.action, ProposalAction::PromoteStagedOrgan { .. }))
        .cloned()
        .expect("PromoteStagedOrgan proposal must be staged");

    let staged_body = match &prop.action {
        ProposalAction::PromoteStagedOrgan {
            staged_rel_dir,
            organ_rel_path,
            ..
        } => fs::read_to_string(root.join(staged_rel_dir).join(organ_rel_path))
            .expect("read staged organ"),
        _ => unreachable!(),
    };

    machine
        .decide_proposal(&prop.id, "accept")
        .expect("accept PromoteStagedOrgan");

    let primary_after = fs::read_to_string(root.join("organ.py")).unwrap();
    assert_eq!(
        primary_after, staged_body,
        "Accept must copy staged organ onto primary"
    );
    assert_ne!(
        sha256_file(root.join("organ.py")),
        before,
        "primary organ hash must change after Accept"
    );
    assert!(
        primary_after.contains("n * (n + 1) // 2"),
        "promoted organ should contain closed-form candidate"
    );
}

#[test]
fn sanitize_workspace_rel_path_rejects_traversal() {
    let root = PathBuf::from("/tmp/carnot-sanitize-root");
    assert!(sanitize_workspace_rel_path(&root, "organ.py").is_ok());
    assert!(sanitize_workspace_rel_path(&root, ".carnot/staged/t1").is_ok());
    assert!(sanitize_workspace_rel_path(&root, "../etc/passwd").is_err());
    assert!(sanitize_workspace_rel_path(&root, "organs/../../secret").is_err());
    assert!(sanitize_workspace_rel_path(&root, "/abs/path.py").is_err());
    assert!(sanitize_workspace_rel_path(&root, "").is_err());
}

#[test]
fn e2_proposals_persist_for_cross_process_accept() {
    let (root, _guard) = materialize_toy_cli_git();
    let before = sha256_file(root.join("organ.py"));
    let better = "    return n * (n + 1) // 2\n";

    let mut writer = CarnotMachine::new_seeded();
    writer.set_tier(AccountTier::Pro);
    writer.manifest.black_box_enforced = false;
    writer.daemon_policy.require_human_accept = true;
    writer.manifest.organs = vec![toy_organ()];
    writer.shell.selected_organ_id = "toy".to_string();
    writer.organ_flags.clear();
    writer.organ_flags.insert("toy".to_string(), true);
    writer
        .point_target(&root)
        .expect("point_target toy_cli workspace");

    writer
        .evolve_organ_with_opts(EvolveOpts {
            organ_id: Some("toy".to_string()),
            generations: None,
            demo: false,
            apply: false,
            explicit_candidate: Some(better.to_string()),
            organ_rel_path: Some("organ.py".to_string()),
        })
        .expect("StageOnly live evolve");

    let prop_id = writer
        .shell
        .proposals
        .iter()
        .find(|p| matches!(p.action, ProposalAction::PromoteStagedOrgan { .. }))
        .map(|p| p.id.clone())
        .expect("PromoteStagedOrgan proposal");

    let proposals_path = root.join(".carnot/proposals.json");
    assert!(
        proposals_path.is_file(),
        "StageOnly win must flush proposals to disk"
    );

    // Simulate a fresh CLI process: reload workspace and Accept by id.
    let mut reader = CarnotMachine::from_workspace(&root).expect("from_workspace reload");
    reader.set_tier(AccountTier::Pro);
    assert!(
        reader.shell.proposals.iter().any(|p| p.id == prop_id),
        "reloaded machine must hydrate pending PromoteStagedOrgan from .carnot/proposals.json"
    );
    reader
        .decide_proposal(&prop_id, "accept")
        .expect("cross-process accept");

    assert_ne!(
        sha256_file(root.join("organ.py")),
        before,
        "cross-process Accept must promote primary organ"
    );
}

#[test]
fn daemon_tick_populates_trial_on_live_win() {
    let (root, _guard) = materialize_toy_cli_git();
    let better = "    return n * (n + 1) // 2\n";
    let mut machine = pointed_toy_machine(&root);
    let report = machine
        .daemon_tick(Some(better))
        .expect("daemon_tick with candidate");
    assert!(
        report.trial.is_some(),
        "DaemonTickReport.trial must be set when a live trial ran: {:?}",
        report
    );
    let trial = report.trial.as_ref().unwrap();
    assert_eq!(trial.organ_id, "toy");
    assert!(report.staged_trial_id.is_some() || report.ratcheted);
}

#[test]
fn evolve_rejects_traversing_organ_rel_path() {
    let (root, _guard) = materialize_toy_cli_git();
    let mut machine = pointed_toy_machine(&root);
    let err = machine
        .evolve_organ_with_opts(EvolveOpts {
            organ_id: Some("toy".to_string()),
            generations: None,
            demo: false,
            apply: false,
            explicit_candidate: Some("    return 0\n".to_string()),
            organ_rel_path: Some("../secret.py".to_string()),
        })
        .expect_err("path traversal must be rejected");
    assert!(
        err.contains("traversal") || err.contains(".."),
        "unexpected error: {err}"
    );
}

#[test]
fn point_target_bare_toy_dir_replaces_seeded_organs() {
    let (root, _guard) = materialize_toy_cli_git();
    let mut machine = CarnotMachine::new_seeded();
    assert_eq!(machine.shell.selected_organ_id, "verifier");
    assert!(machine.manifest.organs.iter().any(|o| o.id == "verifier"));

    machine
        .point_target(&root)
        .expect("point_target bare toy_cli");

    assert_eq!(
        machine.shell.selected_organ_id, "toy",
        "bare organ.py EVOLVE_START toy must select toy, not seeded verifier"
    );
    assert!(
        machine.manifest.organs.iter().any(|o| o.id == "toy"),
        "manifest must include discovered toy organ"
    );
    assert!(
        !machine.manifest.organs.iter().any(|o| o.id == "verifier"),
        "seeded leftover organs must not survive bare toy_cli point"
    );
    assert!(
        machine
            .manifest
            .target_bindings
            .iter()
            .any(|b| b.organ_id == "toy" && b.entrypoint_path.as_deref() == Some("organ.py")),
        "toy must bind entrypoint to organ.py"
    );
}

#[test]
fn resolve_organ_py_does_not_default_unrelated_organ() {
    let (root, _guard) = materialize_toy_cli_git();
    let mut machine = CarnotMachine::new_seeded();
    machine.set_tier(AccountTier::Pro);
    machine.manifest.black_box_enforced = false;
    machine.daemon_policy.allow_offline_demo_fallback = false;
    // Point then re-inject a leftover unrelated organ so resolve is exercised directly.
    machine
        .point_target(&root)
        .expect("point_target bare toy_cli");
    machine.manifest.organs.push(OrganSpec {
        id: "verifier".to_string(),
        capability: "leftover".to_string(),
        inputs: vec![],
        outputs: vec![],
        invariants: vec![],
        conformance_suite: "specs/verifier_vectors.json".to_string(),
    });
    machine.organ_flags.insert("verifier".to_string(), true);

    let err = machine
        .evolve_organ_with_opts(EvolveOpts {
            organ_id: Some("verifier".to_string()),
            generations: None,
            demo: false,
            apply: false,
            explicit_candidate: Some("    return 0\n".to_string()),
            organ_rel_path: None,
        })
        .expect_err("verifier must not resolve to organ.py");
    assert!(
        err.contains("Could not locate organ file for 'verifier'")
            || err.contains("not found for live evolve"),
        "unexpected error: {err}"
    );
}

#[test]
fn mcp_carnot_point_and_daemon_tick_smoke() {
    let (root, _guard) = materialize_toy_cli_git();
    let mut machine = CarnotMachine::new_seeded();
    machine.set_tier(AccountTier::Pro);
    machine.manifest.black_box_enforced = false;

    let init = handle_jsonrpc_with_budget(
        &mut machine,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        })
        .to_string(),
        4096,
    )
    .unwrap();
    assert_eq!(
        init["result"]["serverInfo"]["version"].as_str().unwrap(),
        env!("CARGO_PKG_VERSION")
    );

    let point = handle_jsonrpc_with_budget(
        &mut machine,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "carnot_point",
                "arguments": { "path": root.to_string_lossy() }
            }
        })
        .to_string(),
        16_384,
    )
    .unwrap();
    assert_eq!(point["result"]["isError"], false);
    let point_txt = point["result"]["content"][0]["text"].as_str().unwrap();
    let pointed: Value = serde_json::from_str(point_txt).unwrap();
    assert_eq!(pointed["kind"], "workspace_dir");
    assert!(
        machine.workspace_root.as_ref().is_some_and(|p| p == &root),
        "MCP carnot_point must set workspace_root"
    );
    assert_eq!(machine.shell.selected_organ_id, "toy");

    let tick = handle_jsonrpc_with_budget(
        &mut machine,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "carnot_daemon_tick",
                "arguments": {}
            }
        })
        .to_string(),
        16_384,
    )
    .unwrap();
    assert_eq!(tick["result"]["isError"], false);
    let tick_txt = tick["result"]["content"][0]["text"].as_str().unwrap();
    let report: Value = serde_json::from_str(tick_txt).unwrap();
    assert!(
        report["skipped_reason"].as_str().is_some(),
        "tick without candidate should skip with reason: {tick_txt}"
    );
}

fn pointed_toy_machine(root: &Path) -> CarnotMachine {
    let mut machine = CarnotMachine::new_seeded();
    machine.set_tier(AccountTier::Pro);
    machine.manifest.black_box_enforced = false;
    machine.daemon_policy.require_human_accept = true;
    machine.daemon_policy.allow_offline_demo_fallback = false;
    machine.daemon_policy.max_trials_per_hour = 100;
    machine
        .point_target(root)
        .expect("point_target toy_cli workspace");
    machine
}

/// E3 Memory: a prior GoodAlgorithm ExperienceCard is retrieved into the live evolve
/// operator prompt (measurable proxy for warm-start retrieval; no LLM required).
#[test]
fn e3_experience_card_appears_in_operator_prompt() {
    let (root, _guard) = materialize_toy_cli_git();
    let mut machine = pointed_toy_machine(&root);

    const MARKER: &str = "E3_CLOSED_FORM_HINT_n_times_n_plus_1_over_2";
    let injected = ExperienceCard {
        card_id: "exp-e3-good-toy".to_string(),
        organ_id: "toy".to_string(),
        generation: 1,
        island_role: IslandRole::Exploitation,
        card_kind: ExperienceCardKind::GoodAlgorithm,
        pattern_title: "Closed-form sum".to_string(),
        actionable_lesson: MARKER.to_string(),
        baseline_score: 0.10,
        achieved_score: 0.95,
        p95_latency_ms: 5,
        evolved_block_code: "    return n * (n + 1) // 2\n".to_string(),
        receipt_id: "ev_e3_memory".to_string(),
    };
    // Decoy low-gain cards so A-Res retrieval must prefer the high-gain GoodAlgorithm.
    let decoys: Vec<ExperienceCard> = (0..4)
        .map(|i| ExperienceCard {
            card_id: format!("exp-e3-decoy-{i}"),
            organ_id: "toy".to_string(),
            generation: i,
            island_role: IslandRole::Exploration,
            card_kind: ExperienceCardKind::ErrorReflection,
            pattern_title: format!("decoy-{i}"),
            actionable_lesson: format!("noise lesson {i}"),
            baseline_score: 0.50,
            achieved_score: 0.51,
            p95_latency_ms: 40,
            evolved_block_code: "    return n\n".to_string(),
            receipt_id: format!("ev_decoy_{i}"),
        })
        .collect();
    machine.experience_cards.clear();
    machine.experience_cards.push(injected.clone());
    machine.experience_cards.extend(decoys);

    let retrieved = retrieve_experience_cards_ares(&machine.experience_cards, 2, 42);
    assert!(
        retrieved.iter().any(|c| c.card_id == injected.card_id),
        "A-Res retrieval must include the high-gain GoodAlgorithm card; got {:?}",
        retrieved
            .iter()
            .map(|c| c.card_id.as_str())
            .collect::<Vec<_>>()
    );

    let organ_src = fs::read_to_string(root.join("organ.py")).unwrap();
    let blocks = extract_evolve_blocks(&organ_src, 2).expect("toy evolve blocks");
    let organ = machine
        .manifest
        .organs
        .iter()
        .find(|o| o.id == "toy")
        .cloned()
        .expect("toy organ");

    let warm = build_operator_prompt(
        &organ,
        PromptOperator::M1MutateStructural,
        &blocks[0],
        &[(&blocks[0].body, 0.1)],
        None,
        &retrieved,
    );
    assert!(
        warm.prompt_text.contains(MARKER),
        "warm operator prompt must embed retrieved ExperienceCard lesson"
    );
    assert!(
        warm.prompt_text.contains("Retrieved Experience Cards"),
        "prompt must label the experience section"
    );

    let cold = build_operator_prompt(
        &organ,
        PromptOperator::M1MutateStructural,
        &blocks[0],
        &[(&blocks[0].body, 0.1)],
        None,
        &[],
    );
    assert!(
        !cold.prompt_text.contains(MARKER),
        "cold prompt must not contain the injected lesson"
    );
}

fn tick_is_measured_win(report: &carnot::daemon::DaemonTickReport) -> bool {
    report.ratcheted || report.staged_trial_id.is_some()
}

/// E4 Continuous (toy proxy): three daemon ticks (better / no-op / better) accumulate at
/// least as many staged wins as a single-tick control on the same toy organ — not a claim
/// of general continuous-search advantage beyond this fixture.
#[test]
fn e4_multi_tick_beats_or_ties_one_shot() {
    let better = "    return n * (n + 1) // 2\n";

    // One-shot control
    let (root_ctrl, _g1) = materialize_toy_cli_git();
    let mut ctrl = pointed_toy_machine(&root_ctrl);
    let one_shot = ctrl
        .daemon_tick(Some(better))
        .expect("one-shot daemon_tick");
    assert!(
        tick_is_measured_win(&one_shot),
        "control better candidate must stage/ratchet: {:?}",
        one_shot
    );
    let control_wins: usize = usize::from(tick_is_measured_win(&one_shot));

    // Multi-tick: better → no-op (None) → better
    let (root_multi, _g2) = materialize_toy_cli_git();
    let mut multi = pointed_toy_machine(&root_multi);
    let mut cumulative = 0usize;

    let t1 = multi.daemon_tick(Some(better)).expect("tick 1");
    assert!(
        tick_is_measured_win(&t1),
        "tick 1 better must win: {:?}",
        t1
    );
    cumulative += usize::from(tick_is_measured_win(&t1));

    let t2 = multi.daemon_tick(None).expect("tick 2 no-op");
    assert!(
        t2.skipped_reason.is_some(),
        "tick 2 without candidate must skip: {:?}",
        t2
    );
    assert!(
        !tick_is_measured_win(&t2),
        "no-op tick must not count as a win"
    );

    let t3 = multi.daemon_tick(Some(better)).expect("tick 3");
    assert!(
        tick_is_measured_win(&t3),
        "tick 3 better must win again under StageOnly (primary still baseline): {:?}",
        t3
    );
    cumulative += usize::from(tick_is_measured_win(&t3));

    assert!(
        cumulative >= control_wins,
        "multi-tick cumulative wins ({cumulative}) must be ≥ one-shot ({control_wins})"
    );
    assert!(
        cumulative >= 2,
        "expected two staged wins across three ticks, got {cumulative}"
    );
}
