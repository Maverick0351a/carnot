//! `carnot verify` runs a detected test runner, and a pointed foreign tree
//! keeps evolve scratch space out of the target.

use carnot::bridge::{CarnotMachine, EvolveOpts};
use carnot::proposals::ProposalAction;
use carnot::workspace::point_state_dir;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(label: &str) -> (PathBuf, TempDirGuard) {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!(
        "carnot-verify-{label}-{}-{nanos}-{seq}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let guard = TempDirGuard(root.clone());
    (root, guard)
}

fn run_git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("git {}: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn names(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        out.push(entry.unwrap().file_name().to_string_lossy().into_owned());
    }
    out.sort();
    out
}

#[test]
fn verify_runs_python_tests_and_does_not_add_carnot_state() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("py-pass");
    fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"sample\"\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/test_add.py"),
        "def test_add():\n    assert 1 + 1 == 2\n",
    )
    .unwrap();
    let before = names(&root);

    let out = Command::new(exe)
        .args(["verify", root.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}\n{stdout}");
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["checks_executed"], true);
    assert_eq!(report["demo"], false);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["passed"], 1);
    assert_eq!(report["failed"], 0);
    assert!(report["duration_ms"].as_u64().unwrap() > 0);
    let command = report["test_command"].as_str().unwrap();
    assert!(
        command.contains("pytest") || command.contains("unittest"),
        "{command}"
    );
    assert!(!report["timed_out"].as_bool().unwrap());
    assert!(!stderr.contains("no test runner detected"), "{stderr}");

    let after = names(&root);
    let extra: Vec<_> = after
        .iter()
        .filter(|name| !before.contains(name))
        .cloned()
        .collect();
    assert!(
        extra
            .iter()
            .all(|name| name == ".pytest_cache" || name == "__pycache__"),
        "verify wrote into the tree: {extra:?}"
    );
    assert!(!root.join(".carnot").exists());
    assert!(!root.join("carnot.manifest.json").exists());
}

#[test]
fn verify_reports_a_failing_suite() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("py-fail");
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/test_bad.py"),
        "import unittest\nclass T(unittest.TestCase):\n    def test_bad(self):\n        self.assertEqual(1, 2)\n",
    )
    .unwrap();
    let out = Command::new(exe)
        .args(["verify", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["checks_executed"], true);
    assert_ne!(report["exit_code"], 0);
    assert_eq!(report["failed"], 1);
}

#[test]
fn verify_timeout_is_reported() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("py-slow");
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/test_slow.py"),
        "import time\ndef test_slow():\n    time.sleep(30)\n",
    )
    .unwrap();
    let out = Command::new(exe)
        .args(["verify", "--timeout", "1", root.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}\n{stdout}");
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["checks_executed"], true);
    assert_eq!(report["timed_out"], true);
    assert!(report["duration_ms"].as_u64().unwrap() < 15_000, "{report}");
    assert!(stderr.contains("timeout"), "{stderr}");
}

#[test]
fn verify_runs_cargo_test() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("cargo");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"tiny_verify\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() { assert_eq!(super::add(1, 1), 2); }\n}\n",
    )
    .unwrap();
    let out = Command::new(exe)
        .args(["verify", "--timeout", "180", root.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}\n{stdout}");
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["test_command"], "cargo test");
    assert_eq!(report["checks_executed"], true);
    assert_eq!(report["exit_code"], 0);
    assert!(report["passed"].as_u64().unwrap() >= 1, "{report}");
    assert_eq!(report["failed"], 0);
    assert!(!root.join(".carnot").exists());
}

#[test]
fn verify_timeout_zero_exits_2() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let out = Command::new(exe)
        .args(["verify", "--timeout", "0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn live_evolve_keeps_worktrees_and_staged_out_of_a_foreign_tree() {
    let (root, _guard) = temp_dir("foreign-evolve");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("experiments/toy_cli");
    for name in ["organ.py", "solve_bench.py", "test_organ.py"] {
        fs::copy(fixture.join(name), root.join(name)).unwrap();
    }
    fs::write(
        root.join("LICENSE"),
        "MIT License\nPermission is hereby granted, free of charge, to any person\n",
    )
    .unwrap();
    run_git(&root, &["init"]);
    run_git(&root, &["config", "user.email", "refinery@carnot.local"]);
    run_git(&root, &["config", "user.name", "Carnot Refinery"]);
    run_git(&root, &["add", "-A"]);
    run_git(&root, &["commit", "-m", "toy"]);

    let mut machine = CarnotMachine::new_seeded();
    let pointed = machine.point_target(&root).unwrap();
    assert!(!pointed.in_tree_state);
    assert!(!root.join(".carnot").exists());
    let state = point_state_dir(&root, false);
    let _state_guard = TempDirGuard(state.clone());

    let report = machine
        .evolve_organ_with_opts(EvolveOpts {
            organ_id: Some("toy".to_string()),
            generations: Some(1),
            demo: false,
            apply: false,
            explicit_candidate: Some("    return n * (n + 1) // 2\n".to_string()),
            organ_rel_path: Some("organ.py".to_string()),
        })
        .unwrap();
    assert!(!report.offline_demo, "{report:?}");
    assert!(
        report.best_score > report.baseline_score,
        "trial did not stage a win: {report:?}"
    );
    assert!(
        !root.join(".carnot").exists(),
        "trial wrote .carnot into the target"
    );
    assert!(state.join(".carnot/worktrees").is_dir());
    let staged = fs::read_dir(state.join(".carnot/staged"))
        .expect("staged dir in the point state directory")
        .flatten()
        .find_map(|entry| fs::read_to_string(entry.path().join("organ.py")).ok())
        .expect("staged organ");
    assert!(staged.contains("n * (n + 1) // 2"), "{staged}");

    let proposal_id = machine.shell.proposals[0].id.clone();
    assert!(matches!(
        machine.shell.proposals[0].action,
        ProposalAction::PromoteStagedOrgan { .. }
    ));
    machine
        .decide_proposal(&proposal_id, "accept")
        .expect("accept staged organ from the external state dir");
    let accepted = fs::read_to_string(root.join("organ.py")).unwrap();
    assert!(accepted.contains("n * (n + 1) // 2"), "{accepted}");
    assert!(!root.join(".carnot").exists());
}
