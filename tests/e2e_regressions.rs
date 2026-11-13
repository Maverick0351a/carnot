//! Regressions found by exercising the release binary on real trees:
//! GPL-3 must not be labeled AGPL, root files must be attested, symlinks
//! must not escape the scan root, unreadable licenses must fail visibly,
//! and a generated project must be evolvable with StageOnly.

use carnot::bridge::{CarnotMachine, EvolveOpts};
use carnot::intake::{classify_license_text, scan_directory_spdx_zones, AccessPolicy};
use carnot::recipe::OrganSpec;
use carnot::scout::TargetLanguage;
use carnot::workspace::{init_workspace, materialize_project_to_disk};
use carnot::worktree::{run_git_worktree_trial, CandidateSource, WorktreeTrialRequest};
use std::fs;
use std::path::{Path, PathBuf};

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_tree(label: &str) -> (PathBuf, TempDirGuard) {
    let root = std::env::temp_dir().join(format!(
        "carnot-e2e-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let guard = TempDirGuard(root.clone());
    (root, guard)
}

#[test]
fn gpl3_header_is_not_agpl_because_section_13_mentions_affero() {
    let gpl = "\
GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Preamble

make it effectively proprietary.

TERMS AND CONDITIONS

13. Use with the GNU Affero General Public License.
";
    assert_eq!(classify_license_text(gpl), "GPL-3.0");
    assert_eq!(
        classify_license_text("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3\n"),
        "AGPL-3.0"
    );
}

#[test]
fn root_source_files_keep_the_root_license_when_subdirs_exist() {
    let (root, _guard) = temp_tree("root-files");
    fs::create_dir_all(root.join("helper")).unwrap();
    fs::write(
        root.join("LICENSE"),
        "Apache License\nVersion 2.0, January 2004\n",
    )
    .unwrap();
    fs::write(root.join("main.go"), "package main\n").unwrap();
    fs::write(root.join("helper").join("a.go"), "package helper\n").unwrap();

    let zones = scan_directory_spdx_zones(&root).unwrap();
    let main = zones.iter().find(|z| z.zone_alias == "main.go").unwrap();
    assert_eq!(main.detected_spdx, "Apache-2.0");
    assert_eq!(main.policy, AccessPolicy::PermissiveAlgorithmAndFixtures);
    assert_eq!(main.spec_fixtures_harvested, 1);
    assert_eq!(main.source_files_blocked, 0);
    let helper = zones.iter().find(|z| z.zone_alias == "helper").unwrap();
    assert_eq!(helper.detected_spdx, "Apache-2.0");
    assert!(helper.spec_fixtures_harvested >= 1);
}

#[test]
fn gpl_root_file_is_quarantined_and_not_returned_by_search() {
    let (root, _guard) = temp_tree("gpl-root");
    fs::create_dir_all(root.join("pkg")).unwrap();
    fs::write(
        root.join("LICENSE"),
        "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n\nTERMS AND CONDITIONS\n\n13. Use with the GNU Affero General Public License.\n",
    )
    .unwrap();
    fs::write(root.join("setup.py"), "GPL_ROOT_MARKER = True\n").unwrap();
    fs::write(
        root.join("pkg").join("hidden.py"),
        "GPL_CHILD_MARKER = True\n",
    )
    .unwrap();

    let mut machine = CarnotMachine::new_seeded();
    let cert = machine.scan_intake_directory(&root).unwrap();
    let setup = cert
        .zones
        .iter()
        .find(|z| z.zone_alias == "setup.py")
        .unwrap();
    assert_eq!(setup.detected_spdx, "GPL-3.0");
    assert_eq!(setup.policy, AccessPolicy::QuarantinedBlackBoxSpecOnly);
    assert_eq!(setup.source_files_blocked, 1);
    let pkg = cert.zones.iter().find(|z| z.zone_alias == "pkg").unwrap();
    assert_eq!(pkg.detected_spdx, "GPL-3.0");
    assert_eq!(pkg.source_files_blocked, 1);

    machine.workspace_root = Some(root.clone());
    let rep = machine.search_codebase("GPL_ROOT_MARKER", 5);
    assert!(
        rep.hits
            .iter()
            .all(|h| !h.content.contains("GPL_ROOT_MARKER") && h.file_path != "setup.py"),
        "search leaked GPL root file: {:?}",
        rep.hits
    );
    let child = machine.search_codebase("GPL_CHILD_MARKER", 5);
    assert!(
        child
            .hits
            .iter()
            .all(|h| !h.content.contains("GPL_CHILD_MARKER")),
        "search leaked GPL child file: {:?}",
        child.hits
    );
    assert!(rep.quarantined_files_skipped >= 1);
}

#[test]
fn missing_scan_path_and_non_git_evolve_fail_with_a_reason() {
    let missing = scan_directory_spdx_zones(Path::new("/tmp/carnot-does-not-exist-e2e-xyz"));
    let err = missing.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);

    let (root, _guard) = temp_tree("nongit");
    fs::write(root.join("readme.txt"), "hello").unwrap();
    let organ = OrganSpec {
        id: "verifier".to_string(),
        capability: "x".to_string(),
        inputs: Vec::new(),
        outputs: Vec::new(),
        invariants: Vec::new(),
        conformance_suite: "tests".to_string(),
    };
    let err = run_git_worktree_trial(WorktreeTrialRequest {
        repo_dir: &root,
        organ: &organ,
        organ_rel_path: "organs/verifier.py",
        block_index: 0,
        candidate_source: CandidateSource::ExplicitBlock("pass"),
        test_program: "python3",
        test_args: &["-c", ""],
        bench_program: "python3",
        bench_args: &["-c", ""],
        timeout_ms: 1_000,
        state_dir: None,
    })
    .unwrap_err();
    assert!(
        err.contains("not a git repository"),
        "expected a git error, got {err}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_outside_the_tree_and_unreadable_license_fail_cleanly() {
    use std::os::unix::fs::PermissionsExt;
    let (root, _guard) = temp_tree("symlink");
    let outside = root.join("outside");
    let repo = root.join("repo");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(repo.join("sub")).unwrap();
    fs::write(
        outside.join("secret.rs"),
        "pub fn secret_marker_outside() {}\n",
    )
    .unwrap();
    fs::write(repo.join("sub").join("inside.rs"), "pub fn inside() {}\n").unwrap();
    fs::write(
        repo.join("LICENSE"),
        "MIT License\nPermission is hereby granted, free of charge\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, repo.join("sub").join("escaped")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link-outside")).unwrap();

    let escaped = scan_directory_spdx_zones(&repo).unwrap_err();
    let msg = escaped.to_string();
    assert!(msg.contains("symlink"), "{msg}");
    assert!(msg.contains("outside") || msg.contains("escaped"), "{msg}");

    let as_root = scan_directory_spdx_zones(&root.join("link-outside")).unwrap_err();
    assert!(as_root.to_string().contains("symlink"), "{}", as_root);

    let mut machine = CarnotMachine::new_seeded();
    machine.workspace_root = Some(repo.clone());
    let hits = machine.search_codebase("secret_marker_outside", 5);
    assert!(
        hits.hits
            .iter()
            .all(|h| !h.content.contains("secret_marker_outside")),
        "search followed a symlink out of the repo: {:?}",
        hits.hits
    );

    let locked = root.join("noread");
    fs::create_dir_all(&locked).unwrap();
    let license = locked.join("LICENSE");
    fs::write(
        &license,
        "MIT License\nPermission is hereby granted, free of charge\n",
    )
    .unwrap();
    fs::write(locked.join("a.rs"), "fn hidden() {}\n").unwrap();
    let mut perms = fs::metadata(&license).unwrap().permissions();
    perms.set_mode(0o0);
    fs::set_permissions(&license, perms).unwrap();
    // Root ignores mode 000, so the scan cannot fail. Only assert when the
    // kernel actually refuses the read.
    match fs::read(&license) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let denied = scan_directory_spdx_zones(&locked).unwrap_err();
            let denied_msg = denied.to_string();
            assert!(
                denied.kind() == std::io::ErrorKind::PermissionDenied
                    || denied_msg.contains("license"),
                "{denied_msg}"
            );
        }
        Ok(_) => {}
        Err(e) => panic!("unexpected read of mode 000 license: {e}"),
    }
    let mut restore = fs::metadata(&license).unwrap().permissions();
    restore.set_mode(0o644);
    fs::set_permissions(&license, restore).unwrap();
}

#[test]
fn long_license_without_terms_marker_does_not_slice_mid_character() {
    let mut text = "x".repeat(3999);
    text.push('你');
    assert!(text.len() > 4000);
    assert!(!text.is_char_boundary(4000));
    let _ = classify_license_text(&text);
}

#[test]
fn generated_project_is_permissive_and_stageonly_evolve_accepts() {
    let (root, _guard) = temp_tree("generated");
    let proj = root.join("edge");
    let manifest = init_workspace(&proj, "edge-gateway", TargetLanguage::Python).unwrap();
    materialize_project_to_disk(&manifest, &proj, Some(TargetLanguage::Python), true).unwrap();
    assert!(proj.join("LICENSE").is_file());

    let zones = scan_directory_spdx_zones(&proj).unwrap();
    let organs = zones.iter().find(|z| z.zone_alias == "organs").unwrap();
    assert_eq!(organs.detected_spdx, "MIT");
    assert_eq!(organs.policy, AccessPolicy::PermissiveAlgorithmAndFixtures);
    assert_eq!(organs.source_files_blocked, 0);

    let mut machine = CarnotMachine::from_workspace(&proj).unwrap();
    let before = fs::read_to_string(proj.join("organs/verifier.py")).unwrap();
    let report = machine
        .evolve_organ_with_opts(EvolveOpts {
            organ_id: Some("verifier".to_string()),
            generations: Some(1),
            demo: false,
            apply: false,
            explicit_candidate: Some(
                "    trimmed = payload.strip()\n    if not trimmed or len(trimmed) > 65536 or any(ord(ch) < 32 for ch in trimmed):\n        raise ValueError(\"invalid_payload\")\n    return f\"[verifier] {trimmed}\"\n".to_string(),
            ),
            organ_rel_path: Some("organs/verifier.py".to_string()),
        })
        .unwrap();
    assert!(!report.offline_demo);
    assert!(
        report.best_score > report.baseline_score,
        "live trial did not beat baseline: {:?}",
        report
    );
    let staged = fs::read_to_string(proj.join("organs/verifier.py")).unwrap();
    assert_eq!(
        before, staged,
        "StageOnly must leave the primary organ untouched"
    );
    assert!(!machine.shell.proposals.is_empty());
    let proposal_id = machine.shell.proposals[0].id.clone();
    machine
        .decide_proposal(&proposal_id, "accept")
        .expect("accept staged organ");
    let accepted = fs::read_to_string(proj.join("organs/verifier.py")).unwrap();
    assert!(accepted.contains("ord(ch)"), "{accepted}");
}

#[test]
fn evolve_without_a_workspace_is_labeled_offline_demo() {
    let mut machine = CarnotMachine::new_seeded();
    let report = machine.evolve_organ(Some("verifier"), Some(1)).unwrap();
    assert!(report.offline_demo);
    assert!(report.baseline_replaced);
}
