//! Production guards: license firewall strictness, workspace demo isolation,
//! and contained writes. These cover data-loss and mis-attestation paths.

use carnot::bridge::CarnotMachine;
use carnot::intake::{
    classify_license_text, detect_manifest_spdx, policy_for_spdx, scan_directory_spdx_zones,
    AccessPolicy,
};
use carnot::scout::TargetLanguage;
#[cfg(unix)]
use carnot::workspace::materialize_project_to_disk;
use carnot::workspace::{init_workspace, WorkspaceLayout};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(label: &str) -> (PathBuf, TempDirGuard) {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "carnot-guard-{}-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        seq
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let guard = TempDirGuard(root.clone());
    (root, guard)
}

#[test]
fn mixed_license_expression_is_classified_as_restrictive() {
    let (root, _guard) = temp_dir("spdx");
    let zone = root.join("mixed-expr");
    fs::create_dir_all(&zone).unwrap();
    fs::write(
        zone.join("Cargo.toml"),
        "[package]\nname = \"mixed\"\nlicense = \"MIT OR AGPL-3.0\"\n",
    )
    .unwrap();
    fs::write(zone.join("lib.rs"), "pub fn secret() {}\n").unwrap();

    assert_eq!(detect_manifest_spdx(&zone), "AGPL-3.0");
    assert_eq!(
        policy_for_spdx("AGPL-3.0"),
        AccessPolicy::QuarantinedBlackBoxSpecOnly
    );

    let zones = scan_directory_spdx_zones(&zone).unwrap();
    let decision = zones
        .iter()
        .find(|z| z.detected_spdx == "AGPL-3.0")
        .unwrap();
    assert_eq!(decision.policy, AccessPolicy::QuarantinedBlackBoxSpecOnly);
    assert!(decision.source_files_blocked >= 1);
    assert_eq!(decision.spec_fixtures_harvested, 0);

    let gpl = root.join("gpl-manifest");
    fs::create_dir_all(&gpl).unwrap();
    fs::write(
        gpl.join("Cargo.toml"),
        "[package]\nname = \"copyleft\"\nlicense = \"GPL-3.0-only\"\n",
    )
    .unwrap();
    assert_eq!(detect_manifest_spdx(&gpl), "GPL-3.0-only");
    assert_eq!(
        policy_for_spdx(&detect_manifest_spdx(&gpl)),
        AccessPolicy::QuarantinedBlackBoxSpecOnly
    );

    let permissive = root.join("permissive");
    fs::create_dir_all(&permissive).unwrap();
    fs::write(
        permissive.join("package.json"),
        "{\"name\":\"ok\",\"license\":\"Apache-2.0\"}\n",
    )
    .unwrap();
    assert_eq!(detect_manifest_spdx(&permissive), "Apache-2.0");
    assert_eq!(
        policy_for_spdx("Apache-2.0"),
        AccessPolicy::PermissiveAlgorithmAndFixtures
    );
}

#[test]
fn binding_a_workspace_does_not_write_seeded_demo_state() {
    let (root, _guard) = temp_dir("bind");
    init_workspace(&root, "real-svc", TargetLanguage::Rust).unwrap();
    let layout = WorkspaceLayout::at(&root);
    let ledger_before = fs::read_to_string(&layout.ledger_jsonl).unwrap();
    assert!(ledger_before.contains("Initialized Carnot workspace"));

    let mut pointed = CarnotMachine::new_seeded();
    pointed.point_target(&root).unwrap();
    let ledger_after = fs::read_to_string(&layout.ledger_jsonl).unwrap();
    assert!(
        ledger_after.contains("Initialized Carnot workspace"),
        "point_target must not replace the workspace ledger"
    );
    assert!(
        !ledger_after.contains("target-alpha"),
        "seeded scout zones must not be written into the ledger"
    );
    if layout.proposals_json.is_file() {
        let proposals = fs::read_to_string(&layout.proposals_json).unwrap();
        assert!(
            !proposals.contains("prop-001"),
            "seeded proposal must not be flushed"
        );
    }
    if layout.dataset_jsonl.is_file() {
        let dataset = fs::read_to_string(&layout.dataset_jsonl).unwrap();
        assert!(!dataset.contains("gold-001"));
    }
    let obligations = fs::read_to_string(&layout.obligations_json).unwrap_or_default();
    assert!(
        !obligations.contains("obl_provenance"),
        "demo provenance obligation must not be flushed into a verifier/router workspace"
    );
    assert!(obligations.contains("obl_verifier"));

    let loaded = CarnotMachine::from_workspace(&root).unwrap();
    assert!(loaded.shell.proposals.iter().all(|p| p.id != "prop-001"));
    assert!(loaded.dataset.iter().all(|c| !c.id.starts_with("gold-")));
    assert!(
        loaded.scout_candidates.is_empty(),
        "a bound workspace must not keep seeded scout fixtures"
    );
}

#[cfg(unix)]
#[test]
fn materialize_refuses_symlink_escape() {
    let (root, _guard) = temp_dir("symlink");
    let proj = root.join("proj");
    let outside = root.join("outside");
    fs::create_dir_all(&outside).unwrap();
    let manifest = init_workspace(&proj, "contained", TargetLanguage::Rust).unwrap();
    fs::create_dir_all(proj.join("src")).unwrap();
    let _ = fs::remove_dir_all(proj.join("src"));
    std::os::unix::fs::symlink(&outside, proj.join("src")).unwrap();

    let err = materialize_project_to_disk(&manifest, &proj, Some(TargetLanguage::Rust), false)
        .expect_err("write through src -> outside must fail");
    assert!(
        err.to_lowercase().contains("symlink"),
        "expected symlink refusal, got {err}"
    );
    assert!(
        !outside.join("lib.rs").exists(),
        "organ source must not be written outside the workspace"
    );
}

#[test]
fn cli_help_is_the_default_and_generate_requires_init() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let help = Command::new(exe).arg("--help").output().unwrap();
    assert!(help.status.success(), "help status: {:?}", help.status);
    let help_out = String::from_utf8_lossy(&help.stdout);
    assert!(help_out.contains("demo"));
    assert!(help_out.contains("init"));

    let bare = Command::new(exe).output().unwrap();
    assert!(bare.status.success(), "no-args status: {:?}", bare.status);
    let bare_out = String::from_utf8_lossy(&bare.stdout);
    assert!(
        bare_out.contains("demo"),
        "no-args should print help, not run the demo: {bare_out}"
    );
    assert!(
        !bare_out.contains("Stage 1/5"),
        "no-args must not run the offline demo"
    );

    let (root, _guard) = temp_dir("cli");
    let generate = Command::new(exe)
        .args(["generate", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !generate.status.success(),
        "generate without init should fail"
    );
    let err = String::from_utf8_lossy(&generate.stderr);
    assert!(err.contains("init"), "stderr: {err}");
    assert!(!root.join("src").join("lib.rs").exists());

    fs::write(root.join("carnot.manifest.json"), "{").unwrap();
    let scan = Command::new(exe)
        .args(["intake-scan", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !scan.status.success(),
        "corrupt manifest must not fall back to the demo machine"
    );
    let scan_err = String::from_utf8_lossy(&scan.stderr);
    assert!(
        scan_err.to_lowercase().contains("json") || scan_err.contains("manifest"),
        "stderr: {scan_err}"
    );
}

#[test]
fn mentioning_mit_without_the_grant_is_not_permissive() {
    let disclaimer = "The MIT license terms do not apply to this tree.\nAll rights reserved.\n";
    let classified = classify_license_text(disclaimer);
    assert_ne!(classified, "MIT");
    assert_ne!(
        policy_for_spdx(&classified),
        AccessPolicy::PermissiveAlgorithmAndFixtures
    );
    let real = "MIT License\nPermission is hereby granted, free of charge, to any person\n";
    assert_eq!(classify_license_text(real), "MIT");
    assert_eq!(classify_license_text("Apache-2.0 OR MIT"), "Apache-2.0");
}

#[cfg(unix)]
#[test]
fn license_scan_error_does_not_mint_a_certificate() {
    use std::os::unix::fs::PermissionsExt;
    let (root, _guard) = temp_dir("scan-fail");
    init_workspace(&root, "sealed", TargetLanguage::Rust).unwrap();
    // Search permission stays so the manifest path can be opened. Read permission
    // is removed so directory enumeration, and only that, fails.
    let mut perms = fs::metadata(&root).unwrap().permissions();
    perms.set_mode(0o111);
    fs::set_permissions(&root, perms).unwrap();
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Ok(meta) = fs::metadata(&self.0) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = fs::set_permissions(&self.0, perms);
            }
        }
    }
    let _restore = Restore(root.clone());

    let err = CarnotMachine::from_workspace(&root).expect_err("unreadable tree must not certify");
    assert!(
        err.to_lowercase().contains("license scan"),
        "expected a fail-closed scan error, got {err}"
    );
}
