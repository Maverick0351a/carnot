//! Gaps found by an end-to-end run: nested license zones, license filename
//! case, manifest SPDX ids, unknown generate languages, evolve --candidate,
//! scout/verify on real trees, and point state kept out of foreign trees.

use carnot::bridge::CarnotMachine;
use carnot::intake::{classify_license_text, detect_manifest_spdx, scan_directory_spdx_zones};
use carnot::scout::TargetLanguage;
use carnot::workspace::{init_workspace, materialize_project_to_disk, point_state_dir};
use serde_json::Value;
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
        "carnot-gap-{}-{}-{}-{}",
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

const MPL: &str = "Mozilla Public License Version 2.0\n";
const MIT: &str = "MIT License\nPermission is hereby granted, free of charge, to any person\n";

#[test]
fn vendored_mpl_zone_overrides_parent_mit() {
    let (root, _guard) = temp_dir("nested-mpl");
    let vendor = root.join("src/pkg/_vendor/certifi");
    fs::create_dir_all(&vendor).unwrap();
    fs::write(root.join("LICENSE"), MIT).unwrap();
    fs::write(root.join("src/pkg/app.py"), "def app():\n    return 1\n").unwrap();
    fs::write(vendor.join("LICENSE"), MPL).unwrap();
    fs::write(vendor.join("core.py"), "def core():\n    return 1\n").unwrap();

    let zones = scan_directory_spdx_zones(&root).unwrap();
    let vendored = zones
        .iter()
        .find(|z| z.zone_alias.contains("certifi"))
        .expect("vendored license file must be its own zone");
    assert_eq!(vendored.detected_spdx, "MPL-2.0");
    assert!(vendored.source_files_blocked >= 1);
    let parent = zones.iter().find(|z| z.zone_alias == "src").unwrap();
    assert_eq!(parent.detected_spdx, "MIT");
    assert_eq!(
        parent.spec_fixtures_harvested, 1,
        "parent MIT zone must not count the vendored file: {zones:?}"
    );
}

#[test]
fn license_filenames_are_case_insensitive() {
    let samples = [
        ("license", MIT, "MIT"),
        ("License.md", MIT, "MIT"),
        ("LICENCE", MIT, "MIT"),
        (
            "COPYING",
            "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n",
            "GPL-2.0",
        ),
    ];
    for (name, text, expect) in samples {
        let (root, _guard) = temp_dir(&format!("lic-{name}"));
        fs::write(root.join(name), text).unwrap();
        fs::write(root.join("a.py"), "x = 1\n").unwrap();
        let zones = scan_directory_spdx_zones(&root).unwrap();
        let file = zones.iter().find(|z| z.zone_alias == "a.py").unwrap();
        assert_eq!(file.detected_spdx, expect, "filename {name}");
    }
}

#[test]
fn manifest_fields_keep_spdx_ids_and_gpl_text_versions_differ() {
    let (root, _guard) = temp_dir("manifests");
    let cases = [
        (
            "pkg",
            "package.json",
            "{\"license\":\"GPL-3.0-or-later\"}\n",
            "GPL-3.0-or-later",
        ),
        (
            "cargo",
            "Cargo.toml",
            "license = \"GPL-2.0-only\"\n",
            "GPL-2.0-only",
        ),
        (
            "py",
            "pyproject.toml",
            "license = {text = \"MPL-2.0\"}\n",
            "MPL-2.0",
        ),
        (
            "setup",
            "setup.cfg",
            "[metadata]\nlicense = AGPL-3.0-only\n",
            "AGPL-3.0-only",
        ),
        (
            "lgpl",
            "setup.cfg",
            "[metadata]\nlicense = LGPL-2.1-or-later\n",
            "LGPL-2.1-or-later",
        ),
    ];
    for (dir, file, body, expect) in cases {
        let zone = root.join(dir);
        fs::create_dir_all(&zone).unwrap();
        fs::write(zone.join(file), body).unwrap();
        assert_eq!(detect_manifest_spdx(&zone), expect, "{file}");
    }
    assert_eq!(
        classify_license_text("GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n"),
        "GPL-2.0"
    );
    assert_eq!(
        classify_license_text("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"),
        "GPL-3.0"
    );
    assert_eq!(
        classify_license_text("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999\n"),
        "LGPL-2.1"
    );
    let compatible = "Historically, most releases have also been GPL-compatible.\n\
The GPL-compatible licenses are not the GPL itself.\n";
    let classified = classify_license_text(compatible);
    assert_ne!(classified, "GPL-2.0");
    assert_ne!(classified, "GPL-3.0");
}

#[test]
fn generate_unknown_language_exits_2_with_the_supported_list() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("gen-lang");
    let out = Command::new(exe)
        .args(["generate", root.to_str().unwrap(), "cobol"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cobol"), "{err}");
    assert!(err.contains("supported"), "{err}");
    for name in [
        "rust",
        "go",
        "typescript",
        "python",
        "scala3",
        "zig",
        "auto",
    ] {
        assert!(err.contains(name), "missing {name} in {err}");
    }
    assert!(!root.join("src").exists());
}

#[test]
fn evolve_candidate_file_is_the_explicit_block() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("evolve-candidate");
    let proj = root.join("edge");
    let manifest = init_workspace(&proj, "edge-gateway", TargetLanguage::Python).unwrap();
    materialize_project_to_disk(&manifest, &proj, Some(TargetLanguage::Python), true).unwrap();
    let candidate = root.join("candidate.py");
    let body = "    trimmed = payload.strip()\n    if not trimmed or len(trimmed) > 65536 or any(ord(ch) < 32 for ch in trimmed):\n        raise ValueError(\"invalid_payload\")\n    return f\"[verifier] {trimmed}\"\n";
    fs::write(&candidate, body).unwrap();
    let before = fs::read_to_string(proj.join("organs/verifier.py")).unwrap();
    let out = Command::new(exe)
        .current_dir(&proj)
        .args([
            "evolve",
            "verifier",
            "1",
            "--candidate",
            candidate.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "evolve --candidate failed: {stderr}\n{stdout}"
    );
    assert!(
        stdout.contains("\"offline_demo\": false"),
        "candidate was not a live trial: {stdout}"
    );
    assert_eq!(
        fs::read_to_string(proj.join("organs/verifier.py")).unwrap(),
        before,
        "StageOnly must leave the primary organ untouched"
    );
    let staged = fs::read_dir(proj.join(".carnot/staged"))
        .expect("staged dir")
        .flatten()
        .find_map(|entry| {
            let path = entry.path().join("organs/verifier.py");
            fs::read_to_string(path).ok()
        })
        .expect("staged verifier");
    assert!(staged.contains("ord(ch)"), "{staged}");
}

#[test]
fn scout_and_verify_score_the_tree_unless_demo() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("score");
    fs::write(root.join("kept.py"), "def kept():\n    return 1\n").unwrap();
    fs::write(root.join("LICENSE"), MIT).unwrap();

    let scout = Command::new(exe)
        .args(["scout", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        scout.status.success(),
        "{}",
        String::from_utf8_lossy(&scout.stderr)
    );
    let scout_json: Value = serde_json::from_slice(&scout.stdout).unwrap();
    assert_eq!(scout_json["demo"], false);
    let ranked = scout_json["ranked"].to_string();
    assert!(!ranked.contains("target-alpha-eval-core"), "{ranked}");
    assert!(ranked.contains("MIT"), "{ranked}");

    let verify = Command::new(exe)
        .args(["verify", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_text = String::from_utf8_lossy(&verify.stdout);
    let verify_json: Value = serde_json::from_str(&verify_text).unwrap();
    assert_eq!(verify_json["demo"], false);
    assert_eq!(verify_json["checks_executed"], false);
    assert!(verify_json["summaries"][0]["schema_pass_rate"].is_null());
    assert_eq!(verify_json["summaries"][0]["pareto_optimal"], false);
    assert!(verify_json["summaries"][0]["case_scores"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(
        verify_json["source_files"].to_string().contains("kept.py"),
        "{verify_text}"
    );
    let verify_err = String::from_utf8_lossy(&verify.stderr);
    assert!(
        verify_err.contains("no test runner detected"),
        "{verify_err}"
    );
    assert_eq!(verify_json["note"], "no test runner detected");
    assert!(!verify_text.contains("gold-001"), "{verify_text}");
    assert!(!verify_text.contains("v1-legacy-baseline"), "{verify_text}");

    let demo = Command::new(exe)
        .args(["scout", "--demo"])
        .output()
        .unwrap();
    assert!(
        demo.status.success(),
        "{}",
        String::from_utf8_lossy(&demo.stderr)
    );
    let demo_err = String::from_utf8_lossy(&demo.stderr);
    assert!(demo_err.contains("demo"), "{demo_err}");
    let demo_json: Value = serde_json::from_slice(&demo.stdout).unwrap();
    assert_eq!(demo_json["demo"], true);
    assert!(demo_json["ranked"]
        .to_string()
        .contains("target-alpha-eval-core"));

    let golden = Command::new(exe)
        .args(["verify", "--demo"])
        .output()
        .unwrap();
    assert!(
        golden.status.success(),
        "{}",
        String::from_utf8_lossy(&golden.stderr)
    );
    let golden_err = String::from_utf8_lossy(&golden.stderr);
    assert!(golden_err.contains("demo"), "{golden_err}");
    let golden_text = String::from_utf8_lossy(&golden.stdout);
    let golden_json: Value = serde_json::from_str(&golden_text).unwrap();
    assert_eq!(golden_json["demo"], true);
    assert!(golden_text.contains("gold-001"), "{golden_text}");
}

#[test]
fn point_keeps_state_out_of_a_foreign_tree() {
    let (bare, _guard) = temp_dir("point-bare");
    fs::write(bare.join("main.py"), "x = 1\n").unwrap();
    let mut machine = CarnotMachine::new_seeded();
    let pointed = machine.point_target(&bare).unwrap();
    assert!(!bare.join("carnot.manifest.json").exists());
    assert!(!bare.join(".carnot").exists());
    assert!(!bare.join("Carnot.toml").exists());
    let state = point_state_dir(&bare, false);
    assert_ne!(state, bare);
    assert_eq!(pointed.state_root.as_deref(), Some(state.as_path()));
    assert!(!pointed.in_tree_state);
    assert!(state.join("carnot.manifest.json").is_file());
    assert!(state.join(".carnot").is_dir());

    let (existing, _guard2) = temp_dir("point-existing");
    init_workspace(&existing, "already", TargetLanguage::Rust).unwrap();
    machine.point_target(&existing).unwrap();
    assert!(existing.join("carnot.manifest.json").is_file());
    assert!(existing.join(".carnot").join("ledger.jsonl").is_file());

    let (opt, _guard3) = temp_dir("point-opt");
    fs::write(opt.join("main.py"), "x = 1\n").unwrap();
    machine.point_target_with(&opt, true).unwrap();
    assert!(opt.join("carnot.manifest.json").is_file());
    assert!(opt.join(".carnot").is_dir());
}
