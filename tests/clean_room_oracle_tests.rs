//! Phase 6: Black-Box Shield ON/OFF, hybrid-search quarantine, InspectionFirewall, LCS diff, lossless Undo,
//! workspace SKILL.md playbooks and obligation closure gates.

use carnot::bridge::CarnotMachine;
use carnot::intake::AccessPolicy;
use carnot::oracle::InspectionFirewall;
use carnot::playbooks::load_workspace_playbooks;
use carnot::proposals::{compute_lcs_line_diff, DiffLineKind, ProposalState};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!(
        "carnot_{}_{}_{}_{}",
        tag,
        std::process::id(),
        nanos,
        seq
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn black_box_shield_toggle_is_recorded_honestly() {
    let mut m = CarnotMachine::new_seeded();
    assert!(m.manifest.black_box_enforced, "shield defaults ON");
    assert!(m.clean_room_cert.black_box_enforced);
    let receipts_before = m.evidence.len();

    let off = m.set_black_box_mode(false);
    assert!(!off.black_box_enforced);
    assert!(!m.manifest.black_box_enforced);
    assert!(off
        .attestation_statement
        .contains("WHITE-BOX INSPECTION MODE"));
    assert!(m
        .manifest
        .render_carnot_toml()
        .contains("black_box_enforced = false"));
    assert!(
        m.evidence.len() >= receipts_before + 2,
        "cert + toggle receipts"
    );
    assert!(m.audit_log.iter().any(|e| e.kind == "BLACK_BOX_SHIELD"));

    let on = m.set_black_box_mode(true);
    assert!(on.black_box_enforced);
    assert!(on.attestation_statement.starts_with("BLACK-BOX SHIELD ON"));
    assert_ne!(on.receipt_id, off.receipt_id);
    assert_eq!(on.quarantined_source_bytes_read, 0);
}

#[test]
fn hybrid_search_skips_quarantine_only_when_shield_on() {
    let root = temp_dir("hybrid");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("src/permissive.rs"),
        "// SPDX-License-Identifier: MIT\npub fn murmur_bucket(key: &str) -> u32 { key.len() as u32 % 100 }\n",
    )
    .unwrap();
    fs::write(
        root.join("src/copyleft.rs"),
        "// SPDX-License-Identifier: AGPL-3.0-only\npub fn murmur_bucket_agpl(key: &str) -> u32 { 7 }\n",
    )
    .unwrap();
    fs::write(
        root.join("src/prose.rs"),
        "//! Notes: the AGPL server is excluded; this proprietary-sounding comment is just prose.\npub fn murmur_notes() {}\n",
    )
    .unwrap();

    let mut m = CarnotMachine::new_seeded();
    m.workspace_root = Some(root.clone());

    let on = m.search_codebase("murmur bucket", 10);
    assert!(on.black_box_enforced);
    assert_eq!(on.quarantined_files_skipped, 1);
    assert!(on
        .hits
        .iter()
        .all(|h| !h.file_path.ends_with("copyleft.rs")));
    assert!(on
        .hits
        .iter()
        .any(|h| h.file_path.ends_with("permissive.rs")));
    assert!(
        on.hits.iter().any(|h| h.file_path.ends_with("prose.rs")),
        "prose mentioning AGPL must not be quarantined"
    );

    m.set_black_box_mode(false);
    let off = m.search_codebase("murmur bucket", 10);
    assert!(!off.black_box_enforced);
    assert_eq!(off.quarantined_files_skipped, 0);
    assert!(off
        .hits
        .iter()
        .any(|h| h.file_path.ends_with("copyleft.rs")));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn inspection_firewall_blocks_white_box_subcommands_on_quarantined_targets() {
    assert!(InspectionFirewall::is_subcommand_clean_room_safe(
        "capture-process"
    ));
    assert!(!InspectionFirewall::is_subcommand_clean_room_safe(
        "decompile"
    ));
    let err = InspectionFirewall::invoke_json(
        AccessPolicy::QuarantinedBlackBoxSpecOnly,
        "decompile",
        &["./restricted.bin"],
        2_000,
    )
    .expect_err("decompiler must be blocked");
    assert!(!err.allowed);
    assert!(err.output_sha256.is_none());
    assert!(err.reason.contains("blocked"));
}

#[test]
fn lcs_diff_marks_changed_lines_and_spans() {
    let diff = compute_lcs_line_diff("a = 1\nb = 2\nc = 3", "a = 1\nb = 20\nc = 3\nd = 4");
    let kinds: Vec<DiffLineKind> = diff.iter().map(|d| d.kind).collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == DiffLineKind::Context)
            .count(),
        2
    );
    assert!(diff
        .iter()
        .any(|d| d.kind == DiffLineKind::Removed && d.text == "b = 2"));
    assert!(diff
        .iter()
        .any(|d| d.kind == DiffLineKind::Added && d.text == "b = 20"));
    assert!(diff
        .iter()
        .any(|d| d.kind == DiffLineKind::Added && d.text == "d = 4"));
    assert!(diff
        .iter()
        .any(|d| d.kind == DiffLineKind::Added && d.text == "b = 20" && d.changed_span.is_some()));
}

#[test]
fn accept_then_undo_is_lossless() {
    let mut m = CarnotMachine::new_seeded();
    let before_manifest = serde_json::to_value(&m.manifest).unwrap();
    let before_toml = m.manifest.render_carnot_toml();
    let organs_before = m.manifest.organs.len();

    let card = m.submit_composer_prompt("webhook signature verifier");
    let accepted = m.decide_proposal(&card.id, "accept").expect("accept");
    assert_eq!(accepted.state, ProposalState::Accepted);
    assert!(accepted.can_undo);
    assert!(accepted.before_snapshot.is_some());
    assert!(!accepted.diff_lines.is_empty());
    assert_eq!(m.manifest.organs.len(), organs_before + 1);
    assert!(
        m.decide_proposal(&card.id, "accept").is_err(),
        "double-accept rejected"
    );

    let undone = m.decide_proposal(&card.id, "undo").expect("undo");
    assert!(!undone.can_undo);
    assert_eq!(serde_json::to_value(&m.manifest).unwrap(), before_manifest);
    assert_eq!(m.manifest.render_carnot_toml(), before_toml);
    assert!(
        m.decide_proposal(&card.id, "undo").is_err(),
        "double-undo rejected"
    );
}

#[test]
fn workspace_skill_playbooks_load_and_run() {
    let root = temp_dir("playbooks");
    let pb_dir = root.join(".carnot/playbooks/audit-deps");
    fs::create_dir_all(&pb_dir).unwrap();
    fs::write(
        pb_dir.join("SKILL.md"),
        "---\ntitle: Audit Dependencies\nshortcut: A\nstage: Intake\ndescription: Check licenses of all deps\n---\n# Steps\n1. List deps.\n",
    )
    .unwrap();

    let pbs = load_workspace_playbooks(&root);
    assert_eq!(pbs.len(), 1);
    assert_eq!(pbs[0].id, "audit-deps");
    assert_eq!(pbs[0].title, "Audit Dependencies");
    assert_eq!(pbs[0].stage, "Intake");
    assert_eq!(pbs[0].summary, "Check licenses of all deps");
    assert!(pbs[0].skill_markdown.starts_with("# Steps"));

    let mut m = CarnotMachine::new_seeded();
    m.playbooks.extend(pbs);
    let msg = m
        .execute_playbook("audit-deps")
        .expect("custom playbook runs");
    assert!(msg.contains("audit-deps"));
    assert!(m.shell.chat.iter().any(|c| c.text.contains("List deps")));
    assert!(m.execute_playbook("does-not-exist").is_err());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn seeded_obligations_are_not_closed_without_proof() {
    let mut m = CarnotMachine::new_seeded();
    let ids: Vec<String> = m.manifest.organs.iter().map(|o| o.id.clone()).collect();
    m.obligations = carnot::obligations::ObligationLedger::seeded_for_organs(&ids);
    let verdict = m.evaluate_obligations();
    assert!(verdict.total_obligations >= ids.len());
    assert!(!verdict.all_closed);
    assert!(verdict.closed_obligations < verdict.total_obligations);
    assert!(verdict.coverage_pct < 100.0);
}
