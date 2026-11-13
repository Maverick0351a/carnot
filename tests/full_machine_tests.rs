use carnot::bridge::CarnotMachine;
use carnot::eval::{
    g_eval_metric_from_logprobs, rating_token_to_score, score_from_token_string,
    verify_json_fields, verify_tool_calls, DatasetSplit, TokenLogprob, ToolCallRecord,
    TopLogprobEntry,
};
use carnot::evidence::sha256_hex;
use carnot::evolve::{
    evaluate_json_command_with_timeout, extract_evolve_blocks, splice_evolve_block,
};
use carnot::mcp::handle_jsonrpc_with_budget;
use carnot::rollout::{EvaluatedVariant, FeatureState, RolloutContext, VariantPayload};
use carnot::scout::{inspect_local_directory_metrics, TargetLanguage};
use carnot::server::run_http_server;
use carnot::tier::AccountTier;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Deserialize)]
struct ToggleSpecSuite {
    name: String,
    state: FeatureState,
    #[serde(default)]
    tests: Vec<ToggleTestCase>,
    #[serde(default, rename = "variantTests")]
    variant_tests: Vec<VariantTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToggleTestCase {
    description: String,
    context: RolloutContext,
    toggle_name: String,
    expected_result: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedVariant {
    name: String,
    #[serde(default)]
    payload: Option<VariantPayload>,
    enabled: bool,
    #[serde(default, alias = "feature_enabled")]
    feature_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VariantTestCase {
    #[allow(dead_code)]
    description: String,
    context: RolloutContext,
    toggle_name: String,
    expected_result: ExpectedVariant,
}

fn run_toggle_spec_file(filename: &str) -> (usize, usize) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("specs");
    path.push("feature_toggle_v2");
    path.push(filename);

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    let suite: ToggleSpecSuite = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));

    for tc in &suite.tests {
        let actual = suite.state.is_enabled(&tc.toggle_name, &tc.context);
        assert_eq!(
            actual, tc.expected_result,
            "[Suite {}] toggle test '{}' failed on '{}'",
            suite.name, tc.description, tc.toggle_name
        );
    }

    for vc in &suite.variant_tests {
        let actual: EvaluatedVariant = suite.state.get_variant(&vc.toggle_name, &vc.context);
        assert_eq!(actual.name, vc.expected_result.name);
        assert_eq!(actual.enabled, vc.expected_result.enabled);
        assert_eq!(actual.payload, vc.expected_result.payload);
        if let Some(exp_fe) = vc.expected_result.feature_enabled {
            assert_eq!(actual.feature_enabled, exp_fe);
        }
    }

    (suite.tests.len(), suite.variant_tests.len())
}

#[test]
fn feature_toggle_v2_conformance_suites() {
    let files = [
        "01-simple-examples.json",
        "08-variants.json",
        "10-flexible-rollout-strategy.json",
        "13-constraint-operators.json",
        "15-global-constraints.json",
        "17-dependent-features.json",
    ];
    let mut total_toggles = 0usize;
    let mut total_variants = 0usize;
    for f in files {
        let (t, v) = run_toggle_spec_file(f);
        total_toggles += t;
        total_variants += v;
    }
    assert_eq!(total_toggles + total_variants, 127);
}

#[test]
fn sha256_fips_vector_and_bounded_mcp_paging() {
    // FIPS 180-4 test vector: SHA-256("abc")
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let mut machine = CarnotMachine::new_seeded();
    // Force tiny 256-byte MCP budget so carnot_verify auto-pages into an ev_... receipt
    let resp = handle_jsonrpc_with_budget(
        &mut machine,
        &json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": { "name": "carnot_verify", "arguments": {} }
        })
        .to_string(),
        256,
    )
    .unwrap();

    let txt = resp["result"]["content"][0]["text"].as_str().unwrap();
    let meta: Value = serde_json::from_str(txt).unwrap();
    assert_eq!(meta["truncated"], true);
    let rid = meta["receipt_id"].as_str().unwrap();
    assert!(rid.starts_with("ev_"));

    // Page the receipt back via carnot_evidence_browse
    let browse_resp = handle_jsonrpc_with_budget(
        &mut machine,
        &json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "carnot_evidence_browse",
                "arguments": { "receipt_id": rid, "offset": 0, "limit": 512 }
            }
        })
        .to_string(),
        16_384,
    )
    .unwrap();
    let page_txt = browse_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let page: Value = serde_json::from_str(page_txt).unwrap();
    assert_eq!(page["id"], rid);
    assert!(page["total_bytes"].as_u64().unwrap() > 256);
}

#[test]
fn five_stage_polyglot_tier_gate_and_cutover_closed_loop() {
    let mut machine = CarnotMachine::new_seeded();

    // Local directory scouting works on real filesystem
    let self_metrics =
        inspect_local_directory_metrics(Path::new(env!("CARGO_MANIFEST_DIR")), "self", "Test")
            .unwrap();
    assert!(self_metrics.code_files >= 5);

    // Stage 3: Polyglot emitter generates Go, TypeScript, Python, Scala3, Zig, and Rust plans
    for (lang, expected_cmd) in [
        (TargetLanguage::Go, "go build ./..."),
        (TargetLanguage::TypeScript, "bun run build"),
        (TargetLanguage::Python, "uv build"),
        (TargetLanguage::Scala3, "sbt compile"),
        (TargetLanguage::Zig, "zig build -Doptimize=ReleaseFast"),
        (TargetLanguage::Rust, "cargo build --release"),
    ] {
        let plan = machine.preview_target_build(Some(lang));
        assert_eq!(plan.build_command, expected_cmd);
    }

    // Community tier blocks Pro differentiators while keeping Verify + Polyglot Build open
    machine.set_tier(AccountTier::Community);
    assert!(machine.run_scout(None).is_err());
    assert!(machine.export_clean_room_certificate().is_err());
    assert!(machine
        .promote_canary("v2-carnot-consolidated", 25)
        .is_err());
    assert_eq!(machine.run_evaluations(DatasetSplit::Golden).len(), 3);

    // Switch back to Pro -> all 5 stages unlocked
    machine.set_tier(AccountTier::Pro);
    assert_eq!(
        machine
            .export_clean_room_certificate()
            .unwrap()
            .quarantined_source_bytes_read,
        0
    );
    assert!(machine.promote_canary("v3-unverified-draft", 25).is_err());
    let st = machine
        .promote_canary("v2-carnot-consolidated", 35)
        .unwrap();
    assert_eq!(st.canary_rollout_pct, 35);

    let tripped = machine.simulate_live_traffic(45, true).unwrap();
    assert!(tripped.killswitch_tripped);
    assert_eq!(tripped.canary_rollout_pct, 0);
    assert!(tripped.regressions_captured >= 1);
    assert!(tripped.latest_receipt_id.unwrap().starts_with("ev_"));
}

#[test]
fn evaluators_and_ephemeral_http_workbench_smoke_test() {
    assert_eq!(score_from_token_string(" \"5\" "), Some(5.0));
    assert_eq!(
        rating_token_to_score(&TokenLogprob {
            token: "5".into(),
            logprob: -9999.0,
            top_logprobs: vec![],
        }),
        Some(5.0)
    );
    let stream = vec![
        TokenLogprob {
            token: "{\"coherence\": ".into(),
            logprob: -0.01,
            top_logprobs: vec![],
        },
        TokenLogprob {
            token: "5".into(),
            logprob: -0.22314355,
            top_logprobs: vec![
                TopLogprobEntry {
                    token: "5".into(),
                    logprob: -0.22314355,
                },
                TopLogprobEntry {
                    token: "4".into(),
                    logprob: -1.6094379,
                },
            ],
        },
        TokenLogprob {
            token: "}".into(),
            logprob: -0.01,
            top_logprobs: vec![],
        },
    ];
    let g = g_eval_metric_from_logprobs(&stream, "coherence", &["coherence"]).unwrap();
    assert!((g - 4.8).abs() < 0.01);

    let trace = vec![ToolCallRecord {
        name: "mcp_policy_lookup".into(),
        arguments: Default::default(),
    }];
    assert!(verify_tool_calls(
        &trace,
        &["drop_production_table".into()],
        "never",
        false
    ));
    assert!(verify_json_fields(
        r#"{"verdict":"ok"}"#,
        &["verdict".into()]
    ));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let machine = Arc::new(Mutex::new(CarnotMachine::new_seeded()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        let _ = run_http_server(listener, machine, shutdown_clone);
    });

    let http_get = |path: &str| -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        write!(
            s,
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };

    let root = http_get("/");
    assert!(root.contains("HTTP/1.1 200 OK"));
    assert!(root.contains("closedby=\"any\""));
    assert!(root.contains("focusgroup=\"tablist nomemory\""));

    let cert_resp = http_get("/api/intake/cert");
    assert!(cert_resp.contains("HTTP/1.1 200 OK"));
    assert!(cert_resp.contains("\"quarantined_source_bytes_read\":0"));

    let metrics = http_get("/metrics");
    assert!(metrics.contains("carnot_evidence_receipts_total"));

    let http_post = |path: &str, body: &str| -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        write!(
            s,
            "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            body.len(),
            body
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };

    let nav = http_post(
        "/api/shell/navigate",
        r#"{"screen":"workbench","pane":"dossier","organ_id":"router"}"#,
    );
    assert!(nav.contains("HTTP/1.1 200 OK"));
    assert!(nav.contains("\"selected_organ_id\":\"router\""));

    let submit = http_post(
        "/api/chat/submit",
        r#"{"prompt":"rate limit gateway organ"}"#,
    );
    assert!(submit.contains("HTTP/1.1 200 OK"));
    assert!(submit.contains("\"rate_limit_gateway\""));

    // Point/Tick honesty surfaces in UI HTML + HTTP routes
    assert!(root.contains("id=\"pointWorkspaceBtn\""));
    assert!(root.contains("id=\"daemonTickBtn\""));
    assert!(root.contains("id=\"autopilotToggle\""));
    assert!(root.contains("explicit_candidate"));
    assert!(root.contains("demo offline") || root.contains("demo offline until"));
    assert!(root.contains("carnot daemon --ticks"));

    let tick = http_post("/api/daemon/tick", "{}");
    assert!(tick.contains("HTTP/1.1 200 OK"));
    assert!(
        tick.contains("skipped_reason") || tick.contains("no pointed target"),
        "daemon tick without workspace should skip: {tick}"
    );

    let bad_point = http_post("/api/point", "{}");
    assert!(bad_point.contains("HTTP/1.1 400"));
    assert!(bad_point.contains("Missing 'path'"));

    shutdown.store(true, Ordering::Relaxed);
    handle.join().unwrap();
}

#[test]
fn app_shell_proposals_organ_flags_creep_pruner_and_mcp_navigation() {
    let mut machine = CarnotMachine::new_seeded();
    assert_eq!(machine.agents.len(), 5);
    assert_eq!(machine.playbooks.len(), 6);

    // Every organ gets its own wire toggle ("Build Part-by-Part")
    let ctx = RolloutContext::default();
    assert!(machine
        .feature_state
        .is_enabled("organ.verifier.enabled", &ctx));
    machine.toggle_organ_flag("verifier", false).unwrap();
    assert!(!machine
        .feature_state
        .is_enabled("organ.verifier.enabled", &ctx));
    machine.toggle_organ_flag("verifier", true).unwrap();

    // Shared composer stages ProposalCard -> Accept adds organ -> Undo cleanly reverts it
    let base_organs = machine.manifest.organs.len();
    let card = machine.submit_composer_prompt("webhook signature validator");
    assert_eq!(machine.manifest.organs.len(), base_organs); // Not added until human Accepts!

    let accepted = machine.decide_proposal(&card.id, "accept").unwrap();
    assert_eq!(format!("{:?}", accepted.state), "Accepted");
    assert_eq!(machine.manifest.organs.len(), base_organs + 1);
    assert!(machine
        .feature_state
        .is_enabled("organ.webhook_signature_validator.enabled", &ctx));

    // Entropy audit detects unexercised organ flags or overlapping schemas
    let findings = machine.audit_feature_creep();
    assert!(!findings.is_empty());

    // Undo cleanly removes the added organ and its wire flag
    let undone = machine.decide_proposal(&card.id, "undo").unwrap();
    assert_eq!(format!("{:?}", undone.state), "Undone");
    assert_eq!(machine.manifest.organs.len(), base_organs);

    // MCP window-driving tools (`carnot_ui_navigate` + `carnot_playbook_run`)
    let mcp_nav = handle_jsonrpc_with_budget(
        &mut machine,
        &json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "carnot_ui_navigate",
                "arguments": { "screen": "workbench", "pane": "prune", "organ_id": "provenance" }
            }
        })
        .to_string(),
        16_384,
    )
    .unwrap();
    let nav_txt = mcp_nav["result"]["content"][0]["text"].as_str().unwrap();
    assert!(nav_txt.contains("\"provenance\""));

    let mcp_pb = handle_jsonrpc_with_budget(
        &mut machine,
        &json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "carnot_playbook_run",
                "arguments": { "playbook_id": "parallel-shootout" }
            }
        })
        .to_string(),
        16_384,
    )
    .unwrap();
    let pb_txt = mcp_pb["result"]["content"][0]["text"].as_str().unwrap();
    assert!(pb_txt.contains("Pareto frontier"));
}

/// No embedded double quotes: Windows `Command` quoting then stays a single
/// quoted argv element, which CPython's parser accepts unchanged.
const JSON_OK_PROBE: &str = "import json,sys; sys.stdout.buffer.write(b'boot_log\\r\\n'); sys.stdout.buffer.write(json.dumps({'objective': 2.635983, 'validity': 1.0}).encode()); sys.stdout.buffer.write(b'\\r\\n')";

const JSON_BAD_PROBE: &str = "import json,sys; sys.stdout.buffer.write(json.dumps({'objective': 2.635983, 'validity': 0.0}).encode()); sys.stdout.buffer.write(b'\\r\\n')";

fn json_probe_interpreter() -> &'static str {
    let mut attempts = Vec::new();
    for candidate in ["python", "python3"] {
        let mut cmd = std::process::Command::new(candidate);
        cmd.arg("--version");
        let out = carnot::proc_util::run_command_bounded(cmd, None, 5_000, 16_384);
        if out.spawned && out.success && !out.timed_out {
            return candidate;
        }
        attempts.push(format!("{candidate}: {out:?}"));
    }
    panic!(
        "python interpreter not found; put python or python3 on PATH. attempts: {}",
        attempts.join(" | ")
    );
}

#[test]
fn scoped_evolve_blocks_island_ring_and_subprocess_json_verifier() {
    let src = "fn frozen_wrapper() {\n    // EVOLVE_START\n    let x = 1;\n    // EVOLVE_END\n    assert!(true);\n}\n";
    let blocks = extract_evolve_blocks(src, 1).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].body, "    let x = 1;");

    // Rejects nested EVOLVE marker injection
    assert!(splice_evolve_block(src, 0, "// EVOLVE_START\nlet x = 2;").is_err());

    // Preserves outer wrapper byte-for-byte
    let spliced = splice_evolve_block(src, 0, "    let x = 42;").unwrap();
    assert!(spliced.starts_with("fn frozen_wrapper() {\n    // EVOLVE_START\n"));
    assert!(spliced.ends_with("\n    // EVOLVE_END\n    assert!(true);\n}\n"));
    assert!(spliced.contains("let x = 42;"));

    // Independent subprocess last-line JSON evaluator.
    //
    // The old Windows probe was `powershell.exe -Command` with a 2s budget.
    // On windows-latest that call returned success=false after about 2s and
    // the assertion fired before a JSON line was checked. That lines up with
    // the wall-clock kill. The host is also a poor stand-in for the gym: it
    // re-parses the raw command line, and a redirected pipe can capture UTF-16
    // instead of the UTF-8 text this verifier decodes. This run did not capture
    // that encoding; it is a reason not to keep the probe. Gym benches already
    // run under Python on both CI images. The script writes CRLF bytes itself.
    // The same probe runs on every OS; there is no platform skip.
    let python = json_probe_interpreter();
    let ok_eval = evaluate_json_command_with_timeout(python, &["-c", JSON_OK_PROBE], 10_000);
    assert!(ok_eval.success, "last-line JSON probe failed: {ok_eval:?}");
    assert!((ok_eval.raw_objective - 2.635983).abs() < 1e-6);
    assert!((ok_eval.validity - 1.0).abs() < 1e-9);

    let rejected_eval = evaluate_json_command_with_timeout(python, &["-c", JSON_BAD_PROBE], 10_000);
    assert!(
        !rejected_eval.success,
        "validity <= 0 must be rejected: {rejected_eval:?}"
    );
    assert_eq!(
        rejected_eval.error_message.as_deref(),
        Some("Candidate rejected: non-finite objective or validity <= 0.0")
    );

    // Pro tier gate + 3-island ring evolution + SHA-256 Experience Cards
    let mut machine = CarnotMachine::new_seeded();
    machine.set_tier(AccountTier::Community);
    assert!(machine.evolve_organ(Some("verifier"), Some(4)).is_err());

    machine.set_tier(AccountTier::Pro);
    let report = machine.evolve_organ(Some("verifier"), Some(6)).unwrap();
    assert!(!report.blind_prompt.contains_external_code);
    assert!(report.baseline_replaced);
    assert!(report.best_score > report.baseline_score);
    assert!(report.rejected_candidates >= 1);
    assert!(!report.experience_cards.is_empty());
    assert!(report.experience_cards[0].receipt_id.starts_with("ev_"));

    // MCP tool `carnot_evolve_organ`
    let mcp_ev = handle_jsonrpc_with_budget(
        &mut machine,
        &json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "carnot_evolve_organ",
                "arguments": { "organ_id": "router", "generations": 4 }
            }
        })
        .to_string(),
        32_768,
    )
    .unwrap();
    assert_eq!(mcp_ev["result"]["isError"], false);
}

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn real_disk_spdx_scan_project_generation_and_git_worktree_trial() {
    use carnot::intake::AccessPolicy;
    use carnot::workspace::{
        init_workspace, materialize_project_to_disk, read_jsonl, WorkspaceLayout,
    };
    use carnot::worktree::{run_git_worktree_trial, CandidateSource, WorktreeTrialRequest};

    let root = std::env::temp_dir().join(format!("carnot-e2e-disk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let _guard = TempDirGuard(root.clone());

    // 1. Real filesystem SPDX firewall scan on mixed MIT + AGPL-3.0 tree
    let mixed = root.join("mixed-sources");
    std::fs::create_dir_all(mixed.join("permissive_core")).unwrap();
    std::fs::create_dir_all(mixed.join("copyleft_server")).unwrap();
    std::fs::write(
        mixed.join("permissive_core").join("LICENSE"),
        "MIT License\nPermission is hereby granted, free of charge...",
    )
    .unwrap();
    std::fs::write(
        mixed.join("permissive_core").join("algo.rs"),
        "pub fn ok() -> bool { true }\n",
    )
    .unwrap();
    std::fs::write(
        mixed.join("permissive_core").join("vectors.json"),
        "{\"cases\":[]}\n",
    )
    .unwrap();
    std::fs::write(
        mixed.join("copyleft_server").join("LICENSE"),
        "GNU AFFERO GENERAL PUBLIC LICENSE Version 3",
    )
    .unwrap();
    std::fs::write(
        mixed.join("copyleft_server").join("restricted.rs"),
        "pub fn do_not_read() {}\n",
    )
    .unwrap();

    let mut machine = CarnotMachine::new_seeded();
    let cert = machine.scan_intake_directory(&mixed).unwrap();
    assert_eq!(cert.quarantined_source_bytes_read, 0);
    let agpl_zone = cert
        .zones
        .iter()
        .find(|z| z.zone_alias == "copyleft_server")
        .unwrap();
    assert_eq!(agpl_zone.detected_spdx, "AGPL-3.0");
    assert_eq!(agpl_zone.policy, AccessPolicy::QuarantinedBlackBoxSpecOnly);
    assert_eq!(agpl_zone.source_files_blocked, 1);
    assert_eq!(agpl_zone.spec_fixtures_harvested, 0);

    let mit_zone = cert
        .zones
        .iter()
        .find(|z| z.zone_alias == "permissive_core")
        .unwrap();
    assert_eq!(mit_zone.detected_spdx, "MIT");
    assert_eq!(
        mit_zone.policy,
        AccessPolicy::PermissiveAlgorithmAndFixtures
    );
    assert_eq!(mit_zone.spec_fixtures_harvested, 2);

    // 2. Materialize real Python project + git repo onto disk
    let proj_dir = root.join("synthesized-py");
    let ws_manifest = init_workspace(&proj_dir, "edge-gate", TargetLanguage::Python).unwrap();
    let plan =
        materialize_project_to_disk(&ws_manifest, &proj_dir, Some(TargetLanguage::Python), true)
            .unwrap();
    assert_eq!(plan.target_language, TargetLanguage::Python);
    assert!(proj_dir.join(".git").exists());
    assert!(proj_dir.join("organs/verifier.py").exists());

    // Reload CarnotMachine from real disk workspace
    let loaded_machine = CarnotMachine::from_workspace(&proj_dir).unwrap();
    assert_eq!(loaded_machine.manifest.project_name, "edge-gate");

    // 3a. Broken candidate in isolated git worktree MUST be rejected & leave primary file untouched
    let verifier_organ = &ws_manifest.organs[0];
    let bad_trial = run_git_worktree_trial(WorktreeTrialRequest {
        repo_dir: &proj_dir,
        organ: verifier_organ,
        organ_rel_path: "organs/verifier.py",
        block_index: 0,
        candidate_source: CandidateSource::ExplicitBlock("    raise ValueError(\"broken\")"),
        test_program: "python",
        test_args: &["-m", "unittest", "discover", "-s", "tests"],
        bench_program: "python",
        bench_args: &["solve_bench.py"],
        timeout_ms: 8_000,
        state_dir: None,
    })
    .unwrap();
    assert!(!bad_trial.tests_passed);
    assert!(!bad_trial.ratcheted_baseline);
    assert!(bad_trial.worktree_cleaned_up);

    // 3b. Live headless command agent returning fenced Python code that rejects ASCII control bytes
    // upgrades solve_bench objective from 1.0 -> 1.5 and ratchets primary file + ledger.jsonl!
    let agent_py_script = "print('```python\\n    trimmed = payload.strip()\\n    if not trimmed or len(trimmed) > 65536 or any(ord(ch) < 32 for ch in trimmed):\\n        raise ValueError(\"invalid_payload\")\\n    return f\"[verifier] {trimmed}\"\\n```')";
    let good_trial = run_git_worktree_trial(WorktreeTrialRequest {
        repo_dir: &proj_dir,
        organ: verifier_organ,
        organ_rel_path: "organs/verifier.py",
        block_index: 0,
        candidate_source: CandidateSource::HeadlessAgent {
            agent_id: "python-headless-agent",
            custom_program_and_args: Some(("python", &["-c", agent_py_script])),
            timeout_ms: 5_000,
        },
        test_program: "python",
        test_args: &["-m", "unittest", "discover", "-s", "tests"],
        bench_program: "python",
        bench_args: &["solve_bench.py"],
        timeout_ms: 8_000,
        state_dir: None,
    })
    .unwrap();

    assert!(good_trial.tests_passed, "diag: {}", good_trial.diagnostic);
    assert!(
        good_trial.ratcheted_baseline,
        "diag: {}",
        good_trial.diagnostic
    );
    assert!((good_trial.baseline_objective - 1.0).abs() < 1e-6);
    assert!((good_trial.candidate_eval.raw_objective - 1.5).abs() < 1e-6);
    assert!(good_trial.worktree_cleaned_up);
    assert!(good_trial.receipt_id.as_deref().unwrap().starts_with("ev_"));

    // Verify zero leftover git worktree directories and >= 3 JSONL receipts on disk
    let wt_entries: Vec<_> = std::fs::read_dir(proj_dir.join(".carnot").join("worktrees"))
        .unwrap()
        .collect();
    assert_eq!(wt_entries.len(), 0);

    let layout = WorkspaceLayout::at(&proj_dir);
    let ledger_rows = read_jsonl(&layout.ledger_jsonl).unwrap();
    assert!(ledger_rows.len() >= 3);
}

#[test]
fn real_http_strangler_fig_reverse_proxy_failover_and_regression_jsonl() {
    use carnot::proxy::{run_reverse_proxy, ProxyConfig};
    use carnot::workspace::read_jsonl;
    use std::time::Duration;

    let root = std::env::temp_dir().join(format!("carnot-e2e-proxy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let _guard = TempDirGuard(root.clone());
    let reg_jsonl = root.join(".carnot").join("regressions.jsonl");

    let spawn_mock_upstream = |status_line: &'static str,
                               body: &'static str,
                               stop: Arc<AtomicBool>| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok((mut s, _)) = listener.accept() {
                    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut req_buf = [0u8; 2048];
                    let _ = s.read(&mut req_buf);
                    let resp = format!(
                        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status_line,
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.flush();
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });
        (addr, handle)
    };

    let stop_all = Arc::new(AtomicBool::new(false));
    let (control_addr, ctrl_h) = spawn_mock_upstream(
        "200 OK",
        r#"{"source":"control","verdict":"ok"}"#,
        Arc::clone(&stop_all),
    );
    let (canary_addr, can_h) = spawn_mock_upstream(
        "500 Internal Server Error",
        r#"{"source":"canary","error":"fault"}"#,
        Arc::clone(&stop_all),
    );

    let mut machine = CarnotMachine::new_seeded();
    machine.policy.min_samples_before_trip = 3;
    machine
        .promote_canary("v2-carnot-consolidated", 100)
        .unwrap();
    let shared_machine = Arc::new(Mutex::new(machine));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let cfg = ProxyConfig {
        control_upstream: control_addr,
        canary_upstream: canary_addr,
        upstream_timeout_ms: 1500,
        regressions_jsonl_path: Some(reg_jsonl.clone()),
    };
    let proxy_stop = Arc::clone(&stop_all);
    let proxy_machine = Arc::clone(&shared_machine);
    let proxy_h = std::thread::spawn(move || {
        let _ = run_reverse_proxy(proxy_listener, cfg, proxy_machine, proxy_stop);
    });

    for i in 1..=4 {
        let payload = format!(r#"{{"audit_seq":{}}}"#, i);
        let mut client = TcpStream::connect(proxy_addr).unwrap();
        write!(
            client,
            "POST /v1/audit HTTP/1.1\r\nHost: localhost\r\nX-User-Id: usr-live-{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            i,
            payload.len(),
            payload
        )
        .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        // Every request succeeds for the caller via transparent failover + circuit breaker!
        assert!(resp.contains("HTTP/1.1 200 OK"), "resp={}", resp);
        assert!(resp.contains(r#""source":"control""#), "resp={}", resp);
    }

    {
        let m = shared_machine.lock().unwrap();
        assert!(m.killswitch_tripped);
        assert_eq!(m.canary_rollout_pct, 0);
        assert!(m.regressions_captured >= 1);
    }

    let reg_rows = read_jsonl(&reg_jsonl).unwrap();
    assert_eq!(reg_rows.len(), 3); // 3 canary 500s tripped circuit breaker; 4th went straight to control!
    assert_eq!(reg_rows[0]["method"], "POST");
    assert_eq!(reg_rows[0]["path"], "/v1/audit");
    assert_eq!(reg_rows[0]["canary_status"], 500);

    stop_all.store(true, Ordering::Relaxed);
    proxy_h.join().unwrap();
    ctrl_h.join().unwrap();
    can_h.join().unwrap();
}
