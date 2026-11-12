use carnot::bridge::{CarnotMachine, EvolveOpts, DEFAULT_CUTOVER_FLAG};
use carnot::eval::DatasetSplit;
use carnot::proxy::{run_reverse_proxy, ProxyConfig};
use carnot::scout::{inspect_local_directory_metrics, TargetLanguage};
use carnot::workspace::{
    init_workspace, load_manifest_from_workspace, materialize_project_to_disk, WorkspaceLayout,
};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn launch_desktop_app_window(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let app_arg = format!("--app={}", url);
        let edge_candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ];
        for edge in edge_candidates {
            if Path::new(edge).exists() && Command::new(edge).arg(&app_arg).spawn().is_ok() {
                return;
            }
        }
        if Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .is_ok()
        {
            return;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

fn load_or_seed_machine(workspace_arg: Option<&str>) -> CarnotMachine {
    if let Some(ws) = workspace_arg {
        let p = Path::new(ws);
        if p.join("carnot.manifest.json").exists() {
            if let Ok(m) = CarnotMachine::from_workspace(p) {
                return m;
            }
        }
    }
    let cwd_manifest = Path::new("carnot.manifest.json");
    if cwd_manifest.exists() {
        if let Ok(m) = CarnotMachine::from_workspace(Path::new(".")) {
            return m;
        }
    }
    CarnotMachine::new_seeded()
}

fn serve_workbench(bind_addr: &str, open_app_window: bool, workspace_dir: Option<&str>) {
    let listener = match TcpListener::bind(bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {}: {}", bind_addr, e);
            std::process::exit(1);
        }
    };
    let local = listener.local_addr().unwrap();
    let url = format!("http://{}/", local);
    println!("Carnot App Shell & Cutover Server listening on {}", url);
    println!("  App Shell UI:          {}", url);
    println!(
        "  Client SDK Features:   http://{}/api/client/features",
        local
    );
    println!("  Clean-Room IP Cert:    http://{}/api/intake/cert", local);
    println!("  Prometheus Metrics:    http://{}/metrics", local);
    println!("  Press Ctrl+C to stop server cleanly.");

    if open_app_window {
        launch_desktop_app_window(&url);
    }

    let machine = Arc::new(Mutex::new(load_or_seed_machine(workspace_dir)));
    let shutdown = Arc::new(AtomicBool::new(false));
    if let Err(e) = carnot::server::run_http_server(listener, machine, shutdown) {
        eprintln!("HTTP server error: {}", e);
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("demo");

    match cmd {
        "demo" => run_demo(),
        "init" => {
            let dir = args.get(2).map(|s| s.as_str()).unwrap_or(".");
            let project_name = args
                .get(3)
                .map(|s| s.as_str())
                .unwrap_or("carnot-synthesized-app");
            let lang = args
                .get(4)
                .map(|s| TargetLanguage::from_str_loose(s))
                .unwrap_or(TargetLanguage::Rust);
            match init_workspace(Path::new(dir), project_name, lang) {
                Ok(manifest) => println!("{}", serde_json::to_string_pretty(&manifest).unwrap()),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        "intake-scan" => {
            let dir = args.get(2).map(|s| s.as_str()).unwrap_or(".");
            let mut machine = load_or_seed_machine(Some(dir));
            match machine.scan_intake_directory(Path::new(dir)) {
                Ok(cert) => println!("{}", serde_json::to_string_pretty(&cert).unwrap()),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        "generate" => {
            let dir_str = args.get(2).map(|s| s.as_str()).unwrap_or("./generated-app");
            let target_dir = Path::new(dir_str);
            let lang = args.get(3).map(|s| TargetLanguage::from_str_loose(s));
            let manifest = load_manifest_from_workspace(target_dir)
                .unwrap_or_else(|_| CarnotMachine::new_seeded().manifest);
            match materialize_project_to_disk(&manifest, target_dir, lang, true) {
                Ok(plan) => {
                    println!(
                        "Materialized {:?} project '{}' ({} files) to '{}'",
                        plan.target_language,
                        plan.project_name,
                        plan.planned_files.len(),
                        target_dir.display()
                    );
                    println!("  Build: {}", plan.build_command);
                    println!("  Test:  {}", plan.test_command);
                    println!("  Bench: {}", plan.bench_command);
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        "proxy" => {
            let listen_str = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:8080");
            let control_str = args.get(3).map(|s| s.as_str()).unwrap_or("127.0.0.1:8081");
            let canary_str = args.get(4).map(|s| s.as_str()).unwrap_or("127.0.0.1:8082");
            let canary_pct = args
                .get(5)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(25);
            let ws_dir = args.get(6).map(|s| s.as_str());

            let control_upstream: SocketAddr = control_str.parse().unwrap_or_else(|e| {
                eprintln!("Invalid control upstream '{}': {}", control_str, e);
                std::process::exit(2);
            });
            let canary_upstream: SocketAddr = canary_str.parse().unwrap_or_else(|e| {
                eprintln!("Invalid canary upstream '{}': {}", canary_str, e);
                std::process::exit(2);
            });
            let listener = TcpListener::bind(listen_str).unwrap_or_else(|e| {
                eprintln!("Failed to bind proxy listener '{}': {}", listen_str, e);
                std::process::exit(1);
            });

            let mut machine = load_or_seed_machine(ws_dir);
            let _ = machine.promote_canary("v2-carnot-consolidated", canary_pct);
            let regressions_jsonl_path =
                ws_dir.map(|d| WorkspaceLayout::at(Path::new(d)).regressions_jsonl);

            println!(
                "Carnot Strangler-Fig Reverse Proxy listening on http://{} -> control={} | canary={} ({}%)",
                listener.local_addr().unwrap(),
                control_upstream,
                canary_upstream,
                canary_pct
            );

            let cfg = ProxyConfig {
                control_upstream,
                canary_upstream,
                upstream_timeout_ms: 3000,
                regressions_jsonl_path,
            };
            let shared = Arc::new(Mutex::new(machine));
            let shutdown = Arc::new(AtomicBool::new(false));
            if let Err(e) = run_reverse_proxy(listener, cfg, shared, shutdown) {
                eprintln!("Proxy error: {}", e);
                std::process::exit(1);
            }
        }
        "scout" => {
            let mut machine = load_or_seed_machine(None);
            if let Some(dir_arg) = args.get(2) {
                let p = Path::new(dir_arg);
                if p.exists() {
                    if let Ok(local_metrics) = inspect_local_directory_metrics(
                        p,
                        "local-inspected-target",
                        "Local Directory",
                    ) {
                        machine.scout_candidates.insert(0, local_metrics);
                    }
                }
            }
            let lang = args.get(3).map(|s| TargetLanguage::from_str_loose(s));
            match machine.run_scout(lang) {
                Ok(ranked) => println!("{}", serde_json::to_string_pretty(&ranked).unwrap()),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        "build-plan" => {
            let mut machine = load_or_seed_machine(None);
            let lang = args.get(2).map(|s| TargetLanguage::from_str_loose(s));
            let plan = machine.preview_target_build(lang);
            println!("{}", serde_json::to_string_pretty(&plan).unwrap());
        }
        "verify" => {
            let mut machine = load_or_seed_machine(None);
            let summaries = machine.run_evaluations(DatasetSplit::Golden);
            println!("{}", serde_json::to_string_pretty(&summaries).unwrap());
        }
        "point" => {
            let dir = args.get(2).map(|s| s.as_str()).unwrap_or(".");
            let mut machine = load_or_seed_machine(Some(dir));
            match machine.point_target(Path::new(dir)) {
                Ok(target) => println!("{}", serde_json::to_string_pretty(&target).unwrap()),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        "daemon" => {
            let mut once = false;
            let mut ticks: Option<u64> = None;
            let mut ws: Option<&str> = None;
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--once" => {
                        once = true;
                        i += 1;
                    }
                    "--ticks" => {
                        i += 1;
                        let Some(n) = args.get(i).and_then(|s| s.parse::<u64>().ok()) else {
                            eprintln!("Usage: carnot daemon [--once | --ticks N] [ws]");
                            std::process::exit(2);
                        };
                        ticks = Some(n);
                        i += 1;
                    }
                    other if other.starts_with('-') => {
                        eprintln!("Unknown daemon flag '{}'", other);
                        std::process::exit(2);
                    }
                    other => {
                        ws = Some(other);
                        i += 1;
                    }
                }
            }
            let tick_count = if once {
                1u64
            } else {
                ticks.unwrap_or(u64::MAX)
            };

            let mut machine = if let Some(dir) = ws {
                let mut m = load_or_seed_machine(Some(dir));
                if let Err(e) = m.point_target(Path::new(dir)) {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
                m
            } else {
                load_or_seed_machine(None)
            };

            for n in 0..tick_count {
                match machine.daemon_tick(None) {
                    Ok(report) => {
                        println!("{}", serde_json::to_string_pretty(&report).unwrap())
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
                if n + 1 < tick_count {
                    thread::sleep(Duration::from_millis(machine.daemon_policy.tick_sleep_ms));
                }
            }
        }
        "evolve" => {
            let mut demo = false;
            let mut apply = false;
            let mut positionals: Vec<&str> = Vec::new();
            for a in args.iter().skip(2) {
                match a.as_str() {
                    "--demo" => demo = true,
                    "--apply" => apply = true,
                    other if other.starts_with('-') => {
                        eprintln!("Unknown evolve flag '{}'", other);
                        std::process::exit(2);
                    }
                    other => positionals.push(other),
                }
            }
            let organ_id = positionals.first().copied().map(|s| s.to_string());
            let gens = positionals.get(1).and_then(|s| s.parse::<usize>().ok());
            let mut machine = load_or_seed_machine(None);
            match machine.evolve_organ_with_opts(EvolveOpts {
                organ_id,
                generations: gens,
                demo,
                apply,
                explicit_candidate: None,
                organ_rel_path: None,
            }) {
                Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        "proposal" => {
            let Some(decision) = args.get(2).map(|s| s.as_str()) else {
                eprintln!(
                    "Usage: carnot proposal <accept|decline|undo> <proposal_id> [ws]\n\
                     PromoteStagedOrgan cards persist under <ws>/.carnot/proposals.json for cross-process Accept."
                );
                std::process::exit(2);
            };
            if !matches!(decision, "accept" | "decline" | "undo") {
                eprintln!(
                    "Unknown proposal decision '{}'; use accept|decline|undo",
                    decision
                );
                std::process::exit(2);
            }
            let Some(proposal_id) = args.get(3).map(|s| s.as_str()) else {
                eprintln!("Usage: carnot proposal <accept|decline|undo> <proposal_id> [ws]");
                std::process::exit(2);
            };
            let ws = args.get(4).map(|s| s.as_str());
            let mut machine = load_or_seed_machine(ws);
            match machine.decide_proposal(proposal_id, decision) {
                Ok(card) => println!("{}", serde_json::to_string_pretty(&card).unwrap()),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        "mcp" => {
            let mut machine = load_or_seed_machine(args.get(2).map(|s| s.as_str()));
            if let Err(e) = carnot::mcp::run_mcp_stdio(&mut machine) {
                eprintln!("MCP stdio server error: {}", e);
                std::process::exit(1);
            }
        }
        "serve" => {
            let bind_addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:4242");
            serve_workbench(bind_addr, false, args.get(3).map(|s| s.as_str()));
        }
        "app" => {
            let bind_addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:4242");
            serve_workbench(bind_addr, true, args.get(3).map(|s| s.as_str()));
        }
        "black-box" => {
            let action = args.get(2).map(|s| s.as_str()).unwrap_or("status");
            let ws = args.get(3).map(|s| s.as_str());
            let mut machine = load_or_seed_machine(ws);
            let out = match action {
                "on" => serde_json::to_value(machine.set_black_box_mode(true)).unwrap(),
                "off" => serde_json::to_value(machine.set_black_box_mode(false)).unwrap(),
                "status" => serde_json::json!({
                    "black_box_enforced": machine.manifest.black_box_enforced,
                    "certificate_receipt_id": machine.clean_room_cert.receipt_id,
                    "quarantined_prefixes": machine.quarantined_prefixes(),
                }),
                other => {
                    eprintln!("Unknown black-box action '{}'; use on|off|status", other);
                    std::process::exit(2);
                }
            };
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        "search" => {
            let Some(query) = args.get(2) else {
                eprintln!("Usage: carnot search <query> [dir] [top_k]");
                std::process::exit(2);
            };
            let dir = args.get(3).map(|s| s.as_str()).unwrap_or(".");
            let top_k = args
                .get(4)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(5);
            let machine = machine_rooted_at(dir);
            let rep = machine.search_codebase(query, top_k);
            println!("{}", serde_json::to_string_pretty(&rep).unwrap());
        }
        "related" => {
            let (Some(file), Some(line)) = (
                args.get(2),
                args.get(3).and_then(|s| s.parse::<usize>().ok()),
            ) else {
                eprintln!("Usage: carnot related <file> <line> [dir] [top_k]");
                std::process::exit(2);
            };
            let dir = args.get(4).map(|s| s.as_str()).unwrap_or(".");
            let top_k = args
                .get(5)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(5);
            let machine = machine_rooted_at(dir);
            let rep = machine.find_related_code(file, line, top_k);
            println!("{}", serde_json::to_string_pretty(&rep).unwrap());
        }
        "hotspots" => {
            let goal = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let dir = args.get(3).map(|s| s.as_str()).unwrap_or(".");
            let machine = machine_rooted_at(dir);
            let rep = machine.scan_hotspots(goal);
            println!("{}", serde_json::to_string_pretty(&rep).unwrap());
        }
        "advise" => {
            let machine = load_or_seed_machine(args.get(2).map(|s| s.as_str()));
            println!(
                "{}",
                serde_json::to_string_pretty(&machine.advise_languages()).unwrap()
            );
        }
        "obligations" => {
            let mut machine = load_or_seed_machine(args.get(2).map(|s| s.as_str()));
            let verdict = machine.evaluate_obligations();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "verdict": verdict,
                    "ledger": machine.obligations,
                }))
                .unwrap()
            );
        }
        _ => {
            eprintln!(
                "Usage: carnot [init <dir> [name] [lang] | intake-scan <dir> | generate <dir> [lang] | proxy <listen> <control> <canary> [pct] [ws] | app [host:port] [ws] | serve [host:port] [ws] | demo | scout [dir] [lang] | build-plan [lang] | point <dir> | daemon [--once | --ticks N] [ws] | evolve [organ] [gens] [--demo] [--apply] | proposal <accept|decline|undo> <proposal_id> [ws] | verify | mcp [ws] | black-box <on|off|status> [ws] | search <query> [dir] [top_k] | related <file> <line> [dir] [top_k] | hotspots [goal] [dir] | advise [ws] | obligations [ws]]"
            );
            std::process::exit(2);
        }
    }
}

/// Loads the workspace at `dir` if it has a manifest; otherwise a seeded machine whose
/// read-only search root is `dir` (search/hotspot commands never flush state).
fn machine_rooted_at(dir: &str) -> CarnotMachine {
    let p = Path::new(dir);
    if p.join("carnot.manifest.json").exists() {
        if let Ok(m) = CarnotMachine::from_workspace(p) {
            return m;
        }
    }
    let mut m = CarnotMachine::new_seeded();
    m.workspace_root = Some(p.to_path_buf());
    m
}

fn run_demo() {
    println!(
        "===================================================================================="
    );
    println!(" CARNOT v0.5 — Clean-Room App Refinery, Polyglot Synthesis & Canary Cutover");
    println!(
        "====================================================================================\n"
    );

    let mut machine = CarnotMachine::new_seeded();

    let detected_agents: Vec<&str> = machine
        .agents
        .iter()
        .filter(|a| a.detected_on_host)
        .map(|a| a.id.as_str())
        .collect();
    println!(
        "[App Shell] Auto-detected local coding agents: {:?} | Built-in playbooks: {}",
        detected_agents,
        machine.playbooks.len()
    );

    println!("\n[Stage 1/5: SCOUT] Ranking source organs against PreferenceProfile:");
    let ranked = machine
        .run_scout(Some(TargetLanguage::AutoShootout))
        .unwrap();
    for r in &ranked {
        println!(
            "  • {:<28} eff={:>5.1}% | mode={:<35} | targets={:?}",
            r.alias, r.total_carnot_efficiency, r.extraction_mode, r.recommended_output_targets
        );
    }

    println!("\n[Stage 2/5: INTAKE FIREWALL] Exporting SHA-256 Clean-Room IP Certificate:");
    let cert = machine.export_clean_room_certificate().unwrap();
    println!("  • Receipt ID:          {}", cert.receipt_id);
    println!("  • Certificate SHA-256: {}", cert.certificate_sha256);
    println!(
        "  • Restricted Leaks:    {} bytes read into synthesis context",
        cert.quarantined_source_bytes_read
    );

    println!("\n[Stage 3/5: POLYGLOT BUILD & CREEP PRUNER] Emitting target plans & checking EntropyBudget:");
    for lang in [
        TargetLanguage::Go,
        TargetLanguage::TypeScript,
        TargetLanguage::Rust,
    ] {
        let plan = machine.preview_target_build(Some(lang));
        println!(
            "  • Target {:<12} -> build=`{:<28}` test=`{}` ({} files)",
            format!("{:?}", plan.target_language),
            plan.build_command,
            plan.test_command,
            plan.planned_files.len()
        );
    }
    let findings = machine.audit_feature_creep();
    println!(
        "  • Entropy findings:    {} status check(s) recorded",
        findings.len()
    );

    println!("\n[Stage 4/5: PARETO VERIFY] Synthesizing +2 adversarial cases & scoring builds:");
    machine.synthesize_cases(2);
    for ev in &machine.latest_evals {
        println!(
            "  • {:<26} score={:>5.1}% | p95={:>4}ms | cost=${:.4} | pareto={}",
            ev.variant_id,
            ev.composite_score * 100.0,
            ev.p95_latency_ms,
            ev.cost_per_1k_usd,
            if ev.pareto_optimal { "YES" } else { "no" }
        );
    }

    println!("\n[Stage 5/5: STRANGLER-FIG CUTOVER] Gate enforcement + <0.1ms circuit breaker:");
    if let Err(blocked) = machine.promote_canary("v3-unverified-draft", 25) {
        println!("  • [BLOCKED] {}", blocked);
    }
    let promoted = machine
        .promote_canary("v2-carnot-consolidated", 25)
        .expect("Pareto winner passes GatePolicy");
    println!(
        "  • [PROMOTED] '{}' serving {}% canary on '{}'",
        promoted.canary_variant_id.as_deref().unwrap_or(""),
        promoted.canary_rollout_pct,
        promoted.flag_name
    );

    let _healthy = machine.simulate_live_traffic(24, false).unwrap();
    let t0 = std::time::Instant::now();
    let tripped = machine.simulate_live_traffic(36, true).unwrap();
    let elapsed_us = t0.elapsed().as_micros();
    println!(
        "  • [KILL-SWITCH] Tripped={} in {} us | Active canary={}% | Regressions captured={} | Receipt={}",
        tripped.killswitch_tripped,
        elapsed_us,
        tripped.canary_rollout_pct,
        tripped.regressions_captured,
        tripped.latest_receipt_id.as_deref().unwrap_or("none")
    );
    let post = machine.evaluate_for_user("usr-0007");
    println!(
        "  • [POST-TRIP CHECK] '{}' for 'usr-0007' -> '{}' (total SHA-256 receipts={})",
        DEFAULT_CUTOVER_FLAG,
        post.name,
        machine.evidence.len()
    );
}
