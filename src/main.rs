use carnot::bridge::{CarnotMachine, EvolveOpts, DEFAULT_CUTOVER_FLAG};
use carnot::eval::DatasetSplit;
use carnot::proxy::{run_reverse_proxy, ProxyConfig};
use carnot::scout::{ScoutCommandReport, TargetLanguage};
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
        let launched_edge = edge_candidates.iter().any(|edge| {
            Path::new(edge).exists() && Command::new(edge).arg(&app_arg).spawn().is_ok()
        });
        if !launched_edge {
            let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
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

fn print_json(value: &impl serde::Serialize) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(e) => {
            eprintln!("Failed to serialize JSON: {e}");
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!(
        "\
carnot {version} — clean-room refinery, license firewall, project emitter, worktree evolver

Usage:
  carnot help
  carnot init <dir> [name] [lang]
  carnot intake-scan <dir>
  carnot generate <dir> [lang]
  carnot spec <dir> [--out <file>]
  carnot generate <dir> --spec <file>
  carnot proxy <listen> <control> <canary> [pct] [ws]
  carnot app [host:port] [ws]
  carnot serve [host:port] [ws]
  carnot demo
  carnot scout [--demo] [dir] [lang]
  carnot build-plan [lang]
  carnot point <dir> [--in-tree]
  carnot daemon [--once | --ticks N] [ws]
  carnot evolve [organ] [gens] [--demo] [--apply] [--candidate <file>]
  carnot proposal <accept|decline|undo> <proposal_id> [ws]
  carnot verify [--demo] [--timeout <seconds>] [--against <spec>] [dir]
  carnot mcp [ws]
  carnot black-box <on|off|status> [ws]
  carnot search <query> [dir] [top_k]
  carnot related <file> <line> [dir] [top_k]
  carnot hotspots [goal] [dir]
  carnot advise [ws]
  carnot obligations [ws]

`carnot demo` is an offline walkthrough. It does not modify a workspace and is not a live agent result.
`carnot generate` writes into a directory created by `carnot init`. An unknown language exits 2 and lists the supported names. `carnot generate <dir> --spec <file>` rebuilds a Python library from a spec file and does not read the original tree.
`carnot spec` writes a Python public-API spec (signatures, docstrings, literal examples, no function bodies). Other languages are not supported.
`carnot scout` scores the directory you pass (or `.`). `carnot verify` runs cargo, pytest or unittest, npm, or go tests when that runner is present, and sets checks_executed only after the runner starts. With no runner it inventories the tree and says so. `carnot verify <dir> --against <spec>` replays that spec's examples. `--timeout` defaults to 120 seconds. `--demo` is the seeded set and is labeled in the output.
`carnot point` stores state outside the target unless it is already a Carnot workspace or you pass `--in-tree`. Live evolve writes `.carnot/worktrees` and `.carnot/staged` in that same state directory.
Live evolve reads `--candidate <file>` as the EVOLVE block body. `carnot daemon` still reports a skip until a candidate is supplied.
Account tier defaults to Pro. `CARNOT_TIER=community` locks Pro-gated commands. This is an operator switch, not a license check.
",
        version = env!("CARGO_PKG_VERSION")
    );
}

/// Load a workspace when `carnot.manifest.json` is present.
/// A missing manifest returns the in-memory demo machine and does not bind it
/// to the path. A present but unreadable manifest is an error.
fn load_or_seed_machine(workspace_arg: Option<&str>) -> CarnotMachine {
    match try_load_machine(workspace_arg) {
        Ok(machine) => machine,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn saved_state_for(dir: &Path) -> bool {
    carnot::workspace::workspace_has_in_tree_state(dir)
        || carnot::workspace::external_point_state_dir(dir)
            .join("carnot.manifest.json")
            .is_file()
}

fn try_load_machine(workspace_arg: Option<&str>) -> Result<CarnotMachine, String> {
    if let Some(ws) = workspace_arg {
        let p = Path::new(ws);
        if saved_state_for(p) {
            return CarnotMachine::from_workspace(p);
        }
        return Ok(CarnotMachine::new_seeded());
    }
    if saved_state_for(Path::new(".")) {
        return CarnotMachine::from_workspace(Path::new("."));
    }
    Ok(CarnotMachine::new_seeded())
}

fn serve_workbench(bind_addr: &str, open_app_window: bool, workspace_dir: Option<&str>) {
    let listener = match TcpListener::bind(bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {}: {}", bind_addr, e);
            std::process::exit(1);
        }
    };
    let local = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to read listener address: {e}");
            std::process::exit(1);
        }
    };
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
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "help" | "--help" | "-h" => print_usage(),
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
                Ok(manifest) => print_json(&manifest),
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
                Ok(cert) => print_json(&cert),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        "spec" => {
            let mut out_path: Option<String> = None;
            let mut dir: Option<&str> = None;
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--out" => {
                        i += 1;
                        let Some(path) = args.get(i) else {
                            eprintln!("Usage: carnot spec <dir> --out <file>");
                            std::process::exit(2);
                        };
                        out_path = Some(path.clone());
                    }
                    other if other.starts_with('-') => {
                        eprintln!("Unknown spec flag '{other}'");
                        std::process::exit(2);
                    }
                    other => dir = Some(other),
                }
                i += 1;
            }
            let Some(dir) = dir else {
                eprintln!("Usage: carnot spec <dir> [--out <file>]");
                std::process::exit(2);
            };
            let target = Path::new(dir);
            let default_name = target
                .file_name()
                .map(|name| format!("{}.carnot-spec.json", name.to_string_lossy()))
                .unwrap_or_else(|| "library.carnot-spec.json".to_string());
            let out_file = out_path
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(default_name));
            match carnot::spec::write_spec(target, &out_file) {
                Ok(spec) => {
                    eprintln!(
                        "wrote Python spec ({} modules) to {}",
                        spec.modules.len(),
                        out_file.display()
                    );
                    print_json(&spec);
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        "generate" => {
            let mut spec_path: Option<String> = None;
            let mut positionals: Vec<&str> = Vec::new();
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--spec" => {
                        i += 1;
                        let Some(path) = args.get(i) else {
                            eprintln!("Usage: carnot generate <dir> --spec <file>");
                            std::process::exit(2);
                        };
                        spec_path = Some(path.clone());
                    }
                    other if other.starts_with('-') => {
                        eprintln!("Unknown generate flag '{other}'");
                        std::process::exit(2);
                    }
                    other => positionals.push(other),
                }
                i += 1;
            }
            let dir_str = positionals.first().copied().unwrap_or("./generated-app");
            let target_dir = Path::new(dir_str);
            if let Some(spec_file) = spec_path {
                if let Some(lang) = positionals.get(1) {
                    if !lang.eq_ignore_ascii_case("python") {
                        eprintln!("generate --spec supports Python libraries only");
                        std::process::exit(2);
                    }
                }
                match carnot::spec::generate_from_spec(Path::new(&spec_file), target_dir) {
                    Ok(certificate) => {
                        eprintln!(
                            "rebuilt Python package from spec {} (spec-only, sha256 {})",
                            spec_file, certificate.spec_sha256
                        );
                        print_json(&certificate);
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                }
                return;
            }
            let lang = if let Some(raw) = positionals.get(1) {
                match TargetLanguage::parse_known(raw) {
                    Ok(lang) => Some(lang),
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(2);
                    }
                }
            } else {
                None
            };
            if !target_dir.join("carnot.manifest.json").is_file() {
                eprintln!(
                    "No carnot.manifest.json in '{}'. Run `carnot init {} <name> [lang]` first.",
                    target_dir.display(),
                    dir_str
                );
                std::process::exit(1);
            }
            let manifest = match load_manifest_from_workspace(target_dir) {
                Ok(manifest) => manifest,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
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

            let listen_addr = listener
                .local_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| listen_str.to_string());
            println!(
                "Carnot Strangler-Fig Reverse Proxy listening on http://{} -> control={} | canary={} ({}%)",
                listen_addr, control_upstream, canary_upstream, canary_pct
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
            let mut demo = false;
            let mut positionals: Vec<&str> = Vec::new();
            for arg in args.iter().skip(2) {
                match arg.as_str() {
                    "--demo" => demo = true,
                    other if other.starts_with('-') => {
                        eprintln!("Unknown scout flag '{other}'");
                        std::process::exit(2);
                    }
                    other => positionals.push(other),
                }
            }
            if demo {
                let mut machine = CarnotMachine::new_seeded();
                let lang = positionals
                    .first()
                    .map(|s| TargetLanguage::from_str_loose(s));
                match machine.run_scout(lang) {
                    Ok(ranked) => {
                        eprintln!(
                            "offline demo (seeded candidates); not a score of the pointed workspace"
                        );
                        print_json(&ScoutCommandReport { demo: true, ranked });
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                let dir = positionals.first().copied().unwrap_or(".");
                let lang = positionals
                    .get(1)
                    .map(|s| TargetLanguage::from_str_loose(s));
                let mut machine = CarnotMachine::new_seeded();
                match machine.scout_pointed(Path::new(dir), lang) {
                    Ok(report) => print_json(&report),
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        "build-plan" => {
            let mut machine = load_or_seed_machine(None);
            let lang = args.get(2).map(|s| TargetLanguage::from_str_loose(s));
            let plan = machine.preview_target_build(lang);
            print_json(&plan);
        }
        "verify" => {
            let mut demo = false;
            let mut timeout_secs = carnot::testrun::DEFAULT_VERIFY_TIMEOUT_SECS;
            let mut against: Option<String> = None;
            let mut dir: Option<&str> = None;
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--demo" => demo = true,
                    "--against" => {
                        i += 1;
                        let Some(path) = args.get(i) else {
                            eprintln!("Usage: carnot verify <dir> --against <spec>");
                            std::process::exit(2);
                        };
                        against = Some(path.clone());
                    }
                    "--timeout" => {
                        i += 1;
                        let Some(secs) = args.get(i).and_then(|s| s.parse::<u64>().ok()) else {
                            eprintln!("Usage: carnot verify [--timeout <seconds>] [dir]");
                            std::process::exit(2);
                        };
                        if secs == 0 {
                            eprintln!("--timeout must be at least 1 second");
                            std::process::exit(2);
                        }
                        timeout_secs = secs;
                    }
                    other if other.starts_with('-') => {
                        eprintln!("Unknown verify flag '{other}'");
                        std::process::exit(2);
                    }
                    other => dir = Some(other),
                }
                i += 1;
            }
            if demo && against.is_some() {
                eprintln!("verify --demo and --against cannot be combined");
                std::process::exit(2);
            }
            if let Some(spec_file) = against {
                let dir = dir.unwrap_or(".");
                match carnot::spec::verify_against(
                    Path::new(dir),
                    Path::new(&spec_file),
                    timeout_secs.saturating_mul(1000),
                ) {
                    Ok(report) => {
                        eprintln!(
                            "spec examples: {} passed, {} failed",
                            report.passed, report.failed
                        );
                        print_json(&report);
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                }
            } else if demo {
                let mut machine = CarnotMachine::new_seeded();
                let summaries = machine.run_evaluations(DatasetSplit::Golden);
                eprintln!("offline demo (seeded golden set); not a score of the pointed workspace");
                print_json(&carnot::bridge::VerifyCommandReport {
                    demo: true,
                    checks_executed: true,
                    workspace: None,
                    source_files: Vec::new(),
                    summaries,
                    test_command: None,
                    exit_code: None,
                    passed: None,
                    failed: None,
                    duration_ms: None,
                    note: None,
                    timed_out: false,
                });
            } else {
                let dir = dir.unwrap_or(".");
                let mut machine = CarnotMachine::new_seeded();
                match machine.verify_pointed(Path::new(dir), timeout_secs.saturating_mul(1000)) {
                    Ok(report) => {
                        if report.checks_executed {
                            eprintln!(
                                "ran {} (exit {})",
                                report.test_command.as_deref().unwrap_or("tests"),
                                report
                                    .exit_code
                                    .map(|code| code.to_string())
                                    .unwrap_or_else(|| {
                                        if report.timed_out {
                                            "timeout".to_string()
                                        } else {
                                            "none".to_string()
                                        }
                                    })
                            );
                        } else {
                            eprintln!(
                                "{}",
                                report
                                    .note
                                    .as_deref()
                                    .unwrap_or("no test runner detected; inventory only")
                            );
                        }
                        print_json(&report);
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        "point" => {
            let mut in_tree = false;
            let mut dir: Option<&str> = None;
            for arg in args.iter().skip(2) {
                match arg.as_str() {
                    "--in-tree" => in_tree = true,
                    other if other.starts_with('-') => {
                        eprintln!("Unknown point flag '{other}'");
                        std::process::exit(2);
                    }
                    other => dir = Some(other),
                }
            }
            let dir = dir.unwrap_or(".");
            let mut machine = load_or_seed_machine(Some(dir));
            match machine.point_target_with(Path::new(dir), in_tree) {
                Ok(target) => print_json(&target),
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
                    Ok(report) => print_json(&report),
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
            let mut candidate_path: Option<String> = None;
            let mut positionals: Vec<&str> = Vec::new();
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--demo" => demo = true,
                    "--apply" => apply = true,
                    "--candidate" => {
                        i += 1;
                        let Some(path) = args.get(i) else {
                            eprintln!("Usage: carnot evolve [organ] [gens] --candidate <file>");
                            std::process::exit(2);
                        };
                        candidate_path = Some(path.clone());
                    }
                    other if other.starts_with("--candidate=") => {
                        let path = other.trim_start_matches("--candidate=");
                        if path.is_empty() {
                            eprintln!("Usage: carnot evolve [organ] [gens] --candidate <file>");
                            std::process::exit(2);
                        }
                        candidate_path = Some(path.to_string());
                    }
                    other if other.starts_with('-') => {
                        eprintln!("Unknown evolve flag '{}'", other);
                        std::process::exit(2);
                    }
                    other => positionals.push(other),
                }
                i += 1;
            }
            let organ_id = positionals.first().copied().map(|s| s.to_string());
            let gens = positionals.get(1).and_then(|s| s.parse::<usize>().ok());
            let explicit_candidate = if let Some(path) = candidate_path {
                match std::fs::read_to_string(&path) {
                    Ok(body) => Some(body),
                    Err(e) => {
                        eprintln!("cannot read candidate '{path}': {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                None
            };
            let mut machine = load_or_seed_machine(None);
            match machine.evolve_organ_with_opts(EvolveOpts {
                organ_id,
                generations: gens,
                demo,
                apply,
                explicit_candidate,
                organ_rel_path: None,
            }) {
                Ok(report) => {
                    if report.offline_demo {
                        eprintln!("offline demo (seeded islands); not a live worktree trial");
                    }
                    print_json(&report);
                }
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
                Ok(card) => print_json(&card),
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
                "on" => match serde_json::to_value(machine.set_black_box_mode(true)) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("Failed to serialize black-box state: {e}");
                        std::process::exit(1);
                    }
                },
                "off" => match serde_json::to_value(machine.set_black_box_mode(false)) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("Failed to serialize black-box state: {e}");
                        std::process::exit(1);
                    }
                },
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
            print_json(&out);
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
            print_json(&rep);
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
            print_json(&rep);
        }
        "hotspots" => {
            let goal = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let dir = args.get(3).map(|s| s.as_str()).unwrap_or(".");
            let machine = machine_rooted_at(dir);
            let rep = machine.scan_hotspots(goal);
            print_json(&rep);
        }
        "advise" => {
            let machine = load_or_seed_machine(args.get(2).map(|s| s.as_str()));
            print_json(&machine.advise_languages());
        }
        "obligations" => {
            let mut machine = load_or_seed_machine(args.get(2).map(|s| s.as_str()));
            let verdict = machine.evaluate_obligations();
            print_json(&serde_json::json!({
                "verdict": verdict,
                "ledger": machine.obligations,
            }));
        }
        _ => {
            print_usage();
            std::process::exit(2);
        }
    }
}

/// Loads the workspace at `dir` if it has a manifest; otherwise a seeded machine whose
/// read-only search root is `dir` (search/hotspot commands never flush state).
/// Loads the workspace at `dir` if it has a manifest. Otherwise scans `dir` for
/// SPDX zones on an unbound demo machine so search/hotspots honor the firewall.
/// `workspace_root` is set only after the scan, because `scan_intake_directory`
/// flushes when a root is already bound. Callers must not flush this machine
/// or the demo fixtures will be written into `dir`.
fn machine_rooted_at(dir: &str) -> CarnotMachine {
    let p = Path::new(dir);
    if saved_state_for(p) {
        match CarnotMachine::from_workspace(p) {
            Ok(machine) => return machine,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    let mut machine = CarnotMachine::new_seeded();
    if p.is_dir() {
        let _ = machine.scan_intake_directory(p);
    }
    // Drop demo fixtures before publishing a root. Search does not flush; if a
    // later edit does, it must not write prop-001 / gold-001 into `dir`.
    machine.shell.proposals.clear();
    machine.dataset.clear();
    machine.scout_candidates.clear();
    machine.latest_scout_ranking.clear();
    machine.evidence = carnot::evidence::EvidenceLedger::new();
    machine.workspace_root = Some(p.to_path_buf());
    machine
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
    let ranked = match machine.run_scout(Some(TargetLanguage::AutoShootout)) {
        Ok(ranked) => ranked,
        Err(e) => {
            eprintln!("demo scout failed: {e}");
            std::process::exit(1);
        }
    };
    for r in &ranked {
        println!(
            "  • {:<28} eff={:>5.1}% | mode={:<35} | targets={:?}",
            r.alias, r.total_carnot_efficiency, r.extraction_mode, r.recommended_output_targets
        );
    }

    println!("\n[Stage 2/5: INTAKE FIREWALL] Exporting SHA-256 Clean-Room IP Certificate:");
    let cert = match machine.export_clean_room_certificate() {
        Ok(cert) => cert,
        Err(e) => {
            eprintln!("demo certificate failed: {e}");
            std::process::exit(1);
        }
    };
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
    let promoted = match machine.promote_canary("v2-carnot-consolidated", 25) {
        Ok(promoted) => promoted,
        Err(e) => {
            eprintln!("demo promote failed: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "  • [PROMOTED] '{}' serving {}% canary on '{}'",
        promoted.canary_variant_id.as_deref().unwrap_or(""),
        promoted.canary_rollout_pct,
        promoted.flag_name
    );

    if let Err(e) = machine.simulate_live_traffic(24, false) {
        eprintln!("demo traffic failed: {e}");
        std::process::exit(1);
    }
    let t0 = std::time::Instant::now();
    let tripped = match machine.simulate_live_traffic(36, true) {
        Ok(tripped) => tripped,
        Err(e) => {
            eprintln!("demo kill-switch failed: {e}");
            std::process::exit(1);
        }
    };
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
