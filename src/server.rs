//! Zero-Dependency Multi-Threaded HTTP/1.1 Server (`carnot serve`).
//!
//! Serves:
//! 1. Carnot 5-Stage Workbench UI (`GET /`)
//! 2. Feature Toggle v2 Client SDK Wire API (`GET /api/client/features`, `POST /api/client/register`, `POST /api/client/metrics`)
//! 3. 5-Stage Carnot REST API (`/api/scout`, `/api/intake/cert`, `/api/build/plan`, `/api/verify/run`, `/api/cutover/...`, `/api/tier`, `/api/evidence`)
//! 4. Prometheus metrics (`GET /metrics`).

use crate::bridge::{CarnotMachine, EvolveOpts, DEFAULT_CUTOVER_FLAG};
use crate::eval::DatasetSplit;
use crate::evidence::sha256_hex;
use crate::rollout::ToggleMetricsCounter;
use crate::scout::TargetLanguage;
use crate::tier::AccountTier;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const UI_HTML: &str = include_str!("ui.html");

#[derive(Deserialize)]
struct LangReq {
    #[serde(default)]
    target_language: Option<String>,
}

#[derive(Deserialize)]
struct TierReq {
    tier: String,
}

#[derive(Deserialize)]
struct PromoteReq {
    variant_id: String,
    #[serde(default = "default_rollout")]
    rollout_pct: u32,
}

fn default_rollout() -> u32 {
    25
}

#[derive(Deserialize)]
struct SynthReq {
    #[serde(default = "default_synth_count")]
    count: usize,
}

fn default_synth_count() -> usize {
    2
}

#[derive(Deserialize)]
struct EvalUserReq {
    user_id: String,
}

#[derive(Deserialize)]
struct SimReq {
    #[serde(default = "default_sim_reqs")]
    requests: usize,
    #[serde(default)]
    inject_fault: bool,
}

fn default_sim_reqs() -> usize {
    24
}

pub fn run_http_server(
    listener: TcpListener,
    machine: Arc<Mutex<CarnotMachine>>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let eng = Arc::clone(&machine);
                std::thread::spawn(move || {
                    let _ = handle_connection(stream, eng);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    machine: Arc<Mutex<CarnotMachine>>,
) -> std::io::Result<()> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else {
        return Ok(());
    };
    let Some(raw_path) = parts.next() else {
        return Ok(());
    };
    let path = raw_path.split('?').next().unwrap_or(raw_path);

    let mut content_length = 0usize;
    let mut if_none_match: Option<String> = None;
    loop {
        let mut header_line = String::new();
        if reader.read_line(&mut header_line)? == 0 || header_line == "\r\n" || header_line == "\n"
        {
            break;
        }
        if let Some((k, v)) = header_line.split_once(':') {
            let key = k.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().unwrap_or(0).min(1_048_576);
            } else if key.eq_ignore_ascii_case("if-none-match") {
                if_none_match = Some(v.trim().to_string());
            }
        }
    }

    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body_bytes)?;
    }
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Feature-toggle delta polling: SHA-256 ETag + `If-None-Match` -> 304 Not Modified.
    if method == "GET" && path == "/api/client/delta" {
        let json_str = {
            let guard = machine.lock().unwrap();
            serde_json::to_string(&guard.feature_state).unwrap_or_else(|_| "{}".into())
        };
        let etag = format!("\"{}\"", &sha256_hex(json_str.as_bytes())[..32]);
        let matches = if_none_match
            .as_deref()
            .map(|h| {
                h.split(',')
                    .any(|t| t.trim().trim_start_matches("W/") == etag || t.trim() == "*")
            })
            .unwrap_or(false);
        let extra = format!("ETag: {}\r\n", etag);
        return if matches {
            write_http_response_ext(&mut stream, 304, "application/json", b"", &extra)
        } else {
            write_http_response_ext(
                &mut stream,
                200,
                "application/json",
                json_str.as_bytes(),
                &extra,
            )
        };
    }

    let (status, content_type, resp_body) = dispatch_request(method, path, &body_str, &machine);
    write_http_response(&mut stream, status, content_type, resp_body.as_bytes())
}

fn dispatch_request(
    method: &str,
    path: &str,
    body: &str,
    machine: &Arc<Mutex<CarnotMachine>>,
) -> (u16, &'static str, String) {
    if method == "GET" && path.starts_with("/api/evidence/") {
        let rid = path.trim_start_matches("/api/evidence/");
        let guard = machine.lock().unwrap();
        return match guard.evidence.browse(rid, 0, 16_384) {
            Some(page) => (
                200,
                "application/json",
                serde_json::to_string(&page).unwrap(),
            ),
            None => (
                404,
                "application/json",
                json!({"error": "Receipt not found"}).to_string(),
            ),
        };
    }

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            (200, "text/html; charset=utf-8", UI_HTML.to_string())
        }

        // Feature Toggle v2 Client SDK wire endpoints
        ("GET", "/api/client/features") => {
            let guard = machine.lock().unwrap();
            let json_str =
                serde_json::to_string(&guard.feature_state).unwrap_or_else(|_| "{}".into());
            (200, "application/json", json_str)
        }
        ("POST", "/api/client/register") => {
            let mut guard = machine.lock().unwrap();
            if let Ok(val) = serde_json::from_str::<Value>(body) {
                let app = val
                    .get("appName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("toggle-sdk")
                    .to_string();
                if !guard.registered_sdks.contains(&app) {
                    guard.registered_sdks.push(app);
                }
            }
            (
                202,
                "application/json",
                json!({"status": "registered"}).to_string(),
            )
        }
        ("POST", "/api/client/metrics") => {
            let mut guard = machine.lock().unwrap();
            if let Ok(val) = serde_json::from_str::<Value>(body) {
                if let Some(toggles) = val
                    .get("bucket")
                    .and_then(|b| b.get("toggles"))
                    .and_then(|t| t.as_object())
                {
                    for (flag, counts) in toggles {
                        let entry: &mut ToggleMetricsCounter =
                            guard.sdk_metrics.entry(flag.clone()).or_default();
                        entry.yes += counts.get("yes").and_then(|v| v.as_u64()).unwrap_or(0);
                        entry.no += counts.get("no").and_then(|v| v.as_u64()).unwrap_or(0);
                        if let Some(vars) = counts.get("variants").and_then(|v| v.as_object()) {
                            for (vn, vc) in vars {
                                *entry.variants.entry(vn.clone()).or_insert(0) +=
                                    vc.as_u64().unwrap_or(0);
                            }
                        }
                    }
                }
            }
            (
                202,
                "application/json",
                json!({"status": "accepted"}).to_string(),
            )
        }

        // 5-Stage Carnot API
        ("GET", "/api/state") => {
            let guard = machine.lock().unwrap();
            let summaries = guard.evidence.list_summaries();
            let payload = json!({
                "machine": &*guard,
                "evidence_summaries": summaries,
            });
            (200, "application/json", payload.to_string())
        }
        ("POST", "/api/tier") => {
            let Ok(req) = serde_json::from_str::<TierReq>(body) else {
                return (
                    400,
                    "application/json",
                    json!({"error": "Invalid tier"}).to_string(),
                );
            };
            let mut guard = machine.lock().unwrap();
            guard.set_tier(AccountTier::from_str_loose(&req.tier));
            (
                200,
                "application/json",
                json!({"tier": guard.tier}).to_string(),
            )
        }
        ("POST", "/api/scout") => {
            let req: LangReq = serde_json::from_str(body).unwrap_or(LangReq {
                target_language: None,
            });
            let lang = req
                .target_language
                .as_deref()
                .map(TargetLanguage::from_str_loose);
            let mut guard = machine.lock().unwrap();
            match guard.run_scout(lang) {
                Ok(ranked) => (
                    200,
                    "application/json",
                    serde_json::to_string(&ranked).unwrap(),
                ),
                Err(msg) => (402, "application/json", json!({"error": msg}).to_string()),
            }
        }
        ("GET", "/api/intake/cert") => {
            let guard = machine.lock().unwrap();
            match guard.export_clean_room_certificate() {
                Ok(cert) => (
                    200,
                    "application/json",
                    serde_json::to_string(&cert).unwrap(),
                ),
                Err(msg) => (402, "application/json", json!({"error": msg}).to_string()),
            }
        }
        ("POST", "/api/build/plan") => {
            let req: LangReq = serde_json::from_str(body).unwrap_or(LangReq {
                target_language: None,
            });
            let lang = req
                .target_language
                .as_deref()
                .map(TargetLanguage::from_str_loose);
            let mut guard = machine.lock().unwrap();
            let plan = guard.preview_target_build(lang);
            (
                200,
                "application/json",
                serde_json::to_string(&plan).unwrap(),
            )
        }
        ("POST", "/api/verify/run") => {
            let mut guard = machine.lock().unwrap();
            let res = guard.run_evaluations(DatasetSplit::Golden);
            (
                200,
                "application/json",
                serde_json::to_string(&res).unwrap(),
            )
        }
        ("POST", "/api/dataset/synthesize") => {
            let req: SynthReq = serde_json::from_str(body).unwrap_or(SynthReq { count: 2 });
            let mut guard = machine.lock().unwrap();
            let created = guard.synthesize_cases(req.count);
            (
                200,
                "application/json",
                serde_json::to_string(&created).unwrap(),
            )
        }
        ("POST", "/api/cutover/promote") => {
            let Ok(req) = serde_json::from_str::<PromoteReq>(body) else {
                return (
                    400,
                    "application/json",
                    json!({"error": "Invalid JSON body"}).to_string(),
                );
            };
            let mut guard = machine.lock().unwrap();
            match guard.promote_canary(&req.variant_id, req.rollout_pct) {
                Ok(status) => (
                    200,
                    "application/json",
                    serde_json::to_string(&status).unwrap(),
                ),
                Err(msg) => {
                    let code = if msg.starts_with("Pro Account Required") {
                        402
                    } else {
                        422
                    };
                    (code, "application/json", json!({"error": msg}).to_string())
                }
            }
        }
        ("POST", "/api/cutover/evaluate") => {
            let Ok(req) = serde_json::from_str::<EvalUserReq>(body) else {
                return (
                    400,
                    "application/json",
                    json!({"error": "Missing user_id"}).to_string(),
                );
            };
            let mut guard = machine.lock().unwrap();
            let evaluated = guard.evaluate_for_user(&req.user_id);
            let parsed_payload: Option<Value> = evaluated
                .payload
                .as_ref()
                .and_then(|p| serde_json::from_str(&p.value).ok());
            (
                200,
                "application/json",
                json!({
                    "user_id": req.user_id,
                    "flag": DEFAULT_CUTOVER_FLAG,
                    "variant": evaluated,
                    "decoded_target_config": parsed_payload,
                })
                .to_string(),
            )
        }
        ("POST", "/api/cutover/simulate") => {
            let req: SimReq = serde_json::from_str(body).unwrap_or(SimReq {
                requests: 24,
                inject_fault: false,
            });
            let mut guard = machine.lock().unwrap();
            match guard.simulate_live_traffic(req.requests, req.inject_fault) {
                Ok(status) => (
                    200,
                    "application/json",
                    serde_json::to_string(&status).unwrap(),
                ),
                Err(msg) => (402, "application/json", json!({"error": msg}).to_string()),
            }
        }
        ("POST", "/api/killswitch/reset") => {
            let mut guard = machine.lock().unwrap();
            let status = guard.reset_killswitch();
            (
                200,
                "application/json",
                serde_json::to_string(&status).unwrap(),
            )
        }
        ("GET", "/api/evidence") => {
            let guard = machine.lock().unwrap();
            let list = guard.evidence.list_summaries();
            (
                200,
                "application/json",
                serde_json::to_string(&list).unwrap(),
            )
        }
        ("POST", "/api/shell/navigate") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let mut guard = machine.lock().unwrap();
            guard.navigate_shell(
                val.get("screen").and_then(|v| v.as_str()),
                val.get("pane").and_then(|v| v.as_str()),
                val.get("organ_id").and_then(|v| v.as_str()),
                val.get("agent_id").and_then(|v| v.as_str()),
            );
            (
                200,
                "application/json",
                serde_json::to_string(&guard.shell).unwrap(),
            )
        }
        ("POST", "/api/chat/submit") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let prompt = val.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
            if prompt.trim().is_empty() {
                return (
                    400,
                    "application/json",
                    json!({"error": "Empty prompt"}).to_string(),
                );
            }
            let mut guard = machine.lock().unwrap();
            let card = guard.submit_composer_prompt(prompt);
            (
                200,
                "application/json",
                serde_json::to_string(&card).unwrap(),
            )
        }
        ("POST", "/api/playbook/run") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let pid = val
                .get("playbook_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut guard = machine.lock().unwrap();
            match guard.execute_playbook(pid) {
                Ok(msg) => (200, "application/json", json!({"summary": msg}).to_string()),
                Err(msg) => {
                    let code = if msg.starts_with("Pro Account Required") {
                        402
                    } else {
                        422
                    };
                    (code, "application/json", json!({"error": msg}).to_string())
                }
            }
        }
        ("POST", "/api/proposal/decide") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let pid = val
                .get("proposal_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let decision = val
                .get("decision")
                .and_then(|v| v.as_str())
                .unwrap_or("accept");
            let mut guard = machine.lock().unwrap();
            match guard.decide_proposal(pid, decision) {
                Ok(card) => (
                    200,
                    "application/json",
                    serde_json::to_string(&card).unwrap(),
                ),
                Err(msg) => {
                    let code = if msg.starts_with("Pro Account Required") {
                        402
                    } else {
                        422
                    };
                    (code, "application/json", json!({"error": msg}).to_string())
                }
            }
        }
        ("POST", "/api/organ/flag") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let oid = val.get("organ_id").and_then(|v| v.as_str()).unwrap_or("");
            let enabled = val.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let mut guard = machine.lock().unwrap();
            match guard.toggle_organ_flag(oid, enabled) {
                Ok(()) => (
                    200,
                    "application/json",
                    json!({"organ_id": oid, "enabled": enabled}).to_string(),
                ),
                Err(msg) => (422, "application/json", json!({"error": msg}).to_string()),
            }
        }
        ("POST", "/api/prune/audit") => {
            let mut guard = machine.lock().unwrap();
            let findings = guard.audit_feature_creep();
            (
                200,
                "application/json",
                serde_json::to_string(&findings).unwrap(),
            )
        }
        ("POST", "/api/point") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let path = val
                .get("path")
                .or_else(|| val.get("workspace"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if path.trim().is_empty() {
                return (
                    400,
                    "application/json",
                    json!({"error": "Missing 'path'"}).to_string(),
                );
            }
            let mut guard = machine.lock().unwrap();
            match guard.point_target(Path::new(path)) {
                Ok(target) => (
                    200,
                    "application/json",
                    serde_json::to_string(&target).unwrap(),
                ),
                Err(msg) => (422, "application/json", json!({"error": msg}).to_string()),
            }
        }
        ("POST", "/api/daemon/tick") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let candidate = val.get("explicit_candidate").and_then(|v| v.as_str());
            let mut guard = machine.lock().unwrap();
            match guard.daemon_tick(candidate) {
                Ok(rep) => (
                    200,
                    "application/json",
                    serde_json::to_string(&rep).unwrap(),
                ),
                Err(msg) => {
                    let code = if msg.starts_with("Pro Account Required") {
                        402
                    } else {
                        422
                    };
                    (code, "application/json", json!({"error": msg}).to_string())
                }
            }
        }
        ("POST", "/api/daemon/autopilot") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let ticks = val
                .get("ticks")
                .and_then(|v| v.as_u64())
                .unwrap_or(3)
                .clamp(1, 32) as usize;
            let candidate = val
                .get("explicit_candidate")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let mut guard = machine.lock().unwrap();
            let mut reports = Vec::with_capacity(ticks);
            for _ in 0..ticks {
                match guard.daemon_tick(candidate.as_deref()) {
                    Ok(rep) => reports.push(rep),
                    Err(msg) => {
                        let code = if msg.starts_with("Pro Account Required") {
                            402
                        } else {
                            422
                        };
                        return (
                            code,
                            "application/json",
                            json!({"error": msg, "reports": reports}).to_string(),
                        );
                    }
                }
            }
            (
                200,
                "application/json",
                json!({ "ticks": ticks, "reports": reports }).to_string(),
            )
        }
        ("POST", "/api/evolve/run") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let oid = val
                .get("organ_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let gens = val
                .get("generations")
                .and_then(|v| v.as_u64())
                .map(|g| g as usize);
            let demo = val.get("demo").and_then(|v| v.as_bool()).unwrap_or(false);
            let apply = val.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
            let explicit_candidate = val
                .get("explicit_candidate")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let organ_rel_path = val
                .get("organ_rel_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let mut guard = machine.lock().unwrap();
            match guard.evolve_organ_with_opts(EvolveOpts {
                organ_id: oid,
                generations: gens,
                demo,
                apply,
                explicit_candidate,
                organ_rel_path,
            }) {
                Ok(rep) => (
                    200,
                    "application/json",
                    serde_json::to_string(&rep).unwrap(),
                ),
                Err(msg) => {
                    let code = if msg.starts_with("Pro Account Required") {
                        402
                    } else {
                        422
                    };
                    (code, "application/json", json!({"error": msg}).to_string())
                }
            }
        }

        // Black-Box Shield toggle (`{"enforced": bool}`; omit to read status)
        ("GET", "/api/intake/black-box") => {
            let guard = machine.lock().unwrap();
            (
                200,
                "application/json",
                json!({
                    "black_box_enforced": guard.manifest.black_box_enforced,
                    "certificate_receipt_id": guard.clean_room_cert.receipt_id,
                    "quarantined_prefixes": guard.quarantined_prefixes(),
                })
                .to_string(),
            )
        }
        ("POST", "/api/intake/black-box") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let Some(enforced) = val.get("enforced").and_then(|v| v.as_bool()) else {
                return (
                    400,
                    "application/json",
                    json!({"error": "Missing boolean 'enforced'"}).to_string(),
                );
            };
            let mut guard = machine.lock().unwrap();
            let cert = guard.set_black_box_mode(enforced);
            (
                200,
                "application/json",
                serde_json::to_string(&cert).unwrap(),
            )
        }
        ("POST", "/api/codesearch") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let q = val.get("query").and_then(|v| v.as_str()).unwrap_or("");
            if q.trim().is_empty() {
                return (
                    400,
                    "application/json",
                    json!({"error": "Missing 'query'"}).to_string(),
                );
            }
            let k = val
                .get("top_k")
                .and_then(|v| v.as_u64())
                .unwrap_or(5)
                .min(50) as usize;
            let guard = machine.lock().unwrap();
            let rep = guard.search_codebase(q, k);
            (
                200,
                "application/json",
                serde_json::to_string(&rep).unwrap(),
            )
        }
        ("POST", "/api/codesearch/related") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let fp = val.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
            if fp.is_empty() {
                return (
                    400,
                    "application/json",
                    json!({"error": "Missing 'file_path'"}).to_string(),
                );
            }
            let line = val.get("line").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            let k = val
                .get("top_k")
                .and_then(|v| v.as_u64())
                .unwrap_or(5)
                .min(50) as usize;
            let guard = machine.lock().unwrap();
            let rep = guard.find_related_code(fp, line, k);
            (
                200,
                "application/json",
                serde_json::to_string(&rep).unwrap(),
            )
        }
        ("POST", "/api/evolve/hotspots") => {
            let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
            let goal = val.get("goal").and_then(|v| v.as_str()).unwrap_or("");
            let guard = machine.lock().unwrap();
            let rep = guard.scan_hotspots(goal);
            (
                200,
                "application/json",
                serde_json::to_string(&rep).unwrap(),
            )
        }
        ("GET", "/api/advise/languages") => {
            let guard = machine.lock().unwrap();
            (
                200,
                "application/json",
                serde_json::to_string(&guard.advise_languages()).unwrap(),
            )
        }
        ("GET", "/api/obligations") => {
            let mut guard = machine.lock().unwrap();
            let verdict = guard.evaluate_obligations();
            (
                200,
                "application/json",
                json!({ "verdict": verdict, "ledger": guard.obligations }).to_string(),
            )
        }

        // Prometheus metrics endpoint
        ("GET", "/metrics") => {
            let guard = machine.lock().unwrap();
            let sdk_yes = guard
                .sdk_metrics
                .get(DEFAULT_CUTOVER_FLAG)
                .map(|m| m.yes)
                .unwrap_or(0);
            let prom = format!(
                "# HELP carnot_dataset_cases_total Total conformance & regression cases\n\
                 # TYPE carnot_dataset_cases_total gauge\n\
                 carnot_dataset_cases_total {}\n\
                 # HELP carnot_evidence_receipts_total SHA-256 ev_... receipts minted\n\
                 # TYPE carnot_evidence_receipts_total counter\n\
                 carnot_evidence_receipts_total {}\n\
                 # HELP carnot_canary_rollout_pct Current strangler-fig canary percentage\n\
                 # TYPE carnot_canary_rollout_pct gauge\n\
                 carnot_canary_rollout_pct {}\n\
                 # HELP carnot_killswitch_tripped Circuit breaker status (1=tripped, 0=armed)\n\
                 # TYPE carnot_killswitch_tripped gauge\n\
                 carnot_killswitch_tripped {}\n\
                 # HELP carnot_regressions_captured_total Production divergences captured into suite\n\
                 # TYPE carnot_regressions_captured_total counter\n\
                 carnot_regressions_captured_total {}\n\
                 # HELP carnot_sdk_yes_total Feature toggle evaluations returning enabled=true\n\
                 # TYPE carnot_sdk_yes_total counter\n\
                 carnot_sdk_yes_total {}\n",
                guard.dataset.len(),
                guard.evidence.len(),
                guard.canary_rollout_pct,
                if guard.killswitch_tripped { 1 } else { 0 },
                guard.regressions_captured,
                sdk_yes
            );
            (200, "text/plain; version=0.0.4", prom)
        }

        _ => {
            let mut empty: HashMap<&str, &str> = HashMap::new();
            empty.insert("error", "Not found");
            (
                404,
                "application/json",
                serde_json::to_string(&empty).unwrap(),
            )
        }
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write_http_response_ext(stream, status, content_type, body, "")
}

fn write_http_response_ext(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        304 => "Not Modified",
        400 => "Bad Request",
        402 => "Payment Required",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\nCache-Control: no-store\r\n\r\n",
        status,
        reason,
        content_type,
        body.len(),
        extra_headers
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}
