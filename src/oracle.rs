//! Outside-In Black-Box Differential Oracle (`CLI` + `HTTP`), OpenAPI/HAR Surface Importer,
//! and clean-room `InspectionFirewall` (`carnot-inspect <safe-cmd> --json`).
//!
//! Enables 100% clean-room reverse engineering (`quarantined_source_bytes_read == 0`) by probing
//! an unmodified reference binary or HTTP endpoint externally, comparing its observable I/O and
//! side-effects against a clean-room candidate, minting `ControlledReplay` + `Observed` SHA-256
//! receipts, and converting mismatches into executable `DatasetCase` counterexamples.

use crate::eval::{DatasetCase, DatasetSplit};
use crate::evidence::{
    sha256_hex, CoverageStatus, EvidenceAuthority, EvidenceConfidence, EvidenceKind,
    EvidenceLedger, EvidenceProvenance,
};
use crate::intake::AccessPolicy;
use crate::obligations::{CaseKind, Obligation, ObligationDomain};
use crate::proc_util::{run_command_bounded, DEFAULT_MAX_STREAM_BYTES};
use crate::recipe::OrganSpec;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliOracleScenario {
    pub id: String,
    pub case_kind: CaseKind,
    pub args: Vec<String>,
    #[serde(default)]
    pub stdin_text: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliOracleObservation {
    pub scenario_id: String,
    pub case_kind: CaseKind,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_normalized: String,
    pub stderr_present: bool,
    pub watched_file_sha256: BTreeMap<String, String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliDifferentialVerdict {
    pub scenario_id: String,
    pub case_kind: CaseKind,
    pub matched: bool,
    pub authority: CliOracleObservation,
    pub candidate: CliOracleObservation,
    pub mismatch_summary: Option<String>,
    pub receipt_id: String,
}

fn hash_watched_files(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(rd) = fs::read_dir(&cur) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(bytes) = fs::read(&p) {
                if let Ok(rel) = p.strip_prefix(dir) {
                    let key = rel.to_string_lossy().replace('\\', "/");
                    out.insert(key, sha256_hex(&bytes));
                }
            }
        }
    }
    out
}

fn normalize_terminal_text(s: &str) -> String {
    s.replace("\r\n", "\n").trim_end().to_string()
}

/// Executes a sealed CLI binary against `scenario` inside `watch_dir` without touching source code.
pub fn capture_cli_oracle(
    program: &str,
    scenario: &CliOracleScenario,
    watch_dir: Option<&Path>,
) -> Result<CliOracleObservation, String> {
    let mut cmd = Command::new(program);
    cmd.args(&scenario.args);
    for (k, v) in &scenario.env {
        cmd.env(k, v);
    }
    if let Some(wd) = watch_dir {
        fs::create_dir_all(wd).map_err(|e| format!("Failed to prepare watch dir: {}", e))?;
        cmd.current_dir(wd);
    }

    let stdin_opt = if scenario.stdin_text.is_empty() {
        None
    } else {
        Some(scenario.stdin_text.as_bytes())
    };
    let out = run_command_bounded(
        cmd,
        stdin_opt,
        scenario.timeout_ms,
        DEFAULT_MAX_STREAM_BYTES,
    );
    if !out.spawned {
        return Err(format!(
            "Failed to spawn oracle binary '{}': {}",
            program,
            out.spawn_error.unwrap_or_else(|| "unknown".to_string())
        ));
    }

    let watched_file_sha256 = watch_dir.map(hash_watched_files).unwrap_or_default();

    Ok(CliOracleObservation {
        scenario_id: scenario.id.clone(),
        case_kind: scenario.case_kind,
        exit_code: out.exit_code,
        timed_out: out.timed_out,
        stdout_normalized: normalize_terminal_text(&out.stdout),
        stderr_present: !out.stderr.trim().is_empty(),
        watched_file_sha256,
        duration_ms: out.duration_ms,
    })
}

/// Runs `scenario` identically against `authority_bin` and `candidate_bin` in isolated sibling sandboxes,
/// minting an `Observed` + `ControlledReplay` SHA-256 receipt and optional `DatasetCase` counterexample.
pub fn compare_cli_oracle_runs(
    authority_bin: &str,
    candidate_bin: &str,
    candidate_sha256: Option<String>,
    scenario: &CliOracleScenario,
    sandbox_parent: &Path,
    ledger: &mut EvidenceLedger,
) -> Result<(CliDifferentialVerdict, Option<DatasetCase>), String> {
    let auth_dir = sandbox_parent.join(format!("oracle_auth_{}", scenario.id));
    let cand_dir = sandbox_parent.join(format!("oracle_cand_{}", scenario.id));
    let _ = fs::remove_dir_all(&auth_dir);
    let _ = fs::remove_dir_all(&cand_dir);

    let auth_obs = capture_cli_oracle(authority_bin, scenario, Some(&auth_dir))?;
    let cand_obs = capture_cli_oracle(candidate_bin, scenario, Some(&cand_dir))?;

    let _ = fs::remove_dir_all(&auth_dir);
    let _ = fs::remove_dir_all(&cand_dir);

    let mut diffs = Vec::new();
    if auth_obs.exit_code != cand_obs.exit_code {
        diffs.push(format!(
            "exit_code expected {:?}, got {:?}",
            auth_obs.exit_code, cand_obs.exit_code
        ));
    }
    if auth_obs.timed_out != cand_obs.timed_out {
        diffs.push(format!(
            "timed_out expected {}, got {}",
            auth_obs.timed_out, cand_obs.timed_out
        ));
    }
    if auth_obs.stdout_normalized != cand_obs.stdout_normalized {
        diffs.push(format!(
            "stdout mismatch (expected {} bytes, got {} bytes)",
            auth_obs.stdout_normalized.len(),
            cand_obs.stdout_normalized.len()
        ));
    }
    if auth_obs.watched_file_sha256 != cand_obs.watched_file_sha256 {
        diffs.push("filesystem output SHA-256 mismatch".to_string());
    }

    let matched = diffs.is_empty();
    let mismatch_summary = if matched {
        None
    } else {
        Some(diffs.join("; "))
    };

    let rec = ledger.record_with_provenance(
        EvidenceKind::Observed,
        format!("cli_oracle_{}", scenario.id),
        format!(
            "CLI differential oracle '{}' ({:?}): {}",
            scenario.id,
            scenario.case_kind,
            if matched { "MATCH" } else { "MISMATCH" }
        ),
        None,
        EvidenceProvenance {
            authority: EvidenceAuthority::ControlledReplay,
            confidence: EvidenceConfidence::Observed,
            coverage: CoverageStatus::Complete,
            subject_sha256: candidate_sha256,
            parent_evidence_id: None,
        },
        &json!({
            "scenario": scenario,
            "matched": matched,
            "mismatch_summary": mismatch_summary,
            "authority": auth_obs,
            "candidate": cand_obs,
        }),
    );

    let counterexample = if !matched {
        let mut expected_fields = Vec::new();
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&auth_obs.stdout_normalized) {
            expected_fields = map.keys().cloned().collect();
        }
        Some(DatasetCase {
            id: format!("oracle_ce_{}", scenario.id),
            split: DatasetSplit::RegressionCaptured,
            input: if !scenario.stdin_text.is_empty() {
                scenario.stdin_text.clone()
            } else {
                scenario.args.join(" ")
            },
            expected_fields,
            expected_substring: if auth_obs.stdout_normalized.is_empty() {
                None
            } else {
                Some(auth_obs.stdout_normalized.chars().take(120).collect())
            },
            expected_tools: Vec::new(),
            tool_match_mode: "all".to_string(),
            tags: vec![
                "black_box_oracle".to_string(),
                format!("case:{:?}", scenario.case_kind).to_ascii_lowercase(),
            ],
        })
    } else {
        None
    };

    Ok((
        CliDifferentialVerdict {
            scenario_id: scenario.id.clone(),
            case_kind: scenario.case_kind,
            matched,
            authority: auth_obs,
            candidate: cand_obs,
            mismatch_summary,
            receipt_id: rec.id,
        },
        counterexample,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOracleScenario {
    pub id: String,
    pub case_kind: CaseKind,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpOracleObservation {
    pub scenario_id: String,
    pub status_code: u16,
    pub content_type: Option<String>,
    pub body_text: String,
    pub json_keys: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDifferentialVerdict {
    pub scenario_id: String,
    pub case_kind: CaseKind,
    pub matched: bool,
    pub authority: HttpOracleObservation,
    pub candidate: HttpOracleObservation,
    pub mismatch_summary: Option<String>,
    pub receipt_id: String,
}

/// Sends a single deterministic HTTP/1.1 request to `addr` without reading target source code.
pub fn capture_http_oracle(
    addr: SocketAddr,
    scenario: &HttpOracleScenario,
) -> Result<HttpOracleObservation, String> {
    let t0 = Instant::now();
    let timeout = Duration::from_millis(scenario.timeout_ms.max(50));
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| format!("Connect failed to {}: {}", addr, e))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let body_bytes = scenario.body.as_bytes();
    let mut wire = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        scenario.method,
        scenario.path,
        addr,
        body_bytes.len()
    );
    for (k, v) in &scenario.headers {
        wire.push_str(&format!("{}: {}\r\n", k, v));
    }
    wire.push_str("\r\n");

    stream
        .write_all(wire.as_bytes())
        .and_then(|_| stream.write_all(body_bytes))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("Write failed to {}: {}", addr, e))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("Read failed from {}: {}", addr, e))?;
    let duration_ms = t0.elapsed().as_millis() as u64;

    let raw_str = String::from_utf8_lossy(&raw);
    let (head, body_part) = raw_str
        .split_once("\r\n\r\n")
        .unwrap_or((raw_str.as_ref(), ""));
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);

    let mut content_type = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-type") {
                content_type = Some(v.trim().to_string());
            }
        }
    }

    let mut json_keys = Vec::new();
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(body_part.trim()) {
        json_keys = map.keys().cloned().collect();
        json_keys.sort();
    }

    Ok(HttpOracleObservation {
        scenario_id: scenario.id.clone(),
        status_code,
        content_type,
        body_text: body_part.trim().to_string(),
        json_keys,
        duration_ms,
    })
}

/// Compares `authority_addr` vs `candidate_addr` over an HTTP scenario, minting a `ControlledReplay` receipt.
pub fn compare_http_oracle_runs(
    authority_addr: SocketAddr,
    candidate_addr: SocketAddr,
    candidate_sha256: Option<String>,
    scenario: &HttpOracleScenario,
    ledger: &mut EvidenceLedger,
) -> Result<(HttpDifferentialVerdict, Option<DatasetCase>), String> {
    let auth = capture_http_oracle(authority_addr, scenario)?;
    let cand = capture_http_oracle(candidate_addr, scenario)?;

    let mut diffs = Vec::new();
    if auth.status_code != cand.status_code {
        diffs.push(format!(
            "HTTP status expected {}, got {}",
            auth.status_code, cand.status_code
        ));
    }
    let body_equal = match (
        serde_json::from_str::<Value>(&auth.body_text),
        serde_json::from_str::<Value>(&cand.body_text),
    ) {
        (Ok(aj), Ok(cj)) => aj == cj,
        _ => auth.body_text == cand.body_text,
    };
    if !body_equal {
        diffs.push("Response payload mismatch".to_string());
    }

    let matched = diffs.is_empty();
    let mismatch_summary = if matched {
        None
    } else {
        Some(diffs.join("; "))
    };

    let rec = ledger.record_with_provenance(
        EvidenceKind::Observed,
        format!("http_oracle_{}", scenario.id),
        format!(
            "HTTP differential oracle '{} {}' ({:?}): {}",
            scenario.method,
            scenario.path,
            scenario.case_kind,
            if matched { "MATCH" } else { "MISMATCH" }
        ),
        None,
        EvidenceProvenance {
            authority: EvidenceAuthority::ControlledReplay,
            confidence: EvidenceConfidence::Observed,
            coverage: CoverageStatus::Complete,
            subject_sha256: candidate_sha256,
            parent_evidence_id: None,
        },
        &json!({
            "scenario": scenario,
            "matched": matched,
            "mismatch_summary": mismatch_summary,
            "authority": auth,
            "candidate": cand,
        }),
    );

    let counterexample = if !matched {
        Some(DatasetCase {
            id: format!("http_ce_{}", scenario.id),
            split: DatasetSplit::RegressionCaptured,
            input: format!("{} {} {}", scenario.method, scenario.path, scenario.body)
                .trim()
                .to_string(),
            expected_fields: auth.json_keys.clone(),
            expected_substring: if auth.body_text.is_empty() {
                None
            } else {
                Some(auth.body_text.chars().take(120).collect())
            },
            expected_tools: Vec::new(),
            tool_match_mode: "all".to_string(),
            tags: vec![
                "http_black_box_oracle".to_string(),
                format!("status:{}", auth.status_code),
            ],
        })
    } else {
        None
    };

    Ok((
        HttpDifferentialVerdict {
            scenario_id: scenario.id.clone(),
            case_kind: scenario.case_kind,
            matched,
            authority: auth,
            candidate: cand,
            mismatch_summary,
            receipt_id: rec.id,
        },
        counterexample,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedWireSurface {
    pub format: String,
    pub discovered_endpoints: Vec<String>,
    pub organs: Vec<OrganSpec>,
    pub obligations: Vec<Obligation>,
    pub replay_cases: Vec<DatasetCase>,
}

/// Extracts clean-room `OrganSpec`s, `Obligation`s, and replay `DatasetCase`s from an OpenAPI 3.x
/// JSON specification or a W3C `.har` 1.2 network capture (`0` target source code bytes read).
pub fn import_openapi_or_har_surface(doc: &Value) -> Result<ImportedWireSurface, String> {
    if let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) {
        let mut endpoints = Vec::new();
        let mut organs = Vec::new();
        let mut obligations = Vec::new();
        let mut cases = Vec::new();

        for (route, methods_val) in paths {
            let Some(methods) = methods_val.as_object() else {
                continue;
            };
            for (method, op_val) in methods {
                let m_upper = method.to_ascii_uppercase();
                if !matches!(
                    m_upper.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
                ) {
                    continue;
                }
                let ep_label = format!("{} {}", m_upper, route);
                endpoints.push(ep_label.clone());

                let slug: String = format!("{}_{}", method, route)
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_ascii_lowercase()
                        } else {
                            '_'
                        }
                    })
                    .collect::<String>()
                    .trim_matches('_')
                    .to_string();
                let organ_id = if slug.is_empty() {
                    format!("route_{}", organs.len() + 1)
                } else {
                    slug
                };
                let summary = op_val
                    .get("summary")
                    .and_then(|s| s.as_str())
                    .unwrap_or(&ep_label);

                organs.push(OrganSpec {
                    id: organ_id.clone(),
                    capability: format!("Clean-room wire handler for {} ({})", ep_label, summary),
                    inputs: vec!["HttpRequest".to_string()],
                    outputs: vec!["HttpResponse".to_string()],
                    invariants: vec![format!("Conform to public OpenAPI contract {}", ep_label)],
                    conformance_suite: "specs/openapi_surface.json".to_string(),
                });

                let mut req_cases = BTreeSet::new();
                req_cases.insert(CaseKind::Positive);
                req_cases.insert(CaseKind::Negative);
                req_cases.insert(CaseKind::Malformed);
                obligations.push(Obligation {
                    id: format!("obl_api_{}", organ_id),
                    version: 1,
                    surface_id: organ_id.clone(),
                    description: format!("Match HTTP status & schema for {}", ep_label),
                    domain: ObligationDomain::Protocol,
                    required_authority: EvidenceAuthority::ControlledReplay,
                    required_confidence: EvidenceConfidence::Observed,
                    required_cases: req_cases,
                    proof_bindings: Vec::new(),
                    contradiction_notes: Vec::new(),
                    status: crate::obligations::ObligationStatus::Open,
                });

                cases.push(DatasetCase {
                    id: format!("openapi_{}", organ_id),
                    split: DatasetSplit::Golden,
                    input: ep_label,
                    expected_fields: Vec::new(),
                    expected_substring: None,
                    expected_tools: Vec::new(),
                    tool_match_mode: "all".to_string(),
                    tags: vec!["openapi_import".to_string()],
                });
            }
        }

        return Ok(ImportedWireSurface {
            format: "openapi".to_string(),
            discovered_endpoints: endpoints,
            organs,
            obligations,
            replay_cases: cases,
        });
    }

    if let Some(entries) = doc
        .get("log")
        .and_then(|l| l.get("entries"))
        .and_then(|e| e.as_array())
    {
        let mut endpoints = Vec::new();
        let mut cases = Vec::new();
        let mut seen_routes = BTreeSet::new();

        for (idx, entry) in entries.iter().enumerate() {
            let Some(req) = entry.get("request") else {
                continue;
            };
            let method = req
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("GET")
                .to_ascii_uppercase();
            let raw_url = req.get("url").and_then(|u| u.as_str()).unwrap_or("/");
            let path = raw_url
                .find("://")
                .and_then(|pos| {
                    raw_url[(pos + 3)..]
                        .find('/')
                        .map(|p| &raw_url[(pos + 3 + p)..])
                })
                .unwrap_or(raw_url)
                .split('?')
                .next()
                .unwrap_or("/");

            let route_sig = format!("{} {}", method, path);
            seen_routes.insert(route_sig.clone());

            let resp_text = entry
                .get("response")
                .and_then(|r| r.get("content"))
                .and_then(|c| c.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            let mut expected_fields = Vec::new();
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(resp_text) {
                expected_fields = map.keys().cloned().collect();
            }
            let req_body = req
                .get("postData")
                .and_then(|p| p.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("");

            cases.push(DatasetCase {
                id: format!("har_capture_{:03}", idx + 1),
                split: DatasetSplit::Golden,
                input: format!("{} {}", route_sig, req_body).trim().to_string(),
                expected_fields,
                expected_substring: None,
                expected_tools: Vec::new(),
                tool_match_mode: "all".to_string(),
                tags: vec!["har_capture".to_string()],
            });
        }

        for r in &seen_routes {
            endpoints.push(r.clone());
        }
        let mut organs = Vec::new();
        let mut obligations = Vec::new();
        if !endpoints.is_empty() {
            organs.push(OrganSpec {
                id: "har_protocol_surface".to_string(),
                capability: format!(
                    "Reconstructed HTTP surface across {} captured route(s)",
                    endpoints.len()
                ),
                inputs: vec!["HttpRequest".to_string()],
                outputs: vec!["HttpResponse".to_string()],
                invariants: vec![
                    "Match captured HAR status codes and JSON response keys".to_string()
                ],
                conformance_suite: "specs/har_surface.json".to_string(),
            });
            let mut req_cases = BTreeSet::new();
            req_cases.insert(CaseKind::Positive);
            req_cases.insert(CaseKind::Negative);
            obligations.push(Obligation {
                id: "obl_har_protocol_surface".to_string(),
                version: 1,
                surface_id: "har_protocol_surface".to_string(),
                description: "Replay captured HAR wire traffic with zero schema regressions"
                    .to_string(),
                domain: ObligationDomain::Protocol,
                required_authority: EvidenceAuthority::ControlledReplay,
                required_confidence: EvidenceConfidence::Observed,
                required_cases: req_cases,
                proof_bindings: Vec::new(),
                contradiction_notes: Vec::new(),
                status: crate::obligations::ObligationStatus::Open,
            });
        }

        return Ok(ImportedWireSurface {
            format: "har-1.2".to_string(),
            discovered_endpoints: endpoints,
            organs,
            obligations,
            replay_cases: cases,
        });
    }

    Err("Unrecognized wire specification format: expected OpenAPI (`paths`) or HAR 1.2 (`log.entries`)".to_string())
}

/// Clean-room firewall around an optional outside-in inspection CLI (`carnot-inspect <subcommand> --json`).
/// Blocks all white-box decompilation / source-recovery subcommands when `policy` is quarantined,
/// preventing 200-tool MCP bloat and preserving `quarantined_source_bytes_read == 0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionInvocationRecord {
    pub subcommand: String,
    pub policy: AccessPolicy,
    pub allowed: bool,
    pub output_sha256: Option<String>,
    pub reason: String,
}

pub struct InspectionFirewall;

impl InspectionFirewall {
    /// Returns `true` ONLY for outside-in black-box behavioral/contract subcommands safe on quarantined targets.
    pub fn is_subcommand_clean_room_safe(subcommand: &str) -> bool {
        matches!(
            subcommand.trim(),
            "capture-process"
                | "compare-process-captures"
                | "inspect-web-network-capture"
                | "inspect-api-contract"
                | "inspect-packet-capture"
                | "inspect-pcap-capture"
                | "validate-browser-scenario"
                | "capture-browser-scenario"
                | "build-reconstruction-obligation-ledger"
                | "evaluate-reconstruction-coverage"
        )
    }

    pub fn invoke_json(
        policy: AccessPolicy,
        subcommand: &str,
        args: &[&str],
        timeout_ms: u64,
    ) -> Result<(Value, InspectionInvocationRecord), InspectionInvocationRecord> {
        let trimmed = subcommand.trim();
        let allowed = match policy {
            AccessPolicy::PermissiveAlgorithmAndFixtures => true,
            AccessPolicy::BoundaryInterfaceOnly | AccessPolicy::QuarantinedBlackBoxSpecOnly => {
                Self::is_subcommand_clean_room_safe(trimmed)
            }
        };

        if !allowed {
            return Err(InspectionInvocationRecord {
                subcommand: trimmed.to_string(),
                policy,
                allowed: false,
                output_sha256: None,
                reason: format!(
                    "InspectionFirewall blocked white-box/decompiler subcommand '{}' under {:?} to preserve Clean-Room guarantee",
                    trimmed, policy
                ),
            });
        }

        let inspection_bin = std::env::var("CARNOT_INSPECTION_BIN").unwrap_or_else(|_| {
            for key in ["HOME", "USERPROFILE"] {
                if let Ok(home) = std::env::var(key) {
                    let local = std::path::PathBuf::from(&home).join(".local/bin/carnot-inspect");
                    if local.exists() {
                        return local.to_string_lossy().into_owned();
                    }
                }
            }
            "carnot-inspect".to_string()
        });
        let mut cmd = Command::new(&inspection_bin);
        for token in trimmed.split_whitespace() {
            cmd.arg(token);
        }
        cmd.args(args);
        if !args.contains(&"--json") {
            cmd.arg("--json");
        }

        let out = run_command_bounded(cmd, None, timeout_ms, DEFAULT_MAX_STREAM_BYTES);
        if !out.spawned || !out.success {
            return Err(InspectionInvocationRecord {
                subcommand: trimmed.to_string(),
                policy,
                allowed: true,
                output_sha256: None,
                reason: out.spawn_error.unwrap_or_else(|| {
                    format!(
                        "inspection tool exited with {:?}: {}",
                        out.exit_code,
                        out.stderr.trim()
                    )
                }),
            });
        }

        let digest = sha256_hex(out.stdout.as_bytes());
        match serde_json::from_str::<Value>(out.stdout.trim()) {
            Ok(val) => Ok((
                val,
                InspectionInvocationRecord {
                    subcommand: trimmed.to_string(),
                    policy,
                    allowed: true,
                    output_sha256: Some(digest),
                    reason: "Outside-in JSON contract captured cleanly".to_string(),
                },
            )),
            Err(e) => Err(InspectionInvocationRecord {
                subcommand: trimmed.to_string(),
                policy,
                allowed: true,
                output_sha256: Some(digest),
                reason: format!(
                    "Invalid JSON returned by inspection tool '{}': {}",
                    trimmed, e
                ),
            }),
        }
    }
}
