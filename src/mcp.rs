//! Model Context Protocol (`MCP`) Stdio JSON-RPC 2.0 Server (`carnot mcp`) with Bounded Evidence Paging.
//!
//! Exposes all 5 Carnot stages (`scout`, `intake`, `build`, `verify`, `cutover`) plus
//! SHA-256 `evidence://<id>` resource reading and `carnot_evidence_browse` paging so oversized
//! outputs never flood an agent's context window.

use crate::bridge::{CarnotMachine, EvolveOpts};
use crate::eval::DatasetSplit;
use crate::evidence::{EvidenceKind, DEFAULT_MCP_MAX_BYTES};
use crate::scout::TargetLanguage;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

pub fn run_mcp_stdio(machine: &mut CarnotMachine) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line_res in stdin.lock().lines() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle_jsonrpc_message(machine, &line) {
            writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

pub fn handle_jsonrpc_message(machine: &mut CarnotMachine, raw: &str) -> Option<Value> {
    handle_jsonrpc_with_budget(machine, raw, DEFAULT_MCP_MAX_BYTES)
}

pub fn handle_jsonrpc_with_budget(
    machine: &mut CarnotMachine,
    raw: &str,
    max_response_bytes: usize,
) -> Option<Value> {
    let Ok(req) = serde_json::from_str::<Value>(raw) else {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": { "code": -32700, "message": "Parse error" }
        }));
    };

    let id = req.get("id").cloned()?;
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {}, "resources": {} },
                "serverInfo": { "name": "carnot", "version": env!("CARGO_PKG_VERSION") }
            }
        })),
        "resources/list" => {
            let items: Vec<Value> = machine
                .evidence
                .list_summaries()
                .into_iter()
                .map(|s| {
                    json!({
                        "uri": s.uri,
                        "name": s.subject,
                        "description": format!("[{:?}] {} ({} bytes, sha256={})", s.kind, s.summary, s.byte_len, &s.sha256[..12]),
                        "mimeType": "application/json"
                    })
                })
                .collect();
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "resources": items }
            }))
        }
        "resources/read" => {
            let uri = req
                .get("params")
                .and_then(|p| p.get("uri"))
                .and_then(|u| u.as_str())
                .unwrap_or("");
            match machine.evidence.browse(uri, 0, max_response_bytes) {
                Some(page) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "contents": [{
                            "uri": format!("evidence://{}", page.id),
                            "mimeType": "application/json",
                            "text": serde_json::to_string_pretty(&page).unwrap()
                        }]
                    }
                })),
                None => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": format!("Unknown evidence URI '{}'", uri) }
                })),
            }
        }
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    {
                        "name": "carnot_scout",
                        "description": "Stage 1 (Pro): Rank candidate source repos by signal-to-bloat ratio and user target language preference.",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "target_language": { "type": "string" } }
                        }
                    },
                    {
                        "name": "carnot_intake_cert",
                        "description": "Stage 2 (Pro): Export SHA-256 Clean-Room IP Provenance Certificate proving zero quarantined copyleft bytes were read.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "carnot_build_plan",
                        "description": "Stage 3: Emit a brand-free polyglot project blueprint (rust, go, typescript, python, scala3, zig).",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "target_language": { "type": "string" } }
                        }
                    },
                    {
                        "name": "carnot_verify",
                        "description": "Stage 4: Run multi-scorer conformance checks and compute the 3D Pareto frontier.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "carnot_cutover_promote",
                        "description": "Stage 5 (Pro): Promote a verified build to a MurmurHash3 strangler-fig canary percentage.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "variant_id": { "type": "string" },
                                "rollout_pct": { "type": "integer", "minimum": 1, "maximum": 100 }
                            },
                            "required": ["variant_id"]
                        }
                    },
                    {
                        "name": "carnot_cutover_simulate",
                        "description": "Stage 5 (Pro): Simulate live requests (with optional fault injection) to verify <0.1ms auto-kill-switch and regression capture.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "requests": { "type": "integer" },
                                "inject_fault": { "type": "boolean" }
                            }
                        }
                    },
                    {
                        "name": "carnot_evidence_browse",
                        "description": "Page through a stored SHA-256 ev_... receipt payload by offset and limit.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "receipt_id": { "type": "string" },
                                "offset": { "type": "integer" },
                                "limit": { "type": "integer" }
                            },
                            "required": ["receipt_id"]
                        }
                    },
                    {
                        "name": "carnot_ui_navigate",
                        "description": "Drive the live Carnot workbench window: switch screens (home/workbench), switch panes, or open an organ dossier.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "screen": { "type": "string" },
                                "pane": { "type": "string" },
                                "organ_id": { "type": "string" }
                            }
                        }
                    },
                    {
                        "name": "carnot_playbook_run",
                        "description": "Execute a built-in Carnot playbook (blueprint-brainstorm, discover-and-quarantine, parallel-shootout, prune-feature-creep, flagged-cutover).",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "playbook_id": { "type": "string" } },
                            "required": ["playbook_id"]
                        }
                    },
                    {
                        "name": "carnot_proposal_decide",
                        "description": "Accept, decline, or undo a staged human-in-the-loop ProposalCard.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "proposal_id": { "type": "string" },
                                "decision": { "type": "string", "enum": ["accept", "decline", "undo"] }
                            },
                            "required": ["proposal_id", "decision"]
                        }
                    },
                    {
                        "name": "carnot_point",
                        "description": "Point the machine at a local workspace directory (v1 WorkspaceDir only). Builds/refreshes .carnot/gym and reseeds organs from the workspace.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Absolute or relative workspace directory" }
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "carnot_daemon_tick",
                        "description": "Run one Function Foundry daemon tick against the pointed workspace (StageOnly by default). Requires explicit_candidate; headless agent auto-candidate is deferred — without a candidate the tick skips with a reason.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "explicit_candidate": {
                                    "type": "string",
                                    "description": "Optional EVOLVE block body for a deterministic live trial"
                                }
                            }
                        }
                    },
                    {
                        "name": "carnot_evolve_organ",
                        "description": "Pro: Evolve an organ. Live worktree trial when a workspace is pointed AND explicit_candidate is set (headless auto-candidate deferred). Offline 3-island demo when demo=true or no workspace. apply=true prefers AutoRatchet on live wins.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "organ_id": { "type": "string" },
                                "generations": { "type": "integer", "minimum": 1, "maximum": 20 },
                                "demo": { "type": "boolean", "description": "Force offline island evolution even when a workspace is pointed" },
                                "apply": { "type": "boolean", "description": "Prefer AutoRatchet when a live worktree trial wins" },
                                "explicit_candidate": { "type": "string", "description": "Required for live worktree path (EVOLVE block body)" },
                                "organ_rel_path": { "type": "string", "description": "Workspace-relative organ path (no .. / absolute)" }
                            }
                        }
                    },
                    {
                        "name": "carnot_toggle_black_box",
                        "description": "Toggle the Black-Box Shield. ON (default) = strict Chinese-Wall quarantine of AGPL/GPL/BSL/EULA zones. OFF = white-box inspection for permissive or owned code. Omit 'enforced' to read status. Mode is recorded in the Clean-Room Certificate.",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "enforced": { "type": "boolean" } }
                        }
                    },
                    {
                        "name": "carnot_code_search",
                        "description": "Hybrid code search (BM25 + static embeddings + RRF + rerank) over the workspace; respects the Black-Box Shield and reports token savings.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": { "type": "string" },
                                "top_k": { "type": "integer", "minimum": 1, "maximum": 50 }
                            },
                            "required": ["query"]
                        }
                    },
                    {
                        "name": "carnot_find_related",
                        "description": "Find code chunks related to file_path:line.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "file_path": { "type": "string" },
                                "line": { "type": "integer", "minimum": 1 },
                                "top_k": { "type": "integer", "minimum": 1, "maximum": 50 }
                            },
                            "required": ["file_path"]
                        }
                    },
                    {
                        "name": "carnot_hotspots",
                        "description": "Scan for EVOLVE_START markers or recommend evolution hotspots for a goal.",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "goal": { "type": "string" } }
                        }
                    },
                    {
                        "name": "carnot_advise_languages",
                        "description": "Design-to-Language Fitness Matrix across the 6 target languages.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "carnot_obligations",
                        "description": "Evaluate reconstruction closure across obligations and open unknowns.",
                        "inputSchema": { "type": "object", "properties": {} }
                    }
                ]
            }
        })),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            let (is_err, raw_text) = match tool_name {
                "carnot_scout" => {
                    let lang = args
                        .get("target_language")
                        .and_then(|v| v.as_str())
                        .map(TargetLanguage::from_str_loose);
                    match machine.run_scout(lang) {
                        Ok(r) => (false, serde_json::to_string_pretty(&r).unwrap()),
                        Err(e) => (true, e),
                    }
                }
                "carnot_intake_cert" => match machine.export_clean_room_certificate() {
                    Ok(c) => (false, serde_json::to_string_pretty(&c).unwrap()),
                    Err(e) => (true, e),
                },
                "carnot_build_plan" => {
                    let lang = args
                        .get("target_language")
                        .and_then(|v| v.as_str())
                        .map(TargetLanguage::from_str_loose);
                    let plan = machine.preview_target_build(lang);
                    (false, serde_json::to_string_pretty(&plan).unwrap())
                }
                "carnot_verify" => {
                    let res = machine.run_evaluations(DatasetSplit::Golden);
                    (false, serde_json::to_string_pretty(&res).unwrap())
                }
                "carnot_cutover_promote" => {
                    let vid = args
                        .get("variant_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let pct = args
                        .get("rollout_pct")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(25) as u32;
                    match machine.promote_canary(vid, pct) {
                        Ok(st) => (false, serde_json::to_string_pretty(&st).unwrap()),
                        Err(e) => (true, e),
                    }
                }
                "carnot_cutover_simulate" => {
                    let reqs = args.get("requests").and_then(|v| v.as_u64()).unwrap_or(24) as usize;
                    let fault = args
                        .get("inject_fault")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    match machine.simulate_live_traffic(reqs, fault) {
                        Ok(st) => (false, serde_json::to_string_pretty(&st).unwrap()),
                        Err(e) => (true, e),
                    }
                }
                "carnot_evidence_browse" => {
                    let rid = args
                        .get("receipt_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(4096) as usize;
                    match machine.evidence.browse(rid, offset, limit) {
                        Some(page) => (false, serde_json::to_string_pretty(&page).unwrap()),
                        None => (true, format!("Unknown evidence receipt '{}'", rid)),
                    }
                }
                "carnot_ui_navigate" => {
                    machine.navigate_shell(
                        args.get("screen").and_then(|v| v.as_str()),
                        args.get("pane").and_then(|v| v.as_str()),
                        args.get("organ_id").and_then(|v| v.as_str()),
                        None,
                    );
                    (false, serde_json::to_string_pretty(&machine.shell).unwrap())
                }
                "carnot_playbook_run" => {
                    let pid = args
                        .get("playbook_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    match machine.execute_playbook(pid) {
                        Ok(msg) => (false, msg),
                        Err(e) => (true, e),
                    }
                }
                "carnot_proposal_decide" => {
                    let pid = args
                        .get("proposal_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let dec = args
                        .get("decision")
                        .and_then(|v| v.as_str())
                        .unwrap_or("accept");
                    match machine.decide_proposal(pid, dec) {
                        Ok(card) => (false, serde_json::to_string_pretty(&card).unwrap()),
                        Err(e) => (true, e),
                    }
                }
                "carnot_point" => {
                    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    if path.trim().is_empty() {
                        (true, "Missing required 'path'".to_string())
                    } else {
                        match machine.point_target(Path::new(path)) {
                            Ok(target) => (false, serde_json::to_string_pretty(&target).unwrap()),
                            Err(e) => (true, e),
                        }
                    }
                }
                "carnot_daemon_tick" => {
                    let candidate = args.get("explicit_candidate").and_then(|v| v.as_str());
                    match machine.daemon_tick(candidate) {
                        Ok(rep) => (false, serde_json::to_string_pretty(&rep).unwrap()),
                        Err(e) => (true, e),
                    }
                }
                "carnot_evolve_organ" => {
                    let oid = args
                        .get("organ_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let gens = args
                        .get("generations")
                        .and_then(|v| v.as_u64())
                        .map(|g| g as usize);
                    let demo = args.get("demo").and_then(|v| v.as_bool()).unwrap_or(false);
                    let apply = args.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
                    let explicit_candidate = args
                        .get("explicit_candidate")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let organ_rel_path = args
                        .get("organ_rel_path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    match machine.evolve_organ_with_opts(EvolveOpts {
                        organ_id: oid,
                        generations: gens,
                        demo,
                        apply,
                        explicit_candidate,
                        organ_rel_path,
                    }) {
                        Ok(rep) => (false, serde_json::to_string_pretty(&rep).unwrap()),
                        Err(e) => (true, e),
                    }
                }
                "carnot_toggle_black_box" => match args.get("enforced").and_then(|v| v.as_bool()) {
                    Some(enforced) => {
                        let cert = machine.set_black_box_mode(enforced);
                        (false, serde_json::to_string_pretty(&cert).unwrap())
                    }
                    None => (
                        false,
                        serde_json::to_string_pretty(&json!({
                            "black_box_enforced": machine.manifest.black_box_enforced,
                            "certificate_receipt_id": machine.clean_room_cert.receipt_id,
                        }))
                        .unwrap(),
                    ),
                },
                "carnot_code_search" => {
                    let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                    if q.trim().is_empty() {
                        (true, "Missing required 'query'".to_string())
                    } else {
                        let k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
                        let rep = machine.search_codebase(q, k);
                        (false, serde_json::to_string_pretty(&rep).unwrap())
                    }
                }
                "carnot_find_related" => {
                    let fp = args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
                    let line = args.get("line").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
                    let k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
                    if fp.is_empty() {
                        (true, "Missing required 'file_path'".to_string())
                    } else {
                        let rep = machine.find_related_code(fp, line, k);
                        (false, serde_json::to_string_pretty(&rep).unwrap())
                    }
                }
                "carnot_hotspots" => {
                    let goal = args.get("goal").and_then(|v| v.as_str()).unwrap_or("");
                    let rep = machine.scan_hotspots(goal);
                    (false, serde_json::to_string_pretty(&rep).unwrap())
                }
                "carnot_advise_languages" => {
                    let rep = machine.advise_languages();
                    (false, serde_json::to_string_pretty(&rep).unwrap())
                }
                "carnot_obligations" => {
                    let verdict = machine.evaluate_obligations();
                    (
                        false,
                        serde_json::to_string_pretty(&json!({
                            "verdict": verdict,
                            "ledger": machine.obligations,
                        }))
                        .unwrap(),
                    )
                }
                other => (true, format!("Unknown tool '{}'", other)),
            };

            let bounded_text = if !is_err && raw_text.len() > max_response_bytes {
                let as_val = serde_json::from_str::<Value>(&raw_text)
                    .unwrap_or_else(|_| json!({ "raw": raw_text }));
                let rec = machine.evidence.record(
                    EvidenceKind::Derived,
                    format!("mcp_paged_{}", tool_name),
                    format!("Paged output for {} ({} bytes)", tool_name, raw_text.len()),
                    machine.checkpoint_id.clone(),
                    &as_val,
                );
                let preview = String::from_utf8_lossy(
                    &raw_text.as_bytes()[..max_response_bytes.min(raw_text.len())],
                )
                .into_owned();
                serde_json::to_string_pretty(&json!({
                    "truncated": true,
                    "total_bytes": raw_text.len(),
                    "receipt_id": rec.id,
                    "evidence_uri": format!("evidence://{}", rec.id),
                    "sha256": rec.sha256,
                    "next_action": "Call carnot_evidence_browse with receipt_id and offset to page remaining bytes.",
                    "preview": preview,
                }))
                .unwrap()
            } else {
                raw_text
            };

            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "isError": is_err,
                    "content": [{ "type": "text", "text": bounded_text }]
                }
            }))
        }
        _ => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method '{}' not found", method) }
        })),
    }
}
