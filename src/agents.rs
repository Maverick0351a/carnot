//! Local Coding Agent Discovery, Persistent ACP NDJSON Session Client & Headless CLI Adapter.
//!
//! 1. Login-shell-aware `PATH` discovery for `codex`, `claude`, `gemini`, `agy`, and `opencode`.
//! 2. Persistent **Agent Client Protocol (`ACP`)** NDJSON JSON-RPC 2.0 session client (`AcpSession`):
//!    - Negotiates `initialize` -> `session/new` -> `session/prompt` over child `stdin`/`stdout`.
//!    - Intercepts `session/request_permission` callbacks and enforces Carnot's **Black-Box ON/OFF Shield**:
//!      when `black_box_enforced == true`, any permission request touching `.carnot/quarantine` or
//!      `quarantined_prefixes` is automatically denied (`cancelled`).
//! 3. Non-interactive headless CLI fallback (`invoke_headless_agent`) with wall-clock timeout and
//!    markdown fence stripping.

use crate::proc_util::{adopt_login_shell_path, run_command_bounded, DEFAULT_MAX_STREAM_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Once;
use std::time::Instant;

static LOGIN_PATH_INIT: Once = Once::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAdapterInfo {
    pub id: String,
    pub display_name: String,
    pub protocol: String,
    pub command: String,
    pub detected_on_host: bool,
    pub resolved_path: Option<String>,
    pub recommended_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveAgentOutput {
    pub agent_id: String,
    pub exit_ok: bool,
    pub duration_ms: u64,
    pub raw_stdout: String,
    pub extracted_code: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpPermissionDecision {
    pub tool_or_path: String,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpPromptTurnResult {
    pub session_id: String,
    pub response_text: String,
    pub extracted_code: String,
    pub permission_decisions: Vec<AcpPermissionDecision>,
    pub duration_ms: u64,
}

pub struct AcpSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_rpc_id: u64,
    pub session_id: String,
    pub black_box_enforced: bool,
    pub quarantined_prefixes: Vec<String>,
}

impl AcpSession {
    /// Spawns an ACP-speaking agent subprocess (`initialize` + `session/new`) in `working_dir`.
    pub fn spawn(
        program: &str,
        args: &[&str],
        working_dir: &Path,
        black_box_enforced: bool,
        quarantined_prefixes: Vec<String>,
    ) -> Result<Self, String> {
        let mut child = Command::new(program)
            .args(args)
            .current_dir(working_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to spawn ACP agent '{}': {}", program, e))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Failed to capture ACP stdin".to_string())?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| "Failed to capture ACP stdout".to_string())?,
        );

        let mut sess = Self {
            child,
            stdin,
            stdout,
            next_rpc_id: 1,
            session_id: String::new(),
            black_box_enforced,
            quarantined_prefixes,
        };

        let mut perms = Vec::new();
        let _init_res = sess.send_rpc_and_wait(
            "initialize",
            json!({
                "protocolVersion": 1,
                "clientInfo": { "name": "carnot", "version": "1.0.0" },
                "capabilities": { "fs": { "readTextFile": true, "writeTextFile": true } }
            }),
            &mut perms,
            &mut String::new(),
        )?;

        let new_res = sess.send_rpc_and_wait(
            "session/new",
            json!({
                "cwd": working_dir.to_string_lossy(),
                "mcpServers": []
            }),
            &mut perms,
            &mut String::new(),
        )?;
        sess.session_id = new_res
            .get("sessionId")
            .and_then(|v| v.as_str())
            .unwrap_or("acp-session-1")
            .to_string();

        Ok(sess)
    }

    /// Sends `session/prompt` over the persistent ACP stream, handling streaming `session/update`
    /// notifications and enforcing the Clean-Room firewall on `session/request_permission` calls.
    pub fn prompt(&mut self, text: &str) -> Result<AcpPromptTurnResult, String> {
        let t0 = Instant::now();
        let mut permission_decisions = Vec::new();
        let mut streamed_text = String::new();
        let sid = self.session_id.clone();

        let res = self.send_rpc_and_wait(
            "session/prompt",
            json!({
                "sessionId": sid,
                "prompt": [{ "type": "text", "text": text }]
            }),
            &mut permission_decisions,
            &mut streamed_text,
        )?;

        if streamed_text.is_empty() {
            if let Some(direct) = res.get("text").and_then(|v| v.as_str()) {
                streamed_text.push_str(direct);
            }
        }

        let extracted_code = strip_markdown_code_fences(&streamed_text);
        Ok(AcpPromptTurnResult {
            session_id: self.session_id.clone(),
            response_text: streamed_text,
            extracted_code,
            permission_decisions,
            duration_ms: t0.elapsed().as_millis() as u64,
        })
    }

    fn send_rpc_and_wait(
        &mut self,
        method: &str,
        params: Value,
        permission_decisions: &mut Vec<AcpPermissionDecision>,
        streamed_text: &mut String,
    ) -> Result<Value, String> {
        let req_id = self.next_rpc_id;
        self.next_rpc_id += 1;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        });
        writeln!(self.stdin, "{}", payload)
            .map_err(|e| format!("Failed writing ACP request '{}': {}", method, e))?;
        self.stdin
            .flush()
            .map_err(|e| format!("Failed flushing ACP stdin: {}", e))?;

        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .map_err(|e| format!("Error reading ACP stdout: {}", e))?;
            if n == 0 {
                return Err(format!(
                    "ACP agent closed stream before replying to '{}'",
                    method
                ));
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(msg) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };

            // Incoming server->client request (e.g. `session/request_permission`)
            if let Some(in_method) = msg.get("method").and_then(|m| m.as_str()) {
                if let Some(in_id) = msg.get("id").cloned() {
                    if in_method == "session/request_permission" {
                        let decision = self.evaluate_permission_request(msg.get("params"));
                        let reply = if decision.allowed {
                            json!({
                                "jsonrpc": "2.0",
                                "id": in_id,
                                "result": { "outcome": { "outcome": "selected", "optionId": "allow-once" } }
                            })
                        } else {
                            json!({
                                "jsonrpc": "2.0",
                                "id": in_id,
                                "result": { "outcome": { "outcome": "cancelled" } }
                            })
                        };
                        permission_decisions.push(decision);
                        let _ = writeln!(self.stdin, "{}", reply);
                        let _ = self.stdin.flush();
                    } else {
                        let reply = json!({
                            "jsonrpc": "2.0",
                            "id": in_id,
                            "error": { "code": -32601, "message": "Unsupported client callback" }
                        });
                        let _ = writeln!(self.stdin, "{}", reply);
                        let _ = self.stdin.flush();
                    }
                    continue;
                }

                // Notification (`session/update`)
                if in_method == "session/update" {
                    if let Some(chunk) = msg
                        .pointer("/params/update/content/text")
                        .or_else(|| msg.pointer("/params/text"))
                        .and_then(|v| v.as_str())
                    {
                        streamed_text.push_str(chunk);
                    }
                }
                continue;
            }

            // Response to our request `req_id`
            if msg.get("id").and_then(|v| v.as_u64()) == Some(req_id) {
                if let Some(err) = msg.get("error") {
                    return Err(format!("ACP error on '{}': {}", method, err));
                }
                return Ok(msg.get("result").cloned().unwrap_or_else(|| json!({})));
            }
        }
    }

    fn evaluate_permission_request(&self, params: Option<&Value>) -> AcpPermissionDecision {
        let raw_params = params
            .map(|v| v.to_string())
            .unwrap_or_default()
            .replace('\\', "/");
        if self.black_box_enforced {
            let mut blocked_prefixes = vec![".carnot/quarantine".to_string()];
            blocked_prefixes.extend(self.quarantined_prefixes.iter().cloned());
            for qp in blocked_prefixes {
                let needle = qp.trim_matches('/');
                if !needle.is_empty() && raw_params.contains(needle) {
                    return AcpPermissionDecision {
                        tool_or_path: raw_params,
                        allowed: false,
                        reason: format!(
                            "Blocked by Carnot Black-Box Clean-Room Shield (matches quarantined zone '{}')",
                            needle
                        ),
                    };
                }
            }
        }
        AcpPermissionDecision {
            tool_or_path: raw_params,
            allowed: true,
            reason: if self.black_box_enforced {
                "Permitted clean-room workspace action".to_string()
            } else {
                "Permitted under White-Box Inspection Mode (black_box_enforced=false)".to_string()
            },
        }
    }
}

impl Drop for AcpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn discover_local_agents() -> Vec<AgentAdapterInfo> {
    LOGIN_PATH_INIT.call_once(adopt_login_shell_path);

    let specs = [
        (
            "codex",
            "Codex CLI",
            "ACP / Headless Exec",
            "codex",
            "codex exec (headless)",
        ),
        (
            "claude",
            "Claude Code",
            "ACP / Stdio MCP",
            "claude",
            "claude -p",
        ),
        (
            "gemini",
            "Gemini CLI",
            "ACP / Stdio MCP",
            "gemini",
            "gemini -p",
        ),
        (
            "agy",
            "Antigravity CLI",
            "Native Agentic CLI",
            "agy",
            "agy run",
        ),
        (
            "opencode",
            "OpenCode",
            "ACP / MCP",
            "opencode",
            "opencode run",
        ),
    ];

    specs
        .iter()
        .map(|(id, name, proto, bin, mode)| {
            let found = find_executable_in_path(bin);
            AgentAdapterInfo {
                id: (*id).to_string(),
                display_name: (*name).to_string(),
                protocol: (*proto).to_string(),
                command: (*bin).to_string(),
                detected_on_host: found.is_some(),
                resolved_path: found.map(|p| p.to_string_lossy().into_owned()),
                recommended_mode: (*mode).to_string(),
            }
        })
        .collect()
}

pub fn strip_markdown_code_fences(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(start_fence) = trimmed.find("```") {
        let after_ticks = &trimmed[(start_fence + 3)..];
        if let Some(newline_pos) = after_ticks.find('\n') {
            let body_onward = &after_ticks[(newline_pos + 1)..];
            if let Some(end_fence) = body_onward.find("```") {
                return body_onward[..end_fence]
                    .trim_end_matches(['\r', '\n', ' '])
                    .to_string();
            }
        }
    }
    raw.trim_matches(['\r', '\n']).to_string()
}

/// Spawns a real headless coding agent CLI (or `custom_cmd` / `CARNOT_AGENT_BIN`) in `working_dir`
/// under a hard wall-clock timeout and extracts the replacement code block from stdout.
pub fn invoke_headless_agent(
    agent_id: &str,
    prompt: &str,
    working_dir: &Path,
    timeout_ms: u64,
    custom_program_and_args: Option<(&str, &[&str])>,
) -> LiveAgentOutput {
    LOGIN_PATH_INIT.call_once(adopt_login_shell_path);

    let mut cmd = if let Some((prog, extra_args)) = custom_program_and_args {
        let mut c = Command::new(prog);
        c.args(extra_args);
        c.env("CARNOT_PROMPT", prompt);
        c
    } else if let Ok(override_bin) = std::env::var("CARNOT_AGENT_BIN") {
        let mut c = Command::new(override_bin);
        c.arg(prompt);
        c.env("CARNOT_PROMPT", prompt);
        c
    } else {
        let Some(resolved) = find_executable_in_path(agent_id) else {
            return LiveAgentOutput {
                agent_id: agent_id.to_string(),
                exit_ok: false,
                duration_ms: 0,
                raw_stdout: String::new(),
                extracted_code: String::new(),
                error_message: Some(format!(
                    "Coding agent CLI '{}' was not found on PATH",
                    agent_id
                )),
            };
        };
        let mut c = Command::new(resolved);
        match agent_id {
            "claude" | "gemini" => {
                c.args(["-p", prompt]);
            }
            "codex" => {
                c.args(["exec", prompt]);
            }
            "opencode" => {
                c.args(["run", prompt]);
            }
            _ => {
                c.arg(prompt);
            }
        }
        c
    };

    cmd.current_dir(working_dir);
    let out = run_command_bounded(cmd, None, timeout_ms.max(50), DEFAULT_MAX_STREAM_BYTES);

    if !out.spawned {
        return LiveAgentOutput {
            agent_id: agent_id.to_string(),
            exit_ok: false,
            duration_ms: out.duration_ms,
            raw_stdout: String::new(),
            extracted_code: String::new(),
            error_message: Some(format!(
                "Failed to spawn '{}': {}",
                agent_id,
                out.spawn_error.unwrap_or_else(|| "unknown".to_string())
            )),
        };
    }

    if out.timed_out {
        return LiveAgentOutput {
            agent_id: agent_id.to_string(),
            exit_ok: false,
            duration_ms: out.duration_ms,
            raw_stdout: out.stdout,
            extracted_code: String::new(),
            error_message: Some(format!(
                "Agent '{}' timed out after {} ms",
                agent_id, timeout_ms
            )),
        };
    }

    if !out.success {
        return LiveAgentOutput {
            agent_id: agent_id.to_string(),
            exit_ok: false,
            duration_ms: out.duration_ms,
            raw_stdout: out.stdout,
            extracted_code: String::new(),
            error_message: Some(format!(
                "Agent '{}' exited with {:?}: {}",
                agent_id,
                out.exit_code,
                out.stderr.trim()
            )),
        };
    }

    let extracted_code = strip_markdown_code_fences(&out.stdout);
    LiveAgentOutput {
        agent_id: agent_id.to_string(),
        exit_ok: true,
        duration_ms: out.duration_ms,
        raw_stdout: out.stdout,
        extracted_code,
        error_message: None,
    }
}

fn find_executable_in_path(bin_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ".ps1", ""]
    } else {
        &[""]
    };

    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate = dir.join(format!("{}{}", bin_name, ext));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}
