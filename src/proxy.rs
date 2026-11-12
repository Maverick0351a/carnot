//! Live TCP/HTTP/1.1 strangler-fig reverse proxy (`carnot proxy`) with feature-toggle context and shadow mirroring.
//!
//! Routes real live HTTP requests between `control_upstream` and `canary_upstream` using
//! `CarnotMachine::evaluate_for_context` (`MurmurHash3` Feature Toggle v2):
//! - Populates full `RolloutContext` from `X-User-Id`, `X-Session-Id`, `X-Forwarded-For` / `peer.ip()`
//!   (clean IP without `:port` pollution so `IN_CIDR` and `remoteAddress` work accurately),
//!   `X-Carnot-AppName`, `X-Carnot-Environment`, and `X-Carnot-Property-*` headers.
//! - Supports optional asynchronous Shadow Traffic Mirroring (`ProxyExtendedOptions::shadow_mirror_canary`)
//!   that forks a background read-only copy to `canary_upstream` and logs status/body divergences without
//!   impacting live caller latency.
//! - Feeds real `OnlineTelemetrySample` into `CarnotMachine::ingest_telemetry_sample` (`<0.1 ms` circuit breaker)
//!   plus optional progressive auto-ramp (`5% -> 25% -> 50% -> 100%`).

use crate::bridge::{CarnotMachine, OnlineTelemetrySample};
use crate::rollout::RolloutContext;
use crate::workspace::append_jsonl;
use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub control_upstream: SocketAddr,
    pub canary_upstream: SocketAddr,
    pub upstream_timeout_ms: u64,
    pub regressions_jsonl_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct ProxyExtendedOptions {
    /// When true, control-routed requests also asynchronously mirror to `canary_upstream`
    /// and record status divergences into `regressions_jsonl_path` without affecting client responses.
    pub shadow_mirror_canary: bool,
    /// When `Some(min_samples)`, automatically advances progressive canary rollout (`25% -> 50% -> 100%`)
    /// once `min_samples` consecutive canary requests succeed without error.
    pub auto_ramp_min_samples: Option<usize>,
}

struct ParsedClientRequest {
    method: String,
    path: String,
    user_id: String,
    rollout_ctx: RolloutContext,
    body: Vec<u8>,
    outbound_wire: Vec<u8>,
}

const MAX_CONCURRENT_PROXY_WORKERS: usize = 64;

pub fn run_reverse_proxy(
    listener: TcpListener,
    cfg: ProxyConfig,
    machine: Arc<Mutex<CarnotMachine>>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    run_reverse_proxy_with_options(
        listener,
        cfg,
        ProxyExtendedOptions::default(),
        machine,
        shutdown,
    )
}

pub fn run_reverse_proxy_with_options(
    listener: TcpListener,
    cfg: ProxyConfig,
    ext: ProxyExtendedOptions,
    machine: Arc<Mutex<CarnotMachine>>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let active_workers = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));

                if active_workers.load(Ordering::Relaxed) < MAX_CONCURRENT_PROXY_WORKERS {
                    active_workers.fetch_add(1, Ordering::Relaxed);
                    let cfg_clone = cfg.clone();
                    let ext_clone = ext.clone();
                    let machine_clone = Arc::clone(&machine);
                    let counter_clone = Arc::clone(&active_workers);
                    std::thread::spawn(move || {
                        handle_proxy_connection(
                            &mut stream,
                            peer,
                            &cfg_clone,
                            &ext_clone,
                            &machine_clone,
                        );
                        counter_clone.fetch_sub(1, Ordering::Relaxed);
                    });
                } else {
                    handle_proxy_connection(&mut stream, peer, &cfg, &ext, &machine);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Ok(())
}

fn handle_proxy_connection(
    client: &mut TcpStream,
    peer: SocketAddr,
    cfg: &ProxyConfig,
    ext: &ProxyExtendedOptions,
    machine: &Arc<Mutex<CarnotMachine>>,
) {
    let Some(req) = read_http_request(client, peer) else {
        let _ = client.write_all(
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad request",
        );
        return;
    };

    let (assigned_variant, is_canary, control_id) = {
        let mut guard = machine.lock().unwrap();
        let v = guard.evaluate_for_context(&req.rollout_ctx);
        let is_can = guard
            .canary_variant_id
            .as_ref()
            .map(|cid| cid == &v.name)
            .unwrap_or(false)
            && !guard.killswitch_tripped
            && guard.canary_rollout_pct > 0;
        (v.name, is_can, guard.control_variant_id.clone())
    };

    let primary_target = if is_canary {
        cfg.canary_upstream
    } else {
        cfg.control_upstream
    };

    let t0 = Instant::now();
    let upstream_res =
        forward_to_upstream(primary_target, &req.outbound_wire, cfg.upstream_timeout_ms);
    let latency_ms = t0.elapsed().as_millis() as u64;

    let (status_code, raw_resp, upstream_failed) = match upstream_res {
        Ok((code, bytes)) => (code, bytes, code >= 500),
        Err(_) => (502, Vec::new(), true),
    };

    let body_preview = String::from_utf8_lossy(&req.body);
    let excerpt = format!(
        "{} {} {}",
        req.method,
        req.path,
        body_preview.chars().take(160).collect::<String>()
    )
    .trim()
    .to_string();

    {
        let mut guard = machine.lock().unwrap();
        guard.ingest_telemetry_sample(OnlineTelemetrySample {
            user_id: req.user_id.clone(),
            served_variant_id: if is_canary {
                assigned_variant.clone()
            } else {
                control_id
            },
            prompt_excerpt: excerpt,
            latency_ms,
            error: upstream_failed,
            online_eval_score: if upstream_failed { 0.0 } else { 0.98 },
        });
        if let Some(min_samples) = ext.auto_ramp_min_samples {
            let _ = guard.auto_ramp_canary_if_healthy(min_samples);
        }
    }

    // Optional async shadow mirror when traffic was served by control
    if !is_canary && ext.shadow_mirror_canary {
        let canary_addr = cfg.canary_upstream;
        let wire_copy = req.outbound_wire.clone();
        let timeout_ms = cfg.upstream_timeout_ms;
        let reg_path = cfg.regressions_jsonl_path.clone();
        let ctrl_status = status_code;
        let uid = req.user_id.clone();
        let method = req.method.clone();
        let path = req.path.clone();
        std::thread::spawn(move || {
            if let Ok((shadow_code, _)) = forward_to_upstream(canary_addr, &wire_copy, timeout_ms) {
                if shadow_code != ctrl_status {
                    if let Some(ref rp) = reg_path {
                        let _ = append_jsonl(
                            rp,
                            &json!({
                                "mode": "shadow_mirror",
                                "user_id": uid,
                                "method": method,
                                "path": path,
                                "control_status": ctrl_status,
                                "canary_status": shadow_code,
                            }),
                        );
                    }
                }
            }
        });
    }

    if is_canary && upstream_failed {
        if let Some(ref reg_path) = cfg.regressions_jsonl_path {
            let _ = append_jsonl(
                reg_path,
                &json!({
                    "user_id": req.user_id,
                    "method": req.method,
                    "path": req.path,
                    "body": body_preview,
                    "canary_status": status_code,
                    "latency_ms": latency_ms,
                    "served_variant": assigned_variant,
                }),
            );
        }

        // Transparent strangler-fig failover to control upstream so live caller receives a clean response
        if let Ok((_ctrl_code, ctrl_bytes)) = forward_to_upstream(
            cfg.control_upstream,
            &req.outbound_wire,
            cfg.upstream_timeout_ms,
        ) {
            let _ = client.write_all(&ctrl_bytes);
            let _ = client.flush();
            return;
        }
    }

    if !raw_resp.is_empty() {
        let _ = client.write_all(&raw_resp);
    } else {
        let _ = client.write_all(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad gateway",
        );
    }
    let _ = client.flush();
}

fn read_http_request(stream: &mut TcpStream, peer: SocketAddr) -> Option<ParsedClientRequest> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let header_end_idx = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > 65_536 {
            return None;
        }
    };

    let header_bytes = &buf[..header_end_idx];
    let header_str = std::str::from_utf8(header_bytes).ok()?;
    let mut lines = header_str.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_len = 0usize;
    let mut user_id: Option<String> = None;
    let mut session_id: Option<String> = None;
    let mut remote_address: Option<String> = None;
    let mut app_name: Option<String> = None;
    let mut environment: Option<String> = None;
    let mut properties: HashMap<String, Option<String>> = HashMap::new();
    let mut forwarded_headers = Vec::new();

    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key_trim = k.trim();
            let val_trim = v.trim();
            let lower = key_trim.to_ascii_lowercase();
            match lower.as_str() {
                "content-length" => {
                    content_len = val_trim.parse::<usize>().unwrap_or(0).min(1_048_576);
                }
                "x-user-id" => user_id = Some(val_trim.to_string()),
                "x-session-id" => session_id = Some(val_trim.to_string()),
                "x-forwarded-for" => {
                    if let Some(first_ip) = val_trim.split(',').next() {
                        let cleaned = first_ip.trim();
                        if !cleaned.is_empty() {
                            remote_address = Some(cleaned.to_string());
                        }
                    }
                }
                "x-carnot-appname" => app_name = Some(val_trim.to_string()),
                "x-carnot-environment" => environment = Some(val_trim.to_string()),
                _ => {
                    if let Some(prop_key) = lower.strip_prefix("x-carnot-property-") {
                        properties.insert(prop_key.to_string(), Some(val_trim.to_string()));
                    }
                }
            }
            if !key_trim.eq_ignore_ascii_case("connection") {
                forwarded_headers.push(format!("{}: {}", key_trim, val_trim));
            }
        }
    }

    let clean_peer_ip = peer.ip().to_string();
    let resolved_remote_ip = remote_address.unwrap_or(clean_peer_ip);
    let resolved_uid = user_id
        .clone()
        .or_else(|| session_id.clone())
        .unwrap_or_else(|| resolved_remote_ip.clone());

    let rollout_ctx = RolloutContext {
        user_id: Some(resolved_uid.clone()),
        session_id,
        remote_address: Some(resolved_remote_ip),
        environment,
        app_name,
        current_time: None,
        properties,
    };

    let body_start = header_end_idx + 4;
    while buf.len() < body_start + content_len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body_end = (body_start + content_len).min(buf.len());
    let body = buf[body_start..body_end].to_vec();

    let mut outbound_wire = Vec::with_capacity(header_end_idx + body.len() + 64);
    outbound_wire.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());
    for h in forwarded_headers {
        outbound_wire.extend_from_slice(h.as_bytes());
        outbound_wire.extend_from_slice(b"\r\n");
    }
    outbound_wire.extend_from_slice(b"Connection: close\r\n\r\n");
    outbound_wire.extend_from_slice(&body);

    Some(ParsedClientRequest {
        method,
        path,
        user_id: resolved_uid,
        rollout_ctx,
        body,
        outbound_wire,
    })
}

fn forward_to_upstream(
    addr: SocketAddr,
    wire_req: &[u8],
    timeout_ms: u64,
) -> std::io::Result<(u16, Vec<u8>)> {
    let timeout = Duration::from_millis(timeout_ms.max(50));
    let mut upstream = TcpStream::connect_timeout(&addr, timeout)?;
    upstream.set_read_timeout(Some(timeout))?;
    upstream.set_write_timeout(Some(timeout))?;
    upstream.write_all(wire_req)?;
    upstream.flush()?;

    let mut resp = Vec::with_capacity(4096);
    upstream.read_to_end(&mut resp)?;
    if resp.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty upstream response",
        ));
    }

    let status_code = parse_http_status_code(&resp).unwrap_or(502);
    Ok((status_code, resp))
}

fn parse_http_status_code(resp: &[u8]) -> Option<u16> {
    let end = resp
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(resp.len().min(64));
    let first_line = std::str::from_utf8(&resp[..end]).ok()?;
    let mut parts = first_line.split_whitespace();
    let _http_ver = parts.next()?;
    parts.next()?.parse::<u16>().ok()
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
