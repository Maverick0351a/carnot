//! Non-Deadlocking Threaded Subprocess Runner with Wall-Clock Timeout & Output Caps.
//!
//! Spawns dedicated background reader threads on child `stdout` and `stderr` immediately
//! after process launch so large outputs (>64 KB OS pipe buffer) never deadlock `try_wait()`,
//! while enforcing a hard wall-clock timeout and bounded memory retention (`max_output_bytes`).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Default maximum bytes retained per child stream (`4 MiB`).
pub const DEFAULT_MAX_STREAM_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BoundedProcessOutput {
    pub spawned: bool,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub spawn_error: Option<String>,
}

fn read_stream_bounded<R: Read>(mut reader: R, max_bytes: usize) -> (String, bool) {
    let mut buf = Vec::with_capacity(4096.min(max_bytes));
    let mut chunk = [0u8; 4096];
    let mut truncated = false;

    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < max_bytes {
                    let remaining = max_bytes - buf.len();
                    let take = n.min(remaining);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    (String::from_utf8_lossy(&buf).into_owned(), truncated)
}

/// Spawns `cmd` with piped `stdout`/`stderr` (and optional `stdin_bytes`), drains streams concurrently
/// on background threads so pipes never fill and block, and kills the child if `timeout_ms` elapses.
pub fn run_command_bounded(
    mut cmd: Command,
    stdin_bytes: Option<&[u8]>,
    timeout_ms: u64,
    max_output_bytes: usize,
) -> BoundedProcessOutput {
    let t0 = Instant::now();
    let cap = max_output_bytes.max(1024);

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    // Own process group so a timeout can signal the child and every grandchild.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return BoundedProcessOutput {
                spawned: false,
                timed_out: false,
                exit_code: None,
                success: false,
                duration_ms: t0.elapsed().as_millis() as u64,
                stdout: String::new(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                spawn_error: Some(e.to_string()),
            };
        }
    };

    if let Some(input) = stdin_bytes {
        if let Some(mut child_in) = child.stdin.take() {
            let payload = input.to_vec();
            thread::spawn(move || {
                let _ = child_in.write_all(&payload);
                let _ = child_in.flush();
            });
        }
    }

    let out_handle = child
        .stdout
        .take()
        .map(|so| thread::spawn(move || read_stream_bounded(so, cap)));
    let err_handle = child
        .stderr
        .take()
        .map(|se| thread::spawn(move || read_stream_bounded(se, cap)));

    let limit = Duration::from_millis(timeout_ms.max(20));
    let mut timed_out = false;
    let mut exit_code = None;
    let mut success = false;
    let mut wait_err = None;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                success = status.success();
                break;
            }
            Ok(None) => {
                if t0.elapsed() >= limit {
                    timed_out = true;
                    kill_process_tree(child.id());
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                wait_err = Some(e.to_string());
                kill_process_tree(child.id());
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }

    let duration_ms = t0.elapsed().as_millis() as u64;
    // shortcut: on timeout the reader join is capped at 2s and then detached. Upgrade to a cancellable read if a survivor keeps the pipe open past the group kill.
    let join_cap = timed_out.then_some(Duration::from_millis(2_000));
    let (stdout, stdout_truncated) = join_reader(out_handle, join_cap);
    let (stderr, stderr_truncated) = join_reader(err_handle, join_cap);

    BoundedProcessOutput {
        spawned: true,
        timed_out,
        exit_code,
        success: success && !timed_out && wait_err.is_none(),
        duration_ms,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        spawn_error: wait_err,
    }
}

fn join_reader(
    handle: Option<thread::JoinHandle<(String, bool)>>,
    cap: Option<Duration>,
) -> (String, bool) {
    let Some(handle) = handle else {
        return (String::new(), false);
    };
    let Some(limit) = cap else {
        return handle.join().unwrap_or_else(|_| (String::new(), false));
    };
    let started = Instant::now();
    loop {
        if handle.is_finished() {
            return handle.join().unwrap_or_else(|_| (String::new(), false));
        }
        if started.elapsed() >= limit {
            drop(handle);
            return (String::new(), false);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn kill_process_tree(pid: u32) {
    #[cfg(unix)]
    {
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        // Negative pid is the process group created by `process_group(0)`.
        unsafe {
            kill(-(pid as i32), 9);
        }
    }
    // shortcut: Windows uses taskkill /T rather than a job object. Upgrade to a job object if a detached grandchild survives.
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Strips shell login noise and harvests an interactive login shell's `PATH` when available,
/// ensuring GUI/daemon launches find `~/.cargo/bin`, `nvm`, `bun`, `uv`, and local CLI agents.
pub fn adopt_login_shell_path() {
    if cfg!(windows) {
        return;
    }
    let Ok(shell) = std::env::var("SHELL") else {
        return;
    };
    if shell.trim().is_empty() {
        return;
    }
    let mut cmd = Command::new(&shell);
    cmd.args([
        "-lc",
        "printf '__CARNOT_PATH_START__%s__CARNOT_PATH_END__' \"$PATH\"",
    ]);
    let out = run_command_bounded(cmd, None, 1500, 65_536);
    if !out.success {
        return;
    }
    if let Some(start) = out.stdout.find("__CARNOT_PATH_START__") {
        let rest = &out.stdout[(start + "__CARNOT_PATH_START__".len())..];
        if let Some(end) = rest.find("__CARNOT_PATH_END__") {
            let login_path = &rest[..end];
            if !login_path.is_empty() {
                let current = std::env::var("PATH").unwrap_or_default();
                let mut merged: Vec<String> = Vec::new();
                for seg in current.split(':').chain(login_path.split(':')) {
                    if !seg.is_empty() && !merged.iter().any(|s| s == seg) {
                        merged.push(seg.to_string());
                    }
                }
                std::env::set_var("PATH", merged.join(":"));
            }
        }
    }
}
