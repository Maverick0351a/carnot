//! Detect and run a project's test command for `carnot verify`.
//!
//! The runner is whatever the tree already declares. Carnot does not write a
//! harness into the tree; the child process is the only writer.

use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

/// Default `carnot verify --timeout`, in seconds.
/// shortcut: one budget for the whole suite. Upgrade to a per-test timeout when a hang should not discard results that already finished.
pub const DEFAULT_VERIFY_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerKind {
    Cargo,
    Pytest,
    Unittest,
    Npm,
    Go,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestRunner {
    pub kind: RunnerKind,
    pub program: String,
    pub args: Vec<String>,
}

impl TestRunner {
    pub fn command_line(&self) -> String {
        let mut parts = Vec::with_capacity(1 + self.args.len());
        parts.push(self.program.clone());
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestExecution {
    pub command: String,
    pub exit_code: Option<i32>,
    pub passed: Option<u64>,
    pub failed: Option<u64>,
    /// Wall time of the child, including a timeout kill.
    pub duration_ms: u64,
    pub timed_out: bool,
    /// True only when the child process actually started.
    pub started: bool,
    pub note: Option<String>,
}

/// First matching runner: Cargo, Python (`pyproject.toml` / `setup.py`), npm
/// `scripts.test`, Go, then a Python `tests/` or `test/` directory.
pub fn detect_test_runner(dir: &Path) -> Option<TestRunner> {
    if dir.join("Cargo.toml").is_file() {
        return Some(TestRunner {
            kind: RunnerKind::Cargo,
            program: "cargo".to_string(),
            args: vec!["test".to_string()],
        });
    }
    if dir.join("pyproject.toml").is_file() || dir.join("setup.py").is_file() {
        return Some(python_runner(dir));
    }
    if package_json_has_test_script(dir) {
        return Some(TestRunner {
            kind: RunnerKind::Npm,
            program: "npm".to_string(),
            args: vec!["test".to_string()],
        });
    }
    if dir.join("go.mod").is_file() {
        return Some(TestRunner {
            kind: RunnerKind::Go,
            program: "go".to_string(),
            args: vec!["test".to_string(), "./...".to_string()],
        });
    }
    if dir.join("tests").is_dir() || dir.join("test").is_dir() {
        return Some(python_runner(dir));
    }
    None
}

pub(crate) fn python_program() -> String {
    for candidate in ["python3", "python"] {
        let ok = Command::new(candidate)
            .arg("-c")
            .arg("")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if ok {
            return candidate.to_string();
        }
    }
    "python3".to_string()
}

fn pytest_module_works(python: &str) -> bool {
    Command::new(python)
        .args(["-m", "pytest", "--version"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn python_runner(dir: &Path) -> TestRunner {
    let python = python_program();
    python_runner_with(dir, &python, pytest_module_works(&python))
}

/// shortcut: unittest fallback only discovers `tests/` or `test/`. Upgrade when a project keeps tests beside modules and pytest is not installed.
fn python_runner_with(dir: &Path, python: &str, pytest: bool) -> TestRunner {
    if pytest {
        return TestRunner {
            kind: RunnerKind::Pytest,
            program: python.to_string(),
            args: vec!["-m".to_string(), "pytest".to_string(), "-q".to_string()],
        };
    }
    let start = if dir.join("tests").is_dir() {
        "tests"
    } else if dir.join("test").is_dir() {
        "test"
    } else {
        "tests"
    };
    TestRunner {
        kind: RunnerKind::Unittest,
        program: python.to_string(),
        args: vec![
            "-m".to_string(),
            "unittest".to_string(),
            "discover".to_string(),
            "-s".to_string(),
            start.to_string(),
        ],
    }
}

fn package_json_has_test_script(dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join("package.json")) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    value
        .get("scripts")
        .and_then(|scripts| scripts.get("test"))
        .and_then(|test| test.as_str())
        .is_some_and(|script| !script.trim().is_empty())
}

pub fn run_test_runner(dir: &Path, runner: &TestRunner, timeout_ms: u64) -> TestExecution {
    let command = runner.command_line();
    let mut cmd = Command::new(&runner.program);
    cmd.args(&runner.args).current_dir(dir);
    if matches!(runner.kind, RunnerKind::Pytest | RunnerKind::Unittest) {
        cmd.env("PYTHONDONTWRITEBYTECODE", "1");
    }
    let started_at = Instant::now();
    let out = crate::proc_util::run_command_bounded(
        cmd,
        None,
        timeout_ms.max(1),
        crate::proc_util::DEFAULT_MAX_STREAM_BYTES,
    );
    let duration_ms = started_at.elapsed().as_millis() as u64;
    if !out.spawned {
        return TestExecution {
            command,
            exit_code: None,
            passed: None,
            failed: None,
            duration_ms,
            timed_out: false,
            started: false,
            note: Some(format!(
                "test runner did not start: {}",
                out.spawn_error
                    .unwrap_or_else(|| "spawn failed".to_string())
            )),
        };
    }
    let (passed, failed) = parse_test_counts(runner.kind, &out.stdout, &out.stderr);
    let note = if out.timed_out {
        Some(format!("timed out after {} ms", timeout_ms))
    } else if passed.is_none() && failed.is_none() {
        Some("test command finished; pass/fail counts were not in the output".to_string())
    } else {
        None
    };
    TestExecution {
        command,
        exit_code: out.exit_code,
        passed,
        failed,
        duration_ms: out.duration_ms,
        timed_out: out.timed_out,
        started: true,
        note,
    }
}

/// shortcut: npm and go counts stay empty unless the output has a node:test `# pass`/`# fail` line, a Jest `Tests:` line, or Go `--- PASS:`/`--- FAIL:` lines. Upgrade when those runners are asked for JSON.
pub fn parse_test_counts(
    kind: RunnerKind,
    stdout: &str,
    stderr: &str,
) -> (Option<u64>, Option<u64>) {
    let text = format!("{stdout}\n{stderr}");
    match kind {
        RunnerKind::Cargo => parse_cargo(&text),
        RunnerKind::Pytest => parse_pytest(&text),
        RunnerKind::Unittest => parse_unittest(&text),
        RunnerKind::Npm => parse_npm(&text),
        RunnerKind::Go => parse_go(&text),
    }
}

fn number_before(hay: &str, word: &str) -> Option<u64> {
    let mut found = None;
    let mut start = 0usize;
    while let Some(rel) = hay[start..].find(word) {
        let idx = start + rel;
        let after = hay[idx + word.len()..].chars().next();
        let word_ended = after.map(|c| !c.is_ascii_alphanumeric()).unwrap_or(true);
        if word_ended {
            let before = hay[..idx].trim_end();
            let digits_at = before
                .rfind(|c: char| !c.is_ascii_digit())
                .map(|i| i + 1)
                .unwrap_or(0);
            if digits_at < before.len() {
                let boundary_ok = digits_at == 0
                    || before[..digits_at]
                        .chars()
                        .next_back()
                        .map(|c| !c.is_ascii_alphanumeric())
                        .unwrap_or(true);
                if boundary_ok {
                    if let Ok(n) = before[digits_at..].parse::<u64>() {
                        found = Some(n);
                    }
                }
            }
        }
        start = idx + word.len();
    }
    found
}

fn parse_cargo(text: &str) -> (Option<u64>, Option<u64>) {
    let mut passed = 0u64;
    let mut failed = 0u64;
    let mut saw = false;
    for line in text.lines() {
        if !line.contains("test result:") {
            continue;
        }
        saw = true;
        passed += number_before(line, "passed").unwrap_or(0);
        failed += number_before(line, "failed").unwrap_or(0);
    }
    if saw {
        (Some(passed), Some(failed))
    } else {
        (None, None)
    }
}

fn parse_pytest(text: &str) -> (Option<u64>, Option<u64>) {
    let mut chosen: Option<&str> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if (trimmed.contains(" passed")
            || trimmed.contains(" failed")
            || trimmed.contains(" error"))
            && (trimmed.contains(" in ") || trimmed.contains('='))
        {
            chosen = Some(trimmed);
        }
    }
    let Some(line) = chosen else {
        return (None, None);
    };
    let passed = number_before(line, "passed");
    let failed = number_before(line, "failed").unwrap_or(0)
        + number_before(line, "error").unwrap_or(0)
        + number_before(line, "errors").unwrap_or(0);
    // "errors" contains "error" as a prefix only if we search the shorter word first.
    // number_before requires a non-alphanumeric boundary, so "errors" does not match "error".
    if passed.is_none() && !line.contains("failed") && !line.contains("error") {
        return (None, None);
    }
    let failed_some = if line.contains("failed") || line.contains("error") {
        Some(failed)
    } else {
        Some(0)
    };
    (passed.or(Some(0)), failed_some)
}

fn parse_unittest(text: &str) -> (Option<u64>, Option<u64>) {
    let mut ran = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("Ran ") else {
            continue;
        };
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            continue;
        }
        let after = rest[digits.len()..].trim_start();
        if after.starts_with("test") {
            ran = digits.parse::<u64>().ok();
        }
    }
    let Some(ran) = ran else {
        return (None, None);
    };
    // shortcut: a skipped unittest still counts as passed. Upgrade when the summary's skipped= count must be split out.
    let failed_line = text
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with("FAILED"));
    let Some(line) = failed_line else {
        return (Some(ran), Some(0));
    };
    let failures = key_number(line, "failures=").unwrap_or(0);
    let errors = key_number(line, "errors=").unwrap_or(0);
    let failed = failures + errors;
    (Some(ran.saturating_sub(failed)), Some(failed))
}

fn key_number(line: &str, key: &str) -> Option<u64> {
    let idx = line.find(key)?;
    let rest = line[idx + key.len()..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn parse_npm(text: &str) -> (Option<u64>, Option<u64>) {
    let mut passed = None;
    let mut failed = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("# pass ") {
            passed = leading_u64(rest);
        } else if let Some(rest) = trimmed.strip_prefix("# fail ") {
            failed = leading_u64(rest);
        } else if trimmed.contains("Tests:") {
            if let Some(n) = number_before(trimmed, "passed") {
                passed = Some(n);
            }
            if let Some(n) = number_before(trimmed, "failed") {
                failed = Some(n);
            }
        }
    }
    if passed.is_none() && failed.is_none() {
        (None, None)
    } else {
        (passed, failed)
    }
}

fn parse_go(text: &str) -> (Option<u64>, Option<u64>) {
    let mut passed = 0u64;
    let mut failed = 0u64;
    let mut saw = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("--- PASS:") {
            passed += 1;
            saw = true;
        } else if trimmed.starts_with("--- FAIL:") {
            failed += 1;
            saw = true;
        }
    }
    if saw {
        (Some(passed), Some(failed))
    } else {
        (None, None)
    }
}

fn leading_u64(text: &str) -> Option<u64> {
    let digits: String = text.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "carnot-testrun-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn detection_follows_manifest_order() {
        let cargo = temp_dir("cargo");
        fs::write(cargo.join("Cargo.toml"), "[package]\nname=\"t\"\n").unwrap();
        fs::create_dir_all(cargo.join("tests")).unwrap();
        let found = detect_test_runner(&cargo).unwrap();
        assert_eq!(found.kind, RunnerKind::Cargo);
        assert_eq!(found.command_line(), "cargo test");

        let py = temp_dir("py");
        fs::write(py.join("pyproject.toml"), "[project]\nname='t'\n").unwrap();
        let found = detect_test_runner(&py).unwrap();
        assert!(matches!(
            found.kind,
            RunnerKind::Pytest | RunnerKind::Unittest
        ));
        assert!(found.command_line().contains("python"));

        let setup_py = temp_dir("setup");
        fs::write(setup_py.join("setup.py"), "from setuptools import setup\n").unwrap();
        assert!(detect_test_runner(&setup_py).is_some());

        let npm = temp_dir("npm");
        fs::write(
            npm.join("package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        fs::create_dir_all(npm.join("tests")).unwrap();
        let found = detect_test_runner(&npm).unwrap();
        assert_eq!(found.kind, RunnerKind::Npm);
        assert_eq!(found.command_line(), "npm test");

        let no_script = temp_dir("npm-empty");
        fs::write(
            no_script.join("package.json"),
            r#"{"scripts":{"test":"  "}}"#,
        )
        .unwrap();
        assert!(detect_test_runner(&no_script).is_none());

        let go = temp_dir("go");
        fs::write(go.join("go.mod"), "module example.com/t\n\ngo 1.22\n").unwrap();
        let found = detect_test_runner(&go).unwrap();
        assert_eq!(found.kind, RunnerKind::Go);
        assert_eq!(found.command_line(), "go test ./...");

        let tests_dir = temp_dir("tests-dir");
        fs::create_dir_all(tests_dir.join("test")).unwrap();
        let found = detect_test_runner(&tests_dir).unwrap();
        assert!(matches!(
            found.kind,
            RunnerKind::Pytest | RunnerKind::Unittest
        ));
        let unittest = python_runner_with(&tests_dir, "python3", false);
        assert_eq!(unittest.kind, RunnerKind::Unittest);
        assert_eq!(
            unittest.command_line(),
            "python3 -m unittest discover -s test"
        );
        let tests_named = temp_dir("tests-named");
        fs::create_dir_all(tests_named.join("tests")).unwrap();
        assert_eq!(
            python_runner_with(&tests_named, "python3", false).command_line(),
            "python3 -m unittest discover -s tests"
        );

        let bare = temp_dir("bare");
        fs::write(bare.join("README.md"), "hi\n").unwrap();
        assert!(detect_test_runner(&bare).is_none());

        let _ = fs::remove_dir_all(cargo);
        let _ = fs::remove_dir_all(py);
        let _ = fs::remove_dir_all(setup_py);
        let _ = fs::remove_dir_all(npm);
        let _ = fs::remove_dir_all(no_script);
        let _ = fs::remove_dir_all(go);
        let _ = fs::remove_dir_all(tests_dir);
        let _ = fs::remove_dir_all(tests_named);
        let _ = fs::remove_dir_all(bare);
    }

    #[test]
    fn parsers_read_runner_summaries() {
        let (p, f) = parse_test_counts(
            RunnerKind::Cargo,
            "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n\
             test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out\n",
            "",
        );
        assert_eq!((p, f), (Some(4), Some(2)));

        let (p, f) = parse_test_counts(
            RunnerKind::Pytest,
            "===== 1 failed, 2 passed, 1 error in 0.04s =====\n",
            "",
        );
        assert_eq!((p, f), (Some(2), Some(2)));

        let (p, f) = parse_test_counts(
            RunnerKind::Unittest,
            "Ran 3 tests in 0.001s\n\nFAILED (failures=1, errors=1)\n",
            "",
        );
        assert_eq!((p, f), (Some(1), Some(2)));

        let (p, f) = parse_test_counts(RunnerKind::Unittest, "Ran 2 tests in 0.001s\n\nOK\n", "");
        assert_eq!((p, f), (Some(2), Some(0)));

        let (p, f) = parse_test_counts(RunnerKind::Npm, "# pass 4\n# fail 1\n", "");
        assert_eq!((p, f), (Some(4), Some(1)));

        let (p, f) = parse_test_counts(
            RunnerKind::Npm,
            "Tests:       1 failed, 2 passed, 3 total\n",
            "",
        );
        assert_eq!((p, f), (Some(2), Some(1)));

        let (p, f) = parse_test_counts(RunnerKind::Npm, "ok\n", "");
        assert_eq!((p, f), (None, None));

        let (p, f) = parse_test_counts(
            RunnerKind::Go,
            "--- PASS: TestA (0.00s)\n--- FAIL: TestB (0.00s)\nFAIL\n",
            "",
        );
        assert_eq!((p, f), (Some(1), Some(1)));

        let (p, f) = parse_test_counts(RunnerKind::Go, "ok  \texample.com/t\t0.001s\n", "");
        assert_eq!((p, f), (None, None));
    }
}
