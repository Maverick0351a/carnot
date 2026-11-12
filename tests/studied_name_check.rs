//! Black-box tests for `scripts/check_studied_names.py`.
//!
//! The denylist is supplied by the test (env or a gitignored local file). These
//! cases use synthetic tokens so the checker can be proven without embedding
//! studied-project names in the repository.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/check_studied_names.py")
}

fn python() -> Command {
    if let Ok(bin) = std::env::var("CARNOT_PYTHON") {
        if !bin.trim().is_empty() {
            return Command::new(bin);
        }
    }
    for bin in ["python3", "python"] {
        if Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Command::new(bin);
        }
    }
    panic!("python interpreter not found (set CARNOT_PYTHON)");
}

fn temp_repo(tag: &str) -> (PathBuf, TempDirGuard) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "carnot-namecheck-{}-{}-{}",
        tag,
        std::process::id(),
        nanos
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let guard = TempDirGuard(root.clone());
    let out = Command::new("git")
        .args(["init"])
        .current_dir(&root)
        .output()
        .expect("git init");
    assert!(out.status.success(), "git init failed: {}", stderr(&out));
    (root, guard)
}

fn git_add(root: &Path, rel: &str) {
    let out = Command::new("git")
        .args(["add", "--", rel])
        .current_dir(root)
        .output()
        .expect("git add");
    assert!(
        out.status.success(),
        "git add {rel} failed: {}",
        stderr(&out)
    );
}

fn write_tracked(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, body).unwrap();
    git_add(root, rel);
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

struct CheckOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_check(
    root: &Path,
    denylist_env: Option<&str>,
    denylist_file_env: Option<&str>,
) -> CheckOutput {
    let mut cmd = python();
    cmd.arg(script_path())
        .arg("--root")
        .arg(root)
        .env_remove("CARNOT_STUDIED_NAME_DENYLIST")
        .env_remove("CARNOT_STUDIED_NAME_DENYLIST_FILE");
    if let Some(value) = denylist_env {
        cmd.env("CARNOT_STUDIED_NAME_DENYLIST", value);
    }
    if let Some(value) = denylist_file_env {
        cmd.env("CARNOT_STUDIED_NAME_DENYLIST_FILE", value);
    }
    let out = cmd.output().expect("spawn studied-name check");
    CheckOutput {
        status: out.status.code().unwrap_or(1),
        stdout: stdout(&out),
        stderr: stderr(&out),
    }
}

#[test]
fn skips_when_denylist_is_absent() {
    let (root, _guard) = temp_repo("skip");
    write_tracked(&root, "notes.txt", "hello\n");
    let out = run_check(&root, None, None);
    assert_eq!(out.status, 0, "stdout={} stderr={}", out.stdout, out.stderr);
    let combined = format!("{}{}", out.stdout, out.stderr).to_ascii_lowercase();
    assert!(
        combined.contains("skipped") && combined.contains("denylist"),
        "expected a graceful skip, got stdout={} stderr={}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn fails_when_tracked_content_contains_a_denied_token() {
    let token = "zzqxstudiedtoken";
    let (root, _guard) = temp_repo("hit");
    write_tracked(
        &root,
        "src/lib.rs",
        &format!("// uses {token} for the demo\nfn main() {{}}\n"),
    );
    let out = run_check(&root, Some(token), None);
    assert_eq!(out.status, 1, "stdout={} stderr={}", out.stdout, out.stderr);
    assert!(
        out.stdout.contains("src/lib.rs"),
        "hit must name the tracked path: {}",
        out.stdout
    );
    assert!(
        !out.stdout.contains(token) && !out.stderr.contains(token),
        "check must not echo the denylist token\nstdout={}\nstderr={}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn passes_when_tracked_files_are_clean() {
    let (root, _guard) = temp_repo("clean");
    write_tracked(&root, "README.md", "neutral capability description\n");
    let out = run_check(&root, Some("zzqxstudiedtoken"), None);
    assert_eq!(out.status, 0, "stdout={} stderr={}", out.stdout, out.stderr);
    assert!(
        out.stdout.to_ascii_lowercase().contains("passed"),
        "expected a pass line, got {}",
        out.stdout
    );
}

#[test]
fn ignores_untracked_and_gitignored_files() {
    let token = "zzqxstudiedtoken";
    let (root, _guard) = temp_repo("untracked");
    write_tracked(&root, "kept.txt", "clean\n");
    fs::write(root.join("scratch.txt"), format!("{token}\n")).unwrap();
    fs::write(root.join(".gitignore"), ".carnot/\n").unwrap();
    git_add(&root, ".gitignore");
    fs::create_dir_all(root.join(".carnot")).unwrap();
    fs::write(
        root.join(".carnot/local-lineage.jsonl"),
        format!("{{\"from\":\"{token}\"}}\n"),
    )
    .unwrap();
    let out = run_check(&root, Some(token), None);
    assert_eq!(out.status, 0, "stdout={} stderr={}", out.stdout, out.stderr);
}

#[test]
fn matches_names_inside_identifiers_and_paths() {
    let token = "zzqxstudied";
    let (root, _guard) = temp_repo("ident");
    write_tracked(&root, "src/keep.rs", "fn read_already() {}\n");
    write_tracked(&root, &format!("src/{token}_notes.rs"), "fn ready() {}\n");
    let out = run_check(&root, Some(token), None);
    assert_eq!(out.status, 1, "filename hit: stdout={}", out.stdout);
    assert!(!out.stdout.contains(token) && !out.stderr.contains(token));

    let (root2, _guard2) = temp_repo("camel");
    write_tracked(&root2, "src/lib.rs", &format!("struct {token}Index;\n"));
    let camel = run_check(&root2, Some(token), None);
    assert_eq!(camel.status, 1, "camelCase hit: stdout={}", camel.stdout);
    assert!(!camel.stdout.contains(token));
}

#[test]
fn short_token_does_not_match_an_acronym_prefix() {
    let short = format!("{}{}", "r", "ea");
    let (root, _guard) = temp_repo("acronym");
    write_tracked(&root, "README.md", "See README and STREAM_BYTES.\n");
    let out = run_check(&root, Some(&short), None);
    assert_eq!(
        out.status, 0,
        "an all-caps prefix must not count as a studied name\nstdout={}\nstderr={}",
        out.stdout, out.stderr
    );
}

#[test]
fn short_token_does_not_match_incidental_substrings() {
    let short = format!("{}{}", "r", "ea");
    let (root, _guard) = temp_repo("short");
    write_tracked(
        &root,
        "src/lib.rs",
        "fn read_already() { let reason = \"create thread area\"; let _ = reason; }\n",
    );
    let clean = run_check(&root, Some(&short), None);
    assert_eq!(
        clean.status, 0,
        "incidental substrings must not fail the check\nstdout={}\nstderr={}",
        clean.stdout, clean.stderr
    );

    write_tracked(&root, "src/tool.rs", &format!("struct {short}Firewall;\n"));
    let hit = run_check(&root, Some(&short), None);
    assert_eq!(hit.status, 1, "identifier prefix must fail: {}", hit.stdout);
    assert!(!hit.stdout.contains(&short) && !hit.stderr.contains(&short));
}

#[test]
fn reads_denylist_from_gitignored_local_file() {
    let token = "zzqxfiletoken";
    let (root, _guard) = temp_repo("file");
    write_tracked(&root, ".gitignore", ".carnot/\n");
    write_tracked(&root, "src/lib.rs", &format!("// {token}\n"));
    fs::create_dir_all(root.join(".carnot")).unwrap();
    let list = root.join(".carnot/studied-name-denylist.txt");
    fs::write(&list, format!("# local only\n{token}\n")).unwrap();
    let out = run_check(&root, None, None);
    assert_eq!(out.status, 1, "stdout={} stderr={}", out.stdout, out.stderr);
    assert!(!out.stdout.contains(token) && !out.stderr.contains(token));
}

#[test]
fn empty_env_falls_through_to_local_file_then_skips_when_both_empty() {
    let token = "zzqxfiletoken";
    let (root, _guard) = temp_repo("emptyenv");
    write_tracked(&root, "notes.txt", "plain\n");
    let skipped = run_check(&root, Some("  \n"), None);
    assert_eq!(skipped.status, 0, "stdout={}", skipped.stdout);
    assert!(skipped.stdout.to_ascii_lowercase().contains("skipped"));

    write_tracked(&root, "src/lib.rs", &format!("// {token}\n"));
    fs::create_dir_all(root.join(".carnot")).unwrap();
    fs::write(
        root.join(".carnot/studied-name-denylist.txt"),
        format!("{token}\n"),
    )
    .unwrap();
    let fell_through = run_check(&root, Some("  \n"), None);
    assert_eq!(
        fell_through.status, 1,
        "whitespace env must fall through to the local file\nstdout={}",
        fell_through.stdout
    );
    assert!(!fell_through.stdout.contains(token) && !fell_through.stderr.contains(token));
}

#[test]
fn comment_only_env_is_an_error_not_a_skip() {
    let (root, _guard) = temp_repo("commentenv");
    write_tracked(&root, "notes.txt", "plain\n");
    let out = run_check(&root, Some("# comment only\n"), None);
    assert_eq!(out.status, 2, "stdout={} stderr={}", out.stdout, out.stderr);
    let combined = format!("{}{}", out.stdout, out.stderr).to_ascii_lowercase();
    assert!(
        !combined.contains("skipped"),
        "a configured but empty denylist must not skip: {combined}"
    );
}

#[test]
fn missing_explicit_denylist_file_is_an_error() {
    let (root, _guard) = temp_repo("missingfile");
    write_tracked(&root, "notes.txt", "plain\n");
    let missing = root.join("no-such-denylist.txt");
    let out = run_check(&root, None, Some(missing.to_str().unwrap()));
    assert_eq!(out.status, 2, "stdout={} stderr={}", out.stdout, out.stderr);
    let combined = format!("{}{}", out.stdout, out.stderr).to_ascii_lowercase();
    assert!(!combined.contains("skipped"));
    assert!(!combined.contains("no-such-denylist"));
}

#[test]
fn matches_token_after_a_camel_case_hump_without_echoing_it() {
    let token = "zzqx";
    let (root, _guard) = temp_repo("hump");
    let camel = format!("use{}{}", "Z", "zqx");
    assert!(
        !camel.to_ascii_lowercase().contains(token)
            || camel.to_ascii_lowercase() == format!("use{token}"),
        "fixture must embed the token after a lowercase letter"
    );
    write_tracked(
        &root,
        &format!("src/{camel}.rs"),
        &format!("fn {camel}() {{}}\n"),
    );
    let out = run_check(&root, Some(token), None);
    assert_eq!(out.status, 1, "stdout={} stderr={}", out.stdout, out.stderr);
    let combined = format!("{}{}", out.stdout, out.stderr);
    assert!(
        !combined.to_ascii_lowercase().contains(token),
        "path and content reports must not echo the token\n{combined}"
    );
}

#[test]
fn workspace_gitignore_ignores_carnot_state_dir() {
    let ignore = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".gitignore"))
        .expect("read .gitignore");
    let covered = ignore.lines().any(|line| {
        let line = line.trim();
        line == ".carnot/" || line == ".carnot" || line == "/.carnot/"
    });
    assert!(
        covered,
        ".gitignore must ignore .carnot/ so local lineage and the denylist stay untracked"
    );
}

#[test]
fn repository_self_check_skips_or_passes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = run_check(&root, None, None);
    assert_eq!(
        out.status, 0,
        "self-check must skip or pass\nstdout={}\nstderr={}",
        out.stdout, out.stderr
    );
}
