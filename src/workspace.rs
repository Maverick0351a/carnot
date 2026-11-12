//! Persistent Disk Workspace, Append-Only JSONL Ledgers, and Real Polyglot Project Materializer.
//!
//! Replaces ephemeral demo state with durable project workspaces on disk:
//! - `carnot.manifest.json`: Canonical machine-readable `CarnotManifest`
//! - `Carnot.toml`: Human-readable organ & bridge recipe
//! - `.carnot/ledger.jsonl`: Append-only SHA-256 `ev_...` Evidence Receipt log
//! - `.carnot/regressions.jsonl`: Append-only live proxy regression capture log

use crate::evidence::{EvidenceKind, EvidenceLedger};
use crate::recipe::{CarnotManifest, GeneratedTargetPlan, OrganBridge, OrganSpec};
use crate::scout::{DependencyAppetite, PreferenceProfile, RuntimeShape, TargetLanguage};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct WorkspaceLayout {
    pub root: PathBuf,
    pub manifest_json: PathBuf,
    pub carnot_toml: PathBuf,
    pub state_dir: PathBuf,
    pub ledger_jsonl: PathBuf,
    pub regressions_jsonl: PathBuf,
    pub experience_cards_jsonl: PathBuf,
    pub dataset_jsonl: PathBuf,
    pub obligations_json: PathBuf,
    pub proposals_json: PathBuf,
}

impl WorkspaceLayout {
    pub fn at(root: &Path) -> Self {
        let state_dir = root.join(".carnot");
        Self {
            root: root.to_path_buf(),
            manifest_json: root.join("carnot.manifest.json"),
            carnot_toml: root.join("Carnot.toml"),
            ledger_jsonl: state_dir.join("ledger.jsonl"),
            regressions_jsonl: state_dir.join("regressions.jsonl"),
            experience_cards_jsonl: state_dir.join("experience_cards.jsonl"),
            dataset_jsonl: state_dir.join("dataset.jsonl"),
            obligations_json: state_dir.join("obligations.json"),
            proposals_json: state_dir.join("proposals.json"),
            state_dir,
        }
    }
}

/// Sanitize a workspace-relative path: reject empty, absolute, `..`, and any escape
/// outside `root` (same spirit as quarantine purge).
pub fn sanitize_workspace_rel_path(root: &Path, rel: &str) -> Result<String, String> {
    let trimmed = rel.trim();
    if trimmed.is_empty() {
        return Err("relative path must not be empty".to_string());
    }
    if trimmed.contains('\0') {
        return Err("relative path must not contain NUL".to_string());
    }
    // Reject absolute / drive-prefixed forms before any slash-stripping.
    if trimmed.starts_with('/') || trimmed.starts_with('\\') || Path::new(trimmed).is_absolute() {
        return Err(format!("absolute paths rejected: '{rel}'"));
    }
    let path = Path::new(trimmed);
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(s) => normalized.push(s),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("path traversal rejected ('..' in '{rel}')"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("absolute / prefixed paths rejected: '{rel}'"));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(format!("relative path resolves empty: '{rel}'"));
    }
    let joined = root.join(&normalized);
    // Logical containment: joined must start with root when both are cleaned of `.`.
    let root_clean = root.to_path_buf();
    if !joined.starts_with(&root_clean) {
        return Err(format!(
            "path escapes workspace root (got '{rel}' under {})",
            root.display()
        ));
    }
    // Prefer forward-slash relative form for stable JSON / cross-platform joins.
    let rel_out = normalized
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/");
    Ok(rel_out)
}

/// Appends a single JSON object line atomically to a `.jsonl` ledger file on disk.
pub fn append_jsonl(path: &Path, record: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let serialized = serde_json::to_string(record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writeln!(file, "{}", serialized)?;
    file.flush()
}

/// Writes an entire slice of serializable items as deterministic `.jsonl` on disk.
pub fn write_jsonl_slice<T: serde::Serialize>(path: &Path, items: &[T]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    for item in items {
        let serialized = serde_json::to_string(item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        writeln!(file, "{}", serialized)?;
    }
    file.flush()
}

/// Reads all non-empty JSON lines from a `.jsonl` file on disk.
pub fn read_jsonl(path: &Path) -> std::io::Result<Vec<Value>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let l = line?;
        let trimmed = l.trim();
        if trimmed.is_empty() {
            continue;
        }
        let val: Value = serde_json::from_str(trimmed)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        out.push(val);
    }
    Ok(out)
}

/// Reads typed items from a `.jsonl` file on disk, ignoring malformed legacy lines gracefully.
pub fn read_jsonl_typed<T: serde::de::DeserializeOwned>(path: &Path) -> std::io::Result<Vec<T>> {
    let vals = read_jsonl(path)?;
    let mut out = Vec::with_capacity(vals.len());
    for v in vals {
        if let Ok(parsed) = serde_json::from_value::<T>(v) {
            out.push(parsed);
        }
    }
    Ok(out)
}

/// Initializes a fresh Carnot workspace directory on disk with `carnot.manifest.json`, `Carnot.toml`,
/// and `.carnot/ledger.jsonl`.
pub fn init_workspace(
    dir: &Path,
    project_name: &str,
    target_language: TargetLanguage,
) -> Result<CarnotManifest, String> {
    let layout = WorkspaceLayout::at(dir);
    fs::create_dir_all(&layout.state_dir)
        .map_err(|e| format!("Failed to create workspace dir '{}': {}", dir.display(), e))?;

    let manifest = CarnotManifest {
        project_name: project_name.to_string(),
        black_box_enforced: true,
        preferences: PreferenceProfile {
            target_language,
            dependency_appetite: DependencyAppetite::StdlibFirst,
            runtime_shape: RuntimeShape::SingleBinaryCli,
            max_latency_p95_ms: 15,
            strict_permissive_only: true,
        },
        organs: vec![
            OrganSpec {
                id: "verifier".to_string(),
                capability: "Deterministic payload envelope & control-byte conformance verifier"
                    .to_string(),
                inputs: vec!["InboundPayload".to_string()],
                outputs: vec!["VerifiedPayload".to_string()],
                invariants: vec![
                    "Reject empty, whitespace-only, and embedded NUL/control bytes".to_string(),
                    "Honor per-organ feature flag before executing inner block".to_string(),
                ],
                conformance_suite: "tests/conformance".to_string(),
            },
            OrganSpec {
                id: "router".to_string(),
                capability: "MurmurHash3 canary route selector & fallback guard".to_string(),
                inputs: vec!["VerifiedPayload".to_string(), "RolloutContext".to_string()],
                outputs: vec!["RouteDecision".to_string()],
                invariants: vec!["Deterministic sticky bucket assignment".to_string()],
                conformance_suite: "tests/conformance".to_string(),
            },
        ],
        bridges: vec![OrganBridge {
            from_organ: "verifier".to_string(),
            to_organ: "router".to_string(),
            contract: "Only non-empty, control-free payloads advance to routing".to_string(),
        }],
        target_bindings: Vec::new(),
    };

    let manifest_str = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
    fs::write(&layout.manifest_json, manifest_str)
        .map_err(|e| format!("Failed to write {}: {}", layout.manifest_json.display(), e))?;
    fs::write(&layout.carnot_toml, manifest.render_carnot_toml())
        .map_err(|e| format!("Failed to write {}: {}", layout.carnot_toml.display(), e))?;

    let mut ledger = EvidenceLedger::new();
    let rec = ledger.record(
        EvidenceKind::Observed,
        "workspace_initialized",
        format!(
            "Initialized Carnot workspace '{}' ({:?})",
            project_name, target_language
        ),
        None,
        &json!({
            "project_name": project_name,
            "target_language": target_language,
            "organs": manifest.organs.len(),
        }),
    );
    let rec_val = serde_json::to_value(&rec).unwrap_or_else(|_| json!({}));
    append_jsonl(&layout.ledger_jsonl, &rec_val)
        .map_err(|e| format!("Failed to append initial ledger receipt: {}", e))?;

    Ok(manifest)
}

/// Loads `CarnotManifest` from `<dir>/carnot.manifest.json`.
pub fn load_manifest_from_workspace(dir: &Path) -> Result<CarnotManifest, String> {
    let layout = WorkspaceLayout::at(dir);
    let raw = fs::read_to_string(&layout.manifest_json)
        .map_err(|e| format!("Failed to read '{}': {}", layout.manifest_json.display(), e))?;
    serde_json::from_str::<CarnotManifest>(&raw).map_err(|e| {
        format!(
            "Invalid JSON in '{}': {}",
            layout.manifest_json.display(),
            e
        )
    })
}

/// Materializes all polyglot source files, `solve_bench` harness, test suite, `Carnot.toml`,
/// `carnot.manifest.json`, `.gitignore`, and optional initial `git` repository onto disk.
pub fn materialize_project_to_disk(
    manifest: &CarnotManifest,
    target_dir: &Path,
    lang_override: Option<TargetLanguage>,
    init_git_repo: bool,
) -> Result<GeneratedTargetPlan, String> {
    let plan = manifest.emit_polyglot_plan(lang_override);
    let layout = WorkspaceLayout::at(target_dir);
    fs::create_dir_all(&layout.state_dir)
        .map_err(|e| format!("Failed to create target directory: {}", e))?;

    for (rel_path, content) in &plan.planned_files {
        let dest = target_dir.join(rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create '{}': {}", parent.display(), e))?;
        }
        fs::write(&dest, content)
            .map_err(|e| format!("Failed to write '{}': {}", dest.display(), e))?;
    }

    fs::write(&layout.carnot_toml, &plan.manifest_toml)
        .map_err(|e| format!("Failed to write Carnot.toml: {}", e))?;
    let manifest_json_str = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
    fs::write(&layout.manifest_json, manifest_json_str)
        .map_err(|e| format!("Failed to write carnot.manifest.json: {}", e))?;

    let gitignore_path = target_dir.join(".gitignore");
    if !gitignore_path.exists() {
        let _ = fs::write(
            &gitignore_path,
            "/target\n/node_modules\n/__pycache__\n/.carnot/worktrees\n",
        );
    }

    let mut ledger = EvidenceLedger::new();
    let rec = ledger.record(
        EvidenceKind::Derived,
        "project_materialized_to_disk",
        format!(
            "Materialized {:?} project '{}' ({} files) to '{}'",
            plan.target_language,
            plan.project_name,
            plan.planned_files.len(),
            target_dir.display()
        ),
        None,
        &json!({
            "project_name": plan.project_name,
            "target_language": plan.target_language,
            "files_written": plan.planned_files.iter().map(|(p, _)| p).collect::<Vec<_>>(),
            "test_command": plan.test_command,
            "bench_command": plan.bench_command,
        }),
    );
    let rec_val = serde_json::to_value(&rec).unwrap_or_else(|_| json!({}));
    append_jsonl(&layout.ledger_jsonl, &rec_val)
        .map_err(|e| format!("Failed to append ledger receipt: {}", e))?;

    if init_git_repo && !target_dir.join(".git").exists() {
        run_git(target_dir, &["init"])?;
        run_git(target_dir, &["config", "core.autocrlf", "false"])?;
        run_git(target_dir, &["config", "user.name", "Carnot Refinery"])?;
        run_git(
            target_dir,
            &["config", "user.email", "refinery@carnot.local"],
        )?;
        run_git(target_dir, &["add", "-A"])?;
        run_git(
            target_dir,
            &["commit", "-m", "chore: initial Carnot polyglot scaffold"],
        )?;
    }

    Ok(plan)
}

fn run_git(dir: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("Failed to run `git {}`: {}", args.join(" "), e))?;
    if !out.status.success() {
        return Err(format!(
            "`git {}` exited with {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
