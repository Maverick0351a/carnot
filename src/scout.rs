//! Stage 1 (`carnot scout`): Preference-Matched Source Scouting & Signal-to-Bloat Scorer.
//!
//! Evaluates candidate repositories or local directories against a user's `PreferenceProfile`
//! (preferred output language — Rust, Go, TypeScript, Python, Scala 3, Zig, or Polyglot Shootout —
//! dependency appetite, runtime shape, and license rules), scoring algorithmic signal vs. framework bloat
//! and conformance fixture density.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetLanguage {
    Rust,
    Go,
    TypeScript,
    Python,
    Scala3,
    Zig,
    AutoShootout,
}

impl TargetLanguage {
    pub const SUPPORTED: &'static str = "rust, go, typescript, python, scala3, zig, auto";

    /// Accepts the same aliases as `from_str_loose`, and rejects unknown names.
    pub fn parse_known(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rust" | "rs" => Ok(Self::Rust),
            "go" | "golang" => Ok(Self::Go),
            "ts" | "typescript" | "bun" | "node" => Ok(Self::TypeScript),
            "py" | "python" => Ok(Self::Python),
            "scala" | "scala3" => Ok(Self::Scala3),
            "zig" => Ok(Self::Zig),
            "auto" | "shootout" | "auto_shootout" => Ok(Self::AutoShootout),
            other => Err(format!(
                "unknown language '{other}'; supported: {}",
                Self::SUPPORTED
            )),
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "go" | "golang" => Self::Go,
            "ts" | "typescript" | "bun" | "node" => Self::TypeScript,
            "py" | "python" => Self::Python,
            "scala" | "scala3" => Self::Scala3,
            "zig" => Self::Zig,
            "auto" | "shootout" | "auto_shootout" => Self::AutoShootout,
            _ => Self::Rust,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Rust => "Rust (Single Static Binary)",
            Self::Go => "Go (Cloud / Microservice Binary)",
            Self::TypeScript => "TypeScript (Bun / Node Runtime)",
            Self::Python => "Python 3.12+ (uv / Typed Package)",
            Self::Scala3 => "Scala 3 (Strict Policy / Streaming DSL)",
            Self::Zig => "Zig (Zero-Libc Systems Binary)",
            Self::AutoShootout => "Auto Pareto Shootout (Benchmark Top 2 Languages)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyAppetite {
    ZeroThirdParty,
    StdlibFirst,
    IdiomaticEcosystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeShape {
    SingleBinaryCli,
    EmbeddableLibrary,
    HttpSidecarProxy,
    WasmModule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreferenceProfile {
    pub target_language: TargetLanguage,
    pub dependency_appetite: DependencyAppetite,
    pub runtime_shape: RuntimeShape,
    pub max_latency_p95_ms: u64,
    pub strict_permissive_only: bool,
}

impl Default for PreferenceProfile {
    fn default() -> Self {
        Self {
            target_language: TargetLanguage::Rust,
            dependency_appetite: DependencyAppetite::StdlibFirst,
            runtime_shape: RuntimeShape::HttpSidecarProxy,
            max_latency_p95_ms: 15,
            strict_permissive_only: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateSourceMetrics {
    pub alias: String,
    pub capability_domain: String,
    pub primary_source_lang: String,
    pub code_files: usize,
    pub test_and_fixture_files: usize,
    pub json_conformance_vectors: usize,
    pub transitive_deps_estimate: usize,
    pub detected_license: String,
    pub has_mixed_license_subdirs: bool,
}

/// CLI/library scout result. `demo` is true only for the seeded candidate set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoutCommandReport {
    pub demo: bool,
    pub ranked: Vec<RankedScoutCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedScoutCandidate {
    pub alias: String,
    pub capability_domain: String,
    pub detected_license: String,
    pub extraction_mode: String,
    pub signal_to_bloat_score: f64,
    pub fixture_richness_score: f64,
    pub preference_fit_score: f64,
    pub total_carnot_efficiency: f64,
    pub recommended_output_targets: Vec<String>,
    pub rationale: String,
}

pub fn rank_candidates(
    candidates: &[CandidateSourceMetrics],
    prefs: &PreferenceProfile,
) -> Vec<RankedScoutCandidate> {
    let mut ranked = Vec::with_capacity(candidates.len());

    let recommended_targets = match prefs.target_language {
        TargetLanguage::AutoShootout => {
            if prefs.max_latency_p95_ms <= 5 || prefs.runtime_shape == RuntimeShape::WasmModule {
                vec!["rust".to_string(), "zig".to_string()]
            } else {
                vec!["rust".to_string(), "go".to_string()]
            }
        }
        other => vec![format!("{:?}", other).to_ascii_lowercase()],
    };

    for c in candidates {
        let lic_upper = c.detected_license.to_ascii_uppercase();
        let is_permissive = lic_upper.contains("MIT")
            || lic_upper.contains("APACHE")
            || lic_upper.contains("BSD")
            || lic_upper.contains("ISC");

        let extraction_mode = if is_permissive && !c.has_mixed_license_subdirs {
            "direct_algorithm_and_fixtures"
        } else if is_permissive && c.has_mixed_license_subdirs {
            "split_permissive_core_quarantine_ui"
        } else {
            "clean_room_wire_and_fixtures_only"
        };

        // Higher ratio of test/fixture files to raw code + fewer transitive deps => higher Carnot signal
        let code_denom = c.code_files.max(1) as f64;
        let test_ratio = (c.test_and_fixture_files as f64 / code_denom).clamp(0.0, 1.5);
        let dep_penalty = (c.transitive_deps_estimate as f64 / 250.0).clamp(0.0, 0.55);
        let signal_to_bloat =
            ((0.65 + 0.35 * (test_ratio / 1.5) - dep_penalty).clamp(0.10, 1.0)) * 100.0;

        let fixture_richness = ((c.json_conformance_vectors as f64 / 50.0).clamp(0.0, 1.0) * 70.0)
            + ((c.test_and_fixture_files.min(30) as f64 / 30.0) * 30.0);

        let pref_fit = if is_permissive {
            96.0
        } else if prefs.strict_permissive_only && c.json_conformance_vectors > 0 {
            // Quarantine source, harvest Apache/MIT spec vectors cleanly
            84.0
        } else {
            52.0
        };

        let total = 0.40 * signal_to_bloat + 0.35 * fixture_richness + 0.25 * pref_fit;

        ranked.push(RankedScoutCandidate {
            alias: c.alias.clone(),
            capability_domain: c.capability_domain.clone(),
            detected_license: c.detected_license.clone(),
            extraction_mode: extraction_mode.to_string(),
            signal_to_bloat_score: (signal_to_bloat * 10.0).round() / 10.0,
            fixture_richness_score: (fixture_richness * 10.0).round() / 10.0,
            preference_fit_score: (pref_fit * 10.0).round() / 10.0,
            total_carnot_efficiency: (total * 10.0).round() / 10.0,
            recommended_output_targets: recommended_targets.clone(),
            rationale: format!(
                "{} code files, {} test/fixture files, {} portable JSON vectors -> mode '{}'.",
                c.code_files, c.test_and_fixture_files, c.json_conformance_vectors, extraction_mode
            ),
        });
    }

    ranked.sort_by(|a, b| {
        b.total_carnot_efficiency
            .partial_cmp(&a.total_carnot_efficiency)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked
}

/// Parses lockfiles (`Cargo.lock`, `package-lock.json`, `go.sum`, `uv.lock`, `poetry.lock`, `requirements.txt`)
/// or manifest dependency sections to compute true transitive/direct dependency counts without executing code.
pub fn estimate_lockfile_dependencies(root: &Path) -> usize {
    let mut total = 0usize;

    let cargo_lock = root.join("Cargo.lock");
    if let Ok(txt) = std::fs::read_to_string(&cargo_lock) {
        let pkgs = txt.lines().filter(|l| l.trim() == "[[package]]").count();
        total += pkgs.saturating_sub(1);
    } else if let Ok(txt) = std::fs::read_to_string(root.join("Cargo.toml")) {
        let mut in_deps = false;
        for line in txt.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_deps = t == "[dependencies]" || t.starts_with("[dependencies.");
                continue;
            }
            if in_deps && !t.is_empty() && !t.starts_with('#') && t.contains('=') {
                total += 1;
            }
        }
    }

    let pkg_lock = root.join("package-lock.json");
    if let Ok(txt) = std::fs::read_to_string(&pkg_lock) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(pkgs) = val.get("packages").and_then(|p| p.as_object()) {
                total += pkgs.len().saturating_sub(1);
            } else if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
                total += deps.len();
            }
        }
    } else if let Ok(txt) = std::fs::read_to_string(root.join("package.json")) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
                total += deps.len();
            }
        }
    }

    let go_sum = root.join("go.sum");
    if let Ok(txt) = std::fs::read_to_string(&go_sum) {
        let mut mods = std::collections::BTreeSet::new();
        for line in txt.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(m), Some(v)) = (parts.next(), parts.next()) {
                let clean_v = v.trim_end_matches("/go.mod");
                mods.insert(format!("{}@{}", m, clean_v));
            }
        }
        total += mods.len();
    }

    for py_lock in ["uv.lock", "poetry.lock"] {
        let p = root.join(py_lock);
        if let Ok(txt) = std::fs::read_to_string(&p) {
            let pkgs = txt.lines().filter(|l| l.trim() == "[[package]]").count();
            total += pkgs.saturating_sub(1);
            break;
        }
    }

    let req_txt = root.join("requirements.txt");
    if total == 0 {
        if let Ok(txt) = std::fs::read_to_string(&req_txt) {
            total += txt
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
                .count();
        }
    }

    total
}

/// Counts portable conformance assertions inside a JSON specification/fixture file.
pub fn count_json_conformance_vectors(path: &Path) -> usize {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return 0;
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return 0;
    };
    match val {
        serde_json::Value::Array(arr) => arr.len(),
        serde_json::Value::Object(map) => {
            let mut sum = 0usize;
            for key in [
                "tests",
                "variantTests",
                "cases",
                "vectors",
                "scenarios",
                "examples",
            ] {
                if let Some(arr) = map.get(key).and_then(|v| v.as_array()) {
                    sum += arr.len();
                }
            }
            if sum > 0 {
                sum
            } else if let Some(events) = map
                .get("state")
                .and_then(|s| s.get("events"))
                .and_then(|e| e.as_array())
            {
                events.len()
            } else {
                1
            }
        }
        _ => 0,
    }
}

/// Walks a local directory on disk to compute real `CandidateSourceMetrics` without reading quarantined code into prompts.
pub fn inspect_local_directory_metrics(
    root: &Path,
    alias: &str,
    domain: &str,
) -> std::io::Result<CandidateSourceMetrics> {
    let mut code_files = 0usize;
    let mut test_files = 0usize;
    let mut json_vectors = 0usize;
    let mut licenses_seen: Vec<String> = Vec::new();
    let mut primary_ext_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    fn walk(
        dir: &Path,
        depth: usize,
        code_files: &mut usize,
        test_files: &mut usize,
        json_vectors: &mut usize,
        licenses: &mut Vec<String>,
        ext_counts: &mut std::collections::HashMap<String, usize>,
    ) {
        if depth > 6 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname == ".git"
                || fname == "target"
                || fname == "node_modules"
                || fname == "venv"
                || fname == ".venv"
            {
                continue;
            }
            if p.is_dir() {
                walk(
                    &p,
                    depth + 1,
                    code_files,
                    test_files,
                    json_vectors,
                    licenses,
                    ext_counts,
                );
                continue;
            }
            let lower = fname.to_ascii_lowercase();
            if lower.starts_with("license") || lower.starts_with("copying") {
                if let Ok(txt) = std::fs::read_to_string(&p) {
                    let kind = crate::intake::classify_license_text(&txt);
                    if !licenses.contains(&kind) {
                        licenses.push(kind);
                    }
                }
                continue;
            }
            let path_lower = p.to_string_lossy().to_ascii_lowercase();
            let ext = p
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if matches!(
                ext.as_str(),
                "rs" | "go" | "ts" | "tsx" | "js" | "py" | "scala" | "zig" | "c" | "cpp"
            ) {
                if path_lower.contains("test") || path_lower.contains("spec") {
                    *test_files += 1;
                } else {
                    *code_files += 1;
                }
                *ext_counts.entry(ext).or_insert(0) += 1;
            } else if ext == "json"
                && (path_lower.contains("spec")
                    || path_lower.contains("test")
                    || path_lower.contains("fixture"))
                && lower != "index.json"
            {
                *test_files += 1;
                *json_vectors += count_json_conformance_vectors(&p);
            }
        }
    }

    walk(
        root,
        0,
        &mut code_files,
        &mut test_files,
        &mut json_vectors,
        &mut licenses_seen,
        &mut primary_ext_counts,
    );

    let primary_lang = primary_ext_counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(ext, _)| ext)
        .unwrap_or_else(|| "unknown".to_string());

    let has_mixed = licenses_seen.len() > 1;
    let detected_license = if licenses_seen.is_empty() {
        let fallback = crate::intake::detect_manifest_spdx(root);
        if fallback != "UNKNOWN" {
            fallback
        } else {
            "UNKNOWN".to_string()
        }
    } else {
        licenses_seen.join(" + ")
    };

    let transitive_deps_estimate = estimate_lockfile_dependencies(root);

    Ok(CandidateSourceMetrics {
        alias: alias.to_string(),
        capability_domain: domain.to_string(),
        primary_source_lang: primary_lang,
        code_files,
        test_and_fixture_files: test_files,
        json_conformance_vectors: json_vectors,
        transitive_deps_estimate,
        detected_license,
        has_mixed_license_subdirs: has_mixed,
    })
}

/// Relative paths of source files under `root`, capped, for workspace scoring.
pub fn list_code_rel_paths(root: &Path, limit: usize) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, limit: usize, out: &mut Vec<String>, depth: usize) {
        if out.len() >= limit || depth > 8 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if out.len() >= limit {
                return;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, limit, out, depth + 1);
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !matches!(
                ext.as_str(),
                "rs" | "go" | "py" | "ts" | "tsx" | "js" | "scala" | "zig" | "c" | "cpp"
            ) {
                continue;
            }
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            let text = rel
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect::<Vec<_>>()
                .join("/");
            if !text.is_empty() {
                out.push(text);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, limit, &mut out, 0);
    out
}
