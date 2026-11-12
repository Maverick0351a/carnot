//! Polyglot Design-to-Language Fitness Matrix & Empirical Top-2 Language Shootout (`carnot advise`).
//!
//! Evaluates a `CarnotManifest` and `PreferenceProfile` across all 6 supported target languages
//! (`Rust`, `Go`, `TypeScript`, `Python`, `Scala3`, `Zig`), probing local host toolchains (`PATH`)
//! and optionally benchmarking the Top-2 runnable targets side-by-side in isolated directories.

use crate::evidence::{
    CoverageStatus, EvidenceAuthority, EvidenceConfidence, EvidenceKind, EvidenceLedger,
    EvidenceProvenance,
};
use crate::proc_util::{run_command_bounded, DEFAULT_MAX_STREAM_BYTES};
use crate::recipe::CarnotManifest;
use crate::scout::{DependencyAppetite, PreferenceProfile, RuntimeShape, TargetLanguage};
use crate::workspace::materialize_project_to_disk;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageFitnessScore {
    pub language: TargetLanguage,
    pub label: String,
    pub latency_fit: f64,
    pub dependency_fit: f64,
    pub runtime_shape_fit: f64,
    pub safety_and_invariants_fit: f64,
    pub toolchain_detected_on_host: bool,
    pub detected_toolchain_binary: Option<String>,
    pub composite_fitness: f64,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageAdvisoryReport {
    pub project_name: String,
    pub ranked_languages: Vec<LanguageFitnessScore>,
    pub recommended_primary: TargetLanguage,
    pub recommended_shootout_pair: (TargetLanguage, TargetLanguage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShootoutContenderResult {
    pub language: TargetLanguage,
    pub toolchain_available: bool,
    pub tests_passed: bool,
    pub bench_succeeded: bool,
    pub achieved_objective: f64,
    pub total_wall_ms: u64,
    pub files_emitted: usize,
    pub diagnostic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolyglotShootoutReport {
    pub project_name: String,
    pub contenders: Vec<ShootoutContenderResult>,
    pub winner: TargetLanguage,
    pub receipt_id: String,
}

fn find_in_path(bin_name: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let p = dir.join(format!("{}{}", bin_name, ext));
            if p.is_file() {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    None
}

pub fn detect_language_toolchain(lang: TargetLanguage) -> (bool, Option<String>) {
    let probes: &[&str] = match lang {
        TargetLanguage::Rust => &["cargo", "rustc"],
        TargetLanguage::Go => &["go"],
        TargetLanguage::TypeScript => &["node", "bun"],
        TargetLanguage::Python => &["python3", "python"],
        TargetLanguage::Scala3 => &["sbt", "scala"],
        TargetLanguage::Zig => &["zig"],
        TargetLanguage::AutoShootout => &["cargo"],
    };
    for bin in probes {
        if let Some(p) = find_in_path(bin) {
            return (true, Some(p));
        }
    }
    (false, None)
}

/// Computes the analytical Design-to-Language Fitness Matrix across all 6 concrete target languages.
pub fn advise_target_languages(
    manifest: &CarnotManifest,
    prefs: &PreferenceProfile,
) -> LanguageAdvisoryReport {
    let candidates = [
        TargetLanguage::Rust,
        TargetLanguage::Go,
        TargetLanguage::TypeScript,
        TargetLanguage::Python,
        TargetLanguage::Scala3,
        TargetLanguage::Zig,
    ];

    let invariant_density: usize = manifest.organs.iter().map(|o| o.invariants.len()).sum();
    let mut ranked = Vec::with_capacity(candidates.len());

    for lang in candidates {
        let (toolchain_ok, toolchain_bin) = detect_language_toolchain(lang);

        let latency_fit = match lang {
            TargetLanguage::Rust => {
                if prefs.max_latency_p95_ms <= 20 {
                    99.0
                } else {
                    94.0
                }
            }
            TargetLanguage::Zig => {
                if prefs.max_latency_p95_ms <= 10 {
                    98.0
                } else {
                    90.0
                }
            }
            TargetLanguage::Go => {
                if prefs.max_latency_p95_ms <= 5 {
                    78.0
                } else {
                    93.0
                }
            }
            TargetLanguage::Scala3 => {
                if prefs.max_latency_p95_ms <= 15 {
                    68.0
                } else {
                    85.0
                }
            }
            TargetLanguage::TypeScript => {
                if prefs.max_latency_p95_ms <= 10 {
                    65.0
                } else {
                    84.0
                }
            }
            TargetLanguage::Python => {
                if prefs.max_latency_p95_ms <= 15 {
                    58.0
                } else {
                    82.0
                }
            }
            TargetLanguage::AutoShootout => 0.0,
        };

        let dependency_fit = match (lang, prefs.dependency_appetite) {
            (TargetLanguage::Rust, DependencyAppetite::ZeroThirdParty) => 96.0,
            (TargetLanguage::Rust, DependencyAppetite::StdlibFirst) => 98.0,
            (TargetLanguage::Go, DependencyAppetite::ZeroThirdParty) => 97.0,
            (TargetLanguage::Go, DependencyAppetite::StdlibFirst) => 96.0,
            (TargetLanguage::Zig, DependencyAppetite::ZeroThirdParty) => 99.0,
            (TargetLanguage::Python, DependencyAppetite::StdlibFirst) => 90.0,
            (TargetLanguage::TypeScript, DependencyAppetite::ZeroThirdParty) => 82.0,
            (_, DependencyAppetite::IdiomaticEcosystem) => 92.0,
            _ => 80.0,
        };

        let runtime_shape_fit = match (lang, prefs.runtime_shape) {
            (TargetLanguage::Rust, RuntimeShape::SingleBinaryCli) => 99.0,
            (TargetLanguage::Rust, RuntimeShape::HttpSidecarProxy) => 97.0,
            (TargetLanguage::Rust, RuntimeShape::WasmModule) => 99.0,
            (TargetLanguage::Rust, RuntimeShape::EmbeddableLibrary) => 96.0,
            (TargetLanguage::Zig, RuntimeShape::WasmModule) => 97.0,
            (TargetLanguage::Zig, RuntimeShape::SingleBinaryCli) => 95.0,
            (TargetLanguage::Go, RuntimeShape::HttpSidecarProxy) => 98.0,
            (TargetLanguage::Go, RuntimeShape::SingleBinaryCli) => 95.0,
            (TargetLanguage::TypeScript, RuntimeShape::HttpSidecarProxy) => 86.0,
            (TargetLanguage::Python, RuntimeShape::EmbeddableLibrary) => 88.0,
            (TargetLanguage::Scala3, RuntimeShape::HttpSidecarProxy) => 87.0,
            _ => 75.0,
        };

        let safety_and_invariants_fit = match lang {
            TargetLanguage::Rust => 98.0 + (invariant_density.min(4) as f64 * 0.5),
            TargetLanguage::Scala3 => 94.0,
            TargetLanguage::Go => 89.0,
            TargetLanguage::Zig => 87.0,
            TargetLanguage::TypeScript => 83.0,
            TargetLanguage::Python => 81.0,
            TargetLanguage::AutoShootout => 0.0,
        }
        .min(100.0);

        let host_bonus = if toolchain_ok { 4.0 } else { -6.0 };
        let explicit_pref_bonus = if prefs.target_language != TargetLanguage::AutoShootout
            && prefs.target_language == lang
        {
            8.0
        } else {
            0.0
        };

        let composite = (0.32 * latency_fit
            + 0.24 * dependency_fit
            + 0.24 * runtime_shape_fit
            + 0.20 * safety_and_invariants_fit
            + host_bonus
            + explicit_pref_bonus)
            .clamp(0.0, 100.0);

        ranked.push(LanguageFitnessScore {
            language: lang,
            label: lang.label().to_string(),
            latency_fit,
            dependency_fit,
            runtime_shape_fit,
            safety_and_invariants_fit,
            toolchain_detected_on_host: toolchain_ok,
            detected_toolchain_binary: toolchain_bin,
            composite_fitness: (composite * 10.0).round() / 10.0,
            rationale: format!(
                "p95<={}ms fit {:.0}, {:?} fit {:.0}, {:?} fit {:.0}, host_toolchain={}",
                prefs.max_latency_p95_ms,
                latency_fit,
                prefs.dependency_appetite,
                dependency_fit,
                prefs.runtime_shape,
                runtime_shape_fit,
                toolchain_ok
            ),
        });
    }

    ranked.sort_by(|a, b| {
        b.composite_fitness
            .partial_cmp(&a.composite_fitness)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Prefer runnable host toolchains for the shootout pair when available
    let mut runnable: Vec<TargetLanguage> = ranked
        .iter()
        .filter(|r| r.toolchain_detected_on_host)
        .map(|r| r.language)
        .collect();
    for r in &ranked {
        if !runnable.contains(&r.language) {
            runnable.push(r.language);
        }
    }

    let first = runnable.first().copied().unwrap_or(TargetLanguage::Rust);
    let second = runnable.get(1).copied().unwrap_or(TargetLanguage::Python);

    LanguageAdvisoryReport {
        project_name: manifest.project_name.clone(),
        ranked_languages: ranked,
        recommended_primary: first,
        recommended_shootout_pair: (first, second),
    }
}

fn split_shell_words(cmd_line: &str) -> Option<(String, Vec<String>)> {
    let mut parts = cmd_line.split_whitespace();
    let prog = parts.next()?.to_string();
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();
    Some((prog, args))
}

/// Materializes and benchmarks the Top-2 runnable target languages side-by-side on disk,
/// measuring real conformance test execution and `solve_bench` wall-clock performance.
pub fn run_polyglot_language_shootout(
    manifest: &CarnotManifest,
    scratch_parent: &Path,
    timeout_ms: u64,
    ledger: &mut EvidenceLedger,
) -> Result<PolyglotShootoutReport, String> {
    let advisory = advise_target_languages(manifest, &manifest.preferences);
    let (lang_a, lang_b) = advisory.recommended_shootout_pair;
    let pair = [lang_a, lang_b];

    fs::create_dir_all(scratch_parent)
        .map_err(|e| format!("Failed to create shootout scratch dir: {}", e))?;

    let mut contenders = Vec::with_capacity(2);

    for lang in pair {
        let slug = format!("shootout_{:?}", lang).to_ascii_lowercase();
        let dir = scratch_parent.join(&slug);
        let _ = fs::remove_dir_all(&dir);

        let plan = materialize_project_to_disk(manifest, &dir, Some(lang), false)?;
        let (toolchain_ok, _) = detect_language_toolchain(lang);

        if !toolchain_ok {
            let _ = fs::remove_dir_all(&dir);
            contenders.push(ShootoutContenderResult {
                language: lang,
                toolchain_available: false,
                tests_passed: false,
                bench_succeeded: false,
                achieved_objective: 0.0,
                total_wall_ms: u64::MAX / 2,
                files_emitted: plan.planned_files.len(),
                diagnostic: format!("Host toolchain for {:?} not installed on PATH", lang),
            });
            continue;
        }

        let (test_prog, test_args) =
            split_shell_words(&plan.test_command).unwrap_or_else(|| ("true".into(), vec![]));
        let mut t_cmd = Command::new(&test_prog);
        t_cmd.args(&test_args).current_dir(&dir);
        let t_out = run_command_bounded(t_cmd, None, timeout_ms, DEFAULT_MAX_STREAM_BYTES);

        let (bench_prog, bench_args) =
            split_shell_words(&plan.bench_command).unwrap_or_else(|| ("true".into(), vec![]));
        let mut b_cmd = Command::new(&bench_prog);
        b_cmd.args(&bench_args).current_dir(&dir);
        let b_out = if t_out.success {
            Some(run_command_bounded(
                b_cmd,
                None,
                timeout_ms,
                DEFAULT_MAX_STREAM_BYTES,
            ))
        } else {
            None
        };

        let _ = fs::remove_dir_all(&dir);

        let mut bench_ok = false;
        let mut obj = 0.0;
        let mut total_ms = t_out.duration_ms;

        if let Some(bo) = &b_out {
            total_ms += bo.duration_ms;
            if bo.success {
                if let Some(last_line) = bo.stdout.lines().rev().find(|l| !l.trim().is_empty()) {
                    if let Ok(val) = serde_json::from_str::<Value>(last_line.trim()) {
                        let validity = val.get("validity").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let raw_obj = val.get("objective").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        if validity > 0.0 {
                            bench_ok = true;
                            obj = raw_obj;
                        }
                    }
                }
            }
        }

        let diag = if t_out.success && bench_ok {
            format!(
                "PASS: objective={:.4}, wall={}ms ({} files)",
                obj,
                total_ms,
                plan.planned_files.len()
            )
        } else if !t_out.success {
            format!("Tests failed: {}", t_out.stderr.trim())
        } else {
            "Benchmark output invalid or validity <= 0".to_string()
        };

        contenders.push(ShootoutContenderResult {
            language: lang,
            toolchain_available: true,
            tests_passed: t_out.success,
            bench_succeeded: bench_ok,
            achieved_objective: obj,
            total_wall_ms: total_ms,
            files_emitted: plan.planned_files.len(),
            diagnostic: diag,
        });
    }

    contenders.sort_by(|a, b| {
        b.bench_succeeded
            .cmp(&a.bench_succeeded)
            .then_with(|| {
                b.achieved_objective
                    .partial_cmp(&a.achieved_objective)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.total_wall_ms.cmp(&b.total_wall_ms))
    });

    let winner = contenders
        .first()
        .map(|c| c.language)
        .unwrap_or(advisory.recommended_primary);

    let rec = ledger.record_with_provenance(
        EvidenceKind::Observed,
        "polyglot_language_shootout",
        format!(
            "Empirical Top-2 language shootout ({:?} vs {:?}) -> winner {:?}",
            lang_a, lang_b, winner
        ),
        None,
        EvidenceProvenance {
            authority: EvidenceAuthority::ControlledReplay,
            confidence: EvidenceConfidence::Observed,
            coverage: CoverageStatus::Complete,
            subject_sha256: None,
            parent_evidence_id: None,
        },
        &json!({
            "project_name": manifest.project_name,
            "contenders": contenders,
            "winner": winner,
        }),
    );

    Ok(PolyglotShootoutReport {
        project_name: manifest.project_name.clone(),
        contenders,
        winner,
        receipt_id: rec.id,
    })
}
