//! Python public-API specs and spec-only rebuilds.
//!
//! `spec` reads signatures, docstrings, and literal examples. It does not keep
//! function bodies. `generate --spec` reads that file and nothing from the
//! original tree. Other languages are not supported.

use crate::evidence::sha256_hex;
use crate::proc_util::{run_command_bounded, DEFAULT_MAX_STREAM_BYTES};
use crate::testrun::python_program;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const SCRIPT: &str = include_str!("spec_extract.py");
const MAX_EXAMPLE_ROWS: usize = 50;
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const VERBATIM_N: usize = 12;
pub const DEFAULT_HOLDOUT: f64 = 0.3;
pub const GENERATOR_PROTOTYPE: &str = "prototype_example_table";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorExample {
    pub args: Vec<String>,
    #[serde(default)]
    pub kwargs: BTreeMap<String, String>,
    pub expected: String,
    /// True when this example is withheld from `generate --spec` and graded by `verify --against`.
    #[serde(default)]
    pub held_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecFunction {
    pub name: String,
    pub signature: String,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub lookup: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    #[serde(default)]
    pub examples: Vec<BehaviorExample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecClass {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    #[serde(default)]
    pub methods: Vec<SpecFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecModule {
    pub name: String,
    #[serde(default)]
    pub exports: Vec<String>,
    #[serde(default)]
    pub functions: Vec<SpecFunction>,
    #[serde(default)]
    pub classes: Vec<SpecClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibrarySpec {
    pub language: String,
    pub origin_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub modules: Vec<SpecModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildCertificate {
    pub spec_only: bool,
    pub spec_sha256: String,
    pub language: String,
    /// Prototype example lookup. It does not synthesize logic.
    /// shortcut: recorded training examples only. Upgrade when a proposer can synthesize bodies from signatures without the original source.
    pub generator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbatim_overlap: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbatim_ngram_hits: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleResult {
    pub module: String,
    pub func: String,
    pub ok: bool,
    #[serde(default)]
    pub held_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecVerifyReport {
    pub demo: bool,
    pub checks_executed: bool,
    pub workspace: String,
    pub test_command: String,
    pub exit_code: Option<i32>,
    pub passed: u64,
    pub failed: u64,
    pub held_out_passed: u64,
    pub held_out_failed: u64,
    pub duration_ms: u64,
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub certificate: RebuildCertificate,
    pub examples: Vec<ExampleResult>,
    /// shortcut: at most 50 rows are embedded. `passed` and `failed` still count every example. Upgrade when a caller needs the full list in one response.
    pub examples_omitted: u64,
}

struct TempScript(PathBuf);

impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn temp_script() -> Result<TempScript, String> {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("carnot-spec-{}-{seq}.py", std::process::id()));
    fs::write(&path, SCRIPT).map_err(|e| format!("failed to write spec helper: {e}"))?;
    Ok(TempScript(path))
}

fn run_python(
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout_ms: u64,
) -> Result<crate::proc_util::BoundedProcessOutput, String> {
    let python = python_program();
    let mut cmd = Command::new(&python);
    cmd.args(args).env("PYTHONDONTWRITEBYTECODE", "1");
    let out = run_command_bounded(cmd, stdin, timeout_ms, DEFAULT_MAX_STREAM_BYTES);
    if !out.spawned {
        return Err(format!(
            "python is required for spec extraction ({})",
            out.spawn_error
                .unwrap_or_else(|| "spawn failed".to_string())
        ));
    }
    Ok(out)
}

/// Read `dir` and write a Python spec. The spec has no function bodies.
pub fn write_spec(dir: &Path, out_file: &Path, holdout: f64) -> Result<LibrarySpec, String> {
    if !dir.is_dir() {
        return Err(format!("spec target is not a directory: {}", dir.display()));
    }
    let script = temp_script()?;
    let dir_s = dir.to_string_lossy().into_owned();
    let script_s = script.0.to_string_lossy().into_owned();
    let out = run_python(&[&script_s, "extract", &dir_s], None, 60_000)?;
    if out.timed_out {
        return Err("spec extraction timed out".to_string());
    }
    if !out.success {
        let detail = format!("{}\n{}", out.stderr.trim(), out.stdout.trim());
        let detail = detail.trim();
        if detail.is_empty() {
            return Err("spec extraction supports Python libraries only".to_string());
        }
        return Err(detail.to_string());
    }
    let spec: LibrarySpec = serde_json::from_str(&out.stdout)
        .map_err(|e| format!("spec extractor returned invalid JSON: {e}"))?;
    if spec.language != "python" {
        return Err("spec extraction supports Python libraries only".to_string());
    }
    if spec.modules.is_empty() {
        return Err("spec extraction supports Python libraries only".to_string());
    }
    let mut spec = spec;
    assign_holdout(&mut spec, holdout);
    if let Some(parent) = out_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
    }
    let text = serde_json::to_string_pretty(&spec)
        .map_err(|e| format!("failed to serialize spec: {e}"))?;
    fs::write(out_file, text)
        .map_err(|e| format!("failed to write {}: {e}", out_file.display()))?;
    Ok(spec)
}

/// Build a Python package from `spec_path` alone. Does not open `origin`.
pub fn generate_from_spec(spec_path: &Path, out_dir: &Path) -> Result<RebuildCertificate, String> {
    let bytes = fs::read(spec_path)
        .map_err(|e| format!("failed to read spec {}: {e}", spec_path.display()))?;
    let spec: LibrarySpec = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid spec JSON in {}: {e}", spec_path.display()))?;
    if spec.language != "python" {
        return Err("generate --spec supports Python libraries only".to_string());
    }
    if spec.modules.is_empty() {
        return Err("spec has no Python modules".to_string());
    }
    let mut literals = Vec::new();
    for module in &spec.modules {
        for func in &module.functions {
            collect_literals(func, &mut literals);
        }
    }
    if !literals.is_empty() {
        ensure_literals(&literals)?;
    }
    validate_spec(&spec)?;
    let rendered = render_tree(&spec)?;
    fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create {}: {e}", out_dir.display()))?;
    for (rel, contents) in &rendered {
        let dest = out_dir.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
        fs::write(&dest, contents)
            .map_err(|e| format!("failed to write {}: {e}", dest.display()))?;
    }
    syntax_check(out_dir, &rendered)?;
    let certificate = RebuildCertificate {
        spec_only: true,
        spec_sha256: sha256_hex(&bytes),
        language: "python".to_string(),
        generator: GENERATOR_PROTOTYPE.to_string(),
        verbatim_overlap: None,
        verbatim_ngram_hits: None,
    };
    let cert_path = out_dir.join("carnot.rebuild.json");
    let cert_text = serde_json::to_string_pretty(&certificate)
        .map_err(|e| format!("failed to serialize certificate: {e}"))?;
    fs::write(&cert_path, cert_text)
        .map_err(|e| format!("failed to write {}: {e}", cert_path.display()))?;
    Ok(certificate)
}

fn collect_literals(func: &SpecFunction, out: &mut Vec<String>) {
    for example in &func.examples {
        out.extend(example.args.iter().cloned());
        out.extend(example.kwargs.values().cloned());
        out.push(example.expected.clone());
    }
}

fn ensure_literals(literals: &[String]) -> Result<(), String> {
    let script = temp_script()?;
    let payload =
        serde_json::to_vec(literals).map_err(|e| format!("failed to encode literals: {e}"))?;
    let script_s = script.0.to_string_lossy().into_owned();
    let out = run_python(&[&script_s, "literals"], Some(&payload), 30_000)?;
    if out.timed_out || !out.success {
        return Err(format!(
            "spec example is not a Python literal: {}",
            out.stderr.trim()
        ));
    }
    Ok(())
}

fn assign_holdout(spec: &mut LibrarySpec, fraction: f64) {
    for module in &mut spec.modules {
        for func in &mut module.functions {
            for example in &mut func.examples {
                example.held_out = example_held_out(&module.name, &func.name, example, fraction);
            }
        }
    }
}

fn example_held_out(module: &str, func: &str, example: &BehaviorExample, fraction: f64) -> bool {
    if fraction <= 0.0 {
        return false;
    }
    if fraction >= 1.0 {
        return true;
    }
    let mut payload = format!("{module}\n{func}\n");
    for arg in &example.args {
        payload.push_str(arg);
        payload.push('\n');
    }
    for (key, value) in &example.kwargs {
        payload.push_str(key);
        payload.push('=');
        payload.push_str(value);
        payload.push('\n');
    }
    payload.push_str(&example.expected);
    let hex = sha256_hex(payload.as_bytes());
    let prefix = u64::from_str_radix(&hex[..16], 16).unwrap_or(0);
    (prefix as f64) < fraction * (u64::MAX as f64)
}

fn validate_spec(spec: &LibrarySpec) -> Result<(), String> {
    for module in &spec.modules {
        module_path(&module.name, spec)?;
        for func in &module.functions {
            check_signature(&func.name, &func.signature)?;
            check_params(&func.params)?;
        }
        for class in &module.classes {
            if !is_ident(&class.name) {
                return Err(format!("invalid class name '{}'", class.name));
            }
            for method in &class.methods {
                check_signature(&method.name, &method.signature)?;
                check_params(&method.params)?;
            }
        }
    }
    Ok(())
}

fn check_params(params: &[String]) -> Result<(), String> {
    for param in params {
        if !is_ident(param) {
            return Err(format!("refusing parameter '{param}'"));
        }
    }
    // Defaults from the signature text are not emitted. `def` uses `name=None`.
    // shortcut: non-literal defaults are dropped, not checked. Upgrade when a spec records defaults as literals worth keeping.
    Ok(())
}

fn check_signature(name: &str, signature: &str) -> Result<(), String> {
    if !is_ident(name) || signature.contains('\n') || signature.contains(';') {
        return Err(format!("refusing signature for '{name}'"));
    }
    if !signature.starts_with(&format!("{name}(")) {
        return Err(format!("signature '{signature}' does not match '{name}'"));
    }
    Ok(())
}

fn render_tree(spec: &LibrarySpec) -> Result<Vec<(PathBuf, String)>, String> {
    let mut files: BTreeMap<PathBuf, String> = BTreeMap::new();
    for module in &spec.modules {
        let rel = module_path(&module.name, spec)?;
        files.insert(rel, render_module(module));
    }
    let paths: Vec<PathBuf> = files.keys().cloned().collect();
    for path in paths {
        let mut parent = path.parent().map(Path::to_path_buf);
        while let Some(dir) = parent {
            if dir.as_os_str().is_empty() {
                break;
            }
            let init = dir.join("__init__.py");
            files
                .entry(init)
                .or_insert_with(|| "\"Rebuilt from a Carnot spec.\"\n".to_string());
            parent = dir.parent().map(Path::to_path_buf);
        }
    }
    Ok(files.into_iter().collect())
}

fn module_path(name: &str, spec: &LibrarySpec) -> Result<PathBuf, String> {
    let parts: Vec<&str> = name.split('.').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() || parts.iter().any(|part| !is_ident(part)) {
        return Err(format!("invalid Python module name '{name}'"));
    }
    let has_child = spec
        .modules
        .iter()
        .any(|module| module.name.starts_with(&format!("{name}.")));
    let mut path = PathBuf::new();
    if parts.len() == 1 && !has_child {
        path.push(format!("{}.py", parts[0]));
        return Ok(path);
    }
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        if last && !has_child {
            path.push(format!("{part}.py"));
        } else if last {
            path.push(part);
            path.push("__init__.py");
        } else {
            path.push(part);
        }
    }
    Ok(path)
}

fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn render_module(module: &SpecModule) -> String {
    // shortcut: module-level functions return recorded literal examples and raise otherwise. Upgrade when a proposer can synthesize bodies from signatures without the original source.
    let mut out = String::from("\"Rebuilt from a Carnot spec. Example lookup only.\"\n\n");
    for func in &module.functions {
        out.push_str(&render_function(func));
        out.push('\n');
    }
    for class in &module.classes {
        out.push_str(&render_class(class));
        out.push('\n');
    }
    if module.functions.is_empty() && module.classes.is_empty() {
        out.push_str("pass\n");
    }
    out
}

fn render_function(func: &SpecFunction) -> String {
    // shortcut: generated defs drop annotations and non-literal defaults, and an example that omits a trailing argument matches on the arguments it did pass. Upgrade when defaults are recorded and calls must distinguish them.
    let mut out = format!("{}:\n", def_header(&func.name, &func.params));
    if let Some(doc) = func.doc.as_ref().filter(|doc| !doc.is_empty()) {
        out.push_str(&format!("    {}\n", python_string(doc)));
    }
    if func.lookup {
        for example in func.examples.iter().filter(|example| !example.held_out) {
            if let Some((names, values)) = match_call(&func.params, example) {
                out.push_str(&format!(
                    "    if {} == {}:\n        return {}\n",
                    tuple_literal(&names),
                    tuple_literal(&values),
                    example.expected
                ));
            }
        }
    }
    out.push_str(&format!(
        "    raise NotImplementedError({})\n",
        python_string(&func.name)
    ));
    out
}

fn def_header(name: &str, params: &[String]) -> String {
    if params.is_empty() {
        format!("def {name}()")
    } else {
        let args = params
            .iter()
            .map(|param| format!("{param}=None"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("def {name}({args})")
    }
}

fn match_call(params: &[String], example: &BehaviorExample) -> Option<(Vec<String>, Vec<String>)> {
    if example.kwargs.is_empty() && example.args.len() <= params.len() {
        return Some((params[..example.args.len()].to_vec(), example.args.clone()));
    }
    let bound = bound_args(params, example)?;
    Some((params.to_vec(), bound))
}

fn render_class(class: &SpecClass) -> String {
    let mut out = format!("class {}:\n", class.name);
    let doc = class.doc.as_ref().filter(|doc| !doc.is_empty());
    if let Some(doc) = doc {
        out.push_str(&format!("    {}\n", python_string(doc)));
    }
    if class.methods.is_empty() {
        if doc.is_none() {
            out.push_str("    pass\n");
        }
        return out;
    }
    for method in &class.methods {
        out.push_str(&format!(
            "    {}:\n",
            def_header(&method.name, &method.params)
        ));
        if let Some(doc) = method.doc.as_ref().filter(|doc| !doc.is_empty()) {
            out.push_str(&format!("        {}\n", python_string(doc)));
        }
        out.push_str(&format!(
            "        raise NotImplementedError({})\n",
            python_string(&format!("{}.{}", class.name, method.name))
        ));
    }
    out
}

fn bound_args(params: &[String], example: &BehaviorExample) -> Option<Vec<String>> {
    if example.args.len() > params.len() {
        return None;
    }
    let mut bound = example.args.clone();
    for name in params.iter().skip(example.args.len()) {
        bound.push(example.kwargs.get(name)?.clone());
    }
    if example.kwargs.len() != params.len() - example.args.len() {
        return None;
    }
    Some(bound)
}

fn tuple_literal(items: &[String]) -> String {
    if items.is_empty() {
        "()".to_string()
    } else if items.len() == 1 {
        format!("({},)", items[0])
    } else {
        format!("({})", items.join(", "))
    }
}

fn python_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn syntax_check(out_dir: &Path, files: &[(PathBuf, String)]) -> Result<(), String> {
    let python = python_program();
    for (rel, _) in files {
        let path = out_dir.join(rel);
        let path_s = path.to_string_lossy().into_owned();
        let mut cmd = Command::new(&python);
        cmd.args([
            "-c",
            "import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), sys.argv[1], 'exec')",
            &path_s,
        ])
        .env("PYTHONDONTWRITEBYTECODE", "1");
        let out = run_command_bounded(cmd, None, 30_000, DEFAULT_MAX_STREAM_BYTES);
        if !out.success {
            return Err(format!(
                "generated {} is not valid Python: {}",
                rel.display(),
                out.stderr.trim()
            ));
        }
    }
    Ok(())
}

/// Replay the spec's examples against `rebuild_dir`.
/// Reads `origin` only to count shared token 12-grams. Generation does not.
pub fn verify_against(
    rebuild_dir: &Path,
    spec_path: &Path,
    timeout_ms: u64,
    grade_all: bool,
) -> Result<SpecVerifyReport, String> {
    if !rebuild_dir.is_dir() {
        return Err(format!(
            "verify target is not a directory: {}",
            rebuild_dir.display()
        ));
    }
    let bytes = fs::read(spec_path)
        .map_err(|e| format!("failed to read spec {}: {e}", spec_path.display()))?;
    let spec: LibrarySpec = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid spec JSON in {}: {e}", spec_path.display()))?;
    if spec.language != "python" {
        return Err("verify --against supports Python specs only".to_string());
    }
    let graded = |example: &BehaviorExample| grade_all || example.held_out;
    let example_count: usize = spec
        .modules
        .iter()
        .map(|module| {
            module
                .functions
                .iter()
                .map(|func| {
                    func.examples
                        .iter()
                        .filter(|example| graded(example))
                        .count()
                })
                .sum::<usize>()
        })
        .sum();
    let which = if grade_all { "all" } else { "held-out" };
    let python = python_program();
    let script = temp_script()?;
    let script_s = script.0.to_string_lossy().into_owned();
    let rebuild_s = rebuild_dir.to_string_lossy().into_owned();
    let spec_s = spec_path.to_string_lossy().into_owned();
    let command = format!("{python} spec_extract.py check {rebuild_s} {spec_s} {which}");
    let mut certificate = RebuildCertificate {
        spec_only: true,
        spec_sha256: sha256_hex(&bytes),
        language: "python".to_string(),
        generator: GENERATOR_PROTOTYPE.to_string(),
        verbatim_overlap: None,
        verbatim_ngram_hits: None,
    };
    let mut note = None;
    if let Some(origin) = spec.origin.as_deref() {
        let origin_path = Path::new(origin);
        if origin_path.is_dir() {
            let hits = verbatim_ngram_hits(origin_path, rebuild_dir);
            certificate.verbatim_ngram_hits = Some(hits);
            certificate.verbatim_overlap = Some(hits > 0);
        } else {
            note = Some("original tree is not available; similarity was not checked".to_string());
        }
    }
    if example_count == 0 {
        let why = if grade_all {
            "spec has no behavioral examples"
        } else {
            "spec has no held-out examples"
        };
        let empty = if let Some(existing) = note {
            format!("{existing}; {why}")
        } else {
            why.to_string()
        };
        return Ok(SpecVerifyReport {
            demo: false,
            checks_executed: false,
            workspace: rebuild_dir.display().to_string(),
            test_command: command,
            exit_code: None,
            passed: 0,
            failed: 0,
            held_out_passed: 0,
            held_out_failed: 0,
            duration_ms: 0,
            timed_out: false,
            note: Some(empty),
            certificate,
            examples: Vec::new(),
            examples_omitted: 0,
        });
    }
    let out = run_python(
        &[&script_s, "check", &rebuild_s, &spec_s, which],
        None,
        timeout_ms.max(1),
    )?;
    if out.timed_out {
        return Ok(SpecVerifyReport {
            demo: false,
            checks_executed: true,
            workspace: rebuild_dir.display().to_string(),
            test_command: command,
            exit_code: None,
            passed: 0,
            failed: 0,
            held_out_passed: 0,
            held_out_failed: 0,
            duration_ms: out.duration_ms,
            timed_out: true,
            note: Some(format!("timed out after {timeout_ms} ms")),
            certificate,
            examples: Vec::new(),
            examples_omitted: 0,
        });
    }
    let parsed: Value = serde_json::from_str(&out.stdout).map_err(|e| {
        format!(
            "spec checker returned invalid JSON: {e}; {}",
            out.stderr.trim()
        )
    })?;
    let mut results = Vec::new();
    if let Some(rows) = parsed.get("results").and_then(|v| v.as_array()) {
        for row in rows {
            results.push(ExampleResult {
                module: row
                    .get("module")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                func: row
                    .get("func")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                ok: row.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
                held_out: row
                    .get("held_out")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                error: row
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(|text| text.chars().take(200).collect()),
            });
        }
    }
    let passed = results.iter().filter(|row| row.ok).count() as u64;
    let failed = results.len() as u64 - passed;
    let held_out_passed = results.iter().filter(|row| row.held_out && row.ok).count() as u64;
    let held_out_failed = results.iter().filter(|row| row.held_out && !row.ok).count() as u64;
    let omitted = results.len().saturating_sub(MAX_EXAMPLE_ROWS) as u64;
    results.truncate(MAX_EXAMPLE_ROWS);
    Ok(SpecVerifyReport {
        demo: false,
        checks_executed: true,
        workspace: rebuild_dir.display().to_string(),
        test_command: command,
        exit_code: Some(if failed == 0 { 0 } else { 1 }),
        passed,
        failed,
        held_out_passed,
        held_out_failed,
        duration_ms: out.duration_ms,
        timed_out: false,
        note,
        certificate,
        examples: results,
        examples_omitted: omitted,
    })
}

/// shortcut: exact token 12-grams after a quote strip, at most 1 MiB per file, tests/ skipped. Misses reflowed or renamed copies. Upgrade to winnowed fingerprints when a synthesizer can emit near-copies.
pub fn verbatim_ngram_hits(origin: &Path, generated: &Path) -> u64 {
    let left = token_ngrams(&strip_quoted(&python_corpus(origin)), VERBATIM_N);
    let right = token_ngrams(&strip_quoted(&python_corpus(generated)), VERBATIM_N);
    left.intersection(&right).count() as u64
}

fn python_corpus(dir: &Path) -> String {
    let mut files = Vec::new();
    collect_py(dir, &mut files);
    files.sort();
    let mut out = String::new();
    for path in files {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let clipped = if bytes.len() > MAX_SOURCE_BYTES {
            &bytes[..MAX_SOURCE_BYTES]
        } else {
            &bytes[..]
        };
        out.push_str(&String::from_utf8_lossy(clipped));
        out.push('\n');
    }
    out
}

fn collect_py(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "__pycache__" || name == "venv" || name == ".venv" {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if name == "tests" || name == "test" {
                continue;
            }
            collect_py(&path, out);
        } else if name.ends_with(".py")
            && !name.starts_with("test_")
            && !name.ends_with("_test.py")
            && name != "conftest.py"
        {
            out.push(path);
        }
    }
}

fn strip_quoted(src: &str) -> String {
    // shortcut: this is not Python's tokenizer. A quote hidden in an f-string can desync it. Upgrade to `tokenize` if a copied body hides inside a string.
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        let prefix = string_prefix_len(&chars, i);
        let quote_at = i + prefix;
        if prefix > 0 {
            if let Some(end) = skip_string(&chars, quote_at) {
                i = end;
                out.push(' ');
                continue;
            }
        }
        if chars[i] == '"' || chars[i] == '\'' {
            if let Some(end) = skip_string(&chars, i) {
                i = end;
                out.push(' ');
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn string_prefix_len(chars: &[char], i: usize) -> usize {
    if i > 0 && (chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_') {
        return 0;
    }
    let mut n = 0;
    while i + n < chars.len()
        && n < 3
        && matches!(chars[i + n], 'r' | 'R' | 'f' | 'F' | 'b' | 'B' | 'u' | 'U')
    {
        n += 1;
    }
    if n > 0 && i + n < chars.len() && (chars[i + n] == '"' || chars[i + n] == '\'') {
        n
    } else {
        0
    }
}

fn skip_string(chars: &[char], i: usize) -> Option<usize> {
    let quote = chars.get(i).copied()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let triple = i + 2 < chars.len() && chars[i + 1] == quote && chars[i + 2] == quote;
    let mut j = i + if triple { 3 } else { 1 };
    while j < chars.len() {
        if chars[j] == '\\' && !triple {
            j += 2;
            continue;
        }
        if triple
            && j + 2 < chars.len()
            && chars[j] == quote
            && chars[j + 1] == quote
            && chars[j + 2] == quote
        {
            return Some(j + 3);
        }
        if !triple && chars[j] == quote {
            return Some(j + 1);
        }
        if !triple && chars[j] == '\n' {
            return Some(j);
        }
        j += 1;
    }
    Some(j)
}

fn token_ngrams(src: &str, n: usize) -> HashSet<Vec<String>> {
    let tokens: Vec<String> = src
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect();
    if tokens.len() < n {
        return HashSet::new();
    }
    tokens.windows(n).map(|window| window.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holdout_boundaries_are_deterministic() {
        let example = BehaviorExample {
            args: vec!["1".to_string()],
            kwargs: BTreeMap::new(),
            expected: "2".to_string(),
            held_out: false,
        };
        assert!(!example_held_out("m", "f", &example, 0.0));
        assert!(example_held_out("m", "f", &example, 1.0));
        assert_eq!(
            example_held_out("m", "f", &example, 0.3),
            example_held_out("m", "f", &example, 0.3)
        );
    }

    #[test]
    fn twelve_token_run_flags_overlap_and_docstrings_do_not() {
        let original = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu";
        let copied =
            "prelude alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu tail";
        assert!(verbatim_ngram_hits_text(original, copied) > 0);
        assert_eq!(
            verbatim_ngram_hits_text(original, "one two three four five six seven eight nine ten"),
            0
        );
        let documented =
            "\"alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu\"\nreturn 1\n";
        let same_doc =
            "\"alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu\"\nreturn 2\n";
        assert_eq!(verbatim_ngram_hits_text(documented, same_doc), 0);
    }

    fn verbatim_ngram_hits_text(left: &str, right: &str) -> u64 {
        let a = token_ngrams(&strip_quoted(left), VERBATIM_N);
        let b = token_ngrams(&strip_quoted(right), VERBATIM_N);
        a.intersection(&b).count() as u64
    }
}
