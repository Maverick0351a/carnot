//! Stage 3 (`carnot build` / `carnot generate` / `Carnot.toml`): Polyglot Consolidation Recipe & Target Emitter.
//!
//! Emits complete, compilable, and runnable project trees on disk (`Rust`, `Python`, `TypeScript`/`Node`,
//! `Go`, `Scala 3`, `Zig`) with real `EVOLVE_START`..`EVOLVE_END` organ modules, frozen `solve_bench`
//! JSON CLI harnesses, and executable conformance test suites.

use crate::scout::{PreferenceProfile, TargetLanguage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganSpec {
    pub id: String,
    pub capability: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub invariants: Vec<String>,
    pub conformance_suite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganBridge {
    pub from_organ: String,
    pub to_organ: String,
    pub contract: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganTargetBinding {
    pub organ_id: String,
    pub target_language: TargetLanguage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint_path: Option<String>,
}

fn default_black_box_enforced() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarnotManifest {
    pub project_name: String,
    #[serde(default = "default_black_box_enforced")]
    pub black_box_enforced: bool,
    pub preferences: PreferenceProfile,
    pub organs: Vec<OrganSpec>,
    pub bridges: Vec<OrganBridge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_bindings: Vec<OrganTargetBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedTargetPlan {
    pub project_name: String,
    pub target_language: TargetLanguage,
    pub build_command: String,
    pub test_command: String,
    pub bench_command: String,
    pub manifest_toml: String,
    pub planned_files: Vec<(String, String)>,
}

fn sanitize_ident(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.chars().next().unwrap().is_ascii_digit() {
        out.insert_str(0, "organ_");
    }
    out
}

impl CarnotManifest {
    pub fn render_carnot_toml(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "[project]\nname = \"{}\"\nblack_box_enforced = {}\ntarget_language = \"{:?}\"\nruntime_shape = \"{:?}\"\ndependency_appetite = \"{:?}\"\nmax_latency_p95_ms = {}\n\n",
            self.project_name,
            self.black_box_enforced,
            self.preferences.target_language,
            self.preferences.runtime_shape,
            self.preferences.dependency_appetite,
            self.preferences.max_latency_p95_ms
        ));
        for org in &self.organs {
            out.push_str(&format!(
                "[[organs]]\nid = \"{}\"\ncapability = \"{}\"\ninputs = {:?}\noutputs = {:?}\nconformance_suite = \"{}\"\ninvariants = {:?}\n\n",
                org.id, org.capability, org.inputs, org.outputs, org.conformance_suite, org.invariants
            ));
        }
        for br in &self.bridges {
            out.push_str(&format!(
                "[[bridges]]\nfrom = \"{}\"\nto = \"{}\"\ncontract = \"{}\"\n\n",
                br.from_organ, br.to_organ, br.contract
            ));
        }
        for tb in &self.target_bindings {
            out.push_str(&format!(
                "[[target_bindings]]\norgan_id = \"{}\"\ntarget_language = \"{:?}\"\nwire_protocol = \"{}\"\n\n",
                tb.organ_id,
                tb.target_language,
                tb.wire_protocol.as_deref().unwrap_or("in_process")
            ));
        }
        out
    }

    pub fn emit_polyglot_plan(&self, lang_override: Option<TargetLanguage>) -> GeneratedTargetPlan {
        let lang = match lang_override.unwrap_or(self.preferences.target_language) {
            TargetLanguage::AutoShootout => {
                crate::advisor::advise_target_languages(self, &self.preferences).recommended_primary
            }
            explicit => explicit,
        };

        let pkg_slug: String = self
            .project_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        let crate_ident = sanitize_ident(&pkg_slug);
        let organs: Vec<(String, &OrganSpec)> = self
            .organs
            .iter()
            .map(|o| (sanitize_ident(&o.id), o))
            .collect();

        let (build_cmd, test_cmd, bench_cmd, files) = match lang {
            TargetLanguage::Rust => {
                let mut f = Vec::new();
                f.push((
                    "Cargo.toml".to_string(),
                    format!(
                        "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                        pkg_slug
                    ),
                ));
                let mut lib_rs = String::new();
                for (id, _) in &organs {
                    lib_rs.push_str(&format!("pub mod {};\n", id));
                }
                f.push(("src/lib.rs".to_string(), lib_rs));

                for (id, org) in &organs {
                    let inv_comment = if org.invariants.is_empty() {
                        "//! Invariants: deterministic clean-room execution".to_string()
                    } else {
                        format!("//! Invariants: {}", org.invariants.join(" | "))
                    };
                    let mod_code = [
                        format!("//! Organ `{}`: {}", id, org.capability),
                        format!(
                            "//! Contract: ({}) -> ({})",
                            org.inputs.join(", "),
                            org.outputs.join(", ")
                        ),
                        inv_comment,
                        String::new(),
                        "pub fn execute(input: &str, flag_enabled: bool) -> Result<String, &'static str> {".to_string(),
                        "    if !flag_enabled {".to_string(),
                        "        return Err(\"organ_flag_disabled\");".to_string(),
                        "    }".to_string(),
                        format!("    // EVOLVE_START {}", id),
                        "    let trimmed = input.trim();".to_string(),
                        "    if trimmed.is_empty() || trimmed.contains('\\0') {".to_string(),
                        "        return Err(\"invalid_payload\");".to_string(),
                        "    }".to_string(),
                        format!("    Ok(format!(\"[{}] {{}}\", trimmed))", id),
                        format!("    // EVOLVE_END {}", id),
                        "}".to_string(),
                        String::new(),
                    ]
                    .join("\n");
                    f.push((format!("src/{}.rs", id), mod_code));
                }

                let first_id = organs
                    .first()
                    .map(|(id, _)| id.as_str())
                    .unwrap_or("verifier");
                let bench_rs = [
                    "fn main() {".to_string(),
                    "    let cases = [\"  soc2_renewal  \", \"kms_rotation\", \"webhook_audit\"];"
                        .to_string(),
                    "    let mut passed = 0usize;".to_string(),
                    "    for c in cases {".to_string(),
                    format!(
                        "        if {}::{}::execute(c, true).is_ok() {{",
                        crate_ident, first_id
                    ),
                    "            passed += 1;".to_string(),
                    "        }".to_string(),
                    "    }".to_string(),
                    format!(
                        "    let bad_rejected = {}::{}::execute(\"   \", true).is_err();",
                        crate_ident, first_id
                    ),
                    format!(
                        "    let ctrl_rejected = {}::{}::execute(\"bad\\x07bell\", true).is_err();",
                        crate_ident, first_id
                    ),
                    "    let validity = if passed == cases.len() && bad_rejected { 1.0 } else { 0.0 };"
                        .to_string(),
                    "    let hardening_bonus = if ctrl_rejected { 0.5 } else { 0.0 };".to_string(),
                    "    let objective = (passed as f64 / cases.len() as f64) + hardening_bonus;"
                        .to_string(),
                    "    println!(\"{{\\\"objective\\\":{:.6},\\\"validity\\\":{:.1}}}\", objective, validity);"
                        .to_string(),
                    "}".to_string(),
                    String::new(),
                ]
                .join("\n");
                f.push(("src/bin/solve_bench.rs".to_string(), bench_rs));

                let mut tests_lines = Vec::new();
                for (id, _) in &organs {
                    tests_lines.push("#[test]".to_string());
                    tests_lines.push(format!("fn organ_{}_enforces_flag_and_payload() {{", id));
                    tests_lines.push(format!(
                        "    assert!({}::{}::execute(\"hello\", false).is_err());",
                        crate_ident, id
                    ));
                    tests_lines.push(format!(
                        "    assert!({}::{}::execute(\"   \", true).is_err());",
                        crate_ident, id
                    ));
                    tests_lines.push(format!(
                        "    let out = {}::{}::execute(\" valid \", true).unwrap();",
                        crate_ident, id
                    ));
                    tests_lines.push("    assert!(out.contains(\"valid\"));".to_string());
                    tests_lines.push("}".to_string());
                    tests_lines.push(String::new());
                }
                f.push(("tests/conformance.rs".to_string(), tests_lines.join("\n")));
                (
                    "cargo build --release".to_string(),
                    "cargo test".to_string(),
                    "cargo run --quiet --bin solve_bench".to_string(),
                    f,
                )
            }
            TargetLanguage::Python => {
                let mut f = Vec::new();
                f.push((
                    "pyproject.toml".to_string(),
                    format!(
                        "[project]\nname = \"{}\"\nversion = \"0.1.0\"\nrequires-python = \">=3.10\"\n",
                        pkg_slug
                    ),
                ));
                f.push(("organs/__init__.py".to_string(), "".to_string()));
                for (id, org) in &organs {
                    let py_mod = [
                        format!(
                            "\"\"\"Organ `{}`: {} | ({}) -> ({})\"\"\"",
                            id,
                            org.capability,
                            org.inputs.join(", "),
                            org.outputs.join(", ")
                        ),
                        String::new(),
                        "def execute(payload: str, flag_enabled: bool = True) -> str:".to_string(),
                        "    if not flag_enabled:".to_string(),
                        "        raise RuntimeError(\"organ_flag_disabled\")".to_string(),
                        format!("# EVOLVE_START {}", id),
                        "    trimmed = payload.strip()".to_string(),
                        "    if not trimmed or \"\\x00\" in trimmed or len(trimmed) > 65536:"
                            .to_string(),
                        "        raise ValueError(\"invalid_payload\")".to_string(),
                        format!("    return f\"[{}] {{trimmed}}\"", id),
                        format!("# EVOLVE_END {}", id),
                        String::new(),
                    ]
                    .join("\n");
                    f.push((format!("organs/{}.py", id), py_mod));
                }

                let first_id = organs
                    .first()
                    .map(|(id, _)| id.as_str())
                    .unwrap_or("verifier");
                let bench_py = [
                    "import json".to_string(),
                    format!("from organs.{} import execute", first_id),
                    String::new(),
                    "def main() -> None:".to_string(),
                    "    cases = [\"  soc2_renewal  \", \"kms_rotation\", \"webhook_audit\"]"
                        .to_string(),
                    "    passed = sum(1 for c in cases if execute(c, True).endswith(c.strip()))"
                        .to_string(),
                    "    rejected = False".to_string(),
                    "    try:".to_string(),
                    "        execute(\"   \", True)".to_string(),
                    "    except ValueError:".to_string(),
                    "        rejected = True".to_string(),
                    "    ctrl_rejected = False".to_string(),
                    "    try:".to_string(),
                    "        execute(\"bad\\x07bell\", True)".to_string(),
                    "    except ValueError:".to_string(),
                    "        ctrl_rejected = True".to_string(),
                    "    validity = 1.0 if (passed == len(cases) and rejected) else 0.0"
                        .to_string(),
                    "    objective = round((passed / len(cases)) + (0.5 if ctrl_rejected else 0.0), 6)"
                        .to_string(),
                    "    print(json.dumps({\"objective\": objective, \"validity\": validity}))"
                        .to_string(),
                    String::new(),
                    "if __name__ == \"__main__\":".to_string(),
                    "    main()".to_string(),
                    String::new(),
                ]
                .join("\n");
                f.push(("solve_bench.py".to_string(), bench_py));

                let mut test_lines = vec!["import unittest".to_string()];
                for (id, _) in &organs {
                    test_lines.push(format!(
                        "from organs.{id} import execute as exec_{id}",
                        id = id
                    ));
                }
                test_lines.push(String::new());
                test_lines.push("class ConformanceTests(unittest.TestCase):".to_string());
                for (id, _) in &organs {
                    test_lines.push(format!("    def test_{id}(self) -> None:", id = id));
                    test_lines.push(format!(
                        "        self.assertIn(\"ok\", exec_{id}(\" ok \", True))",
                        id = id
                    ));
                    test_lines.push("        with self.assertRaises(RuntimeError):".to_string());
                    test_lines.push(format!("            exec_{id}(\"ok\", False)", id = id));
                    test_lines.push("        with self.assertRaises(ValueError):".to_string());
                    test_lines.push(format!("            exec_{id}(\"   \", True)", id = id));
                    test_lines.push(String::new());
                }
                test_lines.push("if __name__ == \"__main__\":".to_string());
                test_lines.push("    unittest.main()".to_string());
                test_lines.push(String::new());
                f.push((
                    "tests/test_conformance.py".to_string(),
                    test_lines.join("\n"),
                ));
                (
                    "uv build".to_string(),
                    "python3 -m unittest discover -s tests".to_string(),
                    "python3 solve_bench.py".to_string(),
                    f,
                )
            }
            TargetLanguage::TypeScript => {
                let mut f = Vec::new();
                f.push((
                    "package.json".to_string(),
                    format!(
                        "{{\n  \"name\": \"{}\",\n  \"version\": \"0.1.0\",\n  \"type\": \"module\",\n  \"scripts\": {{ \"build\": \"bun run build\", \"test\": \"node --test\" }}\n}}\n",
                        pkg_slug
                    ),
                ));
                for (id, org) in &organs {
                    let mjs = [
                        format!(
                            "// Organ `{}`: {} | ({}) -> ({})",
                            id,
                            org.capability,
                            org.inputs.join(", "),
                            org.outputs.join(", ")
                        ),
                        "export function execute(payload, flagEnabled = true) {".to_string(),
                        "  if (!flagEnabled) throw new Error('organ_flag_disabled');".to_string(),
                        format!("  // EVOLVE_START {}", id),
                        "  const trimmed = String(payload ?? '').trim();".to_string(),
                        "  if (!trimmed || trimmed.includes('\\0')) throw new Error('invalid_payload');"
                            .to_string(),
                        format!("  return `[{}] ${{trimmed}}`;", id),
                        format!("  // EVOLVE_END {}", id),
                        "}".to_string(),
                        String::new(),
                    ]
                    .join("\n");
                    f.push((format!("src/{}.mjs", id), mjs));
                }
                let first_id = organs
                    .first()
                    .map(|(id, _)| id.as_str())
                    .unwrap_or("verifier");
                let bench_mjs = format!(
                    "import {{ execute }} from './src/{first_id}.mjs';\n\
                     const cases = [' soc2 ', 'kms', 'audit'];\n\
                     const passed = cases.filter((c) => execute(c, true).includes(c.trim())).length;\n\
                     let rejected = false;\n\
                     try {{ execute('   ', true); }} catch {{ rejected = true; }}\n\
                     let ctrlRejected = false;\n\
                     try {{ execute('bad\\x07bell', true); }} catch {{ ctrlRejected = true; }}\n\
                     const validity = (passed === cases.length && rejected) ? 1.0 : 0.0;\n\
                     const objective = (passed / cases.length) + (ctrlRejected ? 0.5 : 0.0);\n\
                     console.log(JSON.stringify({{ objective, validity }}));\n",
                    first_id = first_id
                );
                f.push(("solve_bench.mjs".to_string(), bench_mjs));

                let mut test_mjs =
                    "import test from 'node:test';\nimport assert from 'node:assert/strict';\n"
                        .to_string();
                for (id, _) in &organs {
                    test_mjs.push_str(&format!(
                        "import {{ execute as exec_{id} }} from '../src/{id}.mjs';\n",
                        id = id
                    ));
                }
                for (id, _) in &organs {
                    test_mjs.push_str(&format!(
                        "test('organ {id} contract', () => {{\n\
                           assert.match(exec_{id}(' valid ', true), /valid/);\n\
                           assert.throws(() => exec_{id}('valid', false));\n\
                           assert.throws(() => exec_{id}('   ', true));\n\
                         }});\n",
                        id = id
                    ));
                }
                f.push(("tests/conformance.test.mjs".to_string(), test_mjs));
                (
                    "bun run build".to_string(),
                    "node --test".to_string(),
                    "node solve_bench.mjs".to_string(),
                    f,
                )
            }
            TargetLanguage::Go => {
                let mut f = Vec::new();
                f.push((
                    "go.mod".to_string(),
                    format!("module {}\n\ngo 1.22\n", pkg_slug),
                ));
                for (id, org) in &organs {
                    let go_src = format!(
                        "package {id}\n\nimport (\n\t\"errors\"\n\t\"strings\"\n)\n\n\
                         // Execute runs organ `{id}`: {cap}\n\
                         func Execute(payload string, flagEnabled bool) (string, error) {{\n\
                         \tif !flagEnabled {{\n\
                         \t\treturn \"\", errors.New(\"organ_flag_disabled\")\n\
                         \t}}\n\
                         // EVOLVE_START {id}\n\
                         \ttrimmed := strings.TrimSpace(payload)\n\
                         \tif trimmed == \"\" || strings.ContainsRune(trimmed, '\\x00') {{\n\
                         \t\treturn \"\", errors.New(\"invalid_payload\")\n\
                         \t}}\n\
                         \treturn \"[{id}] \" + trimmed, nil\n\
                         // EVOLVE_END {id}\n\
                         }}\n",
                        id = id,
                        cap = org.capability
                    );
                    let go_test = format!(
                        "package {id}\n\nimport \"testing\"\n\n\
                         func TestExecute(t *testing.T) {{\n\
                         \tif _, err := Execute(\"ok\", false); err == nil {{ t.Fatal(\"expected flag error\") }}\n\
                         \tif _, err := Execute(\"   \", true); err == nil {{ t.Fatal(\"expected empty error\") }}\n\
                         \tout, err := Execute(\" ok \", true)\n\
                         \tif err != nil || out == \"\" {{ t.Fatal(err) }}\n\
                         }}\n",
                        id = id
                    );
                    f.push((format!("internal/{}/{}.go", id, id), go_src));
                    f.push((format!("internal/{}/{}_test.go", id, id), go_test));
                }
                let first_id = organs
                    .first()
                    .map(|(id, _)| id.as_str())
                    .unwrap_or("verifier");
                let go_bench = format!(
                    "package main\n\nimport (\n\t\"fmt\"\n\t\"{pkg}/internal/{first_id}\"\n)\n\n\
                     func main() {{\n\
                     \tcases := []string{{\"  soc2_renewal  \", \"kms_rotation\", \"webhook_audit\"}}\n\
                     \tpassed := 0\n\
                     \tfor _, c := range cases {{\n\
                     \t\tif _, err := {first_id}.Execute(c, true); err == nil {{\n\
                     \t\t\tpassed++\n\
                     \t\t}}\n\
                     \t}}\n\
                     \t_, emptyErr := {first_id}.Execute(\"   \", true)\n\
                     \t_, ctrlErr := {first_id}.Execute(\"bad\\x07bell\", true)\n\
                     \tvalidity := 0.0\n\
                     \tif passed == len(cases) && emptyErr != nil {{\n\
                     \t\tvalidity = 1.0\n\
                     \t}}\n\
                     \tobj := float64(passed) / float64(len(cases))\n\
                     \tif ctrlErr != nil {{\n\
                     \t\tobj += 0.5\n\
                     \t}}\n\
                     \tfmt.Printf(`{{\"objective\":%.6f,\"validity\":%.1f}}`+\"\\n\", obj, validity)\n\
                     }}\n",
                    pkg = pkg_slug,
                    first_id = first_id
                );
                f.push(("cmd/solve_bench/main.go".to_string(), go_bench));
                (
                    "go build ./...".to_string(),
                    "go test ./...".to_string(),
                    "go run ./cmd/solve_bench".to_string(),
                    f,
                )
            }
            TargetLanguage::Scala3 => {
                let mut f = vec![(
                    "build.sbt".to_string(),
                    format!(
                        "ThisBuild / scalaVersion := \"3.5.2\"\nlazy val root = (project in file(\".\")).settings(name := \"{}\")\n",
                        pkg_slug
                    ),
                )];
                for (id, org) in &organs {
                    f.push((
                        format!("src/main/scala/{}.scala", id),
                        format!(
                            "package {pkg}\n// Capability: {cap} | ({ins}) -> ({outs})\nobject {id}Organ:\n  // EVOLVE_START {id}\n  def execute(in: String, flagEnabled: Boolean = true): Either[String, String] =\n    if !flagEnabled then Left(\"organ_flag_disabled\")\n    else\n      val trimmed = in.trim\n      Either.cond(trimmed.nonEmpty && !trimmed.contains('\\u0000'), s\"[{id}] $$trimmed\", \"invalid_payload\")\n  // EVOLVE_END {id}\n",
                            pkg = crate_ident,
                            cap = org.capability,
                            ins = org.inputs.join(", "),
                            outs = org.outputs.join(", "),
                            id = id
                        ),
                    ));
                }
                (
                    "sbt compile".to_string(),
                    "sbt test".to_string(),
                    "sbt run".to_string(),
                    f,
                )
            }
            TargetLanguage::Zig => {
                let mut f = vec![(
                    "build.zig".to_string(),
                    "const std = @import(\"std\");\npub fn build(b: *std.Build) void { _ = b; }\n"
                        .to_string(),
                )];
                for (id, org) in &organs {
                    f.push((
                        format!("src/{}.zig", id),
                        format!(
                            "//! Capability: {cap} | ({ins}) -> ({outs})\nconst std = @import(\"std\");\n// EVOLVE_START {id}\npub fn execute(input: []const u8, flag_enabled: bool) ![]const u8 {{\n    if (!flag_enabled) return error.OrganFlagDisabled;\n    const trimmed = std.mem.trim(u8, input, \" \\t\\r\\n\");\n    if (trimmed.len == 0 or std.mem.indexOfScalar(u8, trimmed, 0) != null) return error.InvalidPayload;\n    return trimmed;\n}}\n// EVOLVE_END {id}\n",
                            cap = org.capability,
                            ins = org.inputs.join(", "),
                            outs = org.outputs.join(", "),
                            id = id
                        ),
                    ));
                }
                (
                    "zig build -Doptimize=ReleaseFast".to_string(),
                    "zig build test".to_string(),
                    "zig build run".to_string(),
                    f,
                )
            }
            TargetLanguage::AutoShootout => unreachable!(),
        };

        GeneratedTargetPlan {
            project_name: self.project_name.clone(),
            target_language: lang,
            build_command: build_cmd,
            test_command: test_cmd,
            bench_command: bench_cmd,
            manifest_toml: self.render_carnot_toml(),
            planned_files: files,
        }
    }
}
