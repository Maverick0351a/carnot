//! Python spec extraction, spec-only generate, and example replay.

use carnot::evidence::sha256_hex;
use carnot::spec::verbatim_ngram_hits;
use serde_json::Value;
use std::fs;
use std::process::Command;

#[path = "support/tempdir.rs"]
mod tempdir;

fn temp_dir(label: &str) -> (std::path::PathBuf, tempdir::TempDirGuard) {
    tempdir::temp_dir("carnot-spec", label)
}

fn write_fixture(root: &std::path::Path) {
    let pkg = root.join("sample");
    fs::create_dir_all(&pkg).unwrap();
    fs::write(pkg.join("__init__.py"), "").unwrap();
    fs::write(
        pkg.join("calc.py"),
        r#"
MODE = "plain"

def greet(name, lang="en"):
    """Greet someone."""
    greet_body_sentinel_aaa = name
    greet_body_sentinel_bbb = lang
    return "hi " + greet_body_sentinel_aaa

def paint(color, mode=MODE):
    """Paint a color."""
    paint_body_sentinel_aaa = color
    paint_body_sentinel_bbb = mode
    return paint_body_sentinel_aaa

def add(a, b):
    """Add two numbers."""
    alpha = a
    beta = b
    gamma = alpha + beta
    delta = gamma
    epsilon = delta
    zeta = epsilon
    eta = zeta
    theta = eta
    iota = theta
    kappa = iota
    lambda_ = kappa
    mu = lambda_
    return mu

def _hidden():
    return 0

def neg(n):
    """
    Negate.

    >>> neg(1)
    -1
    """
    nu = -n
    xi = nu
    omicron = xi
    pi = omicron
    rho = pi
    sigma = rho
    tau = sigma
    upsilon = tau
    phi = upsilon
    chi = phi
    psi = chi
    omega = psi
    return omega

class Box:
    """A box."""
    def __init__(self, value):
        self.value = value

    def twice(self):
        sentinel_method_body_aaa = self.value
        sentinel_method_body_bbb = sentinel_method_body_aaa
        return sentinel_method_body_bbb
"#,
    )
    .unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/test_calc.py"),
        r#"
import unittest
from sample.calc import add

class T(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(1, 2), 3)

def test_add_again():
    assert add(2, 3) == 5

def test_defaults():
    assert greet("ada") == "hi ada"
    assert paint("red") == "red"

import pytest
@pytest.mark.parametrize("a,b,expected", [(4, 5, 9)])
def test_param(a, b, expected):
    assert add(a, b) == expected
"#,
    )
    .unwrap();
}

#[test]
fn spec_generate_and_verify_round_trip_without_copying_bodies() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (work, _guard) = temp_dir("lib");
    let root = work.join("lib");
    fs::create_dir_all(&root).unwrap();
    write_fixture(&root);
    let spec_path = work.join("library.carnot-spec.json");
    let spec_out = Command::new(exe)
        .args([
            "spec",
            "--holdout",
            "0.4",
            root.to_str().unwrap(),
            "--out",
            spec_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let spec_err = String::from_utf8_lossy(&spec_out.stderr);
    assert!(
        spec_out.status.success(),
        "{spec_err}\n{}",
        String::from_utf8_lossy(&spec_out.stdout)
    );
    let spec_text = fs::read_to_string(&spec_path).unwrap();
    assert!(spec_text.contains("add(a, b)"), "{spec_text}");
    assert!(spec_text.contains("Add two numbers."), "{spec_text}");
    assert!(spec_text.contains("neg(n)"), "{spec_text}");
    assert!(spec_text.contains("\"Box\""), "{spec_text}");
    assert!(!spec_text.contains("_hidden"), "{spec_text}");
    assert!(!spec_text.contains("lambda_"), "{spec_text}");
    assert!(
        !spec_text.contains("sentinel_method_body_aaa"),
        "{spec_text}"
    );
    assert!(
        !spec_text.contains("greet_body_sentinel_aaa"),
        "{spec_text}"
    );
    assert!(
        !spec_text.contains("paint_body_sentinel_aaa"),
        "{spec_text}"
    );
    assert!(spec_text.contains("\"3\""), "{spec_text}");
    assert!(spec_text.contains("\"-1\""), "{spec_text}");

    fs::write(
        root.join("sample/leaked.py"),
        "def leaked():\n    return 'LEAKED_FROM_ORIGIN_TREE'\n",
    )
    .unwrap();

    let rebuild = work.join("rebuild");
    let gen = Command::new(exe)
        .args([
            "generate",
            rebuild.to_str().unwrap(),
            "--spec",
            spec_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let gen_err = String::from_utf8_lossy(&gen.stderr);
    let gen_out = String::from_utf8_lossy(&gen.stdout);
    assert!(gen.status.success(), "{gen_err}\n{gen_out}");
    let certificate: Value = serde_json::from_str(&gen_out).unwrap();
    assert_eq!(certificate["spec_only"], true);
    assert_eq!(certificate["language"], "python");
    assert_eq!(certificate["generator"], "prototype_example_table");
    assert_eq!(
        certificate["spec_sha256"],
        sha256_hex(&fs::read(&spec_path).unwrap())
    );
    assert!(certificate.get("verbatim_overlap").is_none());
    let on_disk: Value =
        serde_json::from_str(&fs::read_to_string(rebuild.join("carnot.rebuild.json")).unwrap())
            .unwrap();
    assert_eq!(on_disk["spec_sha256"], certificate["spec_sha256"]);

    let spec_json: Value = serde_json::from_str(&spec_text).unwrap();
    let mut held = Vec::new();
    let mut train = Vec::new();
    for module in spec_json["modules"].as_array().unwrap() {
        for func in module["functions"].as_array().unwrap() {
            for example in func["examples"].as_array().unwrap() {
                let expected = example["expected"].as_str().unwrap().to_string();
                if example["held_out"].as_bool().unwrap() {
                    held.push(expected);
                } else {
                    train.push(expected);
                }
            }
        }
    }
    assert!(
        !held.is_empty(),
        "default holdout should withhold at least one example: {spec_text}"
    );
    let generated = fs::read_to_string(rebuild.join("sample/calc.py")).unwrap();
    assert!(generated.contains("Add two numbers."), "{generated}");
    for expected in &train {
        assert!(
            generated.contains(&format!("return {expected}")),
            "training example {expected} missing from {generated}"
        );
    }
    for expected in &held {
        if !train.contains(expected) {
            assert!(
                !generated.contains(&format!("return {expected}")),
                "held-out example {expected} was compiled into {generated}"
            );
        }
    }
    assert!(!generated.contains("lambda_"), "{generated}");
    assert!(
        !generated.contains("sentinel_method_body_aaa"),
        "{generated}"
    );
    assert!(
        !generated.contains("greet_body_sentinel_aaa"),
        "{generated}"
    );
    assert!(!generated.contains("MODE"), "{generated}");
    assert!(
        generated.contains("return 'hi ada'") || generated.contains("return \"hi ada\""),
        "{generated}"
    );
    assert!(
        !generated.contains("LEAKED_FROM_ORIGIN_TREE"),
        "{generated}"
    );
    let tree = fs::read_to_string(rebuild.join("sample/calc.py")).unwrap()
        + &fs::read_to_string(rebuild.join("sample/__init__.py")).unwrap_or_default();
    assert!(!tree.contains("LEAKED_FROM_ORIGIN_TREE"));

    let verify = Command::new(exe)
        .args([
            "verify",
            rebuild.to_str().unwrap(),
            "--against",
            spec_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let verify_err = String::from_utf8_lossy(&verify.stderr);
    let verify_out = String::from_utf8_lossy(&verify.stdout);
    assert_eq!(verify.status.code(), Some(1), "{verify_err}\n{verify_out}");
    let report: Value = serde_json::from_str(&verify_out).unwrap();
    assert_eq!(report["checks_executed"], true);
    assert_eq!(report["demo"], false);
    assert_eq!(report["held_out_passed"], 0);
    assert_eq!(report["held_out_failed"], held.len() as u64);
    assert_eq!(report["failed"], held.len() as u64);
    assert_eq!(report["passed"], 0);
    let graded_all = Command::new(exe)
        .args([
            "verify",
            "--all",
            rebuild.to_str().unwrap(),
            "--against",
            spec_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let all_out = String::from_utf8_lossy(&graded_all.stdout);
    let all: Value = serde_json::from_str(&all_out).unwrap();
    assert_eq!(all["held_out_failed"], held.len() as u64, "{all}");
    assert_eq!(all["held_out_passed"], 0);
    assert!(
        all["passed"].as_u64().unwrap() >= train.len() as u64,
        "{all}"
    );
    assert_eq!(report["certificate"]["spec_only"], true);
    assert_eq!(
        report["certificate"]["spec_sha256"],
        certificate["spec_sha256"]
    );
    assert_eq!(report["certificate"]["verbatim_overlap"], false);
    assert_eq!(report["certificate"]["verbatim_ngram_hits"], 0);
    assert!(!rebuild.join(".carnot").exists());
}

#[test]
fn generate_rejects_a_param_that_is_not_an_identifier() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("inject");
    let spec = root.join("evil.json");
    fs::write(
        &spec,
        r#"{"language":"python","origin_name":"evil","modules":[{"name":"evil","functions":[{"name":"evil","signature":"evil(x)","params":["):\n    import os"],"lookup":true,"examples":[]}]}]}"#,
    )
    .unwrap();
    let out = Command::new(exe)
        .args([
            "generate",
            root.join("out").to_str().unwrap(),
            "--spec",
            spec.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("refusing parameter"), "{err}");
    assert!(!root.join("out").join("evil.py").exists());
}

#[test]
fn spec_rejects_a_non_python_tree() {
    let exe = env!("CARGO_BIN_EXE_carnot");
    let (root, _guard) = temp_dir("not-py");
    fs::write(root.join("README.md"), "hello\n").unwrap();
    let out = Command::new(exe)
        .args(["spec", root.to_str().unwrap(), "--out", "ignored.json"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Python"),
        "expected a Python-only message, got {err}"
    );
}

#[test]
fn verbatim_overlap_flags_a_long_shared_run() {
    let (root, _guard) = temp_dir("grams");
    let origin = root.join("origin");
    let generated = root.join("generated");
    fs::create_dir_all(origin.join("pkg")).unwrap();
    fs::create_dir_all(generated.join("pkg")).unwrap();
    let sentence = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu\n";
    fs::write(origin.join("pkg/mod.py"), sentence).unwrap();
    fs::write(
        generated.join("pkg/mod.py"),
        format!("def f():\n    return 1\n# {sentence}"),
    )
    .unwrap();
    assert_eq!(verbatim_ngram_hits(&origin, &generated), 0);
    fs::write(
        generated.join("pkg/mod.py"),
        format!("def f():\n    {sentence}return 1\n"),
    )
    .unwrap();
    assert!(verbatim_ngram_hits(&origin, &generated) > 0);
}
