//! Python spec extraction, spec-only generate, and example replay.

use carnot::evidence::sha256_hex;
use carnot::spec::verbatim_ngram_hits;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(label: &str) -> (PathBuf, TempDirGuard) {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("carnot-spec-{label}-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let guard = TempDirGuard(root.clone());
    (root, guard)
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
    assert_eq!(certificate["generator"], "python_example_table");
    assert_eq!(
        certificate["spec_sha256"],
        sha256_hex(&fs::read(&spec_path).unwrap())
    );
    assert!(certificate.get("verbatim_overlap").is_none());
    let on_disk: Value =
        serde_json::from_str(&fs::read_to_string(rebuild.join("carnot.rebuild.json")).unwrap())
            .unwrap();
    assert_eq!(on_disk["spec_sha256"], certificate["spec_sha256"]);

    let generated = fs::read_to_string(rebuild.join("sample/calc.py")).unwrap();
    assert!(generated.contains("Add two numbers."), "{generated}");
    assert!(generated.contains("return 3"), "{generated}");
    assert!(generated.contains("return -1"), "{generated}");
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
    assert!(verify.status.success(), "{verify_err}\n{verify_out}");
    let report: Value = serde_json::from_str(&verify_out).unwrap();
    assert_eq!(report["checks_executed"], true);
    assert_eq!(report["demo"], false);
    assert_eq!(report["failed"], 0);
    assert!(report["passed"].as_u64().unwrap() >= 6, "{report}");
    assert_eq!(report["exit_code"], 0);
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
