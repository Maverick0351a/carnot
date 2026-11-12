use carnot::rollout::{FeatureState, RolloutContext, VariantPayload};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpecSuite {
    name: String,
    state: FeatureState,
    #[serde(default)]
    tests: Vec<ToggleTestCase>,
    #[serde(default)]
    variant_tests: Vec<VariantTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToggleTestCase {
    description: String,
    context: RolloutContext,
    toggle_name: String,
    expected_result: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedVariant {
    name: String,
    #[serde(default)]
    payload: Option<VariantPayload>,
    enabled: bool,
    #[serde(default, alias = "feature_enabled")]
    feature_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VariantTestCase {
    description: String,
    context: RolloutContext,
    toggle_name: String,
    expected_result: ExpectedVariant,
}

#[test]
fn passes_all_22_feature_toggle_client_specification_suites() {
    let mut specs_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    specs_dir.push("specs");
    specs_dir.push("feature_toggle_v2");

    let index_raw = fs::read_to_string(specs_dir.join("index.json"))
        .expect("read specs/feature_toggle_v2/index.json");
    let suite_files: Vec<String> = serde_json::from_str(&index_raw).expect("parse index.json");
    assert_eq!(
        suite_files.len(),
        22,
        "Expected all 22 feature-toggle client specification v6.2.1 suites"
    );

    let mut total_toggle_cases = 0usize;
    let mut total_variant_cases = 0usize;

    for filename in &suite_files {
        let raw = fs::read_to_string(specs_dir.join(filename))
            .unwrap_or_else(|e| panic!("Failed reading {}: {}", filename, e));
        let suite: SpecSuite = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("Failed parsing {}: {}", filename, e));

        for tc in &suite.tests {
            let actual = suite.state.is_enabled(&tc.toggle_name, &tc.context);
            assert_eq!(
                actual, tc.expected_result,
                "[Suite {} ({})] Toggle '{}' failed: {}",
                filename, suite.name, tc.toggle_name, tc.description
            );
            total_toggle_cases += 1;
        }

        for vc in &suite.variant_tests {
            let actual = suite.state.get_variant(&vc.toggle_name, &vc.context);
            assert_eq!(
                actual.name, vc.expected_result.name,
                "[Suite {} ({})] Variant name '{}' failed: {}",
                filename, suite.name, vc.toggle_name, vc.description
            );
            assert_eq!(
                actual.enabled, vc.expected_result.enabled,
                "[Suite {} ({})] Variant enabled '{}' failed: {}",
                filename, suite.name, vc.toggle_name, vc.description
            );
            assert_eq!(
                actual.payload, vc.expected_result.payload,
                "[Suite {} ({})] Variant payload '{}' failed: {}",
                filename, suite.name, vc.toggle_name, vc.description
            );
            if let Some(expected_fe) = vc.expected_result.feature_enabled {
                assert_eq!(
                    actual.feature_enabled, expected_fe,
                    "[Suite {} ({})] Variant feature_enabled '{}' failed: {}",
                    filename, suite.name, vc.toggle_name, vc.description
                );
            }
            total_variant_cases += 1;
        }
    }

    assert!(
        total_toggle_cases + total_variant_cases >= 290,
        "Expected >= 290 conformance vectors across 22 suites, got {}",
        total_toggle_cases + total_variant_cases
    );
}

#[test]
fn re2_lite_resists_catastrophic_backtracking_and_rejects_pcre_extensions() {
    use carnot::rollout::re2_lite::CompiledRegex;

    // PCRE lookaround & backreferences must fail closed at compile time
    assert!(CompiledRegex::compile("^(?=a)a$", false).is_err());
    assert!(CompiledRegex::compile("^(?!b)a$", false).is_err());
    assert!(CompiledRegex::compile("(?<=a)b", false).is_err());
    assert!(CompiledRegex::compile("^(a+)\\1$", false).is_err());

    // Pathological ReDoS input `(a+)+b` against 200 'a's runs in microseconds on Thompson NFA
    let re = CompiledRegex::compile("^(a+)+b$", false).expect("valid RE2");
    let t0 = std::time::Instant::now();
    let evil_input = "a".repeat(200);
    assert!(!re.is_match(&evil_input));
    assert!(
        t0.elapsed().as_millis() < 50,
        "Thompson NFA took {}ms on pathological input",
        t0.elapsed().as_millis()
    );
}
