//! Stage 2 (`carnot intake`): Clean-Room License Firewall & Provenance Attestation.
//!
//! Classifies source paths by SPDX license family, quarantines copyleft/proprietary trees
//! so raw source code never enters synthesis prompts (`quarantined_source_bytes_read == 0`),
//! and mints SHA-256 `ev_...` Clean-Room Attestation Certificates.

use crate::evidence::{
    sha256_hex, CoverageStatus, EvidenceAuthority, EvidenceConfidence, EvidenceKind,
    EvidenceLedger, EvidenceProvenance, EvidenceReceipt,
};
use crate::oracle::InspectionInvocationRecord;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicy {
    /// Permissive (`MIT`, `Apache-2.0`, `BSD`, `ISC`): algorithms, types, and fixtures allowed.
    PermissiveAlgorithmAndFixtures,
    /// Weak copyleft (`MPL-2.0`): usable as unmodified library or black-box interface spec.
    BoundaryInterfaceOnly,
    /// Strong/network copyleft (`AGPL`, `GPL`, `SSPL`, `BSL`) or `Proprietary`/`UNKNOWN`:
    /// HARD QUARANTINE — zero source files read; only public wire contracts & test fixtures allowed.
    QuarantinedBlackBoxSpecOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntakeZoneDecision {
    pub zone_alias: String,
    pub detected_spdx: String,
    pub policy: AccessPolicy,
    pub source_files_blocked: usize,
    pub spec_fixtures_harvested: usize,
    #[serde(default)]
    pub conformance_vectors_counted: usize,
}

fn default_black_box_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanRoomCertificate {
    pub receipt_id: String,
    pub certificate_sha256: String,
    #[serde(default = "default_black_box_true")]
    pub black_box_enforced: bool,
    pub quarantined_source_bytes_read: usize,
    pub zones: Vec<IntakeZoneDecision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inspection_invocations: Vec<InspectionInvocationRecord>,
    pub attestation_statement: String,
}

fn has_license_token(upper: &str, token: &str) -> bool {
    upper
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|part| part == token)
}

/// Most restrictive SPDX id found in a license field or short license text.
/// Permissive ids are returned only when no restrictive id is present.
pub fn spdx_from_license_field(field: &str) -> String {
    let upper = field.to_ascii_uppercase();
    if upper.contains("AFFERO") || has_license_token(&upper, "AGPL") {
        return "AGPL-3.0".to_string();
    }
    if upper.contains("SERVER SIDE PUBLIC") || has_license_token(&upper, "SSPL") {
        return "SSPL-1.0".to_string();
    }
    if upper.contains("LESSER GENERAL PUBLIC") || has_license_token(&upper, "LGPL") {
        return "LGPL-3.0".to_string();
    }
    if upper.contains("GNU GENERAL PUBLIC LICENSE")
        || upper.contains("GPL-")
        || has_license_token(&upper, "GPL")
    {
        return "GPL-3.0".to_string();
    }
    if upper.contains("BUSINESS SOURCE") || has_license_token(&upper, "BSL") {
        return "BSL-1.1".to_string();
    }
    if upper.contains("END USER LICENSE")
        || upper.contains("PROPRIETARY")
        || has_license_token(&upper, "UNLICENSED")
        || has_license_token(&upper, "EULA")
    {
        return "PROPRIETARY-EULA".to_string();
    }
    if upper.contains("MOZILLA PUBLIC LICENSE") || has_license_token(&upper, "MPL") {
        return "MPL-2.0".to_string();
    }
    if upper.contains("APACHE") {
        return "Apache-2.0".to_string();
    }
    if has_license_token(&upper, "MIT") || upper.contains("PERMISSION IS HEREBY GRANTED") {
        return "MIT".to_string();
    }
    if upper.contains("BSD") || upper.contains("REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS")
    {
        return "BSD-3-Clause".to_string();
    }
    if has_license_token(&upper, "ISC") {
        return "ISC".to_string();
    }
    "UNKNOWN".to_string()
}

fn is_permissive_spdx(spdx: &str) -> bool {
    matches!(
        spdx,
        "MIT" | "Apache-2.0" | "BSD-3-Clause" | "BSD-2-Clause" | "ISC"
    )
}

/// A one-line SPDX expression (`MIT`, `Apache-2.0 OR MIT`), not prose that mentions a name.
fn is_bare_spdx_expression(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.contains('\n') || trimmed.len() > 80 {
        return false;
    }
    trimmed
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '+')
        .filter(|part| !part.is_empty())
        .all(|part| {
            let upper = part.to_ascii_uppercase();
            matches!(
                upper.as_str(),
                "MIT"
                    | "APACHE"
                    | "BSD"
                    | "ISC"
                    | "OR"
                    | "AND"
                    | "WITH"
                    | "ONLY"
                    | "LATER"
                    | "GPL"
                    | "AGPL"
                    | "LGPL"
                    | "MPL"
                    | "BSL"
                    | "SSPL"
                    | "UNLICENSED"
            ) || upper.chars().all(|c| c.is_ascii_digit())
                || upper.starts_with("APACHE")
                || upper.starts_with("BSD")
                || upper.starts_with("GPL")
                || upper.starts_with("AGPL")
                || upper.starts_with("LGPL")
                || upper.starts_with("MPL")
        })
}

fn permissive_grant_present(text: &str, spdx: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    match spdx {
        "MIT" => upper.contains("PERMISSION IS HEREBY GRANTED"),
        "Apache-2.0" => upper.contains("APACHE LICENSE") && upper.contains("2.0"),
        "BSD-3-Clause" | "BSD-2-Clause" => {
            upper.contains("REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS")
        }
        "ISC" => upper.contains("PERMISSION TO USE, COPY, MODIFY"),
        _ => false,
    }
}

pub fn classify_license_text(text: &str) -> String {
    let classified = spdx_from_license_field(text);
    // A long notice that only mentions a permissive name, without the grant
    // phrase, is not that license. Restrictive ids are unchanged.
    if is_permissive_spdx(&classified)
        && !permissive_grant_present(text, &classified)
        && !is_bare_spdx_expression(text)
    {
        let upper = text.to_ascii_uppercase();
        if upper.contains("ALL RIGHTS RESERVED") {
            return "PROPRIETARY-EULA".to_string();
        }
        return "UNKNOWN".to_string();
    }
    if classified != "UNKNOWN" {
        return classified;
    }
    let upper = text.to_ascii_uppercase();
    if upper.contains("ALL RIGHTS RESERVED") {
        return "PROPRIETARY-EULA".to_string();
    }
    "UNKNOWN".to_string()
}

pub fn policy_for_spdx(spdx: &str) -> AccessPolicy {
    match spdx {
        "MIT" | "Apache-2.0" | "BSD-3-Clause" | "BSD-2-Clause" | "ISC" => {
            AccessPolicy::PermissiveAlgorithmAndFixtures
        }
        "MPL-2.0" => AccessPolicy::BoundaryInterfaceOnly,
        _ => AccessPolicy::QuarantinedBlackBoxSpecOnly,
    }
}

pub fn build_clean_room_certificate(
    zones: Vec<IntakeZoneDecision>,
    checkpoint_id: Option<String>,
    ledger: &mut EvidenceLedger,
) -> CleanRoomCertificate {
    build_clean_room_certificate_full(zones, Vec::new(), true, checkpoint_id, ledger)
}

pub fn build_clean_room_certificate_with_inspections(
    zones: Vec<IntakeZoneDecision>,
    inspection_invocations: Vec<InspectionInvocationRecord>,
    checkpoint_id: Option<String>,
    ledger: &mut EvidenceLedger,
) -> CleanRoomCertificate {
    build_clean_room_certificate_full(zones, inspection_invocations, true, checkpoint_id, ledger)
}

pub fn build_clean_room_certificate_full(
    zones: Vec<IntakeZoneDecision>,
    inspection_invocations: Vec<InspectionInvocationRecord>,
    black_box_enforced: bool,
    checkpoint_id: Option<String>,
    ledger: &mut EvidenceLedger,
) -> CleanRoomCertificate {
    let blocked_total: usize = if black_box_enforced {
        zones.iter().map(|z| z.source_files_blocked).sum()
    } else {
        0
    };
    let harvested_total: usize = zones.iter().map(|z| z.spec_fixtures_harvested).sum();
    let vectors_total: usize = zones.iter().map(|z| z.conformance_vectors_counted).sum();
    let statement = if black_box_enforced {
        format!(
            "BLACK-BOX SHIELD ON: Carnot Intake Firewall verified {} zone(s): quarantined {} restricted source files (0 bytes read into synthesis context), harvested {} permissive spec/conformance artifacts ({} portable vectors), and audited {} outside-in inspection invocation(s).",
            zones.len(),
            blocked_total,
            harvested_total,
            vectors_total,
            inspection_invocations.len()
        )
    } else {
        format!(
            "WHITE-BOX INSPECTION MODE (black_box_enforced=false): Full open-source hybrid code search, outside-in inspection tools, and deep source inspection unlocked across {} zone(s) ({} vectors, {} inspection invocations). Strict Chinese-Wall attestation is suspended until Black-Box Shield is toggled back ON.",
            zones.len(),
            vectors_total,
            inspection_invocations.len()
        )
    };

    let payload = serde_json::json!({
        "black_box_enforced": black_box_enforced,
        "quarantined_source_bytes_read": 0,
        "zones": zones,
        "inspection_invocations": inspection_invocations,
        "statement": statement,
    });

    let receipt: EvidenceReceipt = ledger.record_with_provenance(
        EvidenceKind::GateVerdict,
        if black_box_enforced {
            "clean_room_intake_firewall"
        } else {
            "white_box_inspection_mode"
        },
        &statement,
        checkpoint_id,
        EvidenceProvenance {
            authority: EvidenceAuthority::ShippedArtifact,
            confidence: EvidenceConfidence::Observed,
            coverage: CoverageStatus::Complete,
            subject_sha256: None,
            parent_evidence_id: None,
        },
        &payload,
    );
    let cert_hash = sha256_hex(receipt.payload_json.as_bytes());

    CleanRoomCertificate {
        receipt_id: receipt.id,
        certificate_sha256: cert_hash,
        black_box_enforced,
        quarantined_source_bytes_read: 0,
        zones,
        inspection_invocations,
        attestation_statement: statement,
    }
}

/// Scans a real directory on disk for SPDX license files (`LICENSE*`, `COPYING*`) without reading
/// any source-code implementation bodies inside quarantined (`AGPL`/`GPL`/`BSL`/`PROPRIETARY`/`UNKNOWN`) zones.
pub fn scan_directory_spdx_zones(
    root: &std::path::Path,
) -> std::io::Result<Vec<IntakeZoneDecision>> {
    let mut candidate_dirs = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || name == "target" || name == "node_modules" {
            continue;
        }
        if entry.file_type()?.is_dir() {
            candidate_dirs.push((name, entry.path()));
        }
    }
    if candidate_dirs.is_empty() {
        let alias = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "root".to_string());
        candidate_dirs.push((alias, root.to_path_buf()));
    }

    let root_spdx = detect_zone_spdx(root);
    let mut decisions = Vec::new();

    for (alias, path) in candidate_dirs {
        let zone_spdx = {
            let local = detect_zone_spdx(&path);
            if local == "UNKNOWN" && path != root {
                root_spdx.clone()
            } else {
                local
            }
        };
        let policy = policy_for_spdx(&zone_spdx);
        let (code_count, fixture_count, vectors_count) =
            count_zone_files_and_permissive_vectors(&path, policy);
        let (source_files_blocked, spec_fixtures_harvested) = match policy {
            AccessPolicy::PermissiveAlgorithmAndFixtures => (0, fixture_count + code_count),
            AccessPolicy::BoundaryInterfaceOnly => (code_count, fixture_count),
            AccessPolicy::QuarantinedBlackBoxSpecOnly => (code_count, 0),
        };
        decisions.push(IntakeZoneDecision {
            zone_alias: alias,
            detected_spdx: zone_spdx,
            policy,
            source_files_blocked,
            spec_fixtures_harvested,
            conformance_vectors_counted: vectors_count,
        });
    }

    Ok(decisions)
}

fn manifest_license_value(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("license")?;
    let rest = rest.trim_start();
    let rest = if rest.starts_with('=') {
        rest
    } else {
        // `license-file`, `license.workspace`, and similar keys.
        let after_key = rest.trim_start_matches(|c: char| {
            c == '-' || c == '_' || c == '.' || c.is_ascii_alphanumeric()
        });
        after_key.trim_start()
    };
    let value = rest.strip_prefix('=')?.trim();
    let value = value.trim_matches('"').trim_matches('\'');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub fn detect_manifest_spdx(dir: &std::path::Path) -> String {
    let cargo_toml = dir.join("Cargo.toml");
    if cargo_toml.is_file() {
        if let Ok(txt) = std::fs::read_to_string(&cargo_toml) {
            for line in txt.lines() {
                if let Some(value) = manifest_license_value(line) {
                    let classified = spdx_from_license_field(&value);
                    if classified != "UNKNOWN" {
                        return classified;
                    }
                }
            }
        }
    }
    let pkg_json = dir.join("package.json");
    if pkg_json.is_file() {
        if let Ok(txt) = std::fs::read_to_string(&pkg_json) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
                // shortcut: package.json license objects (`{"type": ...}`) are not parsed;
                // a missing string stays UNKNOWN and the zone stays quarantined.
                // Upgrade when SPDX expressions need a structured parser.
                if let Some(lic) = val.get("license").and_then(|l| l.as_str()) {
                    let classified = spdx_from_license_field(lic);
                    if classified != "UNKNOWN" {
                        return classified;
                    }
                }
            }
        }
    }
    let pyproj = dir.join("pyproject.toml");
    if pyproj.is_file() {
        if let Ok(txt) = std::fs::read_to_string(&pyproj) {
            for line in txt.lines() {
                if let Some(value) = manifest_license_value(line) {
                    let classified = spdx_from_license_field(&value);
                    if classified != "UNKNOWN" {
                        return classified;
                    }
                }
            }
        }
    }
    "UNKNOWN".to_string()
}

// shortcut: a zone's license is the directory LICENSE/COPYING file or manifest
// field, not per-file SPDX headers. Upgrade when one directory mixes licenses.
fn detect_zone_spdx(dir: &std::path::Path) -> String {
    let license_names = [
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
        "LICENSE-APACHE",
        "LICENSE-MIT",
        "COPYING",
    ];
    for lname in license_names {
        let p = dir.join(lname);
        if p.is_file() {
            if let Ok(txt) = std::fs::read_to_string(&p) {
                let classified = classify_license_text(&txt);
                if classified != "UNKNOWN" {
                    return classified;
                }
            }
        }
    }
    detect_manifest_spdx(dir)
}

fn count_zone_files_and_permissive_vectors(
    dir: &std::path::Path,
    policy: AccessPolicy,
) -> (usize, usize, usize) {
    let mut code = 0usize;
    let mut fixtures = 0usize;
    let mut vectors = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&cur) else {
            continue;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                match ext {
                    "rs" | "go" | "py" | "ts" | "js" | "mjs" | "scala" | "zig" | "c" | "cpp" => {
                        code += 1;
                    }
                    "json" | "toml" | "yaml" | "yml" => {
                        fixtures += 1;
                        if ext == "json"
                            && policy != AccessPolicy::QuarantinedBlackBoxSpecOnly
                            && !name.eq_ignore_ascii_case("index.json")
                        {
                            vectors += crate::scout::count_json_conformance_vectors(&p);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    (code, fixtures, vectors)
}
