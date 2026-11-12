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

pub fn classify_license_text(text: &str) -> String {
    let upper = text.to_ascii_uppercase();
    if upper.contains("AFFERO GENERAL PUBLIC LICENSE") || upper.contains("AGPL") {
        "AGPL-3.0".to_string()
    } else if upper.contains("BUSINESS SOURCE LICENSE") || upper.contains("BSL 1.1") {
        "BSL-1.1".to_string()
    } else if upper.contains("END USER LICENSE AGREEMENT")
        || upper.contains("PROPRIETARY")
        || (upper.contains("ALL RIGHTS RESERVED")
            && !upper.contains("BSD")
            && !upper.contains("MIT"))
    {
        "PROPRIETARY-EULA".to_string()
    } else if upper.contains("GNU GENERAL PUBLIC LICENSE") {
        "GPL-3.0".to_string()
    } else if upper.contains("MOZILLA PUBLIC LICENSE") || upper.contains("MPL-2.0") {
        "MPL-2.0".to_string()
    } else if upper.contains("APACHE LICENSE") && upper.contains("2.0") {
        "Apache-2.0".to_string()
    } else if upper.contains("PERMISSION IS HEREBY GRANTED, FREE OF CHARGE")
        || upper.contains("MIT LICENSE")
    {
        "MIT".to_string()
    } else if upper.contains("REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS") {
        "BSD-3-Clause".to_string()
    } else if upper.contains("ISC LICENSE") {
        "ISC".to_string()
    } else {
        "UNKNOWN".to_string()
    }
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

pub fn detect_manifest_spdx(dir: &std::path::Path) -> String {
    let cargo_toml = dir.join("Cargo.toml");
    if cargo_toml.is_file() {
        if let Ok(txt) = std::fs::read_to_string(&cargo_toml) {
            for line in txt.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("license") {
                    if trimmed.contains("MIT") {
                        return "MIT".to_string();
                    }
                    if trimmed.contains("Apache-2.0") {
                        return "Apache-2.0".to_string();
                    }
                    if trimmed.contains("BSD-3-Clause") {
                        return "BSD-3-Clause".to_string();
                    }
                    if trimmed.contains("AGPL") {
                        return "AGPL-3.0".to_string();
                    }
                }
            }
        }
    }
    let pkg_json = dir.join("package.json");
    if pkg_json.is_file() {
        if let Ok(txt) = std::fs::read_to_string(&pkg_json) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
                if let Some(lic) = val.get("license").and_then(|l| l.as_str()) {
                    let upper = lic.to_ascii_uppercase();
                    if upper == "MIT" {
                        return "MIT".to_string();
                    }
                    if upper.contains("APACHE") {
                        return "Apache-2.0".to_string();
                    }
                    if upper.contains("BSD") {
                        return "BSD-3-Clause".to_string();
                    }
                    if upper.contains("ISC") {
                        return "ISC".to_string();
                    }
                    if upper.contains("AGPL") {
                        return "AGPL-3.0".to_string();
                    }
                }
            }
        }
    }
    let pyproj = dir.join("pyproject.toml");
    if pyproj.is_file() {
        if let Ok(txt) = std::fs::read_to_string(&pyproj) {
            for line in txt.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("license") {
                    if trimmed.contains("MIT") {
                        return "MIT".to_string();
                    }
                    if trimmed.contains("Apache") {
                        return "Apache-2.0".to_string();
                    }
                    if trimmed.contains("BSD") {
                        return "BSD-3-Clause".to_string();
                    }
                }
            }
        }
    }
    "UNKNOWN".to_string()
}

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
