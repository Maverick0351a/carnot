//! Reconstruction Obligation Ledger & Revisioned Unknowns (`unk_<sha256>`).
//!
//! Enforces three deterministic fail-closed reconstruction laws:
//! 1. **Authenticity:** Every cited `ev_<sha256>` receipt must exist in `EvidenceLedger` and pass
//!    cryptographic SHA-256 payload digest verification.
//! 2. **Authority Hierarchy:** Static artifact observations (`ShippedArtifact` or `Inferred`) can
//!    only register *candidate* obligations — they **cannot** close behavioral `Process`, `Protocol`,
//!    or `Runtime` obligations, which require `ControlledReplay` or `ExternalService` with
//!    `EvidenceConfidence::Observed`.
//! 3. **Applicability:** Proof bindings must cover every required `CaseKind` (`Positive`, `Negative`,
//!    `Malformed`, `Cancellation`, `Teardown`), match the current build's `owner_sha256` when supplied,
//!    contain zero contradictions, and have zero unresolved `UnknownRecord` blockers.

use crate::evidence::{sha256_hex, EvidenceAuthority, EvidenceConfidence, EvidenceLedger};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObligationDomain {
    StaticStructure,
    ApiContract,
    Process,
    Protocol,
    Runtime,
}

impl ObligationDomain {
    pub fn is_behavioral(self) -> bool {
        matches!(self, Self::Process | Self::Protocol | Self::Runtime)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    Positive,
    Negative,
    Malformed,
    Cancellation,
    Teardown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    Candidate,
    Open,
    Verified,
    Contradicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownStatus {
    Open,
    Investigating,
    Resolved,
    Reopened,
}

impl UnknownStatus {
    pub fn is_blocking(self) -> bool {
        matches!(self, Self::Open | Self::Investigating | Self::Reopened)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownRecord {
    pub id: String,
    pub revision: u64,
    pub domain: ObligationDomain,
    pub question: String,
    pub status: UnknownStatus,
    #[serde(default)]
    pub blocking_obligation_ids: Vec<String>,
    #[serde(default)]
    pub supporting_evidence_ids: Vec<String>,
    #[serde(default)]
    pub contradicting_evidence_ids: Vec<String>,
    pub recommended_probe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationProofBinding {
    pub evidence_id: String,
    pub covered_cases: BTreeSet<CaseKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    pub id: String,
    pub version: u32,
    pub surface_id: String,
    pub description: String,
    pub domain: ObligationDomain,
    pub required_authority: EvidenceAuthority,
    pub required_confidence: EvidenceConfidence,
    pub required_cases: BTreeSet<CaseKind>,
    #[serde(default)]
    pub proof_bindings: Vec<ObligationProofBinding>,
    #[serde(default)]
    pub contradiction_notes: Vec<String>,
    pub status: ObligationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationClosureDetail {
    pub obligation_id: String,
    pub surface_id: String,
    pub domain: ObligationDomain,
    pub closed: bool,
    pub missing_cases: Vec<CaseKind>,
    pub blocking_unknown_ids: Vec<String>,
    pub failure_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosureVerdict {
    pub all_closed: bool,
    pub total_obligations: usize,
    pub closed_obligations: usize,
    pub open_unknowns: usize,
    pub coverage_pct: f64,
    pub details: Vec<ObligationClosureDetail>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObligationLedger {
    pub obligations: Vec<Obligation>,
    pub unknowns: Vec<UnknownRecord>,
}

impl ObligationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seeded_for_organs(organ_ids: &[String]) -> Self {
        let mut ledger = Self::new();
        for oid in organ_ids {
            let mut req_cases = BTreeSet::new();
            req_cases.insert(CaseKind::Positive);
            req_cases.insert(CaseKind::Negative);
            req_cases.insert(CaseKind::Malformed);
            ledger.upsert_obligation(Obligation {
                id: format!("obl_{}", oid),
                version: 1,
                surface_id: oid.clone(),
                description: format!(
                    "Verify clean-room behavioral parity for organ '{}' across positive, negative, and malformed inputs.",
                    oid
                ),
                domain: ObligationDomain::Process,
                required_authority: EvidenceAuthority::ControlledReplay,
                required_confidence: EvidenceConfidence::Observed,
                required_cases: req_cases,
                proof_bindings: Vec::new(),
                contradiction_notes: Vec::new(),
                status: ObligationStatus::Open,
            });
        }
        ledger
    }

    pub fn upsert_obligation(&mut self, ob: Obligation) {
        if let Some(existing) = self.obligations.iter_mut().find(|o| o.id == ob.id) {
            *existing = ob;
        } else {
            self.obligations.push(ob);
        }
    }

    pub fn register_unknown(
        &mut self,
        domain: ObligationDomain,
        question: impl Into<String>,
        blocking_obligation_ids: Vec<String>,
        recommended_probe: impl Into<String>,
    ) -> UnknownRecord {
        let q = question.into();
        let digest = sha256_hex(q.as_bytes());
        let id = format!("unk_{}", &digest[..16]);
        if let Some(existing) = self.unknowns.iter().find(|u| u.id == id) {
            return existing.clone();
        }
        let rec = UnknownRecord {
            id,
            revision: 1,
            domain,
            question: q,
            status: UnknownStatus::Open,
            blocking_obligation_ids,
            supporting_evidence_ids: Vec::new(),
            contradicting_evidence_ids: Vec::new(),
            recommended_probe: recommended_probe.into(),
        };
        self.unknowns.push(rec.clone());
        rec
    }

    /// Updates an `UnknownRecord` using optimistic concurrency (`expected_revision`).
    pub fn update_unknown(
        &mut self,
        unknown_id: &str,
        expected_revision: u64,
        next_status: UnknownStatus,
        supporting_evidence_id: Option<String>,
    ) -> Result<UnknownRecord, String> {
        let unk = self
            .unknowns
            .iter_mut()
            .find(|u| u.id == unknown_id)
            .ok_or_else(|| format!("Unknown record '{}' not found", unknown_id))?;

        if unk.revision != expected_revision {
            return Err(format!(
                "Optimistic concurrency conflict on '{}': expected revision {}, found {}",
                unknown_id, expected_revision, unk.revision
            ));
        }

        if next_status == UnknownStatus::Resolved
            && supporting_evidence_id.is_none()
            && unk.supporting_evidence_ids.is_empty()
        {
            return Err(format!(
                "Cannot resolve unknown '{}' without citing supporting evidence",
                unknown_id
            ));
        }

        if let Some(ev_id) = supporting_evidence_id {
            if !unk.supporting_evidence_ids.contains(&ev_id) {
                unk.supporting_evidence_ids.push(ev_id);
            }
        }
        unk.status = next_status;
        unk.revision += 1;
        Ok(unk.clone())
    }

    pub fn bind_proof(
        &mut self,
        obligation_id: &str,
        evidence_id: impl Into<String>,
        covered_cases: BTreeSet<CaseKind>,
        owner_sha256: Option<String>,
    ) -> Result<(), String> {
        let ob = self
            .obligations
            .iter_mut()
            .find(|o| o.id == obligation_id)
            .ok_or_else(|| format!("Obligation '{}' not found", obligation_id))?;
        ob.proof_bindings.push(ObligationProofBinding {
            evidence_id: evidence_id.into(),
            covered_cases,
            owner_sha256,
        });
        if ob.status == ObligationStatus::Candidate {
            ob.status = ObligationStatus::Open;
        }
        Ok(())
    }

    pub fn flag_contradiction(
        &mut self,
        obligation_id: &str,
        note: impl Into<String>,
    ) -> Result<(), String> {
        let ob = self
            .obligations
            .iter_mut()
            .find(|o| o.id == obligation_id)
            .ok_or_else(|| format!("Obligation '{}' not found", obligation_id))?;
        ob.contradiction_notes.push(note.into());
        ob.status = ObligationStatus::Contradicted;
        Ok(())
    }

    /// Evaluates full reconstruction closure across all registered obligations and unknowns.
    pub fn evaluate_closure(
        &mut self,
        evidence: &EvidenceLedger,
        expected_owner_sha256: Option<&str>,
    ) -> ClosureVerdict {
        let open_unknowns_total = self
            .unknowns
            .iter()
            .filter(|u| u.status.is_blocking())
            .count();

        let mut details = Vec::with_capacity(self.obligations.len());
        let mut closed_count = 0usize;

        for ob in &mut self.obligations {
            let mut reasons = Vec::new();
            let mut verified_cases = BTreeSet::new();

            if !ob.contradiction_notes.is_empty() || ob.status == ObligationStatus::Contradicted {
                reasons.push(format!(
                    "Active contradiction(s): {}",
                    ob.contradiction_notes.join("; ")
                ));
            }

            let blocking_unks: Vec<String> = self
                .unknowns
                .iter()
                .filter(|u| {
                    u.status.is_blocking()
                        && (u.blocking_obligation_ids.iter().any(|id| id == &ob.id)
                            || (u.blocking_obligation_ids.is_empty() && u.domain == ob.domain))
                })
                .map(|u| u.id.clone())
                .collect();

            if !blocking_unks.is_empty() {
                reasons.push(format!(
                    "Blocked by {} unresolved unknown(s): {}",
                    blocking_unks.len(),
                    blocking_unks.join(", ")
                ));
            }

            for binding in &ob.proof_bindings {
                let Some(rec) = evidence.get(&binding.evidence_id) else {
                    reasons.push(format!(
                        "Cited evidence '{}' missing from EvidenceLedger",
                        binding.evidence_id
                    ));
                    continue;
                };

                // 1. Authenticity check
                if !rec.verify_digest() {
                    reasons.push(format!(
                        "Cited evidence '{}' failed SHA-256 digest verification",
                        binding.evidence_id
                    ));
                    continue;
                }

                // 2. Authority hierarchy check
                if ob.domain.is_behavioral()
                    && !matches!(
                        rec.authority,
                        EvidenceAuthority::ControlledReplay | EvidenceAuthority::ExternalService
                    )
                {
                    reasons.push(format!(
                        "Evidence '{}' has authority '{:?}' which cannot close behavioral '{:?}' obligation",
                        binding.evidence_id, rec.authority, ob.domain
                    ));
                    continue;
                }
                if rec.authority < ob.required_authority {
                    reasons.push(format!(
                        "Evidence '{}' authority '{:?}' < required '{:?}'",
                        binding.evidence_id, rec.authority, ob.required_authority
                    ));
                    continue;
                }
                if rec.confidence < ob.required_confidence {
                    reasons.push(format!(
                        "Evidence '{}' confidence '{:?}' < required '{:?}'",
                        binding.evidence_id, rec.confidence, ob.required_confidence
                    ));
                    continue;
                }

                // 3. Applicability / owner SHA-256 check
                if let Some(exp_sha) = expected_owner_sha256 {
                    let bound_sha = binding
                        .owner_sha256
                        .as_deref()
                        .or(rec.subject_sha256.as_deref());
                    if bound_sha != Some(exp_sha) {
                        reasons.push(format!(
                            "Evidence '{}' owner_sha256 {:?} does not match current target '{}'",
                            binding.evidence_id, bound_sha, exp_sha
                        ));
                        continue;
                    }
                }

                for ck in &binding.covered_cases {
                    verified_cases.insert(*ck);
                }
            }

            let missing_cases: Vec<CaseKind> = ob
                .required_cases
                .difference(&verified_cases)
                .copied()
                .collect();
            if !missing_cases.is_empty() {
                reasons.push(format!(
                    "Missing required case coverage: {:?}",
                    missing_cases
                ));
            }

            let closed = reasons.is_empty() && blocking_unks.is_empty() && missing_cases.is_empty();
            if closed {
                ob.status = ObligationStatus::Verified;
                closed_count += 1;
            } else if ob.status == ObligationStatus::Verified {
                ob.status = ObligationStatus::Open;
            }

            details.push(ObligationClosureDetail {
                obligation_id: ob.id.clone(),
                surface_id: ob.surface_id.clone(),
                domain: ob.domain,
                closed,
                missing_cases,
                blocking_unknown_ids: blocking_unks,
                failure_reasons: reasons,
            });
        }

        let total = self.obligations.len();
        let coverage_pct = if total == 0 {
            100.0
        } else {
            ((closed_count as f64 / total as f64) * 1000.0).round() / 10.0
        };

        ClosureVerdict {
            all_closed: total > 0 && closed_count == total && open_unknowns_total == 0,
            total_obligations: total,
            closed_obligations: closed_count,
            open_unknowns: open_unknowns_total,
            coverage_pct,
            details,
        }
    }
}
