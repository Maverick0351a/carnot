//! Hash-Backed Evidence Receipt Ledger & Paged Artifact Store (`ev_<sha256>`).
//!
//! Mints immutable SHA-256 content-addressed receipts (`ev_...`) for every evaluation run,
//! gate block, canary promotion, black-box oracle capture, and sub-millisecond circuit-breaker trip,
//! carrying epistemic `authority` and `confidence` provenance plus bounded `offset`/`limit` paging.

use serde::{Deserialize, Serialize};

/// Default MCP single-response byte cap before returning summary + `evidence://<id>` cursor.
pub const DEFAULT_MCP_MAX_BYTES: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Raw telemetry, request bursts, or trace captures.
    Observed,
    /// Computed multi-scorer matrices and 3D Pareto frontiers.
    Derived,
    /// Authoritative promotion approval, gate block, or circuit-breaker rollback.
    GateVerdict,
}

/// Epistemic source authority hierarchy for reconstruction contracts:
/// static `ShippedArtifact` facts cannot close behavioral `Process`/`Protocol`/`Runtime` obligations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceAuthority {
    #[default]
    Inferred,
    ShippedArtifact,
    ControlledReplay,
    ExternalService,
}

/// Confidence tier of an evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    #[default]
    Derived,
    Inferred,
    Observed,
}

/// Coverage completeness of an evidence observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    #[default]
    Complete,
    Partial,
    Unknown,
    Page,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceProvenance {
    #[serde(default)]
    pub authority: EvidenceAuthority,
    #[serde(default)]
    pub confidence: EvidenceConfidence,
    #[serde(default)]
    pub coverage: CoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_evidence_id: Option<String>,
}

impl EvidenceProvenance {
    pub fn for_kind(kind: EvidenceKind) -> Self {
        match kind {
            EvidenceKind::Observed => Self {
                authority: EvidenceAuthority::ControlledReplay,
                confidence: EvidenceConfidence::Observed,
                coverage: CoverageStatus::Complete,
                subject_sha256: None,
                parent_evidence_id: None,
            },
            EvidenceKind::Derived => Self {
                authority: EvidenceAuthority::ShippedArtifact,
                confidence: EvidenceConfidence::Derived,
                coverage: CoverageStatus::Complete,
                subject_sha256: None,
                parent_evidence_id: None,
            },
            EvidenceKind::GateVerdict => Self {
                authority: EvidenceAuthority::ControlledReplay,
                confidence: EvidenceConfidence::Derived,
                coverage: CoverageStatus::Complete,
                subject_sha256: None,
                parent_evidence_id: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReceipt {
    /// Short content-addressed identifier (`ev_<first-16-hex-of-sha256>`).
    pub id: String,
    /// Full 64-character lowercase hex FIPS 180-4 SHA-256 digest of `payload_json`.
    pub sha256: String,
    pub seq: u64,
    pub kind: EvidenceKind,
    pub subject: String,
    pub summary: String,
    /// Optional Git commit SHA or Entire `Checkpoint-Id` trailer tying code provenance to runtime gating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    #[serde(default)]
    pub authority: EvidenceAuthority,
    #[serde(default)]
    pub confidence: EvidenceConfidence,
    #[serde(default)]
    pub coverage: CoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_evidence_id: Option<String>,
    pub byte_len: usize,
    pub payload_json: String,
}

impl EvidenceReceipt {
    /// Verifies cryptographic payload integrity (`sha256_hex(payload_json) == sha256` and `ev_` prefix).
    pub fn verify_digest(&self) -> bool {
        let computed = sha256_hex(self.payload_json.as_bytes());
        computed == self.sha256
            && self.id == format!("ev_{}", &computed[..16])
            && self.byte_len == self.payload_json.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummaryView {
    pub id: String,
    pub sha256: String,
    pub seq: u64,
    pub kind: EvidenceKind,
    pub subject: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    #[serde(default)]
    pub authority: EvidenceAuthority,
    #[serde(default)]
    pub confidence: EvidenceConfidence,
    #[serde(default)]
    pub coverage: CoverageStatus,
    pub byte_len: usize,
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePage {
    pub id: String,
    pub sha256: String,
    pub kind: EvidenceKind,
    pub subject: String,
    pub summary: String,
    pub checkpoint_id: Option<String>,
    pub authority: EvidenceAuthority,
    pub confidence: EvidenceConfidence,
    pub coverage: CoverageStatus,
    pub total_bytes: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
    pub next_offset: Option<usize>,
    pub slice: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceLedger {
    receipts: Vec<EvidenceReceipt>,
    next_seq: u64,
}

impl EvidenceLedger {
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
            next_seq: 1,
        }
    }

    pub fn receipts(&self) -> &[EvidenceReceipt] {
        &self.receipts
    }

    pub fn record(
        &mut self,
        kind: EvidenceKind,
        subject: impl Into<String>,
        summary: impl Into<String>,
        checkpoint_id: Option<String>,
        payload: &serde_json::Value,
    ) -> EvidenceReceipt {
        let prov = EvidenceProvenance::for_kind(kind);
        self.record_with_provenance(kind, subject, summary, checkpoint_id, prov, payload)
    }

    pub fn record_with_provenance(
        &mut self,
        kind: EvidenceKind,
        subject: impl Into<String>,
        summary: impl Into<String>,
        checkpoint_id: Option<String>,
        provenance: EvidenceProvenance,
        payload: &serde_json::Value,
    ) -> EvidenceReceipt {
        let payload_json =
            serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".to_string());
        let digest = sha256_hex(payload_json.as_bytes());
        let id = format!("ev_{}", &digest[..16]);
        let seq = self.next_seq.max(1);
        self.next_seq = seq + 1;

        let receipt = EvidenceReceipt {
            id,
            sha256: digest,
            seq,
            kind,
            subject: subject.into(),
            summary: summary.into(),
            checkpoint_id,
            authority: provenance.authority,
            confidence: provenance.confidence,
            coverage: provenance.coverage,
            subject_sha256: provenance.subject_sha256,
            parent_evidence_id: provenance.parent_evidence_id,
            byte_len: payload_json.len(),
            payload_json,
        };

        self.receipts.insert(0, receipt.clone());
        if self.receipts.len() > 500 {
            self.receipts.truncate(500);
        }
        receipt
    }

    /// Hydrates receipts loaded from `.carnot/ledger.jsonl` (oldest-first or mixed order) without duplicating IDs.
    pub fn hydrate_from_receipts(&mut self, incoming: Vec<EvidenceReceipt>) {
        for rec in incoming {
            if !self.receipts.iter().any(|existing| existing.id == rec.id) {
                if rec.seq >= self.next_seq {
                    self.next_seq = rec.seq + 1;
                }
                self.receipts.push(rec);
            }
        }
        self.receipts.sort_by_key(|a| std::cmp::Reverse(a.seq));
        if self.receipts.len() > 500 {
            self.receipts.truncate(500);
        }
    }

    pub fn receipts_newest_first(&self) -> &[EvidenceReceipt] {
        &self.receipts
    }

    pub fn verify_all_digests(&self) -> Result<(), String> {
        for r in &self.receipts {
            if !r.verify_digest() {
                return Err(format!(
                    "Evidence receipt '{}' failed SHA-256 authenticity check",
                    r.id
                ));
            }
        }
        Ok(())
    }

    pub fn list_summaries(&self) -> Vec<EvidenceSummaryView> {
        self.receipts
            .iter()
            .map(|r| EvidenceSummaryView {
                id: r.id.clone(),
                sha256: r.sha256.clone(),
                seq: r.seq,
                kind: r.kind,
                subject: r.subject.clone(),
                summary: r.summary.clone(),
                checkpoint_id: r.checkpoint_id.clone(),
                authority: r.authority,
                confidence: r.confidence,
                coverage: r.coverage,
                byte_len: r.byte_len,
                uri: format!("evidence://{}", r.id),
            })
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<&EvidenceReceipt> {
        let normalized = id.strip_prefix("evidence://").unwrap_or(id);
        self.receipts.iter().find(|r| r.id == normalized)
    }

    pub fn browse(&self, id: &str, offset: usize, limit: usize) -> Option<EvidencePage> {
        let r = self.get(id)?;
        let bytes = r.payload_json.as_bytes();
        let total = bytes.len();
        let clamped_limit = limit.clamp(64, 65_536);
        let start = offset.min(total);
        let end = (start + clamped_limit).min(total);
        let slice = String::from_utf8_lossy(&bytes[start..end]).into_owned();
        let has_more = end < total;

        Some(EvidencePage {
            id: r.id.clone(),
            sha256: r.sha256.clone(),
            kind: r.kind,
            subject: r.subject.clone(),
            summary: r.summary.clone(),
            checkpoint_id: r.checkpoint_id.clone(),
            authority: r.authority,
            confidence: r.confidence,
            coverage: r.coverage,
            total_bytes: total,
            offset: start,
            limit: clamped_limit,
            has_more,
            next_offset: if has_more { Some(end) } else { None },
            slice,
        })
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
}

/// Pure-Rust FIPS 180-4 SHA-256 implementation (zero external crate dependencies).
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (slot, word_bytes) in w.iter_mut().take(16).zip(chunk.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*word_bytes);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for word in h {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:08x}", word);
    }
    out
}
