//! Capability & Commercial Entitlement Gate (`Community` vs `Pro` / `Enterprise`).
//!
//! Isolates the high-value commercial differentiators behind a clean entitlement boundary:
//! 1. Multi-repo Signal-to-Bloat Scouting & Polyglot Pareto Shootouts (`ProFeature::MultiRepoScoutShootout`)
//! 2. Exportable SHA-256 Clean-Room IP Provenance Certificates (`ProFeature::CleanRoomAttestationCert`)
//! 3. Live Strangler-Fig Canary Cutover + `<0.1 ms` Auto-Kill-Switch (`ProFeature::LiveStranglerCutover`)
//! 4. Scoped 3-Island Organ Evolution + SHA-256 Experience Cards (`ProFeature::OrganIslandEvolution`)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountTier {
    Community,
    Pro,
    Enterprise,
}

impl AccountTier {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "community" | "free" | "open" => Self::Community,
            "enterprise" | "ent" => Self::Enterprise,
            _ => Self::Pro,
        }
    }

    pub fn allows(self, feature: ProFeature) -> bool {
        match self {
            Self::Community => false,
            Self::Pro | Self::Enterprise => {
                let _ = feature;
                true
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProFeature {
    MultiRepoScoutShootout,
    CleanRoomAttestationCert,
    LiveStranglerCutover,
    OrganIslandEvolution,
}

impl ProFeature {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::MultiRepoScoutShootout => "Multi-Repo Signal-to-Bloat Scout & Polyglot Shootout",
            Self::CleanRoomAttestationCert => "SHA-256 Clean-Room IP Provenance Certificate",
            Self::LiveStranglerCutover => {
                "Live MurmurHash3 Canary Cutover & <0.1ms Auto-Kill-Switch"
            }
            Self::OrganIslandEvolution => "Scoped 3-Island Organ Evolution & Experience Cards",
        }
    }

    pub fn require(self, tier: AccountTier) -> Result<(), String> {
        if tier.allows(self) {
            Ok(())
        } else {
            Err(format!(
                "Pro Account Required: '{}' is gated to Carnot Pro / Enterprise (current tier: Community).",
                self.display_name()
            ))
        }
    }
}
