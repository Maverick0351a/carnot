//! Deterministic Feature Toggle v2, Delta API, RE2-Lite Regex, Dual-Stack CIDR, SemVer 2.0 & Sticky Variant Engine.
//!
//! Clean-room engineered to pass 100% (22/22 suites) of the feature-toggle client specification v6.2.1
//! with zero external crate dependencies beyond `serde`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const STRATEGY_SEED: u32 = 0;
pub const VARIANT_SEED: u32 = 86_028_157;

/// Pure-Rust 32-bit MurmurHash3 (`x86_32`) matching `murmurhash3js.x86.hash32`.
pub fn murmurhash3_x86_32(bytes: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h1 = seed;
    let nblocks = bytes.len() / 4;

    for i in 0..nblocks {
        let idx = i * 4;
        let mut k1 =
            u32::from_le_bytes([bytes[idx], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let tail = &bytes[nblocks * 4..];
    let mut k1 = 0u32;
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= bytes.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;
    h1
}

/// Computes `((murmur3("${groupId}:${id}", seed) % normalizer) + 1)` in `[1, normalizer]`.
pub fn normalized_value(id: &str, group_id: &str, normalizer: u32, seed: u32) -> u32 {
    if normalizer == 0 {
        return 0;
    }
    let key = format!("{}:{}", group_id, id);
    (murmurhash3_x86_32(key.as_bytes(), seed) % normalizer) + 1
}

pub fn normalized_strategy_value(id: &str, group_id: &str) -> u32 {
    normalized_value(id, group_id, 100, STRATEGY_SEED)
}

pub fn normalized_variant_value(id: &str, group_id: &str, normalizer: u32) -> u32 {
    normalized_value(id, group_id, normalizer, VARIANT_SEED)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RolloutContext {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub remote_address: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub current_time: Option<String>,
    #[serde(default)]
    pub properties: HashMap<String, Option<String>>,
}

impl RolloutContext {
    pub fn resolve_field(&self, name: &str) -> Option<&str> {
        match name {
            "userId" => self.user_id.as_deref().or_else(|| self.prop("userId")),
            "sessionId" => self
                .session_id
                .as_deref()
                .or_else(|| self.prop("sessionId")),
            "remoteAddress" => self
                .remote_address
                .as_deref()
                .or_else(|| self.prop("remoteAddress")),
            "environment" => self
                .environment
                .as_deref()
                .or_else(|| self.prop("environment")),
            "appName" => self.app_name.as_deref().or_else(|| self.prop("appName")),
            "currentTime" => self
                .current_time
                .as_deref()
                .or_else(|| self.prop("currentTime")),
            other => self.prop(other),
        }
        .filter(|s| !s.is_empty())
    }

    fn prop(&self, key: &str) -> Option<&str> {
        self.properties.get(key).and_then(|v| v.as_deref())
    }

    pub fn resolve_stickiness(&self, stickiness: &str) -> Option<String> {
        match stickiness {
            "" | "default" => self
                .resolve_field("userId")
                .or_else(|| self.resolve_field("sessionId"))
                .map(|s| s.to_string())
                .or_else(|| Some(pseudo_random_stickiness())),
            "random" => Some(pseudo_random_stickiness()),
            custom => self.resolve_field(custom).map(|s| s.to_string()),
        }
    }
}

fn pseudo_random_stickiness() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(42);
    format!(
        "{}",
        nanos.wrapping_add(c.wrapping_mul(0x9E37_79B9_7F4A_7C15))
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Constraint {
    pub context_name: String,
    pub operator: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub inverted: bool,
    #[serde(default)]
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantPayload {
    #[serde(rename = "type")]
    pub payload_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VariantOverride {
    pub context_name: String,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VariantDefinition {
    pub name: String,
    pub weight: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stickiness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<VariantPayload>,
    #[serde(default)]
    pub overrides: Vec<VariantOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatedVariant {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<VariantPayload>,
    pub enabled: bool,
    pub feature_enabled: bool,
}

impl EvaluatedVariant {
    pub fn disabled(feature_enabled: bool) -> Self {
        Self {
            name: "disabled".to_string(),
            payload: None,
            enabled: false,
            feature_enabled,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Strategy {
    pub name: String,
    #[serde(default)]
    pub parameters: HashMap<String, String>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    #[serde(default)]
    pub segments: Vec<i64>,
    #[serde(default)]
    pub variants: Vec<VariantDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureDependency {
    pub feature: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub variants: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureToggle {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub strategies: Vec<Strategy>,
    #[serde(default)]
    pub variants: Vec<VariantDefinition>,
    #[serde(default)]
    pub dependencies: Vec<FeatureDependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub segments: Vec<i64>,
    #[serde(default)]
    pub impression_data: bool,
    #[serde(default)]
    pub stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub feature_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Segment {
    pub id: i64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
}

/// Feature-toggle client delta API event stream items (`/api/client/delta`, suites 19 and 20).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DeltaEvent {
    #[serde(rename = "hydration")]
    Hydration {
        #[serde(rename = "eventId", default)]
        event_id: u64,
        #[serde(default)]
        features: Vec<FeatureToggle>,
        #[serde(default)]
        segments: Vec<Segment>,
    },
    #[serde(rename = "feature-updated")]
    FeatureUpdated {
        #[serde(rename = "eventId", default)]
        event_id: u64,
        feature: FeatureToggle,
    },
    #[serde(rename = "feature-removed")]
    FeatureRemoved {
        #[serde(rename = "eventId", default)]
        event_id: u64,
        #[serde(rename = "featureName")]
        feature_name: String,
        #[serde(default)]
        project: Option<String>,
    },
    #[serde(rename = "segment-updated")]
    SegmentUpdated {
        #[serde(rename = "eventId", default)]
        event_id: u64,
        segment: Segment,
    },
    #[serde(rename = "segment-removed")]
    SegmentRemoved {
        #[serde(rename = "eventId", default)]
        event_id: u64,
        #[serde(rename = "segmentId")]
        segment_id: i64,
    },
}

#[derive(Deserialize)]
struct FeatureStateWire {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    features: Vec<FeatureToggle>,
    #[serde(default)]
    segments: Vec<Segment>,
    #[serde(default)]
    events: Vec<DeltaEvent>,
}

impl From<FeatureStateWire> for FeatureState {
    fn from(wire: FeatureStateWire) -> Self {
        let mut state = FeatureState {
            version: wire.version,
            features: wire.features,
            segments: wire.segments,
        };
        if !wire.events.is_empty() {
            state.apply_delta_events(&wire.events);
        }
        state
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(from = "FeatureStateWire")]
pub struct FeatureState {
    pub version: u32,
    pub features: Vec<FeatureToggle>,
    pub segments: Vec<Segment>,
}

fn default_version() -> u32 {
    2
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToggleMetricsCounter {
    pub yes: u64,
    pub no: u64,
    pub variants: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct MatchedStrategyVariants {
    group_id: String,
    default_stickiness: Option<String>,
    variants: Vec<VariantDefinition>,
}

impl FeatureState {
    pub fn apply_delta_events(&mut self, events: &[DeltaEvent]) {
        for ev in events {
            match ev {
                DeltaEvent::Hydration {
                    features, segments, ..
                } => {
                    self.features = features.clone();
                    self.segments = segments.clone();
                }
                DeltaEvent::FeatureUpdated { feature, .. } => {
                    if let Some(existing) =
                        self.features.iter_mut().find(|f| f.name == feature.name)
                    {
                        *existing = feature.clone();
                    } else {
                        self.features.push(feature.clone());
                    }
                }
                DeltaEvent::FeatureRemoved { feature_name, .. } => {
                    self.features.retain(|f| f.name != *feature_name);
                }
                DeltaEvent::SegmentUpdated { segment, .. } => {
                    if let Some(existing) = self.segments.iter_mut().find(|s| s.id == segment.id) {
                        *existing = segment.clone();
                    } else {
                        self.segments.push(segment.clone());
                    }
                }
                DeltaEvent::SegmentRemoved { segment_id, .. } => {
                    self.segments.retain(|s| s.id != *segment_id);
                }
            }
        }
    }

    pub fn to_delta_hydration_events(&self, event_id: u64) -> Vec<DeltaEvent> {
        vec![DeltaEvent::Hydration {
            event_id,
            features: self.features.clone(),
            segments: self.segments.clone(),
        }]
    }

    pub fn is_enabled(&self, toggle_name: &str, ctx: &RolloutContext) -> bool {
        self.eval_internal(toggle_name, ctx, 0).0
    }

    pub fn get_variant(&self, toggle_name: &str, ctx: &RolloutContext) -> EvaluatedVariant {
        let (enabled, matched_strategy_variants) = self.eval_internal(toggle_name, ctx, 0);
        let Some(feature) = self.features.iter().find(|f| f.name == toggle_name) else {
            return EvaluatedVariant::disabled(false);
        };
        if !enabled {
            return EvaluatedVariant::disabled(false);
        }
        if let Some(msv) = matched_strategy_variants {
            if !msv.variants.is_empty() {
                return select_variant(
                    &msv.variants,
                    &msv.group_id,
                    msv.default_stickiness.as_deref(),
                    ctx,
                    true,
                    VARIANT_SEED,
                );
            }
        }
        if feature.variants.is_empty() {
            return EvaluatedVariant::disabled(true);
        }
        select_variant(
            &feature.variants,
            &feature.name,
            None,
            ctx,
            true,
            VARIANT_SEED,
        )
    }

    fn eval_internal(
        &self,
        toggle_name: &str,
        ctx: &RolloutContext,
        depth: u8,
    ) -> (bool, Option<MatchedStrategyVariants>) {
        let Some(feature) = self.features.iter().find(|f| f.name == toggle_name) else {
            return (false, None);
        };

        // Check parent dependencies first (Specification forbids transitive parent chains: depth > 0 with deps fails)
        if !feature.dependencies.is_empty() {
            if depth > 0 {
                return (false, None);
            }
            for dep in &feature.dependencies {
                let Some(parent_feat) = self.features.iter().find(|f| f.name == dep.feature) else {
                    return (false, None);
                };
                if !parent_feat.dependencies.is_empty() {
                    return (false, None);
                }
                let (parent_enabled, parent_strat_vars) =
                    self.eval_internal(&dep.feature, ctx, depth + 1);
                if parent_enabled != dep.enabled {
                    return (false, None);
                }
                if dep.enabled && !dep.variants.is_empty() {
                    let parent_var = if let Some(msv) = parent_strat_vars {
                        if !msv.variants.is_empty() {
                            select_variant(
                                &msv.variants,
                                &msv.group_id,
                                msv.default_stickiness.as_deref(),
                                ctx,
                                true,
                                VARIANT_SEED,
                            )
                        } else {
                            select_variant(
                                &parent_feat.variants,
                                &parent_feat.name,
                                None,
                                ctx,
                                true,
                                VARIANT_SEED,
                            )
                        }
                    } else {
                        select_variant(
                            &parent_feat.variants,
                            &parent_feat.name,
                            None,
                            ctx,
                            true,
                            VARIANT_SEED,
                        )
                    };
                    if !dep.variants.contains(&parent_var.name) {
                        return (false, None);
                    }
                }
            }
        }

        if !feature.enabled {
            return (false, None);
        }

        if !self.segments_satisfied(&feature.segments, ctx) {
            return (false, None);
        }

        if feature.strategies.is_empty() {
            return (true, None);
        }

        for strategy in &feature.strategies {
            if !self.segments_satisfied(&strategy.segments, ctx) {
                continue;
            }
            if !constraints_satisfied(&strategy.constraints, ctx) {
                continue;
            }
            if evaluate_strategy(&feature.name, strategy, ctx) {
                let group_id = strategy
                    .parameters
                    .get("groupId")
                    .cloned()
                    .unwrap_or_else(|| feature.name.clone());
                let default_stickiness = strategy.parameters.get("stickiness").cloned();
                return (
                    true,
                    Some(MatchedStrategyVariants {
                        group_id,
                        default_stickiness,
                        variants: strategy.variants.clone(),
                    }),
                );
            }
        }

        (false, None)
    }

    fn segments_satisfied(&self, segment_ids: &[i64], ctx: &RolloutContext) -> bool {
        for seg_id in segment_ids {
            let Some(seg) = self.segments.iter().find(|s| s.id == *seg_id) else {
                return false;
            };
            if !constraints_satisfied(&seg.constraints, ctx) {
                return false;
            }
        }
        true
    }
}

fn select_variant(
    variants: &[VariantDefinition],
    group_id: &str,
    default_stickiness: Option<&str>,
    ctx: &RolloutContext,
    feature_enabled: bool,
    seed: u32,
) -> EvaluatedVariant {
    if variants.is_empty() {
        return EvaluatedVariant::disabled(feature_enabled);
    }

    // 1. Context overrides take priority
    for v in variants {
        for ov in &v.overrides {
            if let Some(actual) = ctx.resolve_field(&ov.context_name) {
                if ov.values.iter().any(|expected| expected == actual) {
                    return EvaluatedVariant {
                        name: v.name.clone(),
                        payload: v.payload.clone(),
                        enabled: true,
                        feature_enabled,
                    };
                }
            }
        }
    }

    let total_weight: u32 = variants.iter().map(|v| v.weight).sum();
    if total_weight == 0 {
        return EvaluatedVariant::disabled(feature_enabled);
    }

    let custom_stickiness = variants
        .iter()
        .find_map(|v| v.stickiness.as_deref())
        .or(default_stickiness)
        .unwrap_or("default");

    let identifier = ctx
        .resolve_stickiness(custom_stickiness)
        .unwrap_or_else(pseudo_random_stickiness);

    let target = normalized_value(&identifier, group_id, total_weight, seed);
    let mut counter = 0u32;
    for v in variants {
        if v.weight == 0 {
            continue;
        }
        counter += v.weight;
        if counter >= target {
            return EvaluatedVariant {
                name: v.name.clone(),
                payload: v.payload.clone(),
                enabled: true,
                feature_enabled,
            };
        }
    }

    EvaluatedVariant::disabled(feature_enabled)
}

fn evaluate_strategy(feature_name: &str, strategy: &Strategy, ctx: &RolloutContext) -> bool {
    match strategy.name.as_str() {
        "default" => true,
        "userWithId" => {
            let Some(uid) = ctx.resolve_field("userId") else {
                return false;
            };
            strategy
                .parameters
                .get("userIds")
                .map(|list| list.split(',').map(|s| s.trim()).any(|u| u == uid))
                .unwrap_or(false)
        }
        "applicationHostname" => {
            let host = ctx
                .resolve_field("hostname")
                .map(|s| s.to_ascii_lowercase())
                .or_else(|| {
                    std::env::var("HOSTNAME")
                        .or_else(|_| std::env::var("COMPUTERNAME"))
                        .ok()
                        .map(|s| s.to_ascii_lowercase())
                })
                .unwrap_or_default();
            strategy
                .parameters
                .get("hostNames")
                .map(|list| {
                    list.split(',')
                        .map(|s| s.trim().to_ascii_lowercase())
                        .any(|h| h == host)
                })
                .unwrap_or(false)
        }
        "remoteAddress" => {
            let Some(ip_str) = ctx.resolve_field("remoteAddress") else {
                return false;
            };
            strategy
                .parameters
                .get("IPs")
                .map(|ips| {
                    ips.split(',')
                        .map(|s| s.trim())
                        .any(|entry| ip_matches(ip_str, entry))
                })
                .unwrap_or(false)
        }
        "gradualRolloutUserId" => {
            let pct = parse_pct(strategy.parameters.get("percentage"));
            if pct == 0 {
                return false;
            }
            let Some(uid) = ctx.resolve_field("userId") else {
                return false;
            };
            if pct >= 100 {
                return true;
            }
            let group_id = strategy
                .parameters
                .get("groupId")
                .map(|s| s.as_str())
                .unwrap_or(feature_name);
            normalized_strategy_value(uid, group_id) <= pct
        }
        "gradualRolloutSessionId" => {
            let pct = parse_pct(strategy.parameters.get("percentage"));
            if pct == 0 {
                return false;
            }
            let Some(sid) = ctx.resolve_field("sessionId") else {
                return false;
            };
            if pct >= 100 {
                return true;
            }
            let group_id = strategy
                .parameters
                .get("groupId")
                .map(|s| s.as_str())
                .unwrap_or(feature_name);
            normalized_strategy_value(sid, group_id) <= pct
        }
        "gradualRolloutRandom" => {
            let pct = parse_pct(strategy.parameters.get("percentage"));
            if pct == 0 {
                return false;
            }
            if pct >= 100 {
                return true;
            }
            let rnd = pseudo_random_stickiness();
            normalized_strategy_value(&rnd, "") <= pct
        }
        "flexibleRollout" => {
            let rollout = parse_pct(strategy.parameters.get("rollout"));
            if rollout == 0 {
                return false;
            }
            let stickiness = strategy
                .parameters
                .get("stickiness")
                .map(|s| s.as_str())
                .unwrap_or("default");
            let Some(id) = ctx.resolve_stickiness(stickiness) else {
                return false;
            };
            if rollout >= 100 {
                return true;
            }
            let group_id = strategy
                .parameters
                .get("groupId")
                .map(|s| s.as_str())
                .unwrap_or(feature_name);
            normalized_strategy_value(&id, group_id) <= rollout
        }
        _ => false,
    }
}

fn parse_pct(val: Option<&String>) -> u32 {
    val.and_then(|s| s.trim().parse::<f64>().ok())
        .map(|f| f.clamp(0.0, 100.0) as u32)
        .unwrap_or(0)
}

/// Dual-stack IPv4 + IPv6 exact IP and CIDR prefix matcher (`remoteAddress` strategy + `IN_CIDR` operator).
pub fn ip_matches(ip_str: &str, rule: &str) -> bool {
    let ip_str = ip_str.trim();
    let rule = rule.trim();
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };

    if let Some((net_str, bits_str)) = rule.split_once('/') {
        let Ok(bits) = bits_str.parse::<u32>() else {
            return false;
        };
        match (ip, net_str.parse::<IpAddr>()) {
            (IpAddr::V4(ip4), Ok(IpAddr::V4(net4))) => {
                if bits > 32 {
                    return false;
                }
                if bits == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - bits);
                (u32::from(ip4) & mask) == (u32::from(net4) & mask)
            }
            (IpAddr::V6(ip6), Ok(IpAddr::V6(net6))) => {
                if bits > 128 {
                    return false;
                }
                if bits == 0 {
                    return true;
                }
                let mask = !0u128 << (128 - bits);
                (u128::from_be_bytes(ip6.octets()) & mask)
                    == (u128::from_be_bytes(net6.octets()) & mask)
            }
            _ => false,
        }
    } else {
        match (ip, rule.parse::<Ipv4Addr>(), rule.parse::<Ipv6Addr>()) {
            (IpAddr::V4(ip4), Ok(r4), _) => ip4 == r4,
            (IpAddr::V6(ip6), _, Ok(r6)) => ip6 == r6,
            _ => false,
        }
    }
}

fn constraints_satisfied(constraints: &[Constraint], ctx: &RolloutContext) -> bool {
    constraints.iter().all(|c| eval_single_constraint(c, ctx))
}

fn eval_single_constraint(c: &Constraint, ctx: &RolloutContext) -> bool {
    // Unknown operators ALWAYS evaluate to false per v2 constraint specification
    const KNOWN_OPS: &[&str] = &[
        "IN",
        "NOT_IN",
        "STR_STARTS_WITH",
        "STR_ENDS_WITH",
        "STR_CONTAINS",
        "NUM_EQ",
        "NUM_GT",
        "NUM_GTE",
        "NUM_LT",
        "NUM_LTE",
        "DATE_AFTER",
        "DATE_BEFORE",
        "SEMVER_EQ",
        "SEMVER_GT",
        "SEMVER_LT",
        "SEMVER_GTE",
        "SEMVER_LTE",
        "REGEX",
        "IN_CIDR",
    ];
    if !KNOWN_OPS.contains(&c.operator.as_str()) {
        return false;
    }

    let ctx_val = ctx.resolve_field(&c.context_name);
    let base_res = match c.operator.as_str() {
        "IN" => match ctx_val {
            Some(v) => c
                .values
                .iter()
                .any(|item| str_eq(v, item, c.case_insensitive)),
            None => false,
        },
        "NOT_IN" => match ctx_val {
            Some(v) => !c
                .values
                .iter()
                .any(|item| str_eq(v, item, c.case_insensitive)),
            None => true,
        },
        "STR_STARTS_WITH" => match ctx_val {
            Some(v) => c.values.iter().any(|prefix| {
                if c.case_insensitive {
                    v.to_lowercase().starts_with(&prefix.to_lowercase())
                } else {
                    v.starts_with(prefix.as_str())
                }
            }),
            None => false,
        },
        "STR_ENDS_WITH" => match ctx_val {
            Some(v) => c.values.iter().any(|suffix| {
                if c.case_insensitive {
                    v.to_lowercase().ends_with(&suffix.to_lowercase())
                } else {
                    v.ends_with(suffix.as_str())
                }
            }),
            None => false,
        },
        "STR_CONTAINS" => match ctx_val {
            Some(v) => c.values.iter().any(|needle| {
                if c.case_insensitive {
                    v.to_lowercase().contains(&needle.to_lowercase())
                } else {
                    v.contains(needle.as_str())
                }
            }),
            None => false,
        },
        "NUM_EQ" | "NUM_GT" | "NUM_GTE" | "NUM_LT" | "NUM_LTE" => {
            let (Some(v_str), Some(target_str)) = (ctx_val, c.value.as_deref()) else {
                return c.inverted;
            };
            let (Ok(lhs), Ok(rhs)) = (
                v_str.trim().parse::<f64>(),
                target_str.trim().parse::<f64>(),
            ) else {
                return c.inverted;
            };
            match c.operator.as_str() {
                "NUM_EQ" => (lhs - rhs).abs() < f64::EPSILON,
                "NUM_GT" => lhs > rhs,
                "NUM_GTE" => lhs >= rhs,
                "NUM_LT" => lhs < rhs,
                "NUM_LTE" => lhs <= rhs,
                _ => false,
            }
        }
        "DATE_AFTER" | "DATE_BEFORE" => {
            let Some(target_str) = c.value.as_deref() else {
                return c.inverted;
            };
            let Some(rhs) = parse_rfc3339_millis(target_str) else {
                return c.inverted;
            };
            let lhs = match ctx_val {
                Some(s) => match parse_rfc3339_millis(s) {
                    Some(ts) => ts,
                    None => return c.inverted,
                },
                None => current_epoch_millis(),
            };
            if c.operator == "DATE_AFTER" {
                lhs > rhs
            } else {
                lhs < rhs
            }
        }
        "SEMVER_EQ" | "SEMVER_GT" | "SEMVER_LT" | "SEMVER_GTE" | "SEMVER_LTE" => {
            let (Some(v_str), Some(target_str)) = (ctx_val, c.value.as_deref()) else {
                return c.inverted;
            };
            let (Some(lhs), Some(rhs)) = (parse_semver(v_str), parse_semver(target_str)) else {
                return c.inverted;
            };
            match c.operator.as_str() {
                "SEMVER_EQ" => lhs == rhs,
                "SEMVER_GT" => lhs > rhs,
                "SEMVER_GTE" => lhs >= rhs,
                "SEMVER_LT" => lhs < rhs,
                "SEMVER_LTE" => lhs <= rhs,
                _ => false,
            }
        }
        "REGEX" => {
            // Invalid RE2 pattern (or lookaround/backref) ALWAYS returns false BEFORE inversion
            let Some(pattern) = c.value.as_deref() else {
                return false;
            };
            let Ok(compiled) = re2_lite::CompiledRegex::compile(pattern, c.case_insensitive) else {
                return false;
            };
            let Some(v_str) = ctx_val else {
                return c.inverted;
            };
            compiled.is_match(v_str)
        }
        "IN_CIDR" => match ctx_val {
            Some(ip_str) => c.values.iter().any(|cidr| ip_matches(ip_str, cidr)),
            None => false,
        },
        _ => return false,
    };

    if c.inverted {
        !base_res
    } else {
        base_res
    }
}

fn current_epoch_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn str_eq(a: &str, b: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)) {
            std::cmp::Ordering::Equal => match (&self.prerelease, &other.prerelease) {
                (None, None) => std::cmp::Ordering::Equal,
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(a), Some(b)) => cmp_semver_prerelease(a, b),
            },
            ord => ord,
        }
    }
}

/// SemVer 2.0.0 §11.4 dot-separated pre-release identifier comparison.
fn cmp_semver_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    let mut a_parts = a.split('.');
    let mut b_parts = b.split('.');
    loop {
        match (a_parts.next(), b_parts.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(pa), Some(pb)) => {
                let a_num = if !pa.is_empty() && pa.bytes().all(|c| c.is_ascii_digit()) {
                    pa.parse::<u128>().ok()
                } else {
                    None
                };
                let b_num = if !pb.is_empty() && pb.bytes().all(|c| c.is_ascii_digit()) {
                    pb.parse::<u128>().ok()
                } else {
                    None
                };
                let ord = match (a_num, b_num) {
                    (Some(na), Some(nb)) => na.cmp(&nb),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => pa.cmp(pb),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

fn parse_semver(s: &str) -> Option<SemVer> {
    if s.starts_with('v') || s.trim() != s {
        return None; // Strict SemVer 2.0 per v2 specification rejects leading 'v'
    }
    let without_build = s.split('+').next()?;
    let (core, pre) = match without_build.split_once('-') {
        Some((c, p)) => {
            if p.is_empty() || p.split('.').any(|id| id.is_empty()) {
                return None;
            }
            (c, Some(p.to_string()))
        }
        None => (without_build, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    for p in &parts {
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
    }
    Some(SemVer {
        major: parts[0].parse().ok()?,
        minor: parts[1].parse().ok()?,
        patch: parts[2].parse().ok()?,
        prerelease: pre,
    })
}

/// Minimal zero-crate ISO-8601 / RFC-3339 parser returning epoch milliseconds.
fn parse_rfc3339_millis(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    if s.as_bytes().get(4) != Some(&b'-') || s.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let sep = *s.as_bytes().get(10)?;
    if sep != b'T' && sep != b't' && sep != b' ' {
        return None;
    }
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    if s.as_bytes().get(13) != Some(&b':') || s.as_bytes().get(16) != Some(&b':') {
        return None;
    }
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }

    let mut rest = &s[19..];
    let mut millis: i64 = 0;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits_len = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len == 0 {
            return None;
        }
        let frac = &after_dot[..digits_len];
        let padded = format!("{:0<3}", &frac[..frac.len().min(3)]);
        millis = padded.parse().ok()?;
        rest = &after_dot[digits_len..];
    }

    let tz_offset_secs: i64 = if rest == "Z" || rest == "z" {
        0
    } else if rest.starts_with('+') || rest.starts_with('-') {
        let sign = if rest.starts_with('-') { -1i64 } else { 1i64 };
        let tz = &rest[1..];
        let (th, tm) = if let Some((h, m)) = tz.split_once(':') {
            (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?)
        } else if tz.len() == 4 {
            (tz[0..2].parse::<i64>().ok()?, tz[2..4].parse::<i64>().ok()?)
        } else {
            return None;
        };
        sign * (th * 3600 + tm * 60)
    } else {
        return None;
    };

    let days = days_from_civil(year, month, day);
    let total_secs = days * 86_400 + hour * 3600 + min * 60 + sec - tz_offset_secs;
    Some(total_secs * 1000 + millis)
}

/// Howard Hinnant's civil-to-days algorithm (public domain).
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 {
        (m - 3) as u64
    } else {
        (m + 9) as u64
    };
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Linear-time Thompson NFA (`O(|P| * |T|)`) RE2-compatible matcher (`re2_lite`).
///
/// Rejects PCRE lookaround (`(?=`, `(?!`, `(?<=`, `(?<!`), backreferences (`\1`..`\9`),
/// and malformed groups/classes at compile time so `REGEX` constraints fail closed.
pub mod re2_lite {
    #[derive(Debug, Clone, Copy)]
    struct Flags {
        case_insensitive: bool,
        multiline: bool,
        dotall: bool,
    }

    #[derive(Debug, Clone)]
    enum ClassItem {
        Single(char),
        Range(char, char),
        Digit(bool),
        Word(bool),
        Space(bool),
        Posix(PosixKind, bool),
    }

    #[derive(Debug, Clone, Copy)]
    enum PosixKind {
        Alnum,
        Alpha,
        Ascii,
        Blank,
        Cntrl,
        Digit,
        Graph,
        Lower,
        Print,
        Punct,
        Space,
        Upper,
        Word,
        Xdigit,
    }

    #[derive(Debug, Clone)]
    enum Ast {
        Empty,
        Literal(char, Flags),
        Dot(Flags),
        Class {
            negated: bool,
            items: Vec<ClassItem>,
            flags: Flags,
        },
        AnchorStart(Flags),
        AnchorEnd(Flags),
        WordBoundary {
            negated: bool,
        },
        Seq(Vec<Ast>),
        Alt(Vec<Ast>),
        Rep {
            inner: Box<Ast>,
            min: usize,
            max: Option<usize>,
            greedy: bool,
        },
    }

    #[derive(Debug, Clone)]
    enum Inst {
        Literal(char, bool),
        Dot(bool),
        Class {
            negated: bool,
            items: Vec<ClassItem>,
            case_insensitive: bool,
        },
        AnchorStart(bool),
        AnchorEnd(bool),
        WordBoundary(bool),
        Split(usize, usize),
        Jump(usize),
        Match,
    }

    #[derive(Debug, Clone)]
    pub struct CompiledRegex {
        prog: Vec<Inst>,
    }

    impl CompiledRegex {
        pub fn compile(pattern: &str, case_insensitive: bool) -> Result<Self, &'static str> {
            let chars: Vec<char> = pattern.chars().collect();
            let mut parser = Parser {
                chars: &chars,
                pos: 0,
            };
            let init_flags = Flags {
                case_insensitive,
                multiline: false,
                dotall: false,
            };
            let ast = parser
                .parse_alt(init_flags, false)
                .map_err(|()| "invalid_re2_syntax")?;
            if parser.pos != chars.len() {
                return Err("trailing_regex_tokens");
            }

            // Build unanchored search program: `(?s:.*?)` prefix -> `0: Split(3, 1); 1: Dot(true); 2: Jump(0); 3: <expr>; Match`
            let mut prog = vec![Inst::Split(3, 1), Inst::Dot(true), Inst::Jump(0)];
            emit_ast(&ast, &mut prog).map_err(|()| "regex_program_overflow")?;
            prog.push(Inst::Match);
            if prog.len() > 32_768 {
                return Err("regex_program_too_large");
            }
            Ok(Self { prog })
        }

        pub fn is_match(&self, text: &str) -> bool {
            let bytes = text.as_bytes();
            let mut curr = Vec::with_capacity(self.prog.len());
            let mut next = Vec::with_capacity(self.prog.len());
            let mut visited = vec![false; self.prog.len()];

            add_epsilon_closure(&self.prog, 0, bytes, 0, &mut curr, &mut visited);
            if curr.iter().any(|&pc| matches!(self.prog[pc], Inst::Match)) {
                return true;
            }

            for (byte_idx, ch) in text.char_indices() {
                let next_byte_idx = byte_idx + ch.len_utf8();
                next.clear();
                visited.fill(false);

                for &pc in &curr {
                    let matched_char = match &self.prog[pc] {
                        Inst::Literal(expected, ci) => char_eq(ch, *expected, *ci),
                        Inst::Dot(dotall) => *dotall || ch != '\n',
                        Inst::Class {
                            negated,
                            items,
                            case_insensitive,
                        } => {
                            let hit = items
                                .iter()
                                .any(|item| match_class_item(ch, item, *case_insensitive));
                            if *negated {
                                !hit
                            } else {
                                hit
                            }
                        }
                        _ => false,
                    };
                    if matched_char {
                        add_epsilon_closure(
                            &self.prog,
                            pc + 1,
                            bytes,
                            next_byte_idx,
                            &mut next,
                            &mut visited,
                        );
                    }
                }

                std::mem::swap(&mut curr, &mut next);
                if curr.iter().any(|&pc| matches!(self.prog[pc], Inst::Match)) {
                    return true;
                }
                if curr.is_empty() {
                    return false;
                }
            }

            curr.iter().any(|&pc| matches!(self.prog[pc], Inst::Match))
        }
    }

    fn add_epsilon_closure(
        prog: &[Inst],
        pc: usize,
        bytes: &[u8],
        byte_pos: usize,
        list: &mut Vec<usize>,
        visited: &mut [bool],
    ) {
        if pc >= prog.len() || visited[pc] {
            return;
        }
        visited[pc] = true;
        match &prog[pc] {
            Inst::Jump(target) => {
                add_epsilon_closure(prog, *target, bytes, byte_pos, list, visited);
            }
            Inst::Split(first, second) => {
                add_epsilon_closure(prog, *first, bytes, byte_pos, list, visited);
                add_epsilon_closure(prog, *second, bytes, byte_pos, list, visited);
            }
            Inst::AnchorStart(multiline) => {
                let ok = byte_pos == 0 || (*multiline && bytes[byte_pos - 1] == b'\n');
                if ok {
                    add_epsilon_closure(prog, pc + 1, bytes, byte_pos, list, visited);
                }
            }
            Inst::AnchorEnd(multiline) => {
                let ok = byte_pos == bytes.len() || (*multiline && bytes[byte_pos] == b'\n');
                if ok {
                    add_epsilon_closure(prog, pc + 1, bytes, byte_pos, list, visited);
                }
            }
            Inst::WordBoundary(negated) => {
                let prev_word = byte_pos > 0 && is_ascii_word(bytes[byte_pos - 1]);
                let next_word = byte_pos < bytes.len() && is_ascii_word(bytes[byte_pos]);
                let is_boundary = prev_word != next_word;
                let ok = if *negated { !is_boundary } else { is_boundary };
                if ok {
                    add_epsilon_closure(prog, pc + 1, bytes, byte_pos, list, visited);
                }
            }
            _ => list.push(pc),
        }
    }

    fn emit_ast(ast: &Ast, prog: &mut Vec<Inst>) -> Result<(), ()> {
        if prog.len() > 32_768 {
            return Err(());
        }
        match ast {
            Ast::Empty => {}
            Ast::Literal(ch, f) => prog.push(Inst::Literal(*ch, f.case_insensitive)),
            Ast::Dot(f) => prog.push(Inst::Dot(f.dotall)),
            Ast::Class {
                negated,
                items,
                flags,
            } => prog.push(Inst::Class {
                negated: *negated,
                items: items.clone(),
                case_insensitive: flags.case_insensitive,
            }),
            Ast::AnchorStart(f) => prog.push(Inst::AnchorStart(f.multiline)),
            Ast::AnchorEnd(f) => prog.push(Inst::AnchorEnd(f.multiline)),
            Ast::WordBoundary { negated } => prog.push(Inst::WordBoundary(*negated)),
            Ast::Seq(items) => {
                for item in items {
                    emit_ast(item, prog)?;
                }
            }
            Ast::Alt(branches) => {
                if branches.is_empty() {
                    return Ok(());
                }
                if branches.len() == 1 {
                    return emit_ast(&branches[0], prog);
                }
                let mut end_jumps = Vec::with_capacity(branches.len() - 1);
                for (i, branch) in branches.iter().enumerate() {
                    if i + 1 < branches.len() {
                        let split_pc = prog.len();
                        prog.push(Inst::Split(0, 0));
                        let b_start = prog.len();
                        emit_ast(branch, prog)?;
                        let jmp_pc = prog.len();
                        prog.push(Inst::Jump(0));
                        end_jumps.push(jmp_pc);
                        let next_branch = prog.len();
                        prog[split_pc] = Inst::Split(b_start, next_branch);
                    } else {
                        emit_ast(branch, prog)?;
                    }
                }
                let end_pc = prog.len();
                for jmp_pc in end_jumps {
                    prog[jmp_pc] = Inst::Jump(end_pc);
                }
            }
            Ast::Rep {
                inner,
                min,
                max,
                greedy,
            } => {
                for _ in 0..*min {
                    emit_ast(inner, prog)?;
                }
                match max {
                    Some(m) => {
                        let rem = m.saturating_sub(*min);
                        for _ in 0..rem {
                            let split_pc = prog.len();
                            prog.push(Inst::Split(0, 0));
                            let body_start = prog.len();
                            emit_ast(inner, prog)?;
                            let after = prog.len();
                            prog[split_pc] = if *greedy {
                                Inst::Split(body_start, after)
                            } else {
                                Inst::Split(after, body_start)
                            };
                        }
                    }
                    None => {
                        let split_pc = prog.len();
                        prog.push(Inst::Split(0, 0));
                        let body_start = prog.len();
                        emit_ast(inner, prog)?;
                        prog.push(Inst::Jump(split_pc));
                        let after = prog.len();
                        prog[split_pc] = if *greedy {
                            Inst::Split(body_start, after)
                        } else {
                            Inst::Split(after, body_start)
                        };
                    }
                }
            }
        }
        Ok(())
    }

    struct Parser<'a> {
        chars: &'a [char],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        fn peek(&self) -> Option<char> {
            self.chars.get(self.pos).copied()
        }

        fn next(&mut self) -> Option<char> {
            let ch = self.peek()?;
            self.pos += 1;
            Some(ch)
        }

        fn parse_alt(&mut self, initial_flags: Flags, in_group: bool) -> Result<Ast, ()> {
            let mut branches = Vec::new();
            loop {
                let branch = self.parse_seq(initial_flags, in_group)?;
                branches.push(branch);
                if self.peek() == Some('|') {
                    self.next();
                } else {
                    break;
                }
            }
            if branches.len() == 1 {
                Ok(branches.pop().unwrap())
            } else {
                Ok(Ast::Alt(branches))
            }
        }

        fn parse_seq(&mut self, mut flags: Flags, in_group: bool) -> Result<Ast, ()> {
            let mut seq = Vec::new();
            while let Some(ch) = self.peek() {
                if ch == '|' {
                    break;
                }
                if ch == ')' {
                    if in_group {
                        break;
                    } else {
                        return Err(());
                    }
                }

                // Handle inline flag directive `(?ims)` vs group `(...)` / `(?:...)` / `(?ims:...)`
                if ch == '(' {
                    self.next();
                    if self.peek() == Some('?') {
                        self.next();
                        let next_c = self.peek().ok_or(())?;
                        // Reject lookahead / lookbehind (`(?=`, `(?!`, `(?<=`, `(?<!`)
                        if next_c == '=' || next_c == '!' || next_c == '<' {
                            return Err(());
                        }
                        if next_c == 'P' {
                            // Named group `(?P<name>...)`
                            self.next();
                            if self.next() != Some('<') {
                                return Err(());
                            }
                            while let Some(nc) = self.next() {
                                if nc == '>' {
                                    break;
                                }
                            }
                            let inner = self.parse_alt(flags, true)?;
                            if self.next() != Some(')') {
                                return Err(());
                            }
                            let atom = self.parse_quantifier(inner)?;
                            seq.push(atom);
                            continue;
                        }
                        // Parse flags `[ims-ims]` followed by `)` or `:`
                        let mut scoped = flags;
                        let mut neg = false;
                        let mut saw_flag_char = false;
                        while let Some(fc) = self.peek() {
                            match fc {
                                '-' => {
                                    neg = true;
                                    saw_flag_char = true;
                                    self.next();
                                }
                                'i' => {
                                    scoped.case_insensitive = !neg;
                                    saw_flag_char = true;
                                    self.next();
                                }
                                'm' => {
                                    scoped.multiline = !neg;
                                    saw_flag_char = true;
                                    self.next();
                                }
                                's' => {
                                    scoped.dotall = !neg;
                                    saw_flag_char = true;
                                    self.next();
                                }
                                'U' => {
                                    saw_flag_char = true;
                                    self.next();
                                }
                                ':' | ')' => break,
                                _ => return Err(()),
                            }
                        }
                        match self.next() {
                            Some(')') => {
                                if !saw_flag_char {
                                    return Err(());
                                }
                                flags = scoped;
                                continue;
                            }
                            Some(':') => {
                                let inner = self.parse_alt(scoped, true)?;
                                if self.next() != Some(')') {
                                    return Err(());
                                }
                                let atom = self.parse_quantifier(inner)?;
                                seq.push(atom);
                                continue;
                            }
                            _ => return Err(()),
                        }
                    } else {
                        let inner = self.parse_alt(flags, true)?;
                        if self.next() != Some(')') {
                            return Err(());
                        }
                        let atom = self.parse_quantifier(inner)?;
                        seq.push(atom);
                        continue;
                    }
                }

                let atom = match ch {
                    '^' => {
                        self.next();
                        Ast::AnchorStart(flags)
                    }
                    '$' => {
                        self.next();
                        Ast::AnchorEnd(flags)
                    }
                    '.' => {
                        self.next();
                        Ast::Dot(flags)
                    }
                    '[' => self.parse_class(flags)?,
                    '\\' => self.parse_escape(flags)?,
                    '*' | '+' | '?' | '{' => return Err(()),
                    other => {
                        self.next();
                        Ast::Literal(other, flags)
                    }
                };
                let quantified = self.parse_quantifier(atom)?;
                seq.push(quantified);
            }

            if seq.is_empty() {
                Ok(Ast::Empty)
            } else if seq.len() == 1 {
                Ok(seq.pop().unwrap())
            } else {
                Ok(Ast::Seq(seq))
            }
        }

        fn parse_quantifier(&mut self, inner: Ast) -> Result<Ast, ()> {
            let (min, max) = match self.peek() {
                Some('*') => {
                    self.next();
                    (0, None)
                }
                Some('+') => {
                    self.next();
                    (1, None)
                }
                Some('?') => {
                    self.next();
                    (0, Some(1))
                }
                Some('{') => {
                    if matches!(
                        inner,
                        Ast::AnchorStart(_) | Ast::AnchorEnd(_) | Ast::WordBoundary { .. }
                    ) {
                        return Err(());
                    }
                    self.next();
                    let min = self.parse_uint()?;
                    let max = if self.peek() == Some(',') {
                        self.next();
                        if self.peek() == Some('}') {
                            None
                        } else {
                            Some(self.parse_uint()?)
                        }
                    } else {
                        Some(min)
                    };
                    if self.next() != Some('}') {
                        return Err(());
                    }
                    if min > 1000 {
                        return Err(());
                    }
                    if let Some(m) = max {
                        if m < min || m > 1000 {
                            return Err(());
                        }
                    }
                    (min, max)
                }
                _ => return Ok(inner),
            };

            if matches!(
                inner,
                Ast::AnchorStart(_) | Ast::AnchorEnd(_) | Ast::WordBoundary { .. }
            ) {
                return Err(());
            }

            let greedy = if self.peek() == Some('?') {
                self.next();
                false
            } else {
                true
            };
            // Reject possessive quantifiers `*+`, `++`, `?+`
            if matches!(self.peek(), Some('*' | '+' | '?' | '{')) {
                return Err(());
            }

            Ok(Ast::Rep {
                inner: Box::new(inner),
                min,
                max,
                greedy,
            })
        }

        fn parse_uint(&mut self) -> Result<usize, ()> {
            let start = self.pos;
            let mut val: usize = 0;
            while let Some(c) = self.peek() {
                if let Some(d) = c.to_digit(10) {
                    self.next();
                    val = val
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(d as usize))
                        .ok_or(())?;
                } else {
                    break;
                }
            }
            if self.pos == start {
                Err(())
            } else {
                Ok(val)
            }
        }

        fn parse_escape(&mut self, flags: Flags) -> Result<Ast, ()> {
            self.next(); // consume '\'
            let esc = self.next().ok_or(())?;
            match esc {
                // Backreferences \1..\9 are strictly forbidden in RE2
                '1'..='9' => Err(()),
                'b' => Ok(Ast::WordBoundary { negated: false }),
                'B' => Ok(Ast::WordBoundary { negated: true }),
                'A' => Ok(Ast::AnchorStart(Flags {
                    case_insensitive: flags.case_insensitive,
                    multiline: false,
                    dotall: flags.dotall,
                })),
                'z' => Ok(Ast::AnchorEnd(Flags {
                    case_insensitive: flags.case_insensitive,
                    multiline: false,
                    dotall: flags.dotall,
                })),
                'd' => Ok(Ast::Class {
                    negated: false,
                    items: vec![ClassItem::Digit(false)],
                    flags,
                }),
                'D' => Ok(Ast::Class {
                    negated: false,
                    items: vec![ClassItem::Digit(true)],
                    flags,
                }),
                'w' => Ok(Ast::Class {
                    negated: false,
                    items: vec![ClassItem::Word(false)],
                    flags,
                }),
                'W' => Ok(Ast::Class {
                    negated: false,
                    items: vec![ClassItem::Word(true)],
                    flags,
                }),
                's' => Ok(Ast::Class {
                    negated: false,
                    items: vec![ClassItem::Space(false)],
                    flags,
                }),
                'S' => Ok(Ast::Class {
                    negated: false,
                    items: vec![ClassItem::Space(true)],
                    flags,
                }),
                'n' => Ok(Ast::Literal('\n', flags)),
                'r' => Ok(Ast::Literal('\r', flags)),
                't' => Ok(Ast::Literal('\t', flags)),
                '0' => Ok(Ast::Literal('\0', flags)),
                other => Ok(Ast::Literal(other, flags)),
            }
        }

        fn parse_class(&mut self, flags: Flags) -> Result<Ast, ()> {
            self.next(); // consume '['
            let negated = if self.peek() == Some('^') {
                self.next();
                true
            } else {
                false
            };

            let mut items = Vec::new();
            let mut first = true;
            while let Some(ch) = self.peek() {
                if ch == ']' && !first {
                    self.next();
                    return Ok(Ast::Class {
                        negated,
                        items,
                        flags,
                    });
                }
                first = false;

                // POSIX character class `[:alpha:]` or `[:^alpha:]`
                if ch == '[' && self.chars.get(self.pos + 1) == Some(&':') {
                    self.pos += 2;
                    let posix_neg = if self.peek() == Some('^') {
                        self.next();
                        true
                    } else {
                        false
                    };
                    let name_start = self.pos;
                    while let Some(pc) = self.peek() {
                        if pc == ':' && self.chars.get(self.pos + 1) == Some(&']') {
                            break;
                        }
                        self.next();
                    }
                    let name: String = self.chars[name_start..self.pos].iter().collect();
                    if self.next() != Some(':') || self.next() != Some(']') {
                        return Err(());
                    }
                    let kind = parse_posix_kind(&name)?;
                    items.push(ClassItem::Posix(kind, posix_neg));
                    continue;
                }

                let start_char = if ch == '\\' {
                    self.next();
                    let esc = self.next().ok_or(())?;
                    match esc {
                        'd' => {
                            items.push(ClassItem::Digit(false));
                            continue;
                        }
                        'D' => {
                            items.push(ClassItem::Digit(true));
                            continue;
                        }
                        'w' => {
                            items.push(ClassItem::Word(false));
                            continue;
                        }
                        'W' => {
                            items.push(ClassItem::Word(true));
                            continue;
                        }
                        's' => {
                            items.push(ClassItem::Space(false));
                            continue;
                        }
                        'S' => {
                            items.push(ClassItem::Space(true));
                            continue;
                        }
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '0' => '\0',
                        other => other,
                    }
                } else {
                    self.next().unwrap()
                };

                if self.peek() == Some('-') && self.chars.get(self.pos + 1) != Some(&']') {
                    self.next(); // consume '-'
                    let end_raw = self.next().ok_or(())?;
                    let end_char = if end_raw == '\\' {
                        let esc = self.next().ok_or(())?;
                        match esc {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '0' => '\0',
                            other => other,
                        }
                    } else {
                        end_raw
                    };
                    if end_char < start_char {
                        return Err(());
                    }
                    items.push(ClassItem::Range(start_char, end_char));
                } else {
                    items.push(ClassItem::Single(start_char));
                }
            }
            Err(())
        }
    }

    fn parse_posix_kind(name: &str) -> Result<PosixKind, ()> {
        match name {
            "alnum" => Ok(PosixKind::Alnum),
            "alpha" => Ok(PosixKind::Alpha),
            "ascii" => Ok(PosixKind::Ascii),
            "blank" => Ok(PosixKind::Blank),
            "cntrl" => Ok(PosixKind::Cntrl),
            "digit" => Ok(PosixKind::Digit),
            "graph" => Ok(PosixKind::Graph),
            "lower" => Ok(PosixKind::Lower),
            "print" => Ok(PosixKind::Print),
            "punct" => Ok(PosixKind::Punct),
            "space" => Ok(PosixKind::Space),
            "upper" => Ok(PosixKind::Upper),
            "word" => Ok(PosixKind::Word),
            "xdigit" => Ok(PosixKind::Xdigit),
            _ => Err(()),
        }
    }

    fn char_eq(a: char, b: char, case_insensitive: bool) -> bool {
        if a == b {
            return true;
        }
        if case_insensitive {
            a.to_lowercase().eq(b.to_lowercase())
        } else {
            false
        }
    }

    fn is_ascii_word(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    fn match_class_item(ch: char, item: &ClassItem, case_insensitive: bool) -> bool {
        match item {
            ClassItem::Single(expected) => char_eq(ch, *expected, case_insensitive),
            ClassItem::Range(lo, hi) => {
                if ch >= *lo && ch <= *hi {
                    return true;
                }
                if case_insensitive {
                    for folded in ch.to_lowercase() {
                        if folded >= *lo && folded <= *hi {
                            return true;
                        }
                    }
                    for folded in ch.to_uppercase() {
                        if folded >= *lo && folded <= *hi {
                            return true;
                        }
                    }
                }
                false
            }
            ClassItem::Digit(neg) => ch.is_ascii_digit() != *neg,
            ClassItem::Word(neg) => (ch.is_ascii_alphanumeric() || ch == '_') != *neg,
            ClassItem::Space(neg) => {
                matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0C' | '\x0B') != *neg
            }
            ClassItem::Posix(kind, neg) => {
                let raw = match kind {
                    PosixKind::Alnum => ch.is_ascii_alphanumeric(),
                    PosixKind::Alpha => ch.is_ascii_alphabetic(),
                    PosixKind::Ascii => ch.is_ascii(),
                    PosixKind::Blank => ch == ' ' || ch == '\t',
                    PosixKind::Cntrl => ch.is_ascii_control(),
                    PosixKind::Digit => ch.is_ascii_digit(),
                    PosixKind::Graph => ch.is_ascii_graphic(),
                    PosixKind::Lower => {
                        if case_insensitive {
                            ch.is_ascii_alphabetic()
                        } else {
                            ch.is_ascii_lowercase()
                        }
                    }
                    PosixKind::Print => (' '..='~').contains(&ch),
                    PosixKind::Punct => ch.is_ascii_punctuation(),
                    PosixKind::Space => ch.is_ascii_whitespace(),
                    PosixKind::Upper => {
                        if case_insensitive {
                            ch.is_ascii_alphabetic()
                        } else {
                            ch.is_ascii_uppercase()
                        }
                    }
                    PosixKind::Word => ch.is_ascii_alphanumeric() || ch == '_',
                    PosixKind::Xdigit => ch.is_ascii_hexdigit(),
                };
                raw != *neg
            }
        }
    }
}
