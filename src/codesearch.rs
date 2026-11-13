//! Fast local hybrid code search (BM25 + static subword embeddings + RRF reranking).
//!
//! Clean-room hybrid index in pure Rust `std`, shaped like a local code-search engine:
//! - Declaration-aware code chunking (`fn`, `struct`, `impl`, `def`, `class`, `func`, `interface`).
//! - CamelCase / PascalCase / `snake_case` compound identifier sub-tokenization.
//! - Hybrid BM25 (`k1 = 1.5, b = 0.75`) + L2-normalized `f64` static character-trigram/subword
//!   feature-hashing embeddings fused with Reciprocal Rank Fusion (`RRF`, `k = 60`).
//! - 5 code-aware reranking signals: adaptive `alpha` (`0.3` symbol vs `0.5` NL), symbol definition
//!   boost (`3.0x`), stem matching, file coherence boost (`+0.2x`), path noise penalties (`0.3x` tests/examples),
//!   and greedy per-file saturation decay (`0.5^excess`).
//! - Enforces Carnot's **Black-Box ON/OFF Shield**: when `black_box_enforced == true`, quarantined paths
//!   and restricted copyleft/proprietary files are excluded before indexing so `0` restricted bytes leak.

use crate::intake::{policy_for_spdx, AccessPolicy};
use crate::proc_util::{run_command_bounded, DEFAULT_MAX_STREAM_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const RRF_K: f64 = 60.0;
const EMBED_DIM: usize = 256;
const ALPHA_SYMBOL: f64 = 0.3;
const ALPHA_NL: f64 = 0.5;
const DEFINITION_BOOST_MULT: f64 = 3.0;
const STEM_BOOST_MULT: f64 = 1.0;
const FILE_COHERENCE_BOOST_FRAC: f64 = 0.2;
const FILE_SATURATION_DECAY: f64 = 0.5;
const MAX_INDEX_FILE_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CodeChunk {
    pub id: usize,
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
    pub file_char_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSearchHit {
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub score: f64,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSearchReport {
    pub query: String,
    pub black_box_enforced: bool,
    pub quarantined_files_skipped: usize,
    pub total_chunks_indexed: usize,
    pub full_files_chars: usize,
    pub snippet_chars: usize,
    pub estimated_tokens_saved: usize,
    pub token_reduction_pct: f64,
    pub hits: Vec<CodeSearchHit>,
}

pub struct HybridCodeIndex {
    pub chunks: Vec<CodeChunk>,
    pub quarantined_files_skipped: usize,
    pub black_box_enforced: bool,
    bm25_doc_freqs: HashMap<String, usize>,
    bm25_term_freqs: Vec<HashMap<String, usize>>,
    bm25_doc_lens: Vec<usize>,
    bm25_avg_dl: f64,
    embeddings: Vec<[f64; EMBED_DIM]>,
}

impl HybridCodeIndex {
    /// Indexes a directory into declaration-aware code chunks while respecting `black_box_enforced`.
    pub fn from_directory(
        root: &Path,
        black_box_enforced: bool,
        quarantined_prefixes: &[String],
    ) -> Self {
        let mut chunks = Vec::new();
        let mut quarantined_skipped = 0usize;
        walk_repo_files(
            root,
            root,
            black_box_enforced,
            quarantined_prefixes,
            &mut chunks,
            &mut quarantined_skipped,
        );
        Self::from_chunks(chunks, black_box_enforced, quarantined_skipped)
    }

    pub fn from_chunks(
        mut chunks: Vec<CodeChunk>,
        black_box_enforced: bool,
        quarantined_files_skipped: usize,
    ) -> Self {
        for (idx, ch) in chunks.iter_mut().enumerate() {
            ch.id = idx;
        }
        let n_docs = chunks.len();
        let mut bm25_doc_freqs: HashMap<String, usize> = HashMap::new();
        let mut bm25_term_freqs: Vec<HashMap<String, usize>> = Vec::with_capacity(n_docs);
        let mut bm25_doc_lens: Vec<usize> = Vec::with_capacity(n_docs);
        let mut embeddings: Vec<[f64; EMBED_DIM]> = Vec::with_capacity(n_docs);
        let mut total_tokens = 0usize;

        for ch in &chunks {
            let tokens = tokenize_code(&ch.content);
            total_tokens += tokens.len();
            bm25_doc_lens.push(tokens.len());
            let mut tf: HashMap<String, usize> = HashMap::new();
            for tok in tokens {
                *tf.entry(tok).or_insert(0) += 1;
            }
            for unique_tok in tf.keys() {
                *bm25_doc_freqs.entry(unique_tok.clone()).or_insert(0) += 1;
            }
            bm25_term_freqs.push(tf);
            embeddings.push(embed_static_subwords(&ch.content));
        }

        let bm25_avg_dl = if n_docs > 0 {
            (total_tokens as f64 / n_docs as f64).max(1.0)
        } else {
            1.0
        };

        Self {
            chunks,
            quarantined_files_skipped,
            black_box_enforced,
            bm25_doc_freqs,
            bm25_term_freqs,
            bm25_doc_lens,
            bm25_avg_dl,
            embeddings,
        }
    }

    pub fn search(&self, query: &str, top_k: usize) -> CodeSearchReport {
        let top_k = top_k.clamp(1, 50);
        if self.chunks.is_empty() || query.trim().is_empty() {
            return CodeSearchReport {
                query: query.to_string(),
                black_box_enforced: self.black_box_enforced,
                quarantined_files_skipped: self.quarantined_files_skipped,
                total_chunks_indexed: self.chunks.len(),
                full_files_chars: 0,
                snippet_chars: 0,
                estimated_tokens_saved: 0,
                token_reduction_pct: 0.0,
                hits: Vec::new(),
            };
        }

        let alpha = if is_symbol_query(query) {
            ALPHA_SYMBOL
        } else {
            ALPHA_NL
        };
        let candidate_pool = (top_k * 5).min(self.chunks.len());

        // 1. Dense static subword cosine similarity -> RRF
        let q_vec = embed_static_subwords(query);
        let mut sem_raw: Vec<(usize, f64)> = self
            .embeddings
            .iter()
            .enumerate()
            .map(|(idx, emb)| (idx, dot_product(&q_vec, emb)))
            .filter(|(_, s)| *s > 0.0)
            .collect();
        sem_raw.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sem_raw.truncate(candidate_pool);
        let sem_rrf = rrf_scores(&sem_raw);

        // 2. Lexical BM25 -> RRF
        let bm25_raw = self.score_bm25(query, candidate_pool);
        let bm25_rrf = rrf_scores(&bm25_raw);

        // 3. Fuse RRF scores
        let mut candidate_ids: Vec<usize> = sem_rrf
            .keys()
            .chain(bm25_rrf.keys())
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        candidate_ids.sort_by_key(|&id| (self.chunks[id].start_line, id));

        let mut combined: HashMap<usize, f64> = HashMap::new();
        for id in candidate_ids {
            let s = alpha * sem_rrf.get(&id).copied().unwrap_or(0.0)
                + (1.0 - alpha) * bm25_rrf.get(&id).copied().unwrap_or(0.0);
            if s > 0.0 {
                combined.insert(id, s);
            }
        }

        // 4. Five-signal code-aware reranking
        boost_multi_chunk_files(&mut combined, &self.chunks);
        apply_query_boost(&mut combined, query, &self.chunks);
        let ranked = rerank_topk(&combined, &self.chunks, top_k, alpha < 1.0);

        self.build_report(query, ranked)
    }

    pub fn find_related(
        &self,
        file_path: &str,
        line_number: usize,
        top_k: usize,
    ) -> CodeSearchReport {
        let normalized_target = file_path.replace('\\', "/");
        let anchor = self
            .chunks
            .iter()
            .find(|c| {
                let norm = c.file_path.replace('\\', "/");
                (norm == normalized_target || norm.ends_with(&normalized_target))
                    && line_number >= c.start_line
                    && line_number <= c.end_line
            })
            .or_else(|| {
                self.chunks.iter().find(|c| {
                    let norm = c.file_path.replace('\\', "/");
                    norm == normalized_target || norm.ends_with(&normalized_target)
                })
            });

        let Some(anchor_chunk) = anchor else {
            return CodeSearchReport {
                query: format!("{}:{}", file_path, line_number),
                black_box_enforced: self.black_box_enforced,
                quarantined_files_skipped: self.quarantined_files_skipped,
                total_chunks_indexed: self.chunks.len(),
                full_files_chars: 0,
                snippet_chars: 0,
                estimated_tokens_saved: 0,
                token_reduction_pct: 0.0,
                hits: Vec::new(),
            };
        };

        let anchor_id = anchor_chunk.id;
        let mut report = self.search(&anchor_chunk.content, top_k + 1);
        report.query = format!("related:{}:{}", file_path, line_number);
        report.hits.retain(|h| {
            !(h.file_path == anchor_chunk.file_path && h.start_line == anchor_chunk.start_line)
        });
        report.hits.truncate(top_k);
        let _ = anchor_id;
        report
    }

    fn score_bm25(&self, query: &str, top_k: usize) -> Vec<(usize, f64)> {
        let q_tokens = tokenize_code(query);
        if q_tokens.is_empty() {
            return Vec::new();
        }
        let n = self.chunks.len() as f64;
        let k1 = 1.5;
        let b = 0.75;
        let mut scores: Vec<(usize, f64)> = Vec::new();

        for (idx, tf_map) in self.bm25_term_freqs.iter().enumerate() {
            let dl = self.bm25_doc_lens[idx] as f64;
            let mut doc_score = 0.0;
            for qt in &q_tokens {
                let Some(&tf_raw) = tf_map.get(qt) else {
                    continue;
                };
                let df = *self.bm25_doc_freqs.get(qt).unwrap_or(&1) as f64;
                let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
                let tf = tf_raw as f64;
                let denom = tf + k1 * (1.0 - b + b * (dl / self.bm25_avg_dl));
                doc_score += idf * ((tf * (k1 + 1.0)) / denom);
            }
            if doc_score > 0.0 {
                scores.push((idx, doc_score));
            }
        }

        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(top_k);
        scores
    }

    fn build_report(&self, query: &str, ranked: Vec<(usize, f64)>) -> CodeSearchReport {
        let mut seen_files: HashMap<&str, usize> = HashMap::new();
        let mut snippet_chars = 0usize;
        let mut hits = Vec::with_capacity(ranked.len());

        for (id, score) in ranked {
            let ch = &self.chunks[id];
            seen_files
                .entry(ch.file_path.as_str())
                .or_insert(ch.file_char_len);
            snippet_chars += ch.content.len();
            hits.push(CodeSearchHit {
                file_path: ch.file_path.clone(),
                start_line: ch.start_line,
                end_line: ch.end_line,
                score: (score * 10_000.0).round() / 10_000.0,
                content: ch.content.clone(),
            });
        }

        let full_files_chars: usize = seen_files.values().sum();
        let saved_chars = full_files_chars.saturating_sub(snippet_chars);
        let estimated_tokens_saved = saved_chars / 4;
        let token_reduction_pct = if full_files_chars > 0 {
            ((saved_chars as f64 / full_files_chars as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };

        CodeSearchReport {
            query: query.to_string(),
            black_box_enforced: self.black_box_enforced,
            quarantined_files_skipped: self.quarantined_files_skipped,
            total_chunks_indexed: self.chunks.len(),
            full_files_chars,
            snippet_chars,
            estimated_tokens_saved,
            token_reduction_pct,
            hits,
        }
    }
}

/// Optional host hybrid-search CLI (`<bin> search <query> <dir> --format json`) when installed
/// and `black_box_enforced == false` (white-box inspection of permissive code).
///
/// Set `CARNOT_HYBRID_SEARCH_BIN` to the local binary. The default name is `carnot-hybrid-search`.
pub fn invoke_host_hybrid_search_if_available(
    query: &str,
    repo_dir: &Path,
    top_k: usize,
    black_box_enforced: bool,
) -> Option<serde_json::Value> {
    if black_box_enforced {
        return None;
    }
    let hybrid_bin = std::env::var("CARNOT_HYBRID_SEARCH_BIN")
        .unwrap_or_else(|_| "carnot-hybrid-search".to_string());
    let mut cmd = Command::new(hybrid_bin);
    cmd.args([
        "search",
        query,
        &repo_dir.to_string_lossy(),
        "--top-k",
        &top_k.to_string(),
        "--format",
        "json",
    ]);
    let out = run_command_bounded(cmd, None, 10_000, DEFAULT_MAX_STREAM_BYTES);
    if out.spawned && out.success {
        serde_json::from_str(out.stdout.trim()).ok()
    } else {
        None
    }
}

fn walk_repo_files(
    root: &Path,
    dir: &Path,
    black_box_enforced: bool,
    quarantined_prefixes: &[String],
    chunks: &mut Vec<CodeChunk>,
    quarantined_skipped: &mut usize,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut sorted_entries: Vec<_> = entries.flatten().collect();
    sorted_entries.sort_by_key(|e| e.file_name());

    for entry in sorted_entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.')
            || matches!(
                name.as_str(),
                "target" | "node_modules" | "dist" | "build" | "vendor" | "__pycache__" | ".git"
            )
        {
            continue;
        }

        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        let Ok(ft) = entry.file_type() else {
            continue;
        };
        // Never follow symlinks: an in-tree link is covered by its real path,
        // and a link out of the repo must not be indexed.
        if ft.is_symlink() {
            continue;
        }

        if black_box_enforced
            && quarantined_prefixes
                .iter()
                .any(|qp| crate::intake::rel_matches_quarantine_prefix(&rel, qp))
        {
            if ft.is_file() {
                *quarantined_skipped += 1;
            }
            continue;
        }

        if ft.is_dir() {
            walk_repo_files(
                root,
                &path,
                black_box_enforced,
                quarantined_prefixes,
                chunks,
                quarantined_skipped,
            );
        } else if path.is_file() && is_indexable_code_file(&name) {
            let Ok(meta) = path.metadata() else {
                continue;
            };
            if meta.len() > MAX_INDEX_FILE_BYTES || meta.len() == 0 {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            if black_box_enforced {
                let header_sample: String = content.chars().take(2048).collect();
                if let Some(spdx) = detect_header_spdx_license(&header_sample) {
                    if policy_for_spdx(&spdx) != AccessPolicy::PermissiveAlgorithmAndFixtures {
                        *quarantined_skipped += 1;
                        continue;
                    }
                }
            }
            chunk_source_file(&rel, &content, chunks);
        }
    }
}

fn detect_header_spdx_license(header: &str) -> Option<String> {
    for line in header.lines().take(40) {
        if let Some((_, rhs)) = line.split_once("SPDX-License-Identifier:") {
            let token = rhs
                .trim()
                .trim_end_matches("*/")
                .trim_end_matches("-->")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    // Only the leading comment block counts as a license notice, and only canonical license
    // titles qualify — prose that merely mentions "AGPL" or "proprietary" must not quarantine a file.
    let mut notice = String::new();
    for (idx, line) in header.lines().enumerate() {
        let t = line.trim();
        if idx == 0 && t.starts_with("#!") {
            continue;
        }
        let is_comment = t.is_empty()
            || t.starts_with("//")
            || t.starts_with('#')
            || t.starts_with("/*")
            || t.starts_with('*')
            || t.starts_with("--")
            || t.starts_with("<!--")
            || t.starts_with("\"\"\"")
            || t.starts_with("'''");
        if !is_comment {
            break;
        }
        notice.push_str(t);
        notice.push('\n');
    }
    let upper = notice.to_ascii_uppercase();
    for (phrase, spdx) in [
        ("GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0"),
        ("GNU LESSER GENERAL PUBLIC LICENSE", "LGPL-3.0"),
        ("GNU GENERAL PUBLIC LICENSE", "GPL-3.0"),
        ("SERVER SIDE PUBLIC LICENSE", "SSPL-1.0"),
        ("BUSINESS SOURCE LICENSE", "BSL-1.1"),
        ("END USER LICENSE AGREEMENT", "PROPRIETARY-EULA"),
    ] {
        if upper.contains(phrase) {
            return Some(spdx.to_string());
        }
    }
    None
}

fn is_indexable_code_file(name: &str) -> bool {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "rs" | "go"
            | "ts"
            | "tsx"
            | "js"
            | "jsx"
            | "mjs"
            | "py"
            | "scala"
            | "zig"
            | "c"
            | "h"
            | "cpp"
            | "hpp"
            | "java"
            | "kt"
            | "rb"
            | "sql"
            | "sh"
            | "md"
    )
}

/// Splits source code along top-level declarations (`fn`, `struct`, `impl`, `def`, `class`, `func`)
/// with bounded ~60-line windows so retrieved chunks stay tight and self-contained.
pub fn chunk_source_file(rel_path: &str, content: &str, out: &mut Vec<CodeChunk>) {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return;
    }
    let file_char_len = content.len();
    let mut start_idx = 0usize;

    for idx in 1..lines.len() {
        let line = lines[idx];
        let window_len = idx - start_idx;
        let is_decl = is_top_level_declaration(line);
        if (is_decl && window_len >= 8) || window_len >= 60 {
            let body = lines[start_idx..idx].join("\n");
            if !body.trim().is_empty() {
                out.push(CodeChunk {
                    id: 0,
                    file_path: rel_path.to_string(),
                    start_line: start_idx + 1,
                    end_line: idx,
                    content: body,
                    file_char_len,
                });
            }
            start_idx = idx;
        }
    }

    if start_idx < lines.len() {
        let body = lines[start_idx..].join("\n");
        if !body.trim().is_empty() {
            out.push(CodeChunk {
                id: 0,
                file_path: rel_path.to_string(),
                start_line: start_idx + 1,
                end_line: lines.len(),
                content: body,
                file_char_len,
            });
        }
    }
}

fn is_top_level_declaration(line: &str) -> bool {
    let trimmed = line.trim_start();
    // Must have minimal indentation (0..=4 spaces) to be a top-level or impl-method declaration
    let indent = line.len() - trimmed.len();
    if indent > 4 {
        return false;
    }
    const PREFIXES: &[&str] = &[
        "pub fn ",
        "pub async fn ",
        "fn ",
        "async fn ",
        "pub struct ",
        "struct ",
        "pub enum ",
        "enum ",
        "pub trait ",
        "trait ",
        "impl ",
        "impl<",
        "def ",
        "async def ",
        "class ",
        "func ",
        "type ",
        "export function ",
        "export async function ",
        "export class ",
        "export interface ",
        "function ",
        "interface ",
    ];
    PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

/// Splits compound identifiers (`HandlerStack` -> `["handlerstack", "handler", "stack"]`,
/// `my_func` -> `["my_func", "my", "func"]`) using camelCase and snake_case splits.
pub fn split_identifier(token: &str) -> Vec<String> {
    let lower = token.to_ascii_lowercase();
    let parts: Vec<String> = if token.contains('_') {
        lower
            .split('_')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    } else {
        split_camel_case(token)
    };
    if parts.len() >= 2 {
        let mut res = Vec::with_capacity(parts.len() + 1);
        res.push(lower);
        res.extend(parts);
        res
    } else {
        vec![lower]
    }
}

fn split_camel_case(token: &str) -> Vec<String> {
    let chars: Vec<char> = token.chars().collect();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let start = i;
        if chars[i].is_ascii_uppercase() {
            i += 1;
            while i < chars.len() && chars[i].is_ascii_uppercase() {
                if i + 1 < chars.len() && chars[i + 1].is_ascii_lowercase() {
                    break;
                }
                i += 1;
            }
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                i += 1;
            }
        } else if chars[i].is_ascii_lowercase() {
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                i += 1;
            }
        } else if chars[i].is_ascii_digit() {
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            i += 1;
            continue;
        }
        let s: String = chars[start..i].iter().collect();
        if !s.is_empty() {
            parts.push(s.to_ascii_lowercase());
        }
    }
    parts
}

pub fn tokenize_code(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut curr = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            curr.push(ch);
        } else if !curr.is_empty() {
            if !curr.bytes().next().unwrap().is_ascii_digit() {
                out.extend(split_identifier(&curr));
            }
            curr.clear();
        }
    }
    if !curr.is_empty() && !curr.bytes().next().unwrap().is_ascii_digit() {
        out.extend(split_identifier(&curr));
    }
    out
}

/// Static CPU-only `f64` subword + character-trigram feature-hashing embedding (`D = 256`).
fn embed_static_subwords(text: &str) -> [f64; EMBED_DIM] {
    let mut vec = [0.0f64; EMBED_DIM];
    let tokens = tokenize_code(text);
    for tok in &tokens {
        add_hashed_feature(&mut vec, tok.as_bytes(), 1.5);
        let bytes = tok.as_bytes();
        if bytes.len() >= 3 {
            for win in bytes.windows(3) {
                add_hashed_feature(&mut vec, win, 0.5);
            }
        }
    }
    let norm_sq: f64 = vec.iter().map(|x| x * x).sum();
    if norm_sq > 1e-12 {
        let inv = 1.0 / norm_sq.sqrt();
        for x in &mut vec {
            *x *= inv;
        }
    }
    vec
}

fn add_hashed_feature(vec: &mut [f64; EMBED_DIM], bytes: &[u8], weight: f64) {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let idx = (h as usize) & (EMBED_DIM - 1);
    let sign = if (h >> 63) == 0 { 1.0 } else { -1.0 };
    vec[idx] += sign * weight;
}

fn dot_product(a: &[f64; EMBED_DIM], b: &[f64; EMBED_DIM]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn rrf_scores(ranked_raw: &[(usize, f64)]) -> HashMap<usize, f64> {
    let mut out = HashMap::with_capacity(ranked_raw.len());
    for (rank_zero, &(chunk_id, _)) in ranked_raw.iter().enumerate() {
        let rank = (rank_zero + 1) as f64;
        out.insert(chunk_id, 1.0 / (RRF_K + rank));
    }
    out
}

pub fn is_symbol_query(query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() || q.contains(char::is_whitespace) {
        return false;
    }
    q.contains("::")
        || q.contains("->")
        || q.contains('.')
        || q.starts_with('_')
        || q.chars().any(|c| c.is_ascii_uppercase() || c == '_')
}

fn extract_symbol_name(query: &str) -> &str {
    let q = query.trim();
    for sep in ["::", "->", ".", "\\"] {
        if let Some((_, last)) = q.rsplit_once(sep) {
            if !last.is_empty() {
                return last;
            }
        }
    }
    q
}

fn chunk_defines_symbol(content: &str, symbol: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "fn ",
        "struct ",
        "enum ",
        "trait ",
        "type ",
        "class ",
        "def ",
        "func ",
        "function ",
        "interface ",
        "module ",
        "object ",
        "record ",
    ];
    for line in content.lines() {
        let t = line.trim();
        for kw in KEYWORDS {
            if let Some(pos) = t.find(kw) {
                if pos == 0 || t.as_bytes()[pos - 1].is_ascii_whitespace() {
                    let after = t[pos + kw.len()..].trim_start();
                    if let Some(rest) = after.strip_prefix(symbol) {
                        if rest.is_empty()
                            || rest.starts_with(|c: char| {
                                c.is_ascii_whitespace()
                                    || matches!(c, '(' | '<' | '{' | ':' | '[' | ';')
                            })
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn file_stem_lower(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn stem_matches(stem: &str, target_lower: &str) -> bool {
    let norm = stem.replace('_', "");
    stem == target_lower
        || norm == target_lower
        || stem.trim_end_matches('s') == target_lower
        || norm.trim_end_matches('s') == target_lower
}

fn boost_multi_chunk_files(scores: &mut HashMap<usize, f64>, chunks: &[CodeChunk]) {
    let max_score = scores.values().copied().fold(0.0f64, f64::max);
    if max_score <= 0.0 {
        return;
    }
    let mut file_sum: HashMap<&str, f64> = HashMap::new();
    let mut best_chunk: HashMap<&str, (usize, f64)> = HashMap::new();
    for (&id, &sc) in scores.iter() {
        let fp = chunks[id].file_path.as_str();
        *file_sum.entry(fp).or_insert(0.0) += sc;
        match best_chunk.get(fp) {
            Some(&(_, best_sc)) if best_sc >= sc => {}
            _ => {
                best_chunk.insert(fp, (id, sc));
            }
        }
    }
    let max_file_sum = file_sum.values().copied().fold(0.0f64, f64::max);
    if max_file_sum <= 0.0 {
        return;
    }
    let boost_unit = max_score * FILE_COHERENCE_BOOST_FRAC;
    for (fp, (best_id, _)) in best_chunk {
        if let Some(slot) = scores.get_mut(&best_id) {
            *slot += boost_unit * (file_sum[fp] / max_file_sum);
        }
    }
}

fn apply_query_boost(scores: &mut HashMap<usize, f64>, query: &str, all_chunks: &[CodeChunk]) {
    let max_score = scores.values().copied().fold(0.0f64, f64::max);
    if max_score <= 0.0 {
        return;
    }

    if is_symbol_query(query) {
        let sym = extract_symbol_name(query);
        let sym_lower = sym.to_ascii_lowercase();
        let boost_unit = max_score * DEFINITION_BOOST_MULT;

        let existing_ids: Vec<usize> = scores.keys().copied().collect();
        for id in existing_ids {
            if chunk_defines_symbol(&all_chunks[id].content, sym) {
                let stem = file_stem_lower(&all_chunks[id].file_path);
                let mult = if stem_matches(&stem, &sym_lower) {
                    1.5
                } else {
                    1.0
                };
                *scores.entry(id).or_insert(0.0) += boost_unit * mult;
            }
        }
        for ch in all_chunks {
            if scores.contains_key(&ch.id) {
                continue;
            }
            let stem = file_stem_lower(&ch.file_path);
            if stem_matches(&stem, &sym_lower) && chunk_defines_symbol(&ch.content, sym) {
                scores.insert(ch.id, boost_unit * 1.5);
            }
        }
    } else {
        // Natural-language query: boost file-stem word matches
        const STOPWORDS: &[&str] = &[
            "a", "an", "and", "are", "as", "at", "be", "by", "do", "does", "for", "from", "has",
            "have", "how", "if", "in", "is", "it", "not", "of", "on", "or", "the", "to", "was",
            "what", "when", "where", "which", "who", "why", "with",
        ];
        let q_words: Vec<String> = tokenize_code(query)
            .into_iter()
            .filter(|w| w.len() >= 3 && !STOPWORDS.contains(&w.as_str()))
            .collect();
        let boost_unit = max_score * STEM_BOOST_MULT * 0.25;
        for (&id, sc) in scores.iter_mut() {
            let stem = file_stem_lower(&all_chunks[id].file_path);
            if q_words.iter().any(|w| stem_matches(&stem, w)) {
                *sc += boost_unit;
            }
        }
    }
}

fn file_path_penalty(file_path: &str) -> f64 {
    let norm = file_path.replace('\\', "/");
    let fname = Path::new(&norm)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let mut penalty = 1.0;

    let is_test_dir = norm.starts_with("tests/")
        || norm.starts_with("test/")
        || norm.contains("/tests/")
        || norm.contains("/__tests__/")
        || norm.contains("/testing/");
    let is_test_file = fname.starts_with("test_")
        || fname.contains("_test.")
        || fname.contains(".test.")
        || fname.contains(".spec.")
        || fname.ends_with("Test.java")
        || fname.ends_with("Spec.scala");
    if is_test_dir || is_test_file {
        penalty *= 0.3;
    }
    if matches!(fname, "__init__.py" | "package-info.java") {
        penalty *= 0.5;
    }
    if norm.contains("/compat/") || norm.contains("/legacy/") || norm.starts_with("legacy/") {
        penalty *= 0.3;
    }
    if norm.contains("/examples/") || norm.starts_with("examples/") {
        penalty *= 0.3;
    }
    if norm.ends_with(".d.ts") {
        penalty *= 0.7;
    }
    penalty
}

fn rerank_topk(
    scores: &HashMap<usize, f64>,
    chunks: &[CodeChunk],
    top_k: usize,
    penalise_paths: bool,
) -> Vec<(usize, f64)> {
    let mut penalised: Vec<(usize, f64)> = scores
        .iter()
        .map(|(&id, &sc)| {
            let p = if penalise_paths {
                file_path_penalty(&chunks[id].file_path)
            } else {
                1.0
            };
            (id, sc * p)
        })
        .collect();
    penalised.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut file_selected: HashMap<&str, u32> = HashMap::new();
    let mut selected: Vec<(usize, f64)> = Vec::new();
    let mut min_selected = f64::INFINITY;

    for (id, pen_score) in penalised {
        if selected.len() >= top_k && pen_score <= min_selected {
            break;
        }
        let fp = chunks[id].file_path.as_str();
        let already = *file_selected.get(fp).unwrap_or(&0);
        let eff = if already >= 1 {
            pen_score * FILE_SATURATION_DECAY.powi(already as i32)
        } else {
            pen_score
        };
        selected.push((id, eff));
        file_selected.insert(fp, already + 1);
        if selected.len() >= top_k {
            min_selected = selected
                .iter()
                .map(|(_, s)| *s)
                .fold(f64::INFINITY, f64::min);
        }
    }

    selected.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    selected.truncate(top_k);
    selected
}
