//! Shared detection pipeline: model inference + gitleaks pre-pass + guards.
//!
//! `Detector::detect` returns the spans that survived the guards plus the spans
//! the guards suppressed (with reasons), so callers can both act on detections
//! and audit the wrapper's vetoes.

use std::collections::HashSet;
use std::path::Path;

use crate::gitleaks;
use crate::guards::{Guards, Suppression};
use privacy_filter_rs::{
    backend::{self, Device, B},
    PrivacyFilterInference,
};

/// One detected span, from the model or the gitleaks pre-pass.
#[derive(Debug, Clone)]
pub struct DetectedSpan {
    pub label: String,
    pub score: f32,
    pub word: String,
    pub start: usize,
    pub end: usize,
    pub source: String,
}

#[derive(Debug, Default, Clone)]
pub struct Detection {
    pub kept: Vec<DetectedSpan>,
    pub suppressed: Vec<(DetectedSpan, Suppression)>,
}

pub struct Detector {
    engine: Option<PrivacyFilterInference<B>>,
    guards: Guards,
    use_gitleaks: bool,
    use_guards: bool,
    categories: Option<HashSet<String>>,
    cache: std::sync::Mutex<DetectionCache>,
}

impl Detector {
    /// Load the model and initialize the guards. `model_dir` must contain
    /// config.json, model.safetensors, tokenizer.json (and optionally
    /// viterbi_calibration.json).
    pub fn load(model_dir: &Path, use_gitleaks: bool, use_guards: bool) -> anyhow::Result<Self> {
        Self::load_with_categories(model_dir, use_gitleaks, use_guards, None, true)
    }

    /// Restrict detection/redaction to the given normalized categories.
    /// `None` means all categories (the default). When only `secret` is enabled,
    /// the model is not loaded at all — gitleaks is the whole detector.
    pub fn load_with_categories(
        model_dir: &Path,
        use_gitleaks: bool,
        use_guards: bool,
        categories: Option<HashSet<String>>,
        use_llm_filter: bool,
    ) -> anyhow::Result<Self> {
        let needs_model = needs_model(&categories, use_llm_filter);
        let engine = if needs_model {
            let device: Device = backend::device();
            Some(PrivacyFilterInference::<B>::load(model_dir, device)?)
        } else {
            None
        };
        Ok(Self {
            engine,
            guards: Guards::new()?,
            use_gitleaks,
            use_guards,
            categories,
            cache: std::sync::Mutex::new(DetectionCache::new(cache_limit_bytes())),
        })
    }

    pub fn uses_model(&self) -> bool {
        self.engine.is_some()
    }

    fn category_enabled(&self, label: &str) -> bool {
        let normalized = label.trim().to_ascii_lowercase().replace('-', "_");
        self.categories
            .as_ref()
            .map(|set| set.contains(&normalized))
            .unwrap_or(true)
    }

    /// Detect spans in `text` and apply the wrapper guards.
    /// Results are cached per exact text: Claude Code re-sends the whole history every
    /// turn, and everything besides `text` is fixed for the life of the Detector.
    pub fn detect(&self, text: &str) -> anyhow::Result<Detection> {
        if let Some(hit) = self.cache.lock().unwrap().get(text) {
            return Ok(hit);
        }
        let model_spans: Vec<DetectedSpan> = match &self.engine {
            Some(engine) => windowed(text, |chunk| {
                Ok(engine
                    .predict(chunk)?
                    .into_iter()
                    .filter(|s| self.category_enabled(&s.entity_group))
                    .map(|s| DetectedSpan {
                        label: s.entity_group.clone(),
                        score: s.score,
                        word: s.word.clone(),
                        start: s.start,
                        end: s.end,
                        source: "model".to_string(),
                    })
                    .collect())
            })?
            .into_iter()
            .map(|span| snap_to_char_boundaries(span, text))
            .collect(),
            None => Vec::new(),
        };

        let pre_spans = if self.use_gitleaks && self.category_enabled("secret") {
            gitleaks_spans(text)?
        } else {
            Vec::new()
        };

        let (model_kept, suppressed, pre_kept) = if self.use_guards {
            let (model_kept, mut suppressed) = apply_guards(model_spans, text, &self.guards);
            let (pre_kept, pre_suppressed) = apply_guards(pre_spans, text, &self.guards);
            suppressed.extend(pre_suppressed);
            (model_kept, suppressed, pre_kept)
        } else {
            (model_spans, Vec::new(), pre_spans)
        };

        let detection = Detection {
            kept: merge_spans(model_kept, pre_kept),
            suppressed,
        };
        self.cache
            .lock()
            .unwrap()
            .insert(text.to_string(), detection.clone());
        Ok(detection)
    }

    /// Convenience wrapper that returns only the spans that survived the guards.
    pub fn detect_kept(&self, text: &str) -> anyhow::Result<Vec<DetectedSpan>> {
        Ok(self.detect(text)?.kept)
    }
}

/// Final detection results per exact text, bounded by the total bytes of cached text.
/// The least recently used entry is evicted first, so a long conversation keeps its
/// history cached instead of thrashing. Keyed on the full text, not a hash, so a hash
/// collision cannot return another text's spans.
struct DetectionCache {
    entries: std::collections::HashMap<String, (Detection, u64)>,
    bytes: usize,
    limit_bytes: usize,
    tick: u64,
}

impl DetectionCache {
    fn new(limit_bytes: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            bytes: 0,
            limit_bytes,
            tick: 0,
        }
    }

    /// A copy of the cached detection, marking it most recently used.
    fn get(&mut self, text: &str) -> Option<Detection> {
        let entry = self.entries.get_mut(text)?;
        self.tick += 1;
        entry.1 = self.tick;
        Some(entry.0.clone())
    }

    /// Cache `detection` for `text`, evicting least recently used entries until it
    /// fits. A text larger than the whole budget is not cached.
    fn insert(&mut self, text: String, detection: Detection) {
        if text.len() > self.limit_bytes {
            return;
        }
        if self.entries.remove(&text).is_some() {
            self.bytes -= text.len();
        }
        while self.bytes + text.len() > self.limit_bytes {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
            self.bytes -= oldest.len();
        }
        self.tick += 1;
        self.bytes += text.len();
        self.entries.insert(text, (detection, self.tick));
    }
}

/// Cache budget in bytes of text: `PIIF_CACHE_MB` (default 64). A Claude Code
/// session is a few MB of text, so the default holds several full sessions.
fn cache_limit_bytes() -> usize {
    std::env::var("PIIF_CACHE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(64)
        .saturating_mul(1024 * 1024)
}

/// True when detection still needs the neural model: any non-secret category,
/// or secret-only with the model explicitly enabled for secrets.
pub fn needs_model(categories: &Option<HashSet<String>>, use_llm_filter: bool) -> bool {
    match categories {
        None => true,
        Some(set) => set.iter().any(|category| category != "secret") || use_llm_filter,
    }
}

/// Longest text the model sees in one forward pass. Attention cost grows with the
/// square of the length: a single 375k-token pass exhausted memory and killed the
/// gateway. Longer text is split into windows of about 2k tokens.
const MODEL_WINDOW_BYTES: usize = 6_000;
/// Bytes each window shares with the next, so a value near a cut is whole in one window.
const MODEL_OVERLAP_BYTES: usize = 1_000;

/// Run `predict` over `text` in overlapping windows. Each window owns the spans that
/// start inside its own region (not its overlap), so a span is kept exactly once.
/// Offsets from `predict` are relative to the chunk it was given.
fn windowed<F>(text: &str, mut predict: F) -> anyhow::Result<Vec<DetectedSpan>>
where
    F: FnMut(&str) -> anyhow::Result<Vec<DetectedSpan>>,
{
    if text.len() <= MODEL_WINDOW_BYTES {
        return predict(text);
    }
    let mut out = Vec::new();
    let mut own_start = 0;
    while own_start < text.len() {
        let own_end = ceil_boundary(text, own_start + MODEL_WINDOW_BYTES);
        let window_end = ceil_boundary(text, own_end + MODEL_OVERLAP_BYTES);
        for mut span in predict(&text[own_start..window_end])? {
            span.start += own_start;
            span.end += own_start;
            if span.start >= own_start && span.start < own_end {
                out.push(span);
            }
        }
        own_start = own_end;
    }
    Ok(out)
}

/// Smallest char boundary at or after `index`, capped at the text length.
fn ceil_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// Widen a span outward to the nearest char boundaries. Slicing or replacing text
/// inside a multi-byte character panics, so a span that cuts one is widened: over-
/// redacting a character is safer than crashing or leaving part of a value visible.
fn snap_to_char_boundaries(mut span: DetectedSpan, text: &str) -> DetectedSpan {
    let len = text.len();
    let mut start = span.start.min(len);
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = span.end.min(len);
    while end < len && !text.is_char_boundary(end) {
        end += 1;
    }
    span.start = start;
    span.end = end.max(start);
    span
}

fn overlaps(a: &DetectedSpan, b: &DetectedSpan) -> bool {
    a.start < b.end && b.start < a.end
}

/// Union model and pre-pass spans. Pre-pass findings that overlap a model span
/// are normally dropped (same credential detected twice), but a deterministic
/// `secret` finding wins over a model PII label covering the same region: the
/// model labels `AKIAIOSFODNN7EXAMPLE` as `private_person` in prose, while
/// gitleaks knows it is a credential.
fn merge_spans(mut model: Vec<DetectedSpan>, pre_pass: Vec<DetectedSpan>) -> Vec<DetectedSpan> {
    for candidate in pre_pass {
        let overlaps_model = model.iter().any(|existing| overlaps(&candidate, existing));
        if !overlaps_model {
            model.push(candidate);
            continue;
        }
        if candidate.label.eq_ignore_ascii_case("secret") {
            // A deterministic secret takes over every model span it touches, and
            // the result covers the union of them. Keeping only the overlap would
            // leave the part of the credential the model span did not reach visible.
            let mut merged = candidate;
            // Growing the union can reach spans kept on an earlier pass, so repeat
            // until a pass no longer widens it.
            loop {
                let before = (merged.start, merged.end);
                model.retain(|existing| {
                    if !overlaps(existing, &merged) {
                        return true;
                    }
                    merged.start = merged.start.min(existing.start);
                    merged.end = merged.end.max(existing.end);
                    false
                });
                if (merged.start, merged.end) == before {
                    break;
                }
            }
            model.push(merged);
        }
    }
    model.sort_by_key(|span| (span.start, span.end));
    model
}

fn apply_guards(
    spans: Vec<DetectedSpan>,
    text: &str,
    guards: &Guards,
) -> (Vec<DetectedSpan>, Vec<(DetectedSpan, Suppression)>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for span in spans {
        match guards.suppress(text, span.start, span.end) {
            Some(reason) => dropped.push((span, reason)),
            None => kept.push(span),
        }
    }
    (kept, dropped)
}

fn gitleaks_spans(text: &str) -> anyhow::Result<Vec<DetectedSpan>> {
    let findings = gitleaks::scan(text)?;
    let mut spans = Vec::new();
    for finding in &findings {
        for (start, end) in gitleaks::locate(finding, text) {
            spans.push(DetectedSpan {
                label: "secret".to_string(),
                score: 1.0,
                word: text[start..end].to_string(),
                start,
                end,
                source: format!("gitleaks:{}", finding.rule_id),
            });
        }
    }
    Ok(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(label: &str, start: usize, end: usize, source: &str) -> DetectedSpan {
        DetectedSpan {
            label: label.to_string(),
            score: 0.9,
            word: String::new(),
            start,
            end,
            source: source.to_string(),
        }
    }

    #[test]
    fn deterministic_secret_replaces_model_person_on_same_span() {
        let model = vec![span("private_person", 44, 63, "model")];
        let pre = vec![span("secret", 44, 63, "gitleaks:piifence-aws-access-token")];
        let merged = merge_spans(model, pre);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].label, "secret");
        assert!(merged[0].source.starts_with("gitleaks"));
    }

    #[test]
    fn secret_with_leading_space_model_span_still_wins() {
        let model = vec![span("private_person", 43, 63, "model")];
        let pre = vec![span("secret", 44, 63, "gitleaks:piifence-aws-access-token")];
        let merged = merge_spans(model, pre);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].label, "secret");
    }

    #[test]
    fn duplicate_secret_is_deduped() {
        let model = vec![span("secret", 5, 88, "model")];
        let pre = vec![span("secret", 5, 88, "gitleaks:jwt")];
        let merged = merge_spans(model, pre);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn model_needed_unless_only_secret_is_enabled() {
        assert!(needs_model(&None, false));
        let mut set = HashSet::new();
        set.insert("secret".to_string());
        assert!(!needs_model(&Some(set.clone()), false));
        assert!(needs_model(&Some(set.clone()), true));
        set.insert("private_email".to_string());
        assert!(needs_model(&Some(set), false));
    }

    #[test]
    fn non_overlapping_spans_are_kept() {
        let model = vec![span("private_email", 11, 29, "model")];
        let pre = vec![span("secret", 44, 63, "gitleaks")];
        let merged = merge_spans(model, pre);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn partially_overlapping_secret_covers_the_union() {
        // The model PII span stops short of the credential; the credential's tail
        // must not be left visible.
        let model = vec![span("private_person", 10, 20, "model")];
        let pre = vec![span("secret", 15, 40, "gitleaks:jwt")];
        let merged = merge_spans(model, pre);
        assert_eq!(merged.len(), 1);
        assert_eq!((merged[0].start, merged[0].end), (10, 40));
        assert_eq!(merged[0].label, "secret");
    }

    #[test]
    fn secret_growth_absorbs_spans_kept_on_an_earlier_pass() {
        // Model [21..30] does not touch the secret 10..20 directly, but the union
        // grows to 5..22 through 5..22, and then reaches 21..30.
        let model = vec![
            span("private_email", 21, 30, "model"),
            span("private_person", 5, 22, "model"),
        ];
        let pre = vec![span("secret", 10, 20, "gitleaks:jwt")];
        let merged = merge_spans(model, pre);
        assert_eq!(merged.len(), 1);
        assert_eq!((merged[0].start, merged[0].end), (5, 30));
    }

    #[test]
    fn windowed_keeps_each_span_once_across_window_cuts() {
        // Fake predictor: reports every "SECRET" it can see in the chunk it gets.
        let predict = |chunk: &str| -> anyhow::Result<Vec<DetectedSpan>> {
            Ok(chunk
                .match_indices("SECRET")
                .map(|(i, m)| span("secret", i, i + m.len(), "fake"))
                .collect())
        };
        let markers = [100usize, 5_998, 6_990, 12_500, 19_000];
        let mut text = "x".repeat(20_000).into_bytes();
        for &at in &markers {
            text[at..at + 6].copy_from_slice(b"SECRET");
        }
        let text = String::from_utf8(text).unwrap();
        let found = windowed(&text, predict).unwrap();
        let starts: Vec<usize> = found.iter().map(|s| s.start).collect();
        assert_eq!(starts, markers.to_vec());
    }

    #[test]
    fn spans_are_widened_to_char_boundaries() {
        // "é" is two bytes: index 2 falls inside it.
        let text = "aéb";
        let snapped = snap_to_char_boundaries(span("secret", 2, 3, "model"), text);
        assert_eq!((snapped.start, snapped.end), (1, 3));
        assert!(text.get(snapped.start..snapped.end).is_some());
    }

    fn one_secret() -> Detection {
        Detection {
            kept: vec![span("secret", 0, 3, "model")],
            suppressed: vec![],
        }
    }

    #[test]
    fn cache_returns_what_was_inserted() {
        let mut cache = DetectionCache::new(1024);
        cache.insert("abc".to_string(), one_secret());
        let hit = cache.get("abc").expect("cached");
        assert_eq!(hit.kept.len(), 1);
        assert_eq!(hit.kept[0].label, "secret");
        assert!(cache.get("zzz").is_none());
    }

    #[test]
    fn cache_evicts_least_recently_used_first() {
        let mut cache = DetectionCache::new(10);
        cache.insert("aaaa".to_string(), one_secret());
        cache.insert("bbbb".to_string(), one_secret());
        assert!(cache.get("aaaa").is_some());
        cache.insert("cccc".to_string(), one_secret());
        assert!(cache.get("bbbb").is_none());
        assert!(cache.get("aaaa").is_some());
        assert!(cache.get("cccc").is_some());
    }

    #[test]
    fn cache_skips_text_larger_than_budget() {
        let mut cache = DetectionCache::new(4);
        cache.insert("abcdef".to_string(), one_secret());
        assert!(cache.get("abcdef").is_none());
    }

    #[test]
    fn cache_reinsert_does_not_double_count() {
        let mut cache = DetectionCache::new(8);
        cache.insert("aaaa".to_string(), one_secret());
        cache.insert("aaaa".to_string(), one_secret());
        cache.insert("bbbb".to_string(), one_secret());
        assert!(cache.get("aaaa").is_some());
        assert!(cache.get("bbbb").is_some());
    }
}
