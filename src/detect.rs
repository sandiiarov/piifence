//! The detection pipeline: the secret model, the key rule and gitleaks, then the guards.
//!
//! ```text
//! text ─┬─ model, 3 KB windows ────────────┐
//!       ├─ model on the isolated copy ─────┤ model spans → Guards::suppress_model
//!       ├─ key rule ───────────────────────┐
//!       └─ gitleaks ───────────────────────┤ rule spans  → Guards::suppress
//!                                          ▼
//!                       kept spans, overlaps unioned, cached per text
//! ```
//!
//! `Detector::detect` returns the spans that survived the guards plus the spans the guards suppressed (with reasons), so callers can both act on detections and audit the guards.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Context;
use regex::Regex;

use crate::cache::{DetectionCache, Fingerprint};
use crate::gitleaks;
use crate::guards::{Guards, Suppression};
use crate::keyrule;
use crate::model::{SecretModel, MODEL_FILES};

/// One detected secret. `source` says what found it: `model:<TYPE>` (`model:API_KEY`), `keyrule`, or `gitleaks:<rule>`.
#[derive(Debug, Clone)]
pub struct DetectedSpan {
    pub word: String,
    pub start: usize,
    pub end: usize,
    pub source: String,
}

impl DetectedSpan {
    /// The engine part of `source`: `model`, `keyrule` or `gitleaks`.
    pub fn engine(&self) -> &str {
        self.source
            .split(':')
            .next()
            .expect("split yields a first part")
    }

    /// What found the span: the model's secret type (`API_KEY`), the gitleaks rule (`github-pat`), or `keyrule`.
    pub fn kind(&self) -> &str {
        match self.source.split_once(':') {
            Some((_, kind)) => kind,
            None => &self.source,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Detection {
    pub kept: Vec<DetectedSpan>,
    pub suppressed: Vec<(DetectedSpan, Suppression)>,
}

pub struct Detector {
    model: SecretModel,
    guards: Guards,
    gitleaks_config: PathBuf,
    cache: std::sync::Mutex<DetectionCache>,
}

impl Detector {
    /// Load the model from `model_dir` and open the detection cache in `cache_dir`, where the gitleaks rules are written too. `allow` holds the user's regexes for values never redacted (`Config::allow_patterns`).
    pub fn load(model_dir: &Path, allow: Vec<Regex>, cache_dir: &Path) -> anyhow::Result<Self> {
        for file in MODEL_FILES {
            anyhow::ensure!(
                model_dir.join(file).is_file(),
                "model file missing: {} (run scripts/fetch-weights.sh)",
                model_dir.join(file).display()
            );
        }
        let gitleaks_config = gitleaks::write_config(cache_dir)?;
        let fingerprint = fingerprint(model_dir, &allow)?;
        Ok(Self {
            model: SecretModel::load(model_dir)?,
            guards: Guards::with_allowlist(allow)?,
            gitleaks_config,
            cache: std::sync::Mutex::new(DetectionCache::open(
                &cache_dir.join("detections.jsonl"),
                fingerprint,
            )?),
        })
    }

    /// Number of texts in the cache.
    pub fn cached(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Detect secrets in `text` and apply the guards. Results are cached per text (`crate::cache`): Claude Code re-sends the whole history every turn, and everything besides `text` is fixed for the life of the Detector.
    pub fn detect(&self, text: &str) -> anyhow::Result<Detection> {
        if let Some(hit) = self.cache.lock().unwrap().get(text) {
            return Ok(hit);
        }
        let mut model_spans = self.model_spans(text)?;
        if let Some((isolated, index)) = isolate(text) {
            model_spans.extend(self.model_spans(&isolated)?.into_iter().map(|mut span| {
                span.start = index[span.start];
                span.end = index[span.end];
                span.word = text[span.start..span.end].to_string();
                span
            }));
        }
        let rule_spans = keyrule::spans(text)
            .into_iter()
            .map(|(start, end)| span(text, start, end, "keyrule".to_string()))
            .chain(self.gitleaks_spans(text)?);

        let mut detection = Detection::default();
        for span in model_spans {
            match self.guards.suppress_model(text, span.start, span.end) {
                Some(reason) => detection.suppressed.push((span, reason)),
                None => detection.kept.push(span),
            }
        }
        for span in rule_spans {
            match self.guards.suppress(text, span.start, span.end) {
                Some(reason) => detection.suppressed.push((span, reason)),
                None => detection.kept.push(span),
            }
        }
        detection.kept = union(detection.kept, text);
        self.cache.lock().unwrap().insert(text, &detection)?;
        Ok(detection)
    }

    fn model_spans(&self, text: &str) -> anyhow::Result<Vec<DetectedSpan>> {
        windowed(text, |chunk| {
            Ok(self
                .model
                .predict(chunk)?
                .into_iter()
                .map(|s| span(chunk, s.start, s.end, format!("model:{}", s.kind)))
                .collect())
        })
    }

    fn gitleaks_spans(&self, text: &str) -> anyhow::Result<Vec<DetectedSpan>> {
        let mut spans = Vec::new();
        for finding in gitleaks::scan(text, &self.gitleaks_config)? {
            for (start, end) in gitleaks::locate(&finding, text)? {
                spans.push(span(
                    text,
                    start,
                    end,
                    format!("gitleaks:{}", finding.rule_id),
                ));
            }
        }
        Ok(spans)
    }
}

fn span(text: &str, start: usize, end: usize, source: String) -> DetectedSpan {
    DetectedSpan {
        word: text[start..end].to_string(),
        start,
        end,
        source,
    }
}

/// Everything besides the text that decides a detection result. `crate::cache` keys entries on it, so a change to any of these misses instead of returning stale spans. The binary's stamp covers the code and the built-in gitleaks rules.
fn fingerprint(model_dir: &Path, allow: &[Regex]) -> anyhow::Result<[u8; 32]> {
    let mut fp = Fingerprint::default();
    fp.add("format", b"2");
    fp.add_file_stamp(
        "exe",
        &std::env::current_exe().context("locate the running binary")?,
    )?;
    for pattern in allow {
        fp.add("allow", pattern.as_str().as_bytes());
    }
    for file in MODEL_FILES {
        fp.add_file_stamp(file, &model_dir.join(file))?;
    }
    fp.add("gitleaks-version", &gitleaks::version()?);
    Ok(fp.finish())
}

/// Longest text the model sees in one pass. Attention cost grows with the square of the length, so long text is read in windows. On an M4 CPU cbx reads a 3 KB window about six times faster per byte than a 24 KB one (`bench/models/speed.py`, 2026-11-09).
const MODEL_WINDOW_BYTES: usize = 3_000;
/// Bytes each window shares with the next, so a value near a cut is whole in one window.
const MODEL_OVERLAP_BYTES: usize = 500;

/// Run `predict` over `text` in overlapping windows. Each window owns the spans that start inside its own region (not its overlap), so a span is kept exactly once. Offsets from `predict` are relative to the chunk it was given.
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

fn long_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\x21-\x7e]{12,}").expect("valid token regex"))
}

/// A copy of `text` where each long random-looking ASCII token glued to non-ASCII text is set apart as ` "token" `, and for each byte of the copy (plus its end) the byte of `text` it came from; an inserted byte maps to the next original one. `None` when there is no such token. The model misses `密钥是<value>请保管`, but finds the value once it stands apart.
fn isolate(text: &str) -> Option<(String, Vec<usize>)> {
    let glued = |m: &regex::Match| {
        text[..m.start()]
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_ascii())
            || text[m.end()..]
                .chars()
                .next()
                .is_some_and(|c| !c.is_ascii())
    };
    let cuts: Vec<(usize, usize)> = long_token()
        .find_iter(text)
        .filter(|m| glued(m) && keyrule::random_looking(m.as_str()))
        .map(|m| (m.start(), m.end()))
        .collect();
    if cuts.is_empty() {
        return None;
    }
    let mut copy = String::with_capacity(text.len() + 4 * cuts.len());
    let mut index = Vec::with_capacity(text.len() + 4 * cuts.len() + 1);
    let mut last = 0;
    for (start, end) in cuts {
        copy.push_str(&text[last..start]);
        index.extend(last..start);
        copy.push_str(" \"");
        index.extend([start, start]);
        copy.push_str(&text[start..end]);
        index.extend(start..end);
        copy.push_str("\" ");
        index.extend([end, end]);
        last = end;
    }
    copy.push_str(&text[last..]);
    index.extend(last..=text.len());
    Some((copy, index))
}

/// Order of trust when overlapping spans are unioned: a rule knows the format, the model guesses.
fn rank(span: &DetectedSpan) -> u8 {
    match span.engine() {
        "gitleaks" => 0,
        "keyrule" => 1,
        _ => 2,
    }
}

/// Sort `spans` and union the ones that overlap, so no part of a value found twice is left visible. The union keeps the source of its most trusted part.
fn union(mut spans: Vec<DetectedSpan>, text: &str) -> Vec<DetectedSpan> {
    spans.sort_by_key(|span| (span.start, span.end));
    let mut out: Vec<DetectedSpan> = Vec::new();
    for span in spans {
        match out.last_mut() {
            Some(current) if span.start < current.end => {
                if rank(&span) < rank(current) {
                    current.source = span.source;
                }
                current.end = current.end.max(span.end);
                current.word = text[current.start..current.end].to_string();
            }
            _ => out.push(span),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(start: usize, end: usize, source: &str) -> DetectedSpan {
        DetectedSpan {
            word: String::new(),
            start,
            end,
            source: source.to_string(),
        }
    }

    const TEXT40: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";

    #[test]
    fn overlapping_spans_become_their_union_with_the_most_trusted_source() {
        let out = union(
            vec![
                at(10, 20, "model:API_KEY"),
                at(15, 30, "gitleaks:jwt"),
                at(28, 35, "keyrule"),
            ],
            TEXT40,
        );
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].start, out[0].end), (10, 35));
        assert_eq!(out[0].source, "gitleaks:jwt");
        assert_eq!(out[0].word, &TEXT40[10..35]);
    }

    #[test]
    fn touching_spans_stay_separate() {
        let out = union(
            vec![at(5, 9, "model:PASSWORD"), at(0, 5, "keyrule")],
            TEXT40,
        );
        assert_eq!(
            out.iter().map(|s| (s.start, s.end)).collect::<Vec<_>>(),
            vec![(0, 5), (5, 9)]
        );
    }

    #[test]
    fn windowed_keeps_each_span_once_across_window_cuts() {
        // Fake predictor: reports every "SECRET" it can see in the chunk it gets.
        let predict = |chunk: &str| -> anyhow::Result<Vec<DetectedSpan>> {
            Ok(chunk
                .match_indices("SECRET")
                .map(|(i, m)| at(i, i + m.len(), "fake"))
                .collect())
        };
        // Across the first cut, inside the first overlap, and well inside later windows.
        let (w, o) = (MODEL_WINDOW_BYTES, MODEL_OVERLAP_BYTES);
        let markers = [100usize, w - 2, w + o - 10, 2 * w + w / 2, 6 * w + 100];
        let mut text = "x".repeat(7 * w).into_bytes();
        for &at in &markers {
            text[at..at + 6].copy_from_slice(b"SECRET");
        }
        let text = String::from_utf8(text).unwrap();
        let found = windowed(&text, predict).unwrap();
        let starts: Vec<usize> = found.iter().map(|s| s.start).collect();
        assert_eq!(starts, markers.to_vec());
    }

    #[test]
    fn isolate_sets_apart_values_glued_to_non_ascii_text() {
        let text = "密钥是SYgeCBkAV*dah5请保管 thanks";
        let (copy, index) = isolate(text).unwrap();
        assert_eq!(copy, "密钥是 \"SYgeCBkAV*dah5\" 请保管 thanks");
        let start = copy.find("SYge").unwrap();
        let end = start + "SYgeCBkAV*dah5".len();
        assert_eq!(&text[index[start]..index[end]], "SYgeCBkAV*dah5");
        // A span over the inserted quotes maps to the value alone.
        assert_eq!(&text[index[start - 1]..index[end + 1]], "SYgeCBkAV*dah5");
        assert_eq!(index[copy.len()], text.len());
        // Nothing glued to non-ASCII text, or nothing random-looking: no copy.
        assert!(isolate("key SYgeCBkAV*dah5 here").is_none());
        assert!(isolate("密钥是configuration请保管").is_none());
    }
}
