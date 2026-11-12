//! The Scrub model: [SporeLabs Scrub](https://huggingface.co/SporeLabs/scrub), a 17M-parameter ModernBERT (Ettin) with one sigmoid head per type plus a `begin` head, run on the CPU with candle.
//!
//! Windows and decoding follow Scrub's own `_model.py` (`OnnxSpans`), so the Rust port finds what the reference finds. Only the `SECRET` type is returned: the other types are personal data, which piifence does not redact.

use std::path::Path;

use anyhow::Context;
use candle_core::{DType, Device, Module, Tensor};
use candle_nn::{Linear, VarBuilder};
use candle_transformers::models::modernbert::{Config, ModernBert};
use tokenizers::Tokenizer;

use crate::model::ModelSpan;

/// Files a Scrub directory must hold.
pub const SCRUB_FILES: [&str; 5] = [
    "config.json",
    "model.safetensors",
    "heads.safetensors",
    "tokenizer.json",
    "scrub_config.json",
];

const KEPT: &str = "SECRET";
/// Characters `normalise` trims off span edges (`_pii.py` `_EDGE`).
const EDGE: &[char] = &[
    ' ', '\t', '\n', '\r', '.', ',', ';', ':', '!', '?', '"', '\'', '(', ')', '[', ']', '{', '}',
    '<', '>', '*', '`',
];

pub struct ScrubModel {
    backbone: ModernBert,
    heads: Linear,
    tokenizer: Tokenizer,
    thresholds: Vec<f32>,
    begin_threshold: f32,
    kept: usize,
    window: usize,
    stride: usize,
}

#[derive(serde::Deserialize)]
struct EncoderConfig {
    vocab_size: usize,
    hidden_size: usize,
    num_hidden_layers: usize,
    num_attention_heads: usize,
    intermediate_size: usize,
    max_position_embeddings: usize,
    norm_eps: f64,
    pad_token_id: u32,
    global_attn_every_n_layers: usize,
    local_attention: usize,
    global_rope_theta: f64,
    local_rope_theta: f64,
}

#[derive(serde::Deserialize)]
struct ScrubConfig {
    types: Vec<String>,
    thresholds: std::collections::HashMap<String, f32>,
    begin_threshold: f32,
    window: usize,
    stride: usize,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

/// Token windows over `n` tokens whose first and last are `[CLS]` and `[SEP]`: `(start, end)` of each window's body (`_model.py` `_windows`).
fn windows(n: usize, size: usize, stride: usize) -> Vec<(usize, usize)> {
    if n <= size {
        return vec![(1, n - 1)];
    }
    let mut out = Vec::new();
    let mut s = 1;
    loop {
        let e = (s + size - 2).min(n - 1);
        out.push((s, e));
        if e >= n - 1 {
            return out;
        }
        s += stride;
    }
}

impl ScrubModel {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let enc: EncoderConfig = read_json(&dir.join("config.json"))?;
        let cfg: ScrubConfig = read_json(&dir.join("scrub_config.json"))?;
        let config = Config {
            vocab_size: enc.vocab_size,
            hidden_size: enc.hidden_size,
            num_hidden_layers: enc.num_hidden_layers,
            num_attention_heads: enc.num_attention_heads,
            intermediate_size: enc.intermediate_size,
            max_position_embeddings: enc.max_position_embeddings,
            layer_norm_eps: enc.norm_eps,
            pad_token_id: enc.pad_token_id,
            global_attn_every_n_layers: enc.global_attn_every_n_layers,
            global_rope_theta: enc.global_rope_theta,
            local_attention: enc.local_attention,
            local_rope_theta: enc.local_rope_theta,
            classifier_config: None,
        };
        // SAFETY: the weights files are memory-mapped read-only and not changed while the process runs.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(
                &[dir.join("model.safetensors")],
                DType::F32,
                &Device::Cpu,
            )?
        };
        // The encoder checkpoint has no `model.` prefix, which candle's ModernBERT expects.
        let backbone = ModernBert::load(
            vb.rename_f(|name| name.strip_prefix("model.").unwrap_or(name).to_string()),
            &config,
        )?;
        let hb = unsafe {
            VarBuilder::from_mmaped_safetensors(
                &[dir.join("heads.safetensors")],
                DType::F32,
                &Device::Cpu,
            )?
        };
        let heads = candle_nn::linear(enc.hidden_size, cfg.types.len() + 1, hb)?;
        let thresholds = cfg
            .types
            .iter()
            .map(|t| {
                cfg.thresholds
                    .get(t)
                    .copied()
                    .with_context(|| format!("scrub_config.json has no threshold for {t}"))
            })
            .collect::<anyhow::Result<Vec<f32>>>()?;
        let kept = cfg
            .types
            .iter()
            .position(|t| t == KEPT)
            .with_context(|| format!("scrub_config.json has no {KEPT} type"))?;
        let tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|e| anyhow::anyhow!("load {}: {e}", dir.join("tokenizer.json").display()))?;
        anyhow::ensure!(
            cfg.window > 2 && cfg.stride > 0,
            "scrub_config.json: bad window or stride"
        );
        Ok(Self {
            backbone,
            heads,
            tokenizer,
            thresholds,
            begin_threshold: cfg.begin_threshold,
            kept,
            window: cfg.window,
            stride: cfg.stride,
        })
    }

    /// The secrets in `text`.
    pub fn predict(&self, text: &str) -> anyhow::Result<Vec<ModelSpan>> {
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;
        let ids = encoding.get_ids();
        let n = ids.len();
        anyhow::ensure!(n >= 2, "tokenizer added no [CLS] and [SEP]");
        let width = self.thresholds.len() + 1;
        let mut probs = vec![0f32; n * width];
        let mut best = vec![-1i64; n];
        for (s, t) in windows(n, self.window, self.stride) {
            let mut input = Vec::with_capacity(t - s + 2);
            input.push(ids[0]);
            input.extend_from_slice(&ids[s..t]);
            input.push(ids[n - 1]);
            let input = Tensor::new(input.as_slice(), &Device::Cpu)?.unsqueeze(0)?;
            let mask = input.ones_like()?;
            let hidden = self.backbone.forward(&input, &mask)?;
            let p: Vec<Vec<f32>> = candle_nn::ops::sigmoid(&self.heads.forward(&hidden)?)?
                .squeeze(0)?
                .to_vec2()?;
            for j in 0..t - s {
                let centre = j.min(t - s - 1 - j) as i64;
                let i = s + j;
                if centre > best[i] {
                    best[i] = centre;
                    probs[i * width..(i + 1) * width].copy_from_slice(&p[j + 1]);
                }
            }
        }
        Ok(self.decode(text, encoding.get_offsets(), &probs, width))
    }

    /// Join per-token probabilities into spans (`_model.py` `decode`, then `_pii.py` `normalise`), keeping the `SECRET` ones.
    fn decode(
        &self,
        text: &str,
        offsets: &[(usize, usize)],
        probs: &[f32],
        width: usize,
    ) -> Vec<ModelSpan> {
        let k = self.thresholds.len();
        let mut spans: Vec<(usize, usize, usize)> = Vec::new();
        let mut cur: Option<(usize, usize, usize)> = None;
        for (i, &(a, b)) in offsets.iter().enumerate() {
            if b <= a {
                continue;
            }
            let (a, b) = (floor_boundary(text, a), ceil_boundary(text, b));
            let p = &probs[i * width..i * width + k];
            let mut j = 0;
            for t in 1..k {
                if p[t] / self.thresholds[t] > p[j] / self.thresholds[j] {
                    j = t;
                }
            }
            let token = &text[a..b];
            let a2 = a + (token.len() - token.trim_start().len());
            if p[j] < self.thresholds[j] {
                spans.extend(cur.take());
                continue;
            }
            match cur.as_mut() {
                Some(c)
                    if c.2 == j && !(probs[i * width + k] >= self.begin_threshold && a2 > c.1) =>
                {
                    c.1 = b
                }
                _ => {
                    spans.extend(cur.take());
                    cur = Some((a2, b, j));
                }
            }
        }
        spans.extend(cur);
        let mut out: Vec<ModelSpan> = spans
            .into_iter()
            .filter(|&(_, _, j)| j == self.kept)
            .filter_map(|(s, e, _)| {
                let value = text[s..e].trim_start_matches(EDGE);
                let s = e - value.len();
                let value = value.trim_end_matches(EDGE);
                (!value.is_empty()).then(|| ModelSpan {
                    start: s,
                    end: s + value.len(),
                    kind: KEPT.to_string(),
                })
            })
            .collect();
        out.sort_by_key(|s| (s.start, s.end));
        out.dedup();
        out
    }
}

fn floor_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_match_the_reference() {
        assert_eq!(windows(10, 512, 384), vec![(1, 9)]);
        assert_eq!(windows(512, 512, 384), vec![(1, 511)]);
        assert_eq!(
            windows(1000, 512, 384),
            vec![(1, 511), (385, 895), (769, 999)]
        );
    }
}
