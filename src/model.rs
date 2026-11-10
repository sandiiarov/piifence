//! The secret model: [cbx-secrets-detector-32M](https://huggingface.co/CobuildX-AI/cbx-secrets-detector-32M), a 32M-parameter ModernBERT (Ettin) token tagger, run on the CPU with candle and Apple Accelerate.
//!
//! The model tags every token with a BIO tag (`B-`/`I-` per secret type, `O` for not a secret). Tags are joined into spans the way the model's own `cbx_secrets.py` does it, so the Rust port finds what the Python reference finds.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use candle_core::{DType, Device, Module, Tensor, D};
use candle_nn::{Linear, VarBuilder};
use candle_transformers::models::modernbert::{Config, ModernBert};
use tokenizers::Tokenizer;

/// Files the model directory must hold.
pub const MODEL_FILES: [&str; 4] = [
    "config.json",
    "model.safetensors",
    "tokenizer.json",
    "secrets_config.json",
];

/// Punctuation a token can glue onto the start or end of a value (`cbx_secrets.py` `_EDGE_LEAD`, `_EDGE_TRAIL`).
const EDGE_LEAD: &[char] = &['=', '.', '"', '\'', '*', '<', ':', ';', ',', '`'];
const EDGE_TRAIL: &[char] = &['.', ',', ';', ':', '"', '\'', '*', '>', '`'];

/// One secret the model found: byte offsets into the text, and the model's secret type (`API_KEY`, `PASSWORD`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSpan {
    pub start: usize,
    pub end: usize,
    pub kind: String,
}

pub struct SecretModel {
    backbone: ModernBert,
    head: Linear,
    tokenizer: Tokenizer,
    tags: Vec<String>,
    /// Shortest span kept, in characters, per secret type.
    min_len: HashMap<String, usize>,
    default_min_len: usize,
    cls: u32,
    sep: u32,
    /// Most tokens one pass can read, without `[CLS]` and `[SEP]`.
    max_tokens: usize,
}

#[derive(serde::Deserialize)]
struct HfConfig {
    vocab_size: usize,
    hidden_size: usize,
    num_hidden_layers: usize,
    num_attention_heads: usize,
    intermediate_size: usize,
    max_position_embeddings: usize,
    norm_eps: f64,
    pad_token_id: u32,
    cls_token_id: u32,
    sep_token_id: u32,
    global_attn_every_n_layers: usize,
    local_attention: usize,
    rope_parameters: HashMap<String, RopeParameters>,
}

#[derive(serde::Deserialize)]
struct RopeParameters {
    rope_theta: f64,
}

#[derive(serde::Deserialize)]
struct SecretsConfig {
    tags: Vec<String>,
    min_len: HashMap<String, usize>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

impl SecretModel {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let hf: HfConfig = read_json(&dir.join("config.json"))?;
        let secrets: SecretsConfig = read_json(&dir.join("secrets_config.json"))?;
        let rope = |kind: &str| -> anyhow::Result<f64> {
            Ok(hf
                .rope_parameters
                .get(kind)
                .with_context(|| format!("config.json has no rope_parameters.{kind}"))?
                .rope_theta)
        };
        let config = Config {
            vocab_size: hf.vocab_size,
            hidden_size: hf.hidden_size,
            num_hidden_layers: hf.num_hidden_layers,
            num_attention_heads: hf.num_attention_heads,
            intermediate_size: hf.intermediate_size,
            max_position_embeddings: hf.max_position_embeddings,
            layer_norm_eps: hf.norm_eps,
            pad_token_id: hf.pad_token_id,
            global_attn_every_n_layers: hf.global_attn_every_n_layers,
            global_rope_theta: rope("full_attention")?,
            local_attention: hf.local_attention,
            local_rope_theta: rope("sliding_attention")?,
            classifier_config: None,
        };
        let weights = dir.join("model.safetensors");
        // SAFETY: the weights file is memory-mapped read-only and not changed while the process runs.
        let vb =
            unsafe { VarBuilder::from_mmaped_safetensors(&[&weights], DType::F32, &Device::Cpu)? };
        // The checkpoint keeps the encoder under `backbone.`, where candle's ModernBERT expects `model.`.
        let backbone = ModernBert::load(
            vb.clone()
                .rename_f(|name| name.replacen("model.", "backbone.", 1)),
            &config,
        )?;
        let head = candle_nn::linear(hf.hidden_size, secrets.tags.len(), vb.pp("head"))?;
        let tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|e| anyhow::anyhow!("load {}: {e}", dir.join("tokenizer.json").display()))?;
        let default_min_len = *secrets
            .min_len
            .get("*")
            .context("secrets_config.json has no min_len.\"*\"")?;
        anyhow::ensure!(
            secrets.tags.first().map(String::as_str) == Some("O"),
            "secrets_config.json: the first tag must be O"
        );
        Ok(Self {
            backbone,
            head,
            tokenizer,
            tags: secrets.tags,
            min_len: secrets.min_len,
            default_min_len,
            cls: hf.cls_token_id,
            sep: hf.sep_token_id,
            max_tokens: hf.max_position_embeddings - 2,
        })
    }

    /// The secrets in `text`, read in one pass. The text must fit the model's context (7,997 tokens); the detector's windows keep it far below that.
    pub fn predict(&self, text: &str) -> anyhow::Result<Vec<ModelSpan>> {
        let encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;
        let ids = encoding.get_ids();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        anyhow::ensure!(
            ids.len() <= self.max_tokens,
            "text of {} tokens exceeds the model's {} tokens",
            ids.len(),
            self.max_tokens
        );
        let mut input = Vec::with_capacity(ids.len() + 2);
        input.push(self.cls);
        input.extend_from_slice(ids);
        input.push(self.sep);
        let input = Tensor::new(input.as_slice(), &Device::Cpu)?.unsqueeze(0)?;
        let mask = input.ones_like()?;
        let hidden = self.backbone.forward(&input, &mask)?;
        let tags: Vec<u32> = self
            .head
            .forward(&hidden)?
            .argmax(D::Minus1)?
            .squeeze(0)?
            .to_vec1()?;
        // Drop the tags of [CLS] and [SEP].
        Ok(self.spans(text, encoding.get_offsets(), &tags[1..tags.len() - 1]))
    }

    /// Join per-token tags into spans (`cbx_secrets.py` `_spans`): a token's edge whitespace is not part of a value, a whitespace-only token neither starts nor ends a span, `B-` or a new type starts a span, and the punctuation a token glues onto a value is trimmed off its edges.
    fn spans(&self, text: &str, offsets: &[(usize, usize)], tags: &[u32]) -> Vec<ModelSpan> {
        let mut raw: Vec<ModelSpan> = Vec::new();
        let mut current: Option<ModelSpan> = None;
        for (&(start, end), &tag) in offsets.iter().zip(tags) {
            // Byte-level tokens can split a multi-byte character; such a token covers the whole character.
            let (start, end) = (floor_boundary(text, start), ceil_boundary(text, end));
            let token = &text[start..end];
            let a = start + (token.len() - token.trim_start().len());
            let b = end - (token.len() - token.trim_end().len());
            if a >= b {
                continue;
            }
            let tag = &self.tags[tag as usize];
            let Some((prefix, kind)) = tag.split_once('-') else {
                raw.extend(current.take());
                continue;
            };
            match current.as_mut() {
                Some(span) if prefix != "B" && span.kind == kind => span.end = b,
                _ => {
                    raw.extend(current.take());
                    current = Some(ModelSpan {
                        start: a,
                        end: b,
                        kind: kind.to_string(),
                    });
                }
            }
        }
        raw.extend(current);
        raw.into_iter()
            .filter_map(|mut span| {
                let value = text[span.start..span.end].trim_start_matches(EDGE_LEAD);
                span.start = span.end - value.len();
                let value = value.trim_end_matches(EDGE_TRAIL);
                span.end = span.start + value.len();
                let min = *self
                    .min_len
                    .get(&span.kind)
                    .unwrap_or(&self.default_min_len);
                (value.chars().count() >= min).then_some(span)
            })
            .collect()
    }
}

/// Largest char boundary at or before `index`.
fn floor_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Smallest char boundary at or after `index`.
fn ceil_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index += 1;
    }
    index
}
