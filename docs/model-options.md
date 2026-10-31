# Model options — beyond the current Privacy Filter

Research (2026-10-25) after a live miss: a bare `oc_sk_…` key in a tool result was
labelled `private_person` and forwarded. Links are to model cards; all candidates are
local-inference, Apache/MIT licensed unless noted.

## What we learned from the miss

The current model is context-sensitive, not format-blind:

| input | prediction |
| --- | --- |
| `oc_sk_…` alone | `private_person` 0.475 |
| `OPENCODE_API_KEY=oc_sk_…` | `secret` 0.983 |
| `Tool call: Bash {"command":"echo $OPENCODE_API_KEY"}\n<key>` | `secret` 0.981 |
| `Tool call: Bash …\nTool output:\n<key>` (the gateway format) | `secret` 0.999 |
| `command: sha256sum file\noutput: 9f86…` | no span (context prevents hash FP) |

So the first fix is **not a new model and not a regex**: give the model the tool call
that produced the output as context. Implemented in `src/bin/gateway.rs`
(`redact_tool_result_content` / `redact_text_with_context`): tool_result fields are
re-scanned with `Tool call: <name> <input>\nTool output:` prepended, and only spans that
fall inside the output are redacted. Verified with gitleaks disabled: with context the
model reports `secret` 0.999 and the provider sees `<secret_1>`; without context the raw
key is forwarded. The vendor rule (`piifence-opencode-key`) stays as a cheap fallback.

## Candidate models

| model | size / runtime | what it gives | fit |
| --- | --- | --- | --- |
| [MaTE X Privacy Sentinel v0.15](https://huggingface.co/enosislabs/matex-privacy-sentinel-v0.15-onnx) | openai/privacy-filter fine-tune, 1.5B MoE (50M active), ONNX | 23 developer/AI categories incl. `api_key`, `database_uri`, `repo_secret`, `cloud_credential`, `auth_token`, `session_cookie`, `payment_token`; BIOES + Viterbi; secret F1 0.924, repo_secret F1 0.970 | **best replacement candidate** — same architecture as ours, developer domain; needs Rust crate label adaptation (crate hardcodes 8 categories) or Python/ONNX sidecar |
| [Secrets Sentinel](https://huggingface.co/hypn05/secrets-sentinel) | DeBERTa-v3-base 184M, ONNX INT8 ~244 MB, MIT | binary safe/secret with context; explicitly treats `password = os.environ.get('DB_PASS')` as safe, `password = "hunter2"` as secret; claimed F1 0.9999 | **best cheap second stage** — run on tool call + output / candidate windows; no spans, so pair with entropy locator or current model |
| [GLiNER2-PII ONNX](https://huggingface.co/okasi/gliner2-privacy-filter-pii-multi-onnx) | mdeberta-v3-base, Q8 510 MB, Apache-2.0 | fixed 7-label PII NER; SPY-200 F1 0.534 vs lower for openai/privacy-filter | PII only — no credential/secret labels; not a fix for this gap |
| [Clef-Flash 9B MLX 4-bit](https://huggingface.co/aufklarer/Clef-flash-9B-MLX-4bit) | Qwen3.5 9B, 5.3 GB MLX, Apache-2.0 | decision model: typed questions → choice probabilities (`noul` yes/no), 64K context, 38 ms on Workers AI GPUs | possible second-stage verifier ("is this a credential?"), but 9B, custom decision head, no spans, cloud Workers AI route would leak candidates; local MLX integration is a project |
| [SafetyNet](https://www.npmjs.com/package/@mhingston5/safetynet) / [SecretMask](https://huggingface.co/AndrewAndrewsen/distilbert-secret-masker) | ModernBERT / DistilBERT 66M | NER secret scanner / tiny masker | worth a benchmark if we want spans + small footprint |

## MaTE X Privacy Sentinel v0.15 — benchmark (2026-10-25)

Setup: ONNX fp32 export (`model.onnx` 4 MB + `model.onnx.data` 5.9 GB), tokenizer =
the o200k HF tokenizer already in `data/` (IDs validated against tiktoken), custom
97-label BIOES Viterbi (zero transition biases), text padded to >=32 tokens (export
quirk). Apple M4 CPU, onnxruntime 1.31.

Corpus (mapped to the 8-label space; secret-family labels -> SECRET):

| case | MaTE X span | base model |
| --- | --- | --- |
| sec-01 AWS key | `cloud_credential` 0.618 (full span) | missed |
| sec-02 `sk-proj-…` | `auth_token` 0.910 | `secret` 1.0 |
| sec-03 JWT | `auth_token` 0.981 | `secret` 0.999 |
| sec-04 postgres URI | `database_uri` 0.849 (full URI) | partial SECRET + URL |
| sec-05 placeholder | none | re-redacted (guard needed) |
| pii-01 … pii-05 | email/phone/person/address/date/account all found; **pii-03 internal URL missed** | 5/5 |
| negatives | all clean (env-ref, hash, config, version, timeouts) | 4/5 (env-ref FP) |

Mapped gate: secret 5/5, pii 4/5 (pii-03 miss; mandatory pii-05 passes), negative 5/5
-> **M1 gate passes** (14/15). Tool-output check: bare `oc_sk_…` -> `session_cookie`
0.396; with tool-call context -> `auth_token` 0.368; SHA256 and env-ref clean.

Speed (CPU, onnxruntime): 15–57 tokens 220–390 ms; 96/128/192/256 tokens
0.8/1.1/1.6/2.0 s; load ~0.36 s, RSS ~1.4 GB after inference, disk 5.9 GB.
**Hard limit: 256 tokens.** The export advertises dynamic axes but fails (reshape
error) at 257+, so it cannot process a full Claude Code prompt (~1.2k tokens) as-is.

Caveats: bare-secret scores are low (0.37–0.40) — a confidence threshold above ~0.4
would drop them; zero-bias Viterbi vs `opf` calibration may differ; known single-token
person-name and internal-URL misses.

## Recommendation

1. **Keep the context-aware re-scan** (done, model-native, no rules needed).
2. Add **Secrets Sentinel** as a second-stage verifier for tool outputs and high-entropy
   candidates: it is 244 MB ONNX, fast on CPU, MIT, and its safe/secret context behavior
   also covers our `os.environ.get(...)` false positives.
3. **MaTE X** is the strongest candidate on quality (corpus gate passes, bare keys and
   env-ref/hash behave correctly), but the ONNX export is capped at 256 tokens. Use it
   as a **hybrid verifier for tool_result text** (short) first; long-term, re-export with
   correct dynamic axes or port its weights to the Rust Burn/sliding-window path before
   replacing the base model.
4. **Clef-Flash** only if a high-precision local decision model is justified later; not a
   drop-in and not on OpenRouter (checked the live catalog).

## Decision (2026-10-25)

**Keep the current pipeline**: `openai/privacy-filter` + gitleaks + guards +
tool-context scanning. MaTE X is not adopted now — its 256-token ONNX cap, the
`pii-03` internal-URL regression, and the extra 5.9 GB / CPU cost outweigh the secret
recall gain for the gateway use case. The benchmark remains above for reference;
revisit only if MaTE X is re-exported with working dynamic axes or ported to the Rust
sliding-window path. The temporary model/venv downloads were removed.


## Small models — benchmark (2026-10-25)

Question: can a much smaller model do the bare-secret job? Tested off-the-shelf, CPU only.

| model | params / size | runtime | bare `oc_sk_…` | env-ref / hash / UUID | notes |
| --- | --- | --- | --- | --- | --- |
| [Secrets Sentinel xsmall](https://huggingface.co/hypn05/secrets-sentinel-xsmall) | 70M, 283 MB fp32, MIT | torch CPU 15–60 ms | 1.000 | env 0.0; **SHA256 1.0, git SHA 1.0, UUID 0.87, base64 1.0** | catches assignment/tool context/AWS/sk/JWT/postgres at 1.0; with tool context (git rev-parse, uuidgen, sha256sum) everything is flagged 1.0 — too recall-heavy as an automatic stage |
| [Secrets Sentinel small](https://huggingface.co/hypn05/secrets-sentinel-small) | 141M, 561 MB fp32, MIT | torch CPU 17–31 ms | 1.000 | env 0.0; SHA 1.0, git SHA 1.0, UUID 1.0; **AWS 0.0, sk-proj 0.0** | same recall bias, less consistent on known formats |
| [DistilBERT Secret Masker](https://huggingface.co/AndrewAndrewsen/distilbert-secret-masker) | 66M, 265 MB, Apache-2.0 | ONNX CPU 4–19 ms | yes (token span) | env 0.0; **SHA 0.95, git SHA 0.93, UUID 0.87**; misses postgres URI | token-level spans; good on AWS/sk/JWT; false positives on structured lookalikes |
| [Secret Masker v3.3a-RS](https://huggingface.co/AndrewAndrewsen/distilbert-secret-masker-v3.3a-rs) | 66M, 265 MB, Apache-2.0 | sliding-window inference | — | card lists **UUID/hash as known precision frontier**; natural-negative FP 0.096, strict F1 0.63–0.70 | newer, better real-code precision, still not negative-clean |
| [GLiNER PII edge](https://huggingface.co/knowledgator/gliner-pii-edge-v1.0) | ~45 MB quint8 ONNX | zero-shot labels | untested | PII-focused, no credential labels | worth a test with labels “API key”/“credential” |
| [bert-small PII detection](https://huggingface.co/gravitee-io/bert-small-pii-detection) | 28.7 MB quantized ONNX | CPU | n/a | PII only | tiny, but no secret category |

Conclusion: a 66–70M model *can* detect the bare-secret class, but off-the-shelf precision on
code lookalikes (SHA/UUID/base64/git SHA) is the blocker — exactly the kinds of strings a
coding agent sees constantly. Making a small model usable requires **fine-tuning on hard
negatives** (hash/UUID/git-SHA/base64/env-ref lines from real repos) or restricting it to
candidate tokens behind a strict context gate. That is a realistic M3 task: a 66M DistilBERT
fine-tune is cheap to train and ~5–20 ms/request, but it must be evaluated against a
negative corpus before replacing or augmenting the current model. Until then, the current
pipeline stays.
