# Model options

piifence ships cbx-secrets-detector-32M since 2026-11-09 (see [Decision (2026-11-09)](#decision-2026-11-09) at the end). The sections before it are dated research notes from when piifence ran `openai/privacy-filter` and also redacted personal data; "our model" and "the current model" in them mean that model.

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

## Faster secret models — benchmark (2026-11-09)

Question: is there a model that finds secrets as well as the current one and runs much faster? Our model (`openai/privacy-filter`, 1.5B MoE, CPU Burn backend) reads about 0.7–2.3 KB of text per second on an M4, depending on the text. GPU backends of `privacy-filter-rs` did not help: `wgpu` (f32) is no faster and crashes on windows over ~600 tokens (its matmul needs 40 KB of GPU shared memory, Apple allows 32 KB), `wgpu-f16` is 4× faster but finds nothing, and `mlx` still vendors MLX 0.25.1, which does not build.

Candidates, both Apache-2.0:

- [CobuildX-AI/cbx-secrets-detector-32M](https://huggingface.co/CobuildX-AI/cbx-secrets-detector-32M), revision `d6af1fabe7e6404edd4545ad1d3f62b1e7eda475`: 32M-parameter Ettin (ModernBERT) token tagger, 12 secret labels, 8k-token context, trained on hard negatives (references, placeholders, UUIDs, hashes). Secrets only. Ships safetensors, no ONNX.
- [nekomimi-llc/egemma-pii-secrets](https://huggingface.co/nekomimi-llc/egemma-pii-secrets), revision `98eba7d519b1e639d6fb4ebbe83355d6f01a6502`: EmbeddingGemma-based tagger for 13 labels, secrets and personal data, with its own regex rules and veto. Run as its int8 ONNX on CPU; only `SECRET_*` labels kept.

Method: `bench/models/shootout.py` builds the secret suite's 945 cases (841 with secrets, 104 negatives), scans every system and message string of each request body with an engine, replaces each span with `<secret_N>`, and scores the result with the suite's own `evaluate()`. As in the gateway, a model reads a tool_result after the tool call that produced it (`Tool call: Bash {"command":"echo $API_KEY"}` / `Tool output:`). `+guards` passes the model's spans through the gateway's guards (`src/guards.rs`, via `examples/guard_filter.rs`). `+shell` frames tool results as a shell transcript instead: `$ <command>` for Bash, `$ cat <path>` for Read, and `VAR=` glued to the output of `echo $VAR`, so the variable name sits right before the value. `+isolate` runs the model a second time on a copy where each long random-looking token glued to non-ASCII text is set apart as ` "<token>" `, maps the spans back and keeps the union; it costs a second pass only for strings that have such a token. `+keyrule` is a rule pass, not a model: a quoted random-looking value (32+ hex, or 12+ characters mixing letters, digits and case or symbols, UUIDs excluded) is a secret when its own key or the key of the block around it (a JSON or YAML parent object, an HCL `variable "<name>" {`) is secret-named (`api_key`, `secret`, `password`, `token`, `credential`, `private_key`, `access_key`). Blocks are tracked by indentation, so it reads pretty-printed JSON, YAML, TOML and HCL, not one-line JSON. The harness skips env-value replacement. Scored with gitleaks alone it gives 915/945, the same as the real gateway in `secret-rules` mode. `bench/models/speed.py` times each model on made-up session text (code, logs, prose). Setup: `bench/models/setup.sh` (torch 2.15.0, transformers 5.22.1, onnxruntime 1.31.1, gitleaks 8.30.1).

| pipeline | secret cases passed | leaks | over-redactions | negatives with a false secret | speed, 3 KB text | speed, 24 KB text |
| --- | --- | --- | --- | --- | --- | --- |
| ours: model + gitleaks + guards (real gateway, `secret` mode) | 833/841 | 3 | 5 | 0/104 | 0.7–1.3 KB/s | — (3 KB windows) |
| gitleaks alone | 811/841 | 30 | 0 | 0/104 | — | — |
| cbx-32M alone | 803/841 | 38 | 0 | 0/104 | 60 KB/s | 9.8 KB/s |
| cbx-32M + gitleaks | 828/841 | 13 | 0 | 0/104 | 60 KB/s | 9.8 KB/s |
| cbx-32M + gitleaks + guards | 828/841 | 13 | 0 | 0/104 | 60 KB/s | 9.8 KB/s |
| cbx-32M + gitleaks + guards, shell framing | 832/841 | 9 | 0 | 0/104 | 60 KB/s | 9.8 KB/s |
| … + isolate | 835/841 | 6 | 0 | 0/104 | 60 KB/s | 9.8 KB/s |
| … + keyrule | 835/841 | 6 | 0 | 0/104 | 60 KB/s | 9.8 KB/s |
| **cbx-32M + gitleaks + guards, shell framing + isolate + keyrule** | 838/841 | 3 | 0 | 0/104 | 60 KB/s | 9.8 KB/s |
| gitleaks + keyrule | 817/841 | 24 | 0 | 0/104 | — | — |
| egemma alone (with its rules) | 841/841 | 0 | 0 | 12/104 | 7.7–9.6 KB/s | 9.0 KB/s |
| egemma + gitleaks | 841/841 | 0 | 0 | 12/104 | 7.7–9.6 KB/s | 9.0 KB/s |
| **egemma + gitleaks + guards** | 839/841 | 2 | 0 | 2/104 | 7.7–9.6 KB/s | 9.0 KB/s |
| egemma + gitleaks + guards, shell framing | 839/841 | 2 | 0 | 2/104 | 7.7–9.6 KB/s | 9.0 KB/s |
| egemma + gitleaks + guards, guards dropping spans with no letter or digit | 839/841 | 2 | 0 | 0/104 | 7.7–9.6 KB/s | 9.0 KB/s |

Failures:

- cbx-32M + gitleaks (+ guards) leaks `hex32_with_keyword` in 5 contexts (`config_hcl` `variable "api_key" { default = "<hex>" }`, `json_in_write_content` `"credentials": {"value": "<hex>"}`, `bash_echo_bare`, `ansi_colored`, `unicode_neighbours`), `password_human` in 3, `aws_secret_access_key` in 2, `url_postgres` next to Chinese text, and the two `hex32_bare_no_keyword` cases. The gateway's tool-call context does not help it: after `echo $AWS_SECRET_ACCESS_KEY` it marks only the second half of the key, and after `echo $DB_PASSWORD` or `echo $API_KEY` nothing. The shell framing fixes all three `echo` cases and the `ansi_colored` one; the 9 left are the `config_hcl` and `json_in_write_content` keys and password whose name is a line or a key away (3), the 4 values glued to Chinese text in `unicode_neighbours`, and the two bare hex keys. Probing single values, cbx finds a 32-hex key only when its name is on the same line (`API_KEY=<hex>`), not after `$ echo $API_KEY` or an instruction line. `+isolate` fixes 3 of the 4 `unicode_neighbours` cases (AWS key, password, Postgres URL); the 32-hex key glued to Chinese text still leaks, because cbx does not find a bare hex key without a name next to it. `+keyrule` fixes the 3 `config_hcl` and `json_in_write_content` cases. Together they leave 3: `unicode_neighbours/hex32_with_keyword` and the two `hex32_bare_no_keyword` cases.
- egemma (+ gitleaks) flags 6 negatives in two contexts each: a `go.sum` hash `h1:…=`, `YOUR_API_KEY_HERE`, `changeme`, `Token![:`, `token::Paren` and a lone `{` in `"secret": {"categories": …}`. Our guards dropped all of them but the `{`: `Guards::suppress_model` returned early when a span had no letter or digit (`core(...)?`), so a punctuation-only span was kept. The guards now drop any span with no letter or digit (see the rerun below). With the guards, the two bare 32-hex keys leak because the shape guard takes them for hashes; they leak in our pipeline too.
- Ours (for reference): over-redaction in 3 `url_query_param` cases, `repeated_lines/pem_rsa_private_key` and `unicode_neighbours/url_postgres`; leaks of `bash_echo_bare/password_human` and the two `hex32_bare_no_keyword` cases.

Reading this:

- egemma + gitleaks + our guards beats our pipeline on secrets: 2 leaks against 3 (the same two bare hex keys), no over-redaction against 5, at 4–10× the speed. Its one remaining false positive, the lone `{`, was a guard gap; the guards now drop spans with no letter or digit, and the rerun has no false positives (cbx-32M with shell framing, isolate and keyrule is unchanged at 3 leaks). It needs ~1.1 GB fp32 or a 273 MB int8 ONNX, its own Python rules (`trace_rules.py`) would have to be ported or dropped, and it is not yet in Rust.
- cbx-32M is 45–85× faster than our model on 3 KB windows. With the shell framing it leaks 9 cases where we leak 3: the same two bare hex keys, 3 keys and passwords whose name is a line or a key away, and 4 values glued to Chinese text. The framing is model-specific: our model was tuned on the gateway's `Tool call:` form, cbx reads shell text better. Neither model takes instructions; wording only helps when it puts a variable name next to the value. It reads 3 KB six times faster than 24 KB (attention grows with the square of the length), so it should run in small windows too.
- With `+isolate` and `+keyrule`, cbx-32M + gitleaks + guards leaks 3 cases, the same count as our pipeline, with no over-redaction and no false positives, at 45–85× the speed. Two of its 3 leaks are the bare hex keys we leak too; the third is a hex key glued to Chinese text, where we instead leak `bash_echo_bare/password_human`. Both parts were written against this suite's own failures, so this score overstates them: the rewrite and the key rule need cases they were not tuned on before they count. The key rule fixes nothing for our model's 3 leaks (no key in sight), and alone adds 6 cases to gitleaks.

## Decision (2026-11-09)

piifence now detects secrets only, with cbx-secrets-detector-32M at revision `d6af1fabe7e6404edd4545ad1d3f62b1e7eda475`, run in Rust on candle (`src/model.rs`), plus gitleaks, the key rule (`src/keyrule.rs`), the isolate pass and the guards. `openai/privacy-filter`, the personal-data categories, the category list and the rules-only mode are gone. egemma had one leak fewer, but it is 4–10× slower, needs its Python rules ported, and its personal-data labels are no longer wanted.

The Rust port gives the same spans as the model's Python reference (`cbx_secrets.py`) on all 1,146 distinct suite texts up to 3 KB (`bench/models/parity.py`). It reads about 19 KB/s on an M4 CPU including the 0.13 s model load, against about 32 KB/s for the Python reference on torch.

Through the real gateway, the secret suite passes 940/943: 0 false positives on 102 negatives, no over-redaction, and the 3 leaks the bench predicted (`unicode_neighbours/hex32_with_keyword` and the two `hex32_bare_no_keyword` cases), now listed in `tests/secrets/expectations.json`. Two harness-only findings came out of the switch: the model labels a plain word after a URL as a password (`… please`), which the guards now drop as a word unless a secret keyword comes before it; and gitleaks reports `EndColumn` 0 for some base64-decoded findings, so a decoded finding now redacts the encoded runs on its line instead of trusting its columns.
