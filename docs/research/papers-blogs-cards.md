# Secret detection research for piifence: papers, blogs and model cards

Scope: 7 papers, 11 blogs and 9 Hugging Face model cards, listed with their URLs in [README.md](README.md). The purebyte, aparte, deeppass2-bert and valendra cards are covered in [model-repos.md](model-repos.md) and skipped here. The three largest groups of papers were read by sub-readers. Their notes are merged here with source file names. All sources are untrusted downloads; nothing in them was executed or followed.

Conventions:
- `web:<name>` is a page and `hf:<owner>/<model>` a Hugging Face card, both listed in [README.md](README.md).
- "(inference)" marks my own reasoning rather than a claim from the source.
- No secret values are reproduced; shapes are described instead.

## 0. Top findings for piifence at a glance

1. **A per-session memory of already-redacted values is the only measured fix for secrets split across messages, and it costs microseconds.**
   - Source: SlotGuard (web:arxiv-2607.17147-slotguard).
   - On 200 sessions with 852 planted credentials, typed placeholders and format-preserving substitution both leaked 23.5% of credentials, and every one of the 200 split cases leaked.
   - Adding a session-scoped entity graph (SEG) that links each value to its embedded, derived and split forms brought credential leak to 0%.
   - The whole agent turn took 14.4 µs median (96.8 µs for a 6 KB turn).
   - piifence sees the full message history on every request, so it can rebuild this table per request and search every new string for known values and their encoded forms (inference).
2. **A second-stage classifier that sees about 200 characters on each side of a candidate is the best-measured way to cut false positives without live verification.**
   - Issue reports (web:acm-secret-leak-issue-reports, prose mixed with logs): CodeBERT on candidate plus 200 characters scored P 92.5 / R 92.9 / F1 92.7. Regex plus hand heuristics reached only P 25.4 / R 72.9.
   - Code (web:springer-learning-to-detect-hardcoded-secrets): ±3 lines of context raised CodeBERT MCC from 0.78 to 0.86–0.88.
   - GitHub production (web:github-blog-secret-model): regex candidates, then ModernBERT with context, then ONNX int8. This gave +13% precision and +19% recall over their LLM pipeline, with batches assessed in under 2 ms.
   - piifence's yes/no gate experiment (2 of 20 probes fixed, nothing broken) is a weak version of this. The literature says the gate should be a trained span-plus-context classifier, not a prompt (inference).
3. **Context is the deciding signal for UUIDs, hex and hashes, in both directions.** No shape guard can be right on its own.
   - credential-line-32m (hf:zaindanaharper/credential-line-32m) found only 10 of 16 UUID-valued API keys.
   - distilbert-secret-masker (hf:AndrewAndrewsen/distilbert-secret-masker-v3.3a-rs) still flags 8% of UUIDs and 9% of sha256 values.
   - The Springer paper reports that LLMs both miss GUID-shaped secrets and flag UUIDs "because Azure uses UUIDs as keys".
   - The fix pattern that worked for credential-line-32m was adding synthetic training lines for both sides: UUIDs in identifier fields (credentialsId-style keys) as negatives and UUIDs as API-key values as positives. That cut flagged UUID lines from 17 to 2 and raised stand-alone or list keys from 10 to 43 of 47.
4. **Never let the model veto a rule hit.** credential-line-32m measured this: among lines the rule catalog flagged, the model's "clean" verdict was right only 139 of 177 times (0.785).
   - OR of rules and model: recall 0.888, precision 0.707.
   - AND of rules and model: recall 0.513, precision 0.968.
   - piifence's current union (gitleaks OR model OR key rule) is the right shape. Guards should only remove model-only spans, which is what piifence already does (inference).
5. **Model confidence is badly calibrated, so thresholding is not a lever.**
   - egemma (hf:nekomimi-llc/egemma-pii-secrets, CredDetX dev split): 123 of 803 real secrets scored below 0.1, and 167 of 1,648 look-alikes scored 0.99 or above.
   - Requiring 0.9 cut fully covered secrets from 630 to 552 and flagged look-alikes from 503 to 305. Real secrets are lost about as fast as false flags.
   - credential-line-32m fixed calibration for its line classifier with temperature scaling (T≈2.10, threshold 0.74). Expected calibration error went from 0.140 to 0.037.
6. **Usable outside test sets are named and public.**
   - The best fit is the ACM issue-report set (zenodo 10.5281/zenodo.17430335; 5,881 secrets / 48,297 non-secrets, prose plus logs). But cbx-secrets-detector-32M trained on its training split, so only its test split is clean for us.
   - CobuildX-AI/CredDetX (CC-BY-4.0) has 3,213 secrets and 7,176 labelled look-alikes in the test split, which suits our false-positive work.
   - The others are covered in §2.

## 1. Techniques that measurably reduced leaks or false positives

### 1a. Two-stage: high-recall candidates, then a context classifier

GitHub production scanner (web:github-blog-secret-model, web:github-blog-secret-protection):
- **Pipeline.**
  1. Regex candidate generation tuned for recall.
  2. A fine-tuned ModernBERT classifier reads the candidate value, file path, secret type and "a bounded amount of surrounding context". It is exported to ONNX at 8-bit.
- **Offline, against their previous LLM pipeline:** +13% precision and +19% recall on the same public traffic.
- **Online A/B:** +11.5% repository-owner-weighted acceptance, −86% median scan time, more than 98% lower serving cost.
- **Speed:** "evaluating candidate batches in under two milliseconds". Adding the model to push protection "could more than double" the number of secrets they prevent.
- **Training data:**
  - Product feedback labels.
  - Human-annotated and weakly labelled regex candidates.
  - Synthetic hard negatives: documentation secrets, test fixtures, public keys, checksums, structured look-alikes and near-miss pairs, gated by deterministic validation plus a model-based quality review.
  - The split was grouped by repository, candidate value and example to avoid leakage.
- **Applies to a per-string local gateway: yes.** It is the same model family as cbx (ModernBERT/Ettin), the same int8 ONNX path, and millisecond latency.

Issue-report paper (web:acm-secret-leak-issue-reports). This is the closest setting to agent transcripts: prose, logs, stack traces and config pastes.
- **Data:** 761 SecretBench regexes as candidate generator, then a binary classifier over the candidate plus a 200-character window.
- **Test set:** 888 secrets and 7,235 non-secrets. P / R / F1:

| Method | P | R | F1 |
| --- | --- | --- | --- |
| Regex only | 6.8 | 100 | 12.8 |
| Regex + entropy | 11.2 | 97.5 | 20.1 |
| Regex + entropy + keyword + heuristics | 13.0 | 68.7 | 21.8 |
| Regex + placeholder / masking / dummy heuristics | 25.4 | 72.9 | 37.7 |
| Random forest on hand features | 74.4 | 46.5 | 57.2 |
| TextCNN | 93.7 | 76.5 | 84.2 |
| CodeBERT (fine-tuned) | 92.5 | 92.9 | 92.7 |
| RoBERTa (fine-tuned) | 93.0 | 91.7 | 92.3 |
| DistilBERT (fine-tuned) | — | — | 90.3 |
| Qwen-7B, QLoRA fine-tuned | 94.8 | 94.1 | 94.5 |

- **Prompted LLMs over-flag in prose:**
  - GPT-4o: zero-shot P 59.3 / R 90.7; few-shot P 70.5 / R 92.9.
  - Gemini-2.0-flash: zero-shot P 45.0.
- **Context window ablation (F1 at 100 / 200 / 300 characters):**
  - CodeBERT: 91.95 / 92.70 / 92.79.
  - Qwen: 93.90 / 94.46 / 94.55.
  - Gains beyond about 400 characters are marginal. The paper cites "relevant context within 6 lines".
- **Out-of-distribution check** (178 unseen repos, 30 real secrets): secret-class precision 51.0, recall 86.7, F1 64.2 (25 FP, 4 FN). Expect a large drop on real data.
- **Latency on an RTX 4090:** BERT-size 50–70 ms per sample; 7B models 100–130 ms.
- **Applies:** the encoder variant yes, if batched; 7B no.

Secret-breach paper (web:arxiv-2504.18784-secret-breach-llm), on source code with the same approach:
- Fine-tuned LLaMA-3.1-8B: P .986 / R .985 / F1 .985 on a balanced 1,500/1,500 test set (4 FP, 37 FN).
- Raw 7–8B models are near chance: zero-shot F1 0.33–0.52.
- GPT-4o: zero-shot F1 .843, few-shot F1 .939.
- Context 200 to 300 characters gave a small but consistent gain on every model (for example DeepSeek .947 to .969).
- Raising the input cap from 512 to 1,024 tokens fixed misses on long RSA keys.
- Latency 0.19 s per sample on a 4090. Too slow for every string; at most an occasional second stage (inference).
- Caveat: a balanced test set flatters precision; real prevalence is about 15% (inference).

Springer, "Learning to detect hardcoded secrets" (web:springer-learning-to-detect-hardcoded-secrets). SecretBench, de-duplicated, 12,433 records, 11% positive:
- **Context helps in-distribution:** value-only CodeBERT MCC 0.78; value plus ±3 lines (7 lines) 0.86–0.88 (F1 0.89).
- **Hand features generalise better:** on unseen C#, random forest on Saha's 20 hand features (entropy, composition) scored MCC 0.67 against CodeBERT's 0.65, with drops of 8% and 21% respectively.
- **Per type:** the learned model wins on API key, auth token and generic secrets. Hand features win on DB/server URL, password (0.64) and private key. Password is the hardest class for every model.
- **Test paths drive LLM false positives:** test-path samples are 27% of the data but 74.7% of LLM errors. Excluding them raises GPT MCC from 0.63 to 0.77.
- **Prompt features help LLMs:** adding entropy, length and an in-test-path flag plus step-by-step reasoning raised LLM MCC from 0.59 to 0.71 on a 373-sample subset.
- **Inference:** an ensemble of a learned span model and a small hand-feature scorer is more robust off-distribution than either alone.

DeepPass2 (web:specterops-deeppass2):
- **Pipeline:** NoseyParker regex removes structured secrets first. Then xlm-RoBERTa-base BIO tagging over 300–400-token chunks. Then Claude Sonnet validates each flagged span with its chunk.
- **Results on 2,200 synthetic test chunks:**

| Model | Strict accuracy | Overlap accuracy (>30%) | FP | FN | Recall | FP rate |
| --- | --- | --- | --- | --- | --- | --- |
| Fine-tuned xlm-RoBERTa | 86.7% | 97.7% | 49 | 138 | 89.7% | 3.9% |
| LLM alone | 85.8% | 95.4% | 57 | 211 | 85.0% | 4.6% |

- The fine-tuned encoder beat the LLM.
- **Key data trick for plain-word passwords.** LLM-written passwords are "conspicuous" (leetspeak plus year). The hardest cases were innocent-looking ones of the shape CamelCase English words with no digits.
  - Fix: 1,000 skeleton sentences ("account created with username {user} and password {pass}") filled from breached username and password lists, then inserted at sentence boundaries into 300–400-token chunks.
  - 23,000 examples; under 0.3% of tokens are passwords.
- **Applies:** the data recipe yes. The LLM validation stage no (remote, slow); it was kept only because the evaluation data was synthetic.

### 1b. Hard-negative training and staged distillation

egemma-pii-secrets (hf:nekomimi-llc/egemma-pii-secrets):
- **Three stages:**
  1. Base fine-tune.
  2. New data plus a KL(teacher‖student) term against the stage-1 model so added data does not erase prior skill.
  3. A final 0.4 epoch on LLM-written look-alikes ("secret-shaped strings that aren't secrets", written from shape descriptions, checked by Sonnet) with the stage-2 model as teacher.
- **Results:**
  - CredDetX test (3,213 secrets): model plus veto fully covers 87.8% of secrets; model plus rules plus veto 97.8%.
  - Look-alikes wrongly flagged: 16.2% (model plus veto) and 20.4% (plus rules). Some of these are deliberate policy, such as placeholders in credential fields.
- **Loss trick:** for sources that label only secrets, untagged tokens are trained toward "not a secret" via a marginal loss, not toward O.
- **Inference:** this is the recipe to copy if piifence ever fine-tunes cbx on its own false positives without losing recall.

credential-line-32m v2 (hf:zaindanaharper/credential-line-32m), human-written holdout of 1,264 lines and 472 credentials:
- **v1 to v2:** F1 0.785 to 0.858, precision 0.848 to 0.916, recall 0.731 to 0.807.
- **The added 6,581 synthetic lines targeted:**
  - Keys standing alone, in lists and in table cells.
  - UUIDs in identifier fields (negative).
  - UUIDs as API-key values (positive).
  - Private-key headers, public keys and END lines.
  - CSRF tokens, nonces and salts (negative).
  - Filler values.
- **Measured fixes:**
  - Stand-alone or list keys: 10 of 47 to 43 of 47.
  - Private-key header lines: 0 of 5 to 5 of 5.
  - Clean UUID lines flagged: 17 to 2.
- Every long random-looking token in human-written training lines was replaced by a random string of the same shape, so the model cannot memorise values.
- **Directly relevant** to piifence's "UUID API key in a table column" and "32-hex with no keyword" leaks.

hypn05/secrets-sentinel (hf:hypn05/secrets-sentinel) lists the hard negatives it added in v4 and v5. Its F1 0.9999 is measured on its own synthetic split and is not credible as a benchmark (inference).
- Pinned commit SHAs in CI `uses:` lines.
- .env.example placeholders, including the literal word "null".
- PHP hashids alphabet strings.
- Framework route strings of the form Controller@method.
- Commit SHAs inside test strings.
- Annotation values that are CamelCase class names.
- Expired JWT test payload fields.
- Date fields.
- Localhost URLs.
- Variable-reference interpolations.

cbx-secrets-detector-32M (hf:CobuildX-AI/cbx-secrets-detector-32M) was trained with hard negatives:
- Placeholders, references, hashes and fake values.
- Explicit non-secret policy: variable references, placeholders, masked values, AWS key IDs, UUIDs, account and request ids, usernames, public keys and certificates, hashes and digests including git SHAs, and documented example keys.
- A realistic value is labelled even when its name says "test" or "example".

### 1c. Rules and post-processing around the model

Rules add large recall cheaply:
- egemma model alone covers 87.8% of CredDetX secrets; with rules, 97.8%.
- LLM-Redactor (web:arxiv-2604.12064-llm-redactor §8.2): one domain regex cut employee-ID leak from 79.8% to 0%.

Verify-then-replace for any model proposer (SlotGuard): the model proposes (line, verbatim span, type), and the span is accepted only if it occurs verbatim in the input and the type is allowed.
- On a 30-example filename probe, rules alone had precision 1.00, recall 0.40. Rules plus a small local model had recall 1.00, F1 0.909.
- The model took 742 ms warm median, so it runs asynchronously as advisory only.

Span widening: egemma widens secret spans to the whole surrounding token, so a partial hit cannot leave half a secret.
- The cbx card notes a database URI is sometimes returned as two spans split at the password.
- DeepPass2 found strict span accuracy 86.7% against overlap accuracy 97.7%: the model gets most boundaries roughly right but not exactly.
- **Inference:** after the model runs, extend every secret span to the maximal run of the secret's character class (stopping at quotes, whitespace, `&`, `@` and similar). This is cheap and turns partial leaks into full redactions.

Constrained Viterbi decoding (web:openai-privacy-filter; hf:enosislabs/matex-privacy-sentinel-v0.15-onnx):
- OpenAI's privacy filter decodes BIOES tags with constrained Viterbi so label sequences are always valid and boundaries clean. The operating point is configurable.
- The MaTE X card says raw argmax "may show slightly more boundary errors on long secrets"; no number is given.
- **Inference:** if piifence decodes cbx BIO output with argmax, Viterbi with a valid-transition mask costs O(n·L²) per window and could reduce fragmented spans. Worth an A/B on the bypass probes.

Sliding windows with overlap: egemma uses 512-token windows with a 128-token overlap; distilbert-secret-masker uses (max−2) windows with stride 128, first window winning on overlap.
- cbx itself reads up to 7,999 tokens in one pass, while piifence uses 3,000-byte windows.
- **Inference:** piifence's windows are much shorter than the model's native context. Check that windows overlap enough that a hint on the line above is in the same window as the value, or use larger windows.

### 1d. LLM validation, rephrasing and noise

LLM validation as a false-positive filter:
- GitGuardian (web:gitguardian-ml) runs a false-positive remover at about 95% precision. On generic secrets from non-code sources (Slack, Jira, Confluence) it filters 25–40% of findings. It reads lines before and after: its example is a JSON i18n file where a key ending in "password" maps to a translated UI label, which is not a secret.
- Legit (web:legit-fp-reduction): an ML false-positive model cut false positives 86% with "negligible impact on true positives" on 10,000+ manually labelled open-source samples.
- Cycode (web:cycode-ml): CodeBERT with both a sequence head and a token head removed 80% of existing false positives and turned 70% of false negatives into true positives (no dataset given).
- None of these are local per-string options except as a trained small encoder.

Prompted LLMs as validators over-flag prose (ACM paper: GPT-4o zero-shot precision 59%). The Springer error analysis shows LLMs:
- Flag placeholders because of the variable name (160 of 298 sampled false positives).
- Trust "test" context too much.
- In one case base64-decoded a value, saw "fake account key" and called it dummy.

Do not do rephrasing or DP noise:
- LLM-Redactor: local 3B rephrasing raised the exact secret leak on secret-heavy configs (WL2) from 0.162 to 0.214 and costs 1.6–2.5 s.
- DP word noise was non-monotonic and added little.

Prompt framing does not help a token classifier (piifence's own finding). Few-shot does help prompted LLMs (+10 F1 for GPT-4o in web:arxiv-2504.18784-secret-breach-llm), which is consistent: it is an instruction-following effect.

### 1e. Verification

Live verification is the largest precision lever in the tool comparison (web:arxiv-2307.00714-secret-tools-comparison): TruffleHog went from 6% precision on about 100K alerts to 90% on 611 with `--only-verified`. It does not apply to piifence: no outbound calls with users' keys on the request path, and an unverifiable secret still must be redacted (inference).

## 2. Published comparisons and datasets

### 2a. Model and tool comparisons

From the cbx card (hf:CobuildX-AI/cbx-secrets-detector-32M and -17M). Span F1, label-agnostic, with (P / R) and the share of non-secret lines or candidates falsely flagged ("FA"):

| System | CredData test F1 | FA | Issue-reports test F1 | FA | CBX own test |
| --- | --- | --- | --- | --- | --- |
| cbx-32M | 0.820 (0.77 / 0.87) | 1.3% | 0.861 (0.86 / 0.86) | 1.4% | 0.998 |
| cbx-17M | 0.805 (0.80 / 0.81) | 0.9% | 0.836 (0.90 / 0.78) | 0.9% | 0.983 |
| gitleaks 8.30.1 | 0.442 (0.90 / 0.29) | 0.6% | 0.678 (0.93 / 0.54) | 0.5% | 0.757 |
| detect-secrets 1.5 | 0.460 (0.47 / 0.45) | 9.8% | 0.290 (0.40 / 0.23) | 4.0% | 0.626 |
| TruffleHog 3.99 (offline, no verification) | 0.042 | 0.8% | 0.228 | 0.9% | 0.215 |

- With exact labels on its own test set, 32M scores 0.991; PASSWORD and SESSION_SECRET are lowest at 0.98.
- On the 17M model, PASSWORD is 0.89 and DATABASE_CREDENTIAL 0.90.
- Speed: 32M median 8 ms per 1,000 tokens on GPU and 81 ms on CPU (i7-10700, 8 threads); 17M 6 ms and 37 ms.
- **Inference:** our model's measured real-world recall is about 0.86–0.87 with precision 0.77–0.86, so about 1 in 7 secrets is missed on outside data before gitleaks and the key rule.

From bardsai/password-detector (hf:bardsai/password-detector), int8 at threshold 0.5:

| System | Size | CredData F1 | GitHub issues F1 | Docs F1 | Speed |
| --- | --- | --- | --- | --- | --- |
| Cascade | 0.7 MB | 0.89 | 0.85 | 0.94 | 138 KB/s |
| Tiny | 97 KB | 0.87 | 0.85 | 0.94 | — |
| Default | — | 0.88 | 0.87 | 0.93 | — |
| CredSweeper (trained on all of CredData, so not held out) | — | 0.94 | 0.79 | 0.41 | — |
| detect-secrets | — | 0.57 | 0.48 | 0.32 | — |
| gitleaks | — | 0.44 | 0.69 | 0.25 | 958 KB/s |

- The CredData figures use 64 held-out repos.
- **Inference:** the "Docs" set is synthetic emails, chats and tickets in 5 languages. A 97 KB byte-level CNN at about 0.85 F1 is cheap enough to run on every string as a recall booster; its own docs flag passwords in prose as a weak spot.

From credential-line-32m (hf:zaindanaharper/credential-line-32m), line-level on 1,264 human lines, P / R / F1:

| System | P | R | F1 |
| --- | --- | --- | --- |
| credential-line-32m v2 | 0.916 | 0.807 | 0.858 |
| Char n-gram logistic regression | 0.761 | 0.761 | 0.761 |
| Zero-shot Qwen2.5-Coder-14B | 0.593 | 0.998 | 0.744 |
| Rule catalog | 0.656 | 0.593 | 0.623 |
| detect-secrets | 0.704 | 0.398 | 0.509 |
| Rules OR model | 0.707 | 0.888 | 0.787 |
| Rules AND model | 0.968 | 0.513 | 0.670 |

- Qwen-14B flagged 323 clean lines against the model's 35.
- A neighbouring-lines context variant scored F1 0.869, inside the error bars, so it was not released.
- Latency: 4.1 ms median per line on a 4-thread CPU with ONNX.

From distilbert-secret-masker v3.3a-RS (hf:AndrewAndrewsen/distilbert-secret-masker-v3.3a-rs):
- **File / line F1 on real OSS benchmarks:**

| Tool | B | C | D (regex-friendly) |
| --- | --- | --- | --- |
| gitleaks | 0.500 / 0.393 | 0.431 / 0.381 | 0.948 / 0.885 |
| detect-secrets | 0.641 / 0.407 | — | 0.953 / 0.891 |
| distilbert v3.3a-RS | 0.830 / 0.701 | 0.873 / 0.766 | 0.952 / 0.916 |

- **Recall by family (prefixless):** password 0.663, basic_auth 0.751, high_entropy 0.870, api_key 0.955.
- **Prowl (synthetic multilingual) F1 by source:** code 0.850, Jira 0.722, Slack 0.675, Confluence 0.645, logs 0.532.
- **Non-English recall 0.46 at precision 0.97.** This matches piifence's Russian-prose leak: a miss problem, not a false-positive problem.
- Synthetic-diversity scaling improved development metrics but did not transfer to real code.

From the tool comparison (web:arxiv-2307.00714-secret-tools-comparison), SecretBench, 9 tools:
- GitHub Secret Scanner: precision 75%, recall 6%.
- gitleaks: precision 46%, recall 88%, F1 60%.
- Commercial ML tool "X": precision 25%. SpectralOps: precision 1%, recall 67–68%. TruffleHog: precision 6%, recall 52%.
- 5 of 9 tools are below 7% precision.
- Unique true positives overlap little (gitleaks vs TruffleHog: 1,533 against 438 non-overlapping), so ensembles add recall.
- **Root causes of false positives:**
  - Generic keyword regexes match placeholder words.
  - Vendor regexes match repeated-digit dummies.
  - A bare private-key BEGIN line with no body.
  - Shannon entropy scores a CamelCase English phrase above a real random string.
  - 40-hex commit SHAs.
  - CSS and style strings.
  - Keyword-within-40-characters proximity firing on a domain name inside a URL path.
- **Root causes of misses:** regex expecting the keyword at the end of the name, skipped file types (HTML), and missing detectors.

From SenScanner (web:mdpi-senscanner):
- **Pipeline:** a naive Bayes code-vs-prose line router (F1 96%), then a 10-feature decision tree for code lines (F1 94.8%) and ELECTRA NER for prose lines (F1 96.0%, synthetic in-distribution).
- **End-to-end** on 2,019 GitHub files plus 1,044 inserted ChatGPT sentences (3,326 secrets): P 84.4 / R 83.8 / F1 84.1. The best baseline values were P 65.2, R 47.3, F1 36.8 (detect-secrets, TruffleHog, PassFinder keyword regex).

Other results:
- LLM-Redactor: regex alone leaves 52.1% combined leak on secret-heavy configs (WL2); regex plus Presidio NER 31.8%; with a local-model routing stage 6.3–6.4%.
- Wiz (web:wiz-slm-secrets): Llama-3.2-1B with LoRA, int8 via llama.cpp: recall 82%, precision 85.7%, about 27 tokens/s on CPU. Qwen-Coder-0.5B: recall 71%, precision 87.5%, about 143 tokens/s. They claim regex reaches about 60% recall. Too slow for a gateway.
- Skarn (web:skarn-precision): 0 of 60 benign decoys flagged and 152 of 152 credential formats detected, on a curated, unpublished corpus. The decoy family list is useful (§4); the numbers are not comparable.

### 2b. Datasets: what is public and usable as an outside test set

Contamination warning for cbx: cbx-32M trained on Samsung CredData (116 repos) and the issue-report training split. Only CredData's held-out half (the 168 test repos the card names) and the issue-report test split are clean outside tests for our model. Several other cards also trained on CredData, so their CredData numbers are not comparable across cards.

| Dataset | Content | Access | Fit for piifence outside test |
| --- | --- | --- | --- |
| Issue-report dataset (Ahmed et al.; zenodo 10.5281/zenodo.17430335; arXiv 2410.23657) | 54,148 candidates from 50,680 GitHub issues; 5,881 secrets; κ 0.95; includes 22 benign-pattern prefilter regexes in the package (not listed in text) | Public, CC-BY-4.0 | Best fit: prose plus logs plus config. Use test split only (cbx trained on train). Regex-extracted candidates, so it tests precision more than keyword-less recall. |
| CobuildX-AI/CredDetX (HF) | Test split has 3,213 secrets and 7,176 labelled look-alikes; dev split also exists | CC-BY-4.0 | Strong for false positives (hashes, ids, look-alikes). Check whether cbx trained on it: the card does not list it, but it is the same vendor (inference). |
| Samsung CredData (github.com/Samsung/CredData) | Real repos, values obfuscated, line labels | Apache-2.0 | Use the cbx test half only. Note CredData labels UUIDs, salts and nonces as credentials (credential-line-32m relabelled 1,082 UUID lines as clean). |
| SecretBench (github.com/setu1421/SecretBench; GCS bucket and BigQuery; zenodo 7571266 for 761 regexes) | 97,479 candidates, 15,084 true; code; only 150 true passwords | 2307 paper says public via GCS/BigQuery; the Springer paper says access needs an ethics agreement | Code-heavy, password-poor; the "Other" class (66,690 candidates, 99% FP) is a hash/id false-positive set. FPSecretBench is gated. |
| apartejs/aparte-secrets-gold and chat-fresh (HF) | 756 and 396 secrets in chat, configs and HTTP | ODC-BY | Covered by the other reader; egemma used it as a frozen test. |
| nyuuzyou/gliner2.5-PII-code-en-data (code benchmark split) | 462 secrets in code | CC0 / CC-BY | Easy (egemma 100%). |
| LLM-Redactor WL2 (github.com/jayluxferro/llm-redactor) | 300 synthetic configs, 730 annotations | MIT | Weak (template-based). Copy its partial-leak metric, though (§4). |
| SlotGuard credential corpus (github.com/illinoisdata/SlotGuard) | 200 sessions, 852 credentials in direct, embedded, split, derived and cross-turn contexts | Released with code | The only public set exercising split and cross-turn secrets. Use it for that leak. |
| sinceaihq/safeprompt-bench, RedactionBench, DocPII, ai4privacy PII-Masking-300k | Mostly PII | Public | Low relevance to secrets. |
| 2504.18784 balanced subset (zenodo 10.5281/zenodo.15273217) | SecretBench sample with 200-character windows | Public | Code only. |
| SenScanner benchmark, PassFinder 20k | — | Not released / unclear | Not usable. |

None of these cover URL-, base64- or hex-encoded secrets, Russian prose, plain-word passphrases or upper-case short passwords. Those need piifence's own probe set (inference).

## 3. Model cards

### cbx-secrets-detector-32M and -17M (CobuildX-AI), our current model

- **Architecture:** Ettin encoder (ModernBERT-style), 32M or 17M parameters. Token classification with character spans.
- **Labels (12):** PASSWORD, DATABASE_CREDENTIAL, API_KEY, ACCESS_TOKEN, JWT_TOKEN, SESSION_SECRET, WEBHOOK_SECRET, CLOUD_CREDENTIAL, PRIVATE_KEY, CERTIFICATE_SECRET, ENCRYPTION_KEY, GENERIC_SECRET.
- **Context:** 7,999 tokens in one pass; longer input is split with overlap. English only. Apache-2.0, v0.1.
- **Numbers:** see §2a.
- **Known weaknesses (card):**
  - Long encoded data (inline base64 source maps, minified bundles, logs full of hex session ids) gets flagged as many short pieces. This matches our base64-dump false positives.
  - Recall is lower for tokens with no prefix and no telling name nearby. This matches our 32-hex leak.
  - Labels are less certain than detection, and a database URI is sometimes split at the password.
- **Inference:**
  - Our 3,000-byte windows discard much of the 8K context the model was trained to use.
  - The base64 false-positive failure suggests a pre-pass that marks long runs of base64 or hex with no surrounding key as "data", and decodes them rather than tagging pieces.

### egemma-pii-secrets (nekomimi-llc)

- **Architecture:** EmbeddingGemma-2 text encoder, 24 layers, about 271M parameters (134M of them a frozen embedding table). Linear head over 27 BIO tags, 13 labels (9 PII, plus SECRET_TOKEN, SECRET_PASSWORD, SECRET_CONNECTION, SECRET_PRIVATE_KEY).
- **Windows:** 512 tokens with a 128 overlap. Apache-2.0.
- **Speed (M4):** 9.0 KB/s Metal fp16; 5.6 KB/s int8 ONNX CPU (273 MB). int8 lost 1 of 149 held-out secrets. Too slow for piifence's hot path (inference).
- **Numbers:** CredDetX test secrets fully covered 87.8% (model plus veto) and 97.8% (plus rules); look-alikes flagged 16.2% / 20.4%. aparte gold 98.4%; gliner code 100%.
- **Known weaknesses:**
  - Passwords as ordinary words or phrases.
  - Very short test values.
  - Unusual contexts.
  - Partial spans.
  - Confidence bimodal and confidently wrong (numbers in §0).
  - Long forms and documents.
- **`trace_rules.py`, worth copying (contents described on the card; the file itself was not in scope):**
  1. Regexes for credential fields, connection strings and database URLs, private keys and known key prefixes, IPs, and usernames in paths.
  2. A base64 decoder that decodes encoded text and re-checks it for secrets. This addresses our base64-encoded leak.
  3. A veto that never redacts provably public shapes: data URIs, public keys, digests.
  4. Exact-match redaction of secrets the harness already knows.
  5. Placeholder values in credential fields are redacted by policy. Safer for a gateway, which leans toward over-redaction (inference).

### credential-line-32m v2 (zaindanaharper)

- **Architecture:** Ettin-32M binary line classifier, max 128 tokens. No spans. MIT. Temperature 2.10 and threshold 0.74 in policy.json.
- **Numbers:** see §2a. Calibration: expected calibration error 0.037, Brier 0.072. CPU latency 4.1 ms median, 7.5 ms p95; 219 lines/s at batch 32.
- **Weaknesses:**
  - Misses 1 in 5: short or word-like passwords, passwords inside long connection strings, and keys whose only clue is the next line.
  - False positives on crypt-style password hashes (`$6$` and `$2y$` prefixes), idempotency tokens and random-looking host names.
  - UUID keys found 10 of 16.
- **Use for piifence (inference):** a candidate yes/no gate for model spans, with the line around the span as input. It is calibrated, fast and the same backbone family. It must not override gitleaks.

### bardsai/password-detector

- **Architecture:** byte-level CNN, no tokenizer, int8 ONNX. Sizes: 97 KB (tiny), 219 KB (default), 0.7 MB (cascade: tiny prefilter, then default plus large).
- **Output:** spans with type (password, api_key, token, private_key, generic). Languages: en, pl, de, es, fr. Apache-2.0.
- **Numbers:** see §2a. Speed about 137 KB/s on one core.
- **Weaknesses:** unusual prose wording ("access code X", short PINs) scores below 0.5; hex and UUIDs next to "secret" raise false alarms; no split secrets.
- **Use for piifence (inference):** a cheap multilingual second opinion for passwords in prose (Polish example in card), OR-ed with cbx. Russian is not listed.

### distilbert-secret-masker v3.3a-RS (AndrewAndrewsen)

- **Architecture:** DistilBERT BIO with a single SECRET label and character spans. Apache-2.0 (weights).
- **Decoding:** span score is the mean of P(B)+P(I) over word pieces, with a frozen τ=0.99. Sliding windows with stride 128.
- **Numbers:** see §2a. False-positive rates on look-alikes: UUID 8.0%, sha256 9.0%, md5 5.5%, sha1 1.6%, SRI 0.6%, IPv4, MAC and env names 0%.
- **Weaknesses:** UUIDs and hashes; prefixless passwords (recall 0.66); chat, logs and non-English (recall 0.46).
- **Lesson:** synthetic scaling did not transfer to real code. Prefer real hard negatives (inference).

### Katerina-Bir/rubert-tiny2-secret-detection

- **Architecture:** rubert-tiny2, BertForTokenClassification, 29.1M parameters, FP32. 17 BIO tags: PERSON, LOCATION, ORGANIZATION, LOGIN, PASSWORD, AUTH_TOKEN, SECRET_KEY, CONTRACT_NUMBER.
- **Use:** built for ru-llm-proxy, an LLM proxy very like piifence, running Presidio plus Triton ONNX.
- **Windows:** 384 tokens, with boundary post-processing and merge with rules. An O-logit bias of 1.0 is applied at serving time.
- **Numbers (after analyzer rules):**
  - Mixed NER corpus: 5,489 of 5,984 values fully covered.
  - PII-Bench: 1,487 of 1,667.
  - No secret-only breakdown. The corpus was used for diagnostics and is not blind.
- **Weaknesses:** more spurious masks in code and plain text than the larger BERT. License not stated in the card.
- **Use for piifence (inference):** the only Russian secret model in scope. Run it on strings with Cyrillic script to address passwords in Russian prose. The O-logit bias is a cheap recall/precision knob for any BIO tagger, including cbx.

### MaTE X Privacy Sentinel v0.15 ONNX (enosislabs)

- **Architecture:** fine-tune of openai/privacy-filter, a 1.5B MoE with 50M active parameters. BIOES with Viterbi decoding, 23 labels including api_key, auth_token, secret, repo_secret, cloud_credential, session_cookie, database_uri, agent_memory_sensitive. Apache-2.0.
- **Numbers:** detection F1 0.987; span F1 0.954; api_key 0.950, secret 0.924, auth_token 0.940, database_uri 0.985. These are on 1,075 synthetic held-out examples from its own generator.
- **Speed:** about 8.5K tokens/s on an L40S GPU.
- **Weaknesses:** all synthetic; single-token person names F1 0; English only.
- **Use for piifence (inference):** not suited to a CPU per-string gateway. The Viterbi point is the transferable idea.

### hypn05/secrets-sentinel v5

- **Architecture:** DeBERTa-v3-base (stated as 86M in one place and 184M in another), binary line classifier, 128 tokens. MIT.
- **Speed:** about 500 ms per line on CPU; ONNX int8 at 320 lines/s with batch 64.
- **Numbers:** claims F1 0.9999 on its own synthetic split. Not a meaningful comparison.
- **Use for piifence:** the explicit hard-negative list (§1b) and its policy that the literal values "null", "changeme" and "YOURPASSWORD" are placeholders. piifence may prefer to redact some of these anyway (inference).

### openai/privacy-filter (web:openai-privacy-filter, blog, not a card)

- **Architecture:** a bidirectional token classifier converted from an autoregressive checkpoint, 128K context, BIOES with constrained Viterbi. 8 labels including `secret`. Apache-2.0.
- **Numbers:** PII-Masking-300k F1 96% (97.4% on corrected labels). Domain fine-tuning moved one benchmark from 54% to 96% F1.
- **Weaknesses:** uncommon identifiers; short sequences with limited context, which is exactly per-string scanning of short tool inputs.

## 4. Ideas mapped to piifence's measured leaks and false positives

### Leaks

**Secrets split across messages.**
- Fix: a session or request-scoped value table, as in SlotGuard's SEG (0% leak against 23.5% without it; all 200 split cases fixed).
- Every value redacted anywhere in the conversation goes into an Aho-Corasick automaton, together with:
  - URL-encoded, base64 (3 alignments), hex, lower- and upper-case variants;
  - prefixes and suffixes of 8 or more characters.
- Every later string is searched against it, and the same `$PIIF_SECRET_N` is reused for the same value.
- egemma does the same with "exact match on secrets the harness already knows".
- Inference: also concatenate adjacent message fragments (the end of one text block plus the start of the next) when scanning, to catch a value cut at a block boundary.

**URL-, base64- and hex-encoded secrets.**
- egemma's rule decodes base64 and re-scans the decoded text.
- SenScanner lists base64 as an admitted miss.
- Inference:
  - Decode candidate runs (base64 of 16 or more characters, hex of 16 or more, `%XX` sequences), re-run gitleaks, the key rule and the model on the decoded text, and map hits back to the encoded span.
  - The cbx card warns that long encoded data causes fragment false positives, so the decoded scan should replace, not add to, model tagging of the raw blob.

**32-hex key with no keyword nearby; UUID API key in a table column or under a heading.**
- Every source agrees that shape alone cannot decide this.
- Fixes with evidence:
  - Wider context in the same window: the ACM context ablation and the Springer ±3 lines.
  - Hard-negative and positive pairs in training: credential-line-32m stand-alone and list keys went 10 to 43 of 47, UUIDs flagged 17 to 2.
- Inference for piifence without retraining:
  1. For tables and markdown, pass the column header and row label as context (re-serialise each table cell as "header: value" before the model sees it).
  2. Treat headings within N lines above as key names for the key rule.

**Key whose hint is on the line above, in prose.**
- credential-line-32m names "keys whose only clue is the next line" as a top miss.
- The ACM paper finds relevant context within 6 lines.
- Inference:
  - Extend the key rule so a secret-word (key, token, password, пароль, ...) in the previous 1–2 lines, followed by a line consisting of only one random-looking value, counts as a hint.
  - Check that the 3,000-byte window boundaries overlap enough to include the previous line.

**Password under a JSON "name" key.**
- The opposite of GitGuardian's i18n false-positive example, so the key alone is not enough.
- Inference: look at sibling keys in the same JSON object (`"type": "password"`, `"kind": "secret"`, credential-like siblings such as username or host) and treat "value"/"name" fields of such objects as secret-named.

**Token used as a host label; random-looking host names.**
- credential-line-32m lists random-looking host names among its false positives, so this cuts both ways.
- SlotGuard handles hostnames as structural slots.
- Inference: flag a high-entropy label of 20 or more characters under a known tunnel or webhook domain pattern (provider-specific). Do not flag arbitrary hosts.

**Plain-word passphrases and upper-case short passwords.**
- Every model card lists them as the hardest misses: DeepPass2 (CamelCase phrases), credential-line-32m (word-like), egemma (ordinary words), distilbert (password recall 0.66).
- The only measured remedy is training data: skeleton sentences filled from breached-password lists (DeepPass2; SenScanner used LinkedIn lists).
- Inference without retraining: any value in an explicit password-assignment context (`password is X`, `pw: X`, `--password X`, Russian `пароль: X`) is redacted regardless of shape. The key rule should not require randomness when the key is password-class.

**Passwords in Russian prose.**
- distilbert non-English recall is 0.46.
- Options:
  - Run rubert-tiny2-secret-detection (29M, PASSWORD/AUTH_TOKEN/SECRET_KEY labels) on Cyrillic-script strings.
  - Add Russian cue words to the key rule (inference).
  - bardsai covers pl, de, es and fr only.

**Password in a neutral URL query param.**
- Inference: in URLs, flag any query value of 12 or more characters with mixed classes or high entropy that is not a known id parameter (utm_*, id, page, ...). The ACM "neutral variable name" false negatives support relying on value features when the name is neutral.
- Also flag the URL userinfo password always (gitleaks already partly does).

**Shell-specific contexts in Bash tool output.**
- SlotGuard's real case is a `ps` listing with a key as the default in `${VAR:-value}`.
- Inference: add rules for:
  - `${NAME:-v}` and `${NAME:=v}` with a secret-named NAME;
  - `--password`/`--token`/`-p` CLI flags;
  - Authorization header values;
  - `env`/`printenv` output lines;
  - `-u user:pass` in curl.

### False positives

**Hashes and digests.**
- Contextual signals worth encoding (Skarn's decoy families):
  - git SHA-1/256 next to "commit" or in `@<sha>` pins;
  - Docker digest prefix `sha256:`;
  - SRI `sha384-`;
  - npm `integrity`;
  - go.sum `h1:`;
  - a field name that itself says hash/digest/checksum/etag.
- egemma vetoes digests outright.
- Crypt-style password hashes (`$2y$`, `$6$`) are false positives for credential-line-32m. piifence policy decides whether those are secrets (inference: they are offline-crackable, so redacting them is defensible).

**IDs and app-id listings.**
- SenScanner's frequency feature: real passwords appear only a few times per file, while repeated values are templates or ids.
- Inference: in a single tool output, if 5 or more values share the same shape (same length and alphabet) in a list or table, treat them as an id listing unless a secret-named key is attached.
- Skarn lists ULIDs, nanoids, KSUIDs, W3C traceparent, error-tracker event ids and payment/cloud API object ids (vendor `xx_` prefixes) as decoys.
- The ACM package has 22 benign-pattern regexes worth pulling.

**Base64 data dumps.**
- The cbx card names this failure. Remedies:
  - egemma's veto for data URIs;
  - Skarn's inline images, fonts and sealed/encrypted blobs;
  - skip model tagging on base64 runs over a length threshold (e.g. 200 characters) and decode instead (inference).

**Variable names and code identifiers.**
- The tool comparison shows entropy ranks CamelCase phrases above random strings.
- Skarn's code-identifier decoys:
  - dotted symbol refs;
  - env var NAMES;
  - .NET public-key tokens;
  - version pins.
- hypn05's negatives: route strings, annotation values.

**Ordinary phrases.**
- GitGuardian's i18n example: a value with spaces and natural-language words under a password key is a label, not a secret.
- Inference: for password-class keys, values of 3 or more words that are all dictionary words and contain spaces are probably UI strings. Plain-word passphrases conflict with this, so require that the containing object looks like an i18n map (many sibling keys with prose values).

**Placeholders.**
- Consensus negatives:
  - `YOUR_..._KEY`;
  - angle brackets;
  - masked values (asterisks, REDACTED, "...", "[truncated]");
  - all-same-character values;
  - `${VAR}` and `os.environ` references;
  - "example", "dummy", "fake" or "replace-me" nearby.
- Note: Skarn and cbx still flag test-mode keys and realistic values named "test", because the model cannot know they are dead.

### Agent-transcript findings (SlotGuard, LLM-Redactor)

**Two leak surfaces.**
- Secret values, and structural bindings (paths, hostnames, branch names, file names).
- Credential scanners miss the second; path sanitizers miss tokens embedded in URLs, shell commands, process listings and config snippets.

**Format-preserving substitutes.**
- SlotGuard samples a surrogate in the same format class (length, prefix, alphabet) and reuses it per value.
- Agent utility, 200 tasks over 4 models:

| Method | Utility |
| --- | --- |
| Raw | 93.5–100% |
| Generic redaction | 2.5% |
| Typed placeholders | 20.5–38.5% |
| SlotGuard | 89.5–100% |

- Typed labels leak the category (100% category leak) and make the model believe a credential is missing.
- piifence's `$PIIF_SECRET_N` hides the type. It may hurt agent behaviour when the model must write a command containing the secret, but it works as an env-var-like reference if piifence restores it in tool_use inputs on the response path (inference).
- Guarded rebinding rejects:
  - unknown handles;
  - wrong types;
  - `..` traversal;
  - shell metacharacters;
  - fabricated credential-shaped strings.
- 64 of 64 crafted attacks were rejected.

**Placeholder hygiene (LLM-Redactor).**
- Use collision-proof delimiters (rare Unicode brackets) so user text cannot spoof placeholders.
- Keep the same value mapped to the same placeholder.
- The reverse map is per-request and memory-only; a crash means no restore, which is the right failure mode.
- Optional strict mode: refuse the request when detection confidence is below 0.5.

**Evaluation metric (LLM-Redactor).**
- "Partial leak" counts any substring of 4 or more characters of a gold secret that survives in the outbound request.
- Adopt it in piifence's probe harness so a half-masked secret counts as a leak (DeepPass2's strict-vs-overlap gap shows partial spans are common).

**Out-of-path deployment ideas.**
- LLM-Redactor ships a Claude Code pre-tool hook that warns before sensitive content leaves via a tool call.
- GitGuardian Endpoint Protection scans agent transcripts on disk (web:skarn-precision).

## 5. Quick wins for piifence, ranked

1. **Session value table plus encoded-variant matching.**
   - Collect every value redacted in the request's message history (and gitleaks or rule hits). Build an Aho-Corasick set over each value and its URL-encoded, base64 (3 offsets), hex, lower- and upper-case forms and prefixes/suffixes of 8 or more characters.
   - Redact all matches with the same `$PIIF_SECRET_N`.
   - Evidence: SlotGuard 23.5% to 0% credential leak, all split cases fixed, at about 14 µs per turn.
   - Fixes: split across messages, partially encoded repeats. Cheap, deterministic, no false positives on unseen text.
2. **Decode-and-rescan pass for encoded runs.**
   - base64 (16 or more characters, valid padding, decodes to mostly printable UTF-8), hex (even length of 16 or more, decodes to printable), and `%XX` URL encoding.
   - Run the existing detectors on the decoded text and map hits back to the whole encoded span.
   - For long base64 runs that decode to binary, mark them as data and suppress model fragments (the cbx-card false-positive).
   - Evidence: egemma's rule set; cbx's stated base64 weakness.
3. **Span widening after the model.** Extend each model or rule span to the full contiguous token (stop at whitespace, quotes and URL delimiters).
   - Evidence: egemma widens secret spans; the DeepPass2 strict-vs-overlap gap is 86.7% against 97.7%; cbx splits DB URIs. Closes partial leaks.
4. **Key-rule extensions for transcript shapes.**
   - Shell `${NAME:-v}` / `${NAME:=v}`, `--password`/`--token`/`-p`, `Authorization:`, `curl -u`, `env` output.
   - Previous-line or heading hints within 2 lines.
   - Table header to cell binding.
   - JSON sibling-key context (a `name`/`value` pair whose object holds a secret-ish type or field).
   - Password-class keys accept any value shape, including plain words and short upper-case.
   - Russian cue words.
   - Evidence: LLM-Redactor's one-regex 79.8% to 0%; SlotGuard's `ps` case; credential-line-32m and ACM context findings.
5. **Hash and id context vetoes plus a frequency rule.**
   - Prefix and field-name vetoes for digests (`sha256:`, `sha384-`, integrity/checksum/etag/digest/commit fields, `@<40hex>` pins, go.sum `h1:`).
   - ULID, KSUID and traceparent shapes.
   - A same-shape repetition rule: 5 or more same-shape values in one tool output count as an id listing unless a secret key is attached.
   - Pull the 22 benign-pattern regexes from zenodo 17430335.
   - Evidence: Skarn decoy families; SecretBench "Other" class 99% FP; SenScanner frequency feature.
6. **Build an outside test harness before tuning further.**
   - Data: ACM issue-report test split; CredDetX test (look-alikes); CredData held-out half; SlotGuard corpus for split and cross-turn.
   - Score with exact plus partial (4 or more characters) leak and false-alarm rate per non-secret candidate, as the cbx card does.
   - Evidence: every card shows a large in-distribution vs out-of-distribution gap (ACM 94% to 64% F1 in the wild).
7. **Larger or overlapping model windows.** Use more of cbx's 8K-token native context than the current 3,000-byte windows, or overlap windows by at least one or two lines.
   - Evidence: the cbx card; ACM, Springer and 2504 context ablations (small but consistent gains).
   - Inference: this should help the hint-above leak and 32-hex-with-distant-keyword.
8. **Cheap second opinions, OR-ed in and never used to veto rules.**
   - bardsai/password-detector cascade (0.7 MB, about 137 KB/s/core, multilingual prose passwords).
   - rubert-tiny2 for Cyrillic strings only.
   - Evidence: credential-line-32m OR raises recall from 0.59 to 0.89; distilbert non-English recall is 0.46.
   - Measure false positives on the harness first.
9. **Replace the shape-guard switch with a calibrated contextual gate.**
   - credential-line-32m (temperature-scaled, 4 ms per line on CPU) or a fine-tuned ModernBERT on (span plus ±200 characters) decides whether a model-only span flagged by a guard survives.
   - Evidence: GitHub two-stage +13% precision / +19% recall; ACM CodeBERT 92.7 F1 vs heuristics 37.7.
   - piifence's perfect-gate experiment bounds the upside on the current probes at 2 of 20, so rank this below the deterministic fixes (inference).
10. **Longer term: fine-tune cbx on piifence's false and missed probes.**
    - Use egemma's staged recipe (KL to the previous model, a final look-alike stage, marginal loss for secret-only sources).
    - Add credential-line-32m-style paired synthetic data (UUIDs as keys vs ids; stand-alone keys in tables) and DeepPass2-style breached-password skeleton sentences, including Russian.
    - Evidence: OpenAI's domain fine-tune moved F1 from 54% to 96%; credential-line-32m's targeted additions.

Not recommended:
- Local LLM rephrasing or DP noise: worse leak, 1–2.5 s.
- Prompted LLM validation on the hot path: precision 45–70% on prose, 0.2–0.7 s.
- Thresholding cbx confidence: bimodal and miscalibrated.
- Live verification: not applicable on the request path.
