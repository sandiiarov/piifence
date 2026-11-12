# More redaction models: second search (2026-11-11)

A wider search for token-classification models that redact secrets: Firecrawl web and developer-index searches, and the Hugging Face model API with the `token-classification` filter over 27 search terms (175 hits). Only model cards and pages were read; no weights were downloaded and nothing was run. Numbers are each author's own claims on their own data, so they do not compare with each other or with piifence's suite.

## Worth testing

### SporeLabs Scrub (`hf:SporeLabs/scrub`)

The strongest new candidate.

- Model: Ettin 17M encoder (the same family as cbx-secrets-detector), one output per type per token, a threshold per type picked on held-out data, plus rules. ONNX fp32 67 MB, int8 19 MB. Weights Apache-2.0, code MIT.
- Secret types: `PASSWORD` (in prose, commands, config files, connection strings, also dictated), `OTP`, `URL_CREDENTIAL` (a password or token inside a URL), provider keys by format (`AWS_KEY`, `STRIPE_KEY`, `OPENAI_KEY`, `ANTHROPIC_KEY`, `HF_TOKEN`, `GITHUB_TOKEN`, `JWT`) and `OTHER_SECRET` (private keys, bearer tokens, session cookies, webhook secrets, database passwords). It also tags personal data (`PERSON`, `USERNAME`, `PATH_USER`, `EMAIL` and more), which piifence would ignore.
- Training: about 305,000 documents built from public human text (WildChat, SMS, OpenAssistant, code) with detected details swapped for generated stand-ins, and generated details placed in command lines, HTTP headers, logs, config and `.env` files, CSV, git history and chat exports, with look-alikes (example keys, test card numbers, hashes, version strings) as negatives.
- Design: rules take precedence for anything with a format; the model finds what has none. "A value found once is found everywhere it repeats in the text."
- Claimed results, held-out `test` of 100 documents (chats, emails, tickets, logs, agent transcripts, config; 135 secrets, 798 look-alikes): secrets caught 0.918 against 0.852 for openai/privacy-filter and 0.770 for GLiNER2-PII; look-alikes scrubbed 0.094 against 0.175 and 0.283. "Caught" means every letter and digit of the item was covered.
- Speed, one CPU thread on an Apple M3: 2.1 ms per chat message (median 42 characters), 34.8 ms per document (median 665 characters), fp32.
- Limits it states: built and tested on English; a first pass, not a guarantee.
- Why it fits piifence (inference): it targets passwords in prose and commands, which are piifence's weakest cases, it was trained on agent transcripts and config, and it is half the size of cbx-32M.
- Its benchmark, `hf:datasets/SporeLabs/scrub-benchmark`, includes agent transcripts and is a second outside test set.

### fef2/ner_rus_bert-secret_detection (`hf:fef2/ner_rus_bert-secret_detection`)

- Model: `DeepPavlov/rubert-base-cased` with a token-classification head, Apache-2.0. Credential labels `LOGIN`, `PASSWORD`, `AUTH_TOKEN`, `SECRET_KEY`, plus Russian personal data. Tuned for recall, "to pick up what regexes miss".
- It runs in 384-wordpiece windows; `pipeline()` alone does not window and fails past 512 wordpieces.
- Its rule layer is worth copying even without the model: a `kv` rule with a key ontology that includes Russian keys (`пароль`, `токен` next to `password`, `api_key`, `login`), a `cli` rule for known flags of known commands (`--password=…`, `curl -u user:pass`), and an `opaque` rule for high-entropy values plus gitleaks rules mapped by rule id.
- Fit: the only secret model found that is trained on Russian. A candidate for the Russian prose leak, as an add-only detector.

### safetype/blackbar-nano (`hf:safetype/blackbar-nano`)

- Model: ModernBERT-base encoder (149M) with span pooling and entity and label heads; 35 labels, mostly personal data, including `password` and `api_key`. Apache-2.0. ONNX fp16 encoder 300 MB plus a 10 MB head.
- About 38 ms per chat-sized message on an Apple M1. Candidates are whitespace-delimited units, capped at 12.
- The card gives no secret-specific scores. Low priority: large, and built for personal data.

## Benchmarks found

### CredDetX (`hf:datasets/CobuildX-AI/CredDetX`)

- By CobuildX AI, the authors of cbx-secrets-detector. CC-BY-4.0. Code: github.com/cobuild-tech/CredDetX.
- 3,027 texts (code, config, logs, tickets, chats, documents) with 4,016 secrets in the same 12 types cbx uses, exact character offsets, and 8,824 annotated look-alikes in 20+ kinds (hashes, ids, public keys, placeholders, masked values, encoded blobs, minified bundles, source maps, repeated log ids). 467 texts have no secret.
- Splits: dev 602 texts, test 2,425. Policy questions (example values, test-named keys, identifiers, weak passwords) are attributes, so piifence can score under its own policy.
- Slices for known failure modes: secrets with no provider prefix or keyword, passwords in URLs, masked values, malformed JWTs, PEM keys in JSON strings, repeated values, and 63 long logs over 17,000 characters.
- Every value is generated (one generator is `gemma-4-31b-it`); a leak guard checks against a public set of real leaked secrets.
- Caveat (inference): it comes from the same team as cbx and may share generators with cbx's training data, which would flatter cbx. Compare other models on it, but read cbx's own score with care.

### redactionbench (`web:arxiv-2606.18782-redactionbench`)

- A redaction benchmark whose labels include `password` and `api_key`, with file types such as `csv_api_keys_export`, `password_manager_csv`, `recovery_keys`, `ssh_config`, `yaml_k8s_secret`, `yaml_docker_compose` and `browser_storage`.
- It proposes an R-Score between IoU and strict F1 that gives partial credit for partial redactions, and lists low-entropy look-alike families (`low_entropy_literal` such as `abc123` or `deadbeef`, `sequential_numeric_run`, `alternating_alnum_run`) that are useful as guard tests.

## Not worth testing

| Model | Why not |
|---|---|
| `divergentlabs/masker`, `masker-mini` | Personal data only (48 BIOES labels), no secret labels. |
| `yanndegat/secretguard-ner-v3` | Personal data only, despite the name. It is notable for running in pure Rust with no ONNX. |
| `AndrewAndrewsen/longformer-secret-masker` | Its own card says it has known problems with PEM blocks and Kubernetes secrets and recommends the DistilBERT expert instead. |
| `AndrewAndrewsen/secretmask-gate` | A 3,042-parameter router between two SecretMask models, not a detector. |
| `screenpipe/pii-redactor` | Has a `secret` label (passwords, API keys, JWTs, DB URIs), but the weights are CC-BY-NC-4.0. |
| `Horizon-Labs/pii-redactor-*`, `Kostya165/pii-redactor-small-ONNX`, `balticml/mmbert-small-pii-redaction`, `koncsik/redacto-eu-pii-ner-q4f16`, `bengid/pii-redaction-deberta-*` | Personal data only. |
| `abdolence/redacter-rs` | A redaction CLI, not a model; its local mode uses a multilingual NER model and a zero-shot span model, and it delegates secrets to other tools. |

## Sources

- Hugging Face cards: [SporeLabs/scrub](https://huggingface.co/SporeLabs/scrub), [fef2/ner_rus_bert-secret_detection](https://huggingface.co/fef2/ner_rus_bert-secret_detection), [safetype/blackbar-nano](https://huggingface.co/safetype/blackbar-nano), [divergentlabs/masker](https://huggingface.co/divergentlabs/masker), [divergentlabs/masker-mini](https://huggingface.co/divergentlabs/masker-mini), [yanndegat/secretguard-ner-v3](https://huggingface.co/yanndegat/secretguard-ner-v3), [AndrewAndrewsen/longformer-secret-masker](https://huggingface.co/AndrewAndrewsen/longformer-secret-masker), [AndrewAndrewsen/secretmask-gate](https://huggingface.co/AndrewAndrewsen/secretmask-gate), [screenpipe/pii-redactor](https://huggingface.co/screenpipe/pii-redactor), [Kostya165/pii-redactor-small-ONNX](https://huggingface.co/Kostya165/pii-redactor-small-ONNX), [balticml/mmbert-small-pii-redaction](https://huggingface.co/balticml/mmbert-small-pii-redaction), [koncsik/redacto-eu-pii-ner-q4f16](https://huggingface.co/koncsik/redacto-eu-pii-ner-q4f16), [bengid/pii-redaction-deberta-small](https://huggingface.co/bengid/pii-redaction-deberta-small).
- Datasets: [CobuildX-AI/CredDetX](https://huggingface.co/datasets/CobuildX-AI/CredDetX), [SporeLabs/scrub-benchmark](https://huggingface.co/datasets/SporeLabs/scrub-benchmark).
- Pages: [redactionbench, arXiv 2606.18782](https://arxiv.org/pdf/2606.18782), [abdolence/redacter-rs](https://github.com/abdolence/redacter-rs), [arXiv 2506.13090](https://arxiv.org/html/2506.13090v1) (detecting hard-coded credentials with embedding models; scraped, not yet read in depth).
