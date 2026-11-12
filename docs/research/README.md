# Secret detection research (2026-11-11)

What other secret detectors, redaction proxies, papers and model cards do, and what piifence can take from them. We read the sources only: nothing was built, installed or run from them, and no secret value is copied here. Each claim names its source file; "(inference)" marks a reader's own reasoning, not a measured result.

| File | What's in it |
|---|---|
| [credsweeper-creddata.md](credsweeper-creddata.md) | Samsung CredSweeper's pipeline, filters, keyword rules and ML step, and CredData as a test set. |
| [model-repos.md](model-repos.md) | Secret-detection model projects (purebyte, aparte-secrets, DeepPass2, Valendra): training data recipes, hard negatives, post-processing and test sets. |
| [proxies.md](proxies.md) | Five redaction proxies for LLM agents: what they scan, how they restore, their rules and tests. |
| [papers-blogs-cards.md](papers-blogs-cards.md) | Papers, vendor blogs and Hugging Face model cards: measured techniques, comparisons and datasets. |
| [more-models.md](more-models.md) | A second, wider search for redaction models: SporeLabs Scrub, a Russian secret model, the CredDetX benchmark, and what to skip. |

## The main finding

No outside model or tool clearly beats piifence's current pipeline. What is worth taking are techniques around the model, mostly rules and checks.

## Ranked for piifence

| # | Finding | piifence gap it targets | Source |
|---|---|---|---|
| 1 | Check the whole body for leaks before forwarding: after redaction, search every string and JSON key, including parts piifence does not scan, for any value found in the session, and refuse the request if one is still there. | Thinking blocks, `server_tool_use`, `mcp_tool_use`, `tools[].description`, web_fetch results, a value detected in a later string of the same request. Works only when the value was also detected somewhere scanned. | redaction-proxy |
| 2 | Decode, then scan again: NFKC normalization, strip zero-width characters, percent-decode one level, decode base64 runs that turn out to be readable text, and map matches back to the original text. Match the encoded forms of session values too. | URL-encoded passwords, zero-width characters, base64 `.env` dumps; moves URL decoding out of gitleaks. | redaction-proxy, purebyte, CredSweeper, SlotGuard |
| 3 | Turn structure back into `key = value`: a table header with its cells, a heading with the value under it, `{"name": …, "value": …}` siblings. | UUID key in a table or under a heading, password under a JSON `name` key. | CredSweeper |
| 4 | Prose rules: a few words allowed between the keyword and `is` ("password for the office is X"), cue words in other languages. | Passwords in prose, non-English prose. | CredSweeper, redaction-proxy |
| 5 | Context rules that tell hashes from secrets: a bare 32+ hex value is a secret unless `sha`, `commit` or `hash` is within 32 characters; a UUID is a secret only under a credential name; a run of same-shape values is an id listing. | 32-hex key with no keyword; hash and id false positives. | redaction-proxy, purebyte-train |
| 6 | Base64-dump guards: drop a span inside a longer base64 run, a `data:` URI or a wrapped block. | Base64 image dumps in tool output. | CredSweeper, purebyte |
| 7 | Widen a model span to its whole token, so half a secret is never left. | Partial redactions. | Valendra decoder, papers |
| 8 | Refuse what cannot be scanned (base64 PDFs, `/v1/complete`) instead of forwarding it. | Unscanned documents and the legacy endpoint. | proxies |

Findings against swapping models:

- A model must never veto a rule hit: credential-line-32m was right only 79% of the time when it called a rule hit clean. A union of rules and model, as piifence has, is the right shape.
- Model confidence is not a usable threshold: egemma's scores are confidently wrong in both directions.
- cbx-secrets-detector-32M's own card names two of piifence's weak spots (base64 dumps flagged as many fragments, keys with no keyword nearby). It reads up to about 8K tokens, more than piifence's 3,000-byte windows give it.
- Small extra detectors could add hits, never remove them: bardsai/password-detector (0.7 MB) for passwords in prose, rubert-tiny2 for Cyrillic.

Where piifence already stands: the gateway keeps a per-session table of found values and replaces them wherever they appear again (`replace_env_values` in `src/bin/gateway.rs`), which is the fix SlotGuard measured for repeated values. It does not match encoded forms or pieces of a found value, and within one request a value first detected in a later string is not replaced in an earlier one (read from the code, not tested).

One proxy finding set aside: `$PIIF_SECRET_N` names are numbered and guessable, so a prompt injection could ask for one in a command. Random names would not help, since the agent sees the names in its own context and can already use them in Bash by design; keeping values from the provider, not from the agent, is piifence's job.

Outside test sets, since every current piifence case was written or mined for piifence:

- aparte `chat-fresh` and `chat-fresh-json`: 440 English and French chat messages each, with decoys, ODC-BY.
- ACM issue-report dataset (zenodo 17430335), prose and logs. cbx trained on its training split, so only the test split is fair.
- CredData: context and hard negatives from 337 repos; its true values are replaced with random strings of the same character classes, so passphrases cannot be tested.

## Sources

GitHub repos, read at these commits:

| Repo | Commit | Date |
|---|---|---|
| [Samsung/CredSweeper](https://github.com/Samsung/CredSweeper/tree/4482593f03b00c39bf2fa33e2c704f87340a7518) | `4482593f` | 2026-11-11 |
| [Samsung/CredData](https://github.com/Samsung/CredData/tree/5b6db1a28df026310200150d16eb87355f5d7a8c) | `5b6db1a2` | 2026-11-09 |
| [purebyte-ai/purebyte](https://github.com/purebyte-ai/purebyte/tree/8a4bea155c8806187270835edf1e91db0057ba7a) | `8a4bea15` | 2026-10-06 |
| [purebyte-ai/purebyte-train](https://github.com/purebyte-ai/purebyte-train/tree/f310bc3bff159b3abb5585060244e4597008186e) | `f310bc3b` | 2026-09-28 |
| [apartejs/aparte-secrets-model](https://github.com/apartejs/aparte-secrets-model/tree/7cfb20c158e8212ebcea2b33566bd121bae4df5f) | `7cfb20c1` | 2026-10-18 |
| [SpecterOps/DeepPass2](https://github.com/SpecterOps/DeepPass2/tree/e51a6960b1e9a4714ed502aaf14d14fc5d50bcbc) | `e51a6960` | 2025-10-15 |
| [valendra-tech/valendra-privacy-filter](https://github.com/valendra-tech/valendra-privacy-filter/tree/79500aae1bbe7877e58b4d373bf69e708a14ec22) | `79500aae` | 2026-11-06 |
| [Exestence/redaction-proxy](https://github.com/Exestence/redaction-proxy/tree/45518d76f61e90433370f176599bb4c8df9a7dfc) | `45518d76` | 2026-11-05 |
| [crp4222/PrivAiTe](https://github.com/crp4222/PrivAiTe/tree/27936d7b319b95829adcd915f3064ffac86483d8) | `27936d7b` | 2026-11-09 |
| [outgate-ai/og-local](https://github.com/outgate-ai/og-local/tree/64abc197bbd0dd5f3ae1b9a5ba7e622929147e30) | `64abc197` | 2026-10-13 |
| [bvolpato/promptlatch](https://github.com/bvolpato/promptlatch/tree/e7e00edc418749279f31d5940d9b8e120fe119a4) | `e7e00edc` | 2026-11-05 |
| [paroque28/claude-code-redact](https://github.com/paroque28/claude-code-redact/tree/d9c57fa4b07ec6ee99a238cf8dd15065c84b2318) | `d9c57fa4` | 2026-03-31 |

Hugging Face cards (`hf:<owner>/<name>` in the files), read 2026-11-11:

- [nekomimi-llc/egemma-pii-secrets](https://huggingface.co/nekomimi-llc/egemma-pii-secrets)
- [CobuildX-AI/cbx-secrets-detector-32M](https://huggingface.co/CobuildX-AI/cbx-secrets-detector-32M), [CobuildX-AI/cbx-secrets-detector-17M](https://huggingface.co/CobuildX-AI/cbx-secrets-detector-17M)
- [bardsai/password-detector](https://huggingface.co/bardsai/password-detector)
- [apartejs/aparte-secrets](https://huggingface.co/apartejs/aparte-secrets), datasets [apartejs/aparte-secrets-gold](https://huggingface.co/datasets/apartejs/aparte-secrets-gold) and [apartejs/aparte-secrets-data](https://huggingface.co/datasets/apartejs/aparte-secrets-data)
- [zaindanaharper/credential-line-32m](https://huggingface.co/zaindanaharper/credential-line-32m)
- [gneeraj/deeppass2-bert](https://huggingface.co/gneeraj/deeppass2-bert)
- [Katerina-Bir/rubert-tiny2-secret-detection](https://huggingface.co/Katerina-Bir/rubert-tiny2-secret-detection)
- [purebyte/secrets-code](https://huggingface.co/purebyte/secrets-code)
- [hypn05/secrets-sentinel](https://huggingface.co/hypn05/secrets-sentinel)
- [AndrewAndrewsen/distilbert-secret-masker-v3.3a-rs](https://huggingface.co/AndrewAndrewsen/distilbert-secret-masker-v3.3a-rs)
- [enosislabs/matex-privacy-sentinel-v0.15-onnx](https://huggingface.co/enosislabs/matex-privacy-sentinel-v0.15-onnx)
- [valendra/privacy-filter-mini](https://huggingface.co/valendra/privacy-filter-mini)

Web pages (`web:<name>` in the files), read 2026-11-11:

| Name | URL |
|---|---|
| arxiv-2504.18784-secret-breach-llm | https://arxiv.org/html/2504.18784v1 |
| arxiv-2604.12064-llm-redactor | https://arxiv.org/html/2604.12064v1 |
| arxiv-2307.00714-secret-tools-comparison | https://arxiv.org/html/2307.00714v1 |
| arxiv-2607.17147-slotguard | https://arxiv.org/pdf/2607.17147 |
| springer-learning-to-detect-hardcoded-secrets | https://link.springer.com/article/10.1007/s10664-026-10929-w |
| acm-secret-leak-issue-reports | https://dl.acm.org/doi/10.1145/3793302.3793348 |
| mdpi-senscanner | https://www.mdpi.com/2078-2489/17/7/648 |
| specterops-deeppass2 | https://specterops.io/blog/2025/07/31/whats-your-secret-secret-scanning-by-deeppass2/ |
| wiz-slm-secrets | https://www.wiz.io/blog/small-language-model-for-secrets-detection-in-code |
| github-blog-secret-model | https://github.blog/ai-and-ml/githubs-model-for-secret-detection-finding-more-secrets-with-less-noise/ |
| github-blog-secret-protection | https://github.blog/ai-and-ml/github-copilot/secret-protection-must-scale-with-software/ |
| gitguardian-ml | https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/machine_learning |
| gitguardian-benchmarks | https://blog.gitguardian.com/tools-for-reproducible-detailed-and-meaningful-benchmarks/ |
| skarn-precision | https://getskarn.com/research/secret-detection-precision/ |
| legit-fp-reduction | https://www.legitsecurity.com/blog/using-ai-to-reduce-false-positives-in-secrets-scanners |
| cycode-ml | https://cycode.com/blog/secrets-detection-powered-by-cycodeai/ |
| sperix-llm-redactor-blog | https://sperixlabs.org/post/2026/04/llm-redactor-what-leaves-your-prompt-when-you-talk-to-a-cloud-llm/ |
| openai-privacy-filter | https://openai.com/index/introducing-openai-privacy-filter/ |
| prismor-tool-boundary | https://www.prismor.dev/blog/tool-boundary-redaction-ai-agents |
| formal-proxies-claude-code | https://www.formal.ai/blog/using-proxies-claude-code/ |
| langsmith-redact-secrets | https://docs.langchain.com/langsmith/redact-secrets |

Not read: the Android secrets paper at https://jordansamhi.com/static/files/papers/secretloc.pdf (the PDF did not download).
