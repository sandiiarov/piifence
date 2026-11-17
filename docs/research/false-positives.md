# How other secret scanners avoid false positives

Most of what piifence names in real sessions is not a secret. A scan of piifence's own detector over the prompts and tool output saved in 7,134 texts from real Claude Code sessions found 121 distinct values. Only 10 of them looked like credentials (GitHub tokens, a password in a URL, long random strings). The rest came from two sources:

| Source | Values | What they were |
|---|---|---|
| The model (`model:SECRET`) | 84 | Hyphenated, snake_case and CamelCase identifiers, enum variants, nanoids and other ids, Slack mention ids, calendar event ids, token counts, file names, an `ls` permission column |
| The key rule (`keyrule`) | 27 | 40-hex commit SHAs after `head`, `Commit:`, `pr_head:` or `index`, and `computedHash` / `sourceRevision` values in lock files |

A value named once is then replaced everywhere in the conversation, so one false positive shows up many times. The audit log of one session held 495 replacements, all of them repeats of values already named.

The cases are in `tests/secrets/negatives.py`. The ones piifence still gets wrong are listed with a reason in `tests/secrets/expectations.json`.

## What other tools do

| Tool | How it decides | Source |
|---|---|---|
| gitleaks `generic-api-key` | Needs a keyword (`key`, `token`, `secret`, `password`, `auth`, `credential`, …) next to an assignment, a value of 10–150 characters with Shannon entropy of at least 3.5, and a value that is not all letters. About 1,450 stopwords are checked against the captured value. | https://github.com/gitleaks/gitleaks , https://nhimg.org/generic-api-key-detection-guide |
| detect-secrets | Entropy limits of 4.5 for base64 and 3.0 for hex. Filters drop UUIDs, id-like strings, sequential strings, templates (`<key>`, `{{key}}`, `${key}`), `$`-prefixed references, indirect references such as `get_secret_key()`, and values a gibberish model scores as words. | https://github.com/Yelp/detect-secrets/blob/master/docs/filters.md |
| BigCode (SantaCoder) on detect-secrets | Dropped the keyword detector because it fired on the word "password". Added the gibberish filter because entropy flagged paths and URLs. A hash filter looks at length plus `sha`, `md5`, `hash` or `byte` nearby. | https://arxiv.org/html/2301.03988v2 |
| TruffleHog | A keyword must be within 40 characters before a detector runs. Unverified hits go through a known-false-positive list and an entropy check. Hits are verified against the provider's API. | https://securityblog.omegapoint.se/en/writeup-trufflehog/ , https://trufflesecurity.com/docs/custom-detectors |
| Nosey Parker | Regex alone gave 82–92% precision. A transformer second stage kept 1,169 of 1,199 real secrets and 24 of 205 false positives, for 98% precision. | https://www.praetorian.com/blog/nosey-parker-ai-secrets-scanner-release/ |
| Kingfisher | Regex, then a syntax-tree check that the hit sits in a string literal, then entropy, then checksums, then live validation. | https://appsecsanta.com/kingfisher |
| GitGuardian | Formats without a fixed prefix or length are reported only when validated. An ML false-positive remover drops secret names, paths, `$VAR` references, versions, dates, error codes and algorithm names, at about 95% precision. | https://blog.gitguardian.com/ai-false-positive-remover-v2/ |
| GitHub secret scanning | An LLM checks how the value is used (passed to an auth header, SDK or database client), which cut false positives by 76%. UUIDs and opaque ids were the main false positives. | https://github.blog/security/making-secret-scanning-more-trustworthy-reducing-false-positives-at-scale/ |

CredSweeper's filters (word lists, dictionary coverage, hex under 22 characters as a number) are in [credsweeper-creddata.md](credsweeper-creddata.md).

## What they share

No tool trusts one signal. A real secret either has a provider format (a prefix such as `ghp_`, `sk-`, `AKIA`, or a checksum), or it has all of these:

1. A credential keyword close before it (`token=`, `password:`, `Authorization: Bearer`).
2. Randomness that is not just high entropy: it does not read as words, and it is not a hash, UUID or id in a hash or id context.
3. A position where a value goes (an assignment, a string literal, a header), not a name, path, type or list of identifiers.

## Proposed change for piifence

Keep everything gitleaks and provider-format rules find. Filter only the spans the model or the key rule finds alone:

1. **Hash and id context.** Drop hex of 7–64 characters when a word like `commit`, `head`, `sha`, `index`, `hash`, `digest`, `revision` or `checksum` is just before it, or when it sits in a diff `index` line. Drop UUIDs unless a credential keyword is within about 40 characters. This fixes every key-rule false positive in the scan.
2. **Identifier shape.** Drop a model-only span that splits fully into dictionary words and numbers (`WhisperLargeV3Turbo`, `frontend-applications`, `focus_visible_in_every_scene`), the way CredSweeper's dictionary rule does. Drop all-digit spans unless a keyword is before them.
3. **Keyword rescue.** Any span with a credential keyword within 40 characters before it skips filters 1 and 2. This keeps passwords that happen to be words, and hex keys after `api_key=`.
4. **Later, if 1–3 are not enough:** a small local second-stage classifier over the span and a few lines around it, as Nosey Parker does. Live verification is out of scope, because it would send users' keys to outside services.

The risk is a real secret that looks like an identifier and has no keyword before it. Filter 3 limits that risk, and the secret suite's 100 formats and 31 mined real secrets must still pass.
