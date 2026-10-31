# Prior art — placeholder round-trip and detector false positives

Research notes (2026-10-25) for the two M1 blockers. Sources were gathered with
firecrawl and are linked inline. `docs/m1-notes.md` holds the M1 evidence; this
file records how existing redaction gateways handle the same problems, plus an
empirical probe against our copy of the model (`examples/probe.rs`).

## 1. How existing tools avoid re-redacting their own placeholders

| Tool | Placeholder | Round-trip strategy |
| --- | --- | --- |
| [og-local](https://github.com/outgate-ai/og-local) | `OG_PRIVATE_EMAIL_<hex>`, `OG_SECRET_<hex>` (deterministic per session) | Agent context always holds real values. Each outbound request is re-redacted from real text; the placeholder map lives only for the request and is inverted on the response. Scanned text never contains previous placeholders. |
| [secretgate](https://github.com/maxgfr/secretgate) | `SECRETGATE_<hmac>`, vault at `~/.secretgate/vault.json` (0600) | Model only ever sees placeholders; restore on Write/Edit. Placeholders are deliberately rule-inert (no secret keyword/entropy); Bash restore is off by default so a prompt-injected `curl $PLACEHOLDER` cannot exfiltrate. |
| [claude-code-redact](https://github.com/paroque28/claude-code-redact) | `__RDX_KEY_a1b2c3d4__` auto-tokens; format-preserving fakes for names | Opaque token namespace; `--no-unredact` "awareness mode" keeps Claude seeing redacted text. |
| [claude-cloakpipe](https://github.com/borgius/claude-cloakpipe) | CloakPipe pseudonyms | Gateway pseudonymizes outbound and rehydrates inbound; hooks rehydrate tool inputs before local execution. Placeholders exist only in flight. |
| [Presidio / MLflow / Preserve](https://mlflow.org/articles/pii-redaction-llm/) | `[PERSON_1]`, `[EMAIL_2]` (stable per session) | Session-scoped vault, restore in response, refuse output containing PII not in the map. |
| [PortEden](https://porteden.com/blog/ai-redaction-placeholders/) | `[PERSON_1]`, `[DATE_2024-03-15]` | Egress redaction + short-lived encrypted vault; placeholder itself is not invertible by the model. |

Common patterns:

1. **Detector-inert namespace.** Placeholders avoid secret-shaped material:
   no hex blob, no keyword like `SECRET`, no `sk-` prefix. Bracketed words plus
   a numeric id are the norm.
2. **Vault owns the mapping**, never the token (the token carries no raw value
   and is not cryptographically reversible on its own).
3. **Rebuild outbound text from real values every turn** where the agent is
   allowed to see real values (og-local, cloakpipe). Then re-scanning a
   placeholder is an edge case, not the steady state.
4. **Stay out of the scanner's way when placeholders do appear** — e.g.
   Secretgate's placeholder format does not match its own gitleaks-derived
   rules. No surveyed tool relies on the model being polite enough not to
   re-flag its own tokens.

### Empirical probe against `openai/privacy-filter`

`cargo run --release --example probe -- "<text>"` (model + tokenizer from
`data/`). Results: `[]` means the model ignores the token.

Flagged (unsafe for this model):

| text | output |
| --- | --- |
| `OPENAI_API_KEY=<PF_SECRET_7f3e9d1c>` | `secret` 0.923 |
| `OPENAI_API_KEY=<PF_TOKEN_7f3e9d1c>` | `secret` 0.932 |
| `OPENAI_API_KEY=[PF_1]` | `secret` 0.982 |
| `email is <PF_EMAIL_a1b2c3d4>` | `private_email` 0.969 |
| `email is SECRETGATE_a1b2c3d4e5f6` | `secret` 1.000 |
| `email is __RDX_KEY_a1b2c3d4__` | `secret` 0.533 |
| `email is <private_email_a1b2c3d4>` | `secret` 0.624 |
| `OPENAI_API_KEY=<private_secret:7f3e9d1c>` | `secret` 0.913 |

Ignored (safe for this model):

| text | output |
| --- | --- |
| `<private_email>`, `<private_email_1>`, `<private_person_1>`, `<private_address_2>` | `[]` |
| `<private_url_1>`, `<private_date_1>`, `<account_number_1>`, `<private_phone_2>` | `[]` |
| `<private_secret>`, `<secret>`, `<private_secret_1>`, `<secret_1>` | `[]` |
| `[EMAIL_1]`, `[REDACTED]`, `REDACTED_EMAIL_1`, `__REDACTED_1__` | `[]` |

Takeaway: **model-native angle tokens with numeric ids are inert; hashes and
secret-ish words are not.** Even Secretgate's own placeholder format is flagged
by this model (1.000), so prior-art formats cannot be copied blindly.

## 2. How existing tools control detector false positives

- **gitleaks**: per-rule allowlists, inline `# gitleaks:allow` pragma,
  `.gitleaksignore` fingerprints, and `--baseline-path` for existing findings.
  The canonical env-var FP is tracked as
  [gitleaks#1828](https://github.com/gitleaks/gitleaks/issues/1828)
  (`QUESTIONNAIRE_DB_PASSWORD=` followed by `..._ENABLED=1` triggers
  `generic-api-key`); the workaround is an allowlist/pragma, not a detector fix.
- **secretgate**: narrowest-first allowlisting —
  `secretgate allow <value>` (stored as SHA-256, never plaintext),
  `secretgate allow --path 'tests/fixtures/**'`, `secretgate allow --rule <id>`
  (last resort); project `.secretgate.json` allowlists are only honored after
  `secretgate trust` (a cloned repo cannot disable detection). Hooks ignore
  inline pragmas because model-bound text could carry a forged one. Known
  limitation: low-entropy and spaced passwords are not attempted because the
  false-positive cost is too high.
- **Presidio**: analyzer-level `allow_list` / `allow_list_match`
  (`exact` / `regex` / `contains`) plus context-word boosting; recognizers are
  tuned per entity type. ([analyzer docs](https://microsoft.github.io/presidio/analyzer/))
- **Layered pipeline** (MLflow/Preserve): deterministic regex + checksum first,
  NER/classifier only for free text; versioned policy doc with allow-lists;
  warn-only rollout, per-entity precision/recall tracking, then enforcement.
- **Model-native controls**: privacy-filter ships precision-tuned by default;
  the Viterbi bias knob trades recall for far more predictions (Tonic benchmark
  measured 0.77–0.85 precision at default, with recall the weak axis —
  [Tonic](https://www.tonic.ai/blog/benchmarking-openai-privacy-filter-pii-detection)).
  Our bundled `viterbi_calibration.json` only contains the all-zero `default`
  operating point, so a "high precision" preset is not available without
  patching the crate/calibration.

### Empirical probe: the env-var false positive is narrow

`neg-01` (`password = os.environ.get('DB_PASS')`, single quotes) → `secret`
0.542. Adjacent variants the model leaves clean:

- `password = os.environ.get("DB_PASS")` (double quotes)
- `password = os.environ.get("DB_PASSWORD")`, `('DB_PASSWORD')`, `('API_KEY')`
- `password = os.environ['DB_PASSWORD']`
- `password = os.getenv("DB_PASS")`
- `x = os.environ.get('DB_PASS')`
- `api_key = os.environ.get("OPENAI_API_KEY")`, `process.env.*`, `export DB_PASSWORD=""`

So a targeted allowlist for `os\.environ\.get\(['"][A-Z0-9_]+['"]\)` (and
siblings) suppresses `neg-01` without a broad confidence floor.

## 3. Concrete consequences for piifence M2

1. **Placeholder scheme**: switch the M2 enum to model-inert, typed, numbered
   tokens — `<private_email_1>`, `<private_person_2>`, `<secret_1>`,
   `<account_number_1>` — not the hex-hash `<PF_*_8hex>` format. Vault maps the
   full token (including the numeric id) to the real value; ids are stable per
   session so the model keeps referential consistency.
2. **Skip guard**: before inference, skip any span inside a recognized
   placeholder token (`<(private_)?[a-z_]+_\d+>`); after inference, drop spans
   fully contained in such tokens. This makes `sec-05` pass regardless of the
   model's opinion. Implemented in `src/guards.rs` (see `docs/m1-notes.md`).
3. **False-positive guard**: versioned allowlist policy with narrow regexes for
   env-var references (`os.environ.get(...)`, `os.getenv(...)`,
   `process.env.*`) instead of a global confidence floor; keep a per-rule
   justification and warn-only telemetry, as secretgate/Presidio do.
   Implemented in `src/guards.rs` (see `docs/m1-notes.md`).
4. **Architecture**: prefer the og-local/cloakpipe shape (agent sees real
   values; placeholders exist only inside one request/response cycle) so
   re-scanning placeholders is the exception, not the steady state. The skip
   guard is still required for the model's own emitted tokens and pasted text.
5. **Secret authority**: keep gitleaks/rules as the deterministic secret
   layer; do not let the model's `secret` category alone decide. The model is
   the semantic PII layer (emails, names, addresses, dates, account numbers).

## Sources

- og-local — https://github.com/outgate-ai/og-local
- secretgate — https://github.com/maxgfr/secretgate
- claude-code-redact — https://github.com/paroque28/claude-code-redact
- claude-cloakpipe — https://github.com/borgius/claude-cloakpipe
- PortEden, "AI Redaction Placeholders: What They Do and Do Not Protect" —
  https://porteden.com/blog/ai-redaction-placeholders/
- MLflow, "PII Redaction before LLM calls" — https://mlflow.org/articles/pii-redaction-llm/
- Presidio Analyzer docs — https://microsoft.github.io/presidio/analyzer/
- gitleaks#1828 — https://github.com/gitleaks/gitleaks/issues/1828
- Tonic.ai privacy-filter benchmark —
  https://www.tonic.ai/blog/benchmarking-openai-privacy-filter-pii-detection
