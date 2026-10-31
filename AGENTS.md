# piifence

## Purpose

Local redaction gateway for coding-agent traffic (Claude Code hooks + local gateway).
M1 is the model-validation milestone: prove that OpenAI Privacy Filter span extraction
via `privacy-filter-rs` (NdArray + Accelerate CPU backend for M1) behaves as expected on a 15-case corpus before
building the placeholder/redaction layer (M2).

## Ownership

- M1 harness: `src/main.rs`, `src/detect.rs`, `src/guards.rs`, `src/config.rs`,
  `src/gitleaks.rs`,
  `gitleaks.toml`, `tests/corpus.json`, `scripts/fetch-weights.sh`; `examples/probe.rs`
  probes arbitrary strings for spans.
- Gateway spike (test-only): `src/bin/gateway.rs`, documented in `docs/gateway-spike.md`.
- CLI launcher: `src/bin/piifence.rs` (`piifence claude ...`), symlinked at
  `/opt/homebrew/bin/piifence`; starts/reuses the gateway, resolves the upstream from
  `PIIF_UPSTREAM` / `ANTHROPIC_BASE_URL` / Claude settings (no default provider),
  applies a temporary `--settings` override, and tears the gateway down if it started
  it. Reuses a running gateway only when its reported upstream matches. Never edits
  the user's settings file.
- Installer: `scripts/install.sh` (macOS) installs release binaries under `PREFIX`
  (default `~/.local`), copies the gitleaks config and both plugins, writes a wrapper
  that points the launcher at them, and optionally fetches weights with
  `--with-weights`.
- Claude Code notice plugin: `plugin/piifence-notice/` (hooks + `scripts/notice.py`);
  `piifence claude` auto-loads it per session via `--plugin-dir` unless a global copy
  exists at `~/.claude/skills/piifence-notice` (optional install lives outside this
  repo — re-copy after plugin changes).
- Claude Code approval mod: `plugin/piifence-approval/` (`prompt.submit` hook using
  `$.ui.ask` for Use env var / Redact / Send raw / Block; talks to gateway `/scan` and
  `/control/allow-prompt-once`); `piifence claude` loads it per session via
  `--plugin-dir` unless `~/.claude/skills/piifence-approval` exists.
- Env replacement: the approval mod can set `PIIF_<CATEGORY>_<N>` (`$.env.set`, literal
  names, up to 4 per category per prompt) and rewrite the prompt span to
  `$PIIF_<CATEGORY>_<N>`; the guard suppresses those env references, and Bash commands
  can expand them. The same `session.append` hook rewrites `tool_result` content and
  Bash-mode `command` rows (doors `tool-result` / `command`), and `prompt.context`
  rewrites `claudeMd` / `attachedProject` context (CLAUDE.md and @ imports) to `$PIIF_…`
  before they are stored/sent. `/scan` returns UTF-16 code-unit offsets so JS rewriting
  matches Rust detection on non-ASCII text. System prompt/assistant history remain
  gateway placeholders because the gateway cannot set `$.env` and the mod has no hook
  for those request fields. The raw value stays in the Claude Code process, never the
  provider.
- Validation artifacts: `tests/m1-report.txt`, `docs/m1-notes.md`, `docs/labels.md`,
  `docs/prior-art.md`, `docs/gateway-spike.md`, `docs/model-options.md`.
- Model weights live in `data/` (untracked, ~2.8 GB, fetched on demand).
- Do not edit another milestone's files under this root without updating this contract.

## Local Contracts

- Build: `cargo run --release` (Apple Silicon, CPU). `privacy-filter-rs` uses the default
  `ndarray` backend with `blas-accelerate`; MLX was attempted first but MLX 0.25.1 Metal
  kernels do not compile with Xcode 27's Metal toolchain, so M1 runs on CPU (documented in
  `docs/m1-notes.md`). Revisit MLX only after the toolchain incompatibility is fixed.
- Model directory: `data/` by default, overridable with `PIIF_MODEL_DIR`.
- gitleaks pre-pass: requires `gitleaks` on PATH (`brew install gitleaks`), runs once
  per text block with `gitleaks.toml` (the default rules plus about twenty `piifence-*`
  rules for formats the default set misses: passwords and secrets assigned with `=` or
  `:`, URL and header credentials, Azure, Discord, Docker Hub, Braintree, delimiter-free
  Anthropic/Stripe/JWT variants and eight vendor prefixes; `tests/secrets/run.py
  --check-generators` is the list's test), and is merged with model spans by overlap:
  pre-pass findings are labelled `secret`, a deterministic secret takes over every
  span it overlaps (the model labels the AWS key `private_person` in prose), and the
  gateway's `normalize_spans` unions overlapping spans, clamps them to the text and
  trims surrounding whitespace. Every copy of a gitleaks secret in a block is
  redacted; findings gitleaks reports from decoded base64 redact the encoded segment. `PIIF_GITLEAKS=0` disables it (14/15 with guards on,
  12/15 with guards off); `PIIF_GITLEAKS_CONFIG` overrides the config path. The
  pre-pass is pattern matching only — it cannot fix model false positives/re-redaction.
- Category configuration: `src/config.rs` + `piifence.toml.example`. Only configured
  categories are detected/redacted; sources `PIIF_CATEGORIES` (comma/space list, wins),
  then `PIIF_CONFIG` / `~/.config/piifence/config.toml` / `./piifence.toml`, else all 8.
  Unknown names fail closed before model load; disabling `secret` disables the gitleaks
  pre-pass. `llm_filter` (default true) keeps the model in the secret path; false is
  the rules-only fast path. Disabled categories are forwarded raw by design.
  `piifence.toml` is ignored; `piifence.toml.example` is tracked.
- Detector performance: when configured categories are a subset of `secret` AND
  `llm_filter=false`, the model is not loaded at all (gitleaks-only fast path); final
  detection results (model + gitleaks + guards) are cached per exact text in a
  least-recently-used cache bounded by `PIIF_CACHE_MB` (default 64 MB of text), so
  re-sent history is not re-scanned. Text over 6 KB is split into ~2k-token
  overlapping windows so one huge request cannot exhaust memory; secret spans are
  merged with every model span they touch. `/stats` exposes
  `redact_ms_last/max/total` in addition to counts.
- Wrapper guards: `src/guards.rs` vetoes model output before replacement. Placeholder
  guard suppresses spans fully inside pipeline-owned placeholder tokens
  (`<(private_)?[a-z_]+_\d+>`, legacy `PII_<LABEL>_<8hex>`); env-ref allowlist suppresses
  `SECRET` spans overlapping `os.environ.get(...)` / `os.environ[...]` / `os.getenv(...)` /
  `process.env.*`. Every suppression is printed with its reason; `PIIF_GUARDS=0` disables
  the guards (13/15 baseline). Guards decide keep/drop only — they do not fix span
  boundaries, and they are policy (narrow, versioned, unit-tested), not test scaffolding.
- Context-aware scanning: `tool_result` text is re-scanned with the originating
  `tool_use` name/input as model context (`Tool call: …\nTool output:`); Bash-mode
  output (`!command`, `<bash-input>`/`<bash-stdout>` tags, no tool_use pair) is scanned
  with `Shell command: …\nShell output:` as context. Only spans inside the output are
  redacted. This is the primary fix for bare secrets; gitleaks prefix rules are the
  fallback. `PIIF_GITLEAKS=0` turns the pre-pass off for model-only tests.
- Gateway spike contract: **input-only by design and the only mode** — redacts
  `POST /v1/messages` text fields, then streams the upstream response byte-for-byte
  (no buffering, no SSE parsing, no vault, no rehydration); the agent sees placeholders.
  Audit log contains metadata only (never raw values); `PIIF_AUDIT_BODY=1` writes the
  already-redacted body for verification; fail closed on redaction errors. Test
  scaffolding, not the M2 gateway: per-process placeholder counters, single detector
  worker, no local auth, unknown payload shapes passed through. Every content
  block type that can carry text is routed through `redact_block` in the gateway;
  a new block type is added there and nowhere else. `/stats` exposes
  redaction counts, a `values` counter of distinct placeholders, and metadata for
  recent first sightings only — including a masked first4+last4 `preview` for notice
  verification, never the raw value. The notice reports only values redacted for
  the first time.
  Prompt approval is handled by the approval mod, not the gateway: `POST /scan` returns
  findings (detection only; UTF-16 code-unit offsets), `POST /control/allow-prompt-once`
  sets a one-shot grant that lets only the last user prompt through raw (tool results
  still redacted; audit `allowed_prompt`; grant expires after 60s). `/stats.allowed`
  counts allowed prompts. No osascript/native macOS dialog is used.
  Gateway hardening: requires `PIIF_UPSTREAM` (no default provider); binds loopback and
  rejects requests with an `Origin` header or a non-loopback `Host`; accepts POST only
  for `/v1/messages` and `/v1/messages/count_tokens` (both redacted) and refuses other
  `/v1/messages/*` shapes; 64 MB body limit; gitleaks must exist at startup; audit logs
  are created mode 0600; the session `--settings` override uses a unique name and
  `create_new`; long tool input is truncated on a char boundary.
  The notice plugin displays that metadata via hook `systemMessage`; it must stay
  metadata-only, silent when the gateway is absent, and never read raw values.
  `piifence claude` is the supported entrypoint: fail closed if the gateway cannot
  start, pass `--settings` internally (reject user-supplied `--settings`), and never
  edit `~/.claude/settings.json`. Never commit a Claude Code test settings file or
  auth token.
- Corpus expectations are hypotheses, not ground truth. Record actual behavior in
  `tests/m1-report.txt` and explain every mismatch in `docs/m1-notes.md`; correct the
  corpus only when the report proves the expectation was wrong.
- Acceptance gate (M1): secret >= 4/5 (`sec-05` mandatory), pii >= 4/5 (`pii-05`
  mandatory), negative 5/5 mandatory. The gate applies to the shipped pipeline
  (model + gitleaks + guards), which currently passes 15/15 with exit 0. Baselines:
  12/15 model-only, 13/15 with gitleaks only, 14/15 with guards only, 15/15 with both.
- Harness exits non-zero on any mismatch; raw stdout is the committed report.

## Work Guidance

- Keep the dependency list to what `Cargo.toml` has; justify additions. No HTTP layer
  belongs in the M1 harness (`src/main.rs`). Wrapper guards are allowed because M1 gates the shipped
  pipeline, but each guard needs a failure case in the corpus, a printed suppression, and
  a unit test.
- Compare multi-sets of normalized entity groups (sorted), not span order.
- Never commit `data/` or `target/`.
- Probe detector behavior on candidate strings with
  `cargo run --release --example probe -- "<text>"`; use it to validate placeholder
  formats and false-positive allowlist patterns before changing the corpus.

## Verification

- `scripts/check.sh` runs every check; CI runs it on every push to main and every pull
  request (`.github/workflows/ci.yml`). It skips the model-backed suite modes and the M1
  gate when no weights are present (`PIIF_MODEL_DIR`, default `data/`); `--no-suite`
  skips the gateway-backed suites. The bullets below describe what it runs; a new check
  is added to the script, not to the workflow.
- `cargo run --release 2>&1 | tee tests/m1-report.txt` must run to completion with the
  model loaded, gitleaks + guards status printed, all 15 cases evaluated, and 15/15 with
  exit 0. `PIIF_GITLEAKS=0` reproduces 14/15; `PIIF_GUARDS=0` reproduces 13/15; both off
  reproduces 12/15.
- `cargo test --release` runs the guard unit tests (placeholder shapes, env-ref
  variants, real secrets/PII not suppressed). `cargo build --release` builds both the
  harness and the gateway spike.
- `python3 -I tests/secrets/run.py --model-dir <weights>` runs the end-to-end secret suite (formats × Claude Code request locations) through the real gateway. It must exit 0. Known gaps are listed in `tests/secrets/expectations.json`; a change that fixes one must remove its entry. `--mode secret-rules` runs without weights in about 30 seconds. `--check-generators` checks that each generated format is found by one of the gitleaks rules it lists.
- End-to-end check: `piifence claude --version` (smoke) and a real
  `piifence claude -p ...` run; verify the upstream-visible request has placeholders,
  the client result has placeholders (input-only), the Stop notice lists the redaction,
  raw values appear in no log, and the gateway process is gone after exit.
  `docs/gateway-spike.md` has the mock-upstream variant.
- `docs/m1-notes.md` covers every failed case with span evidence and a
  corpus-error vs model-limitation verdict.

## Child DOX Index

- (none)
