# Gateway — input-only redaction proxy for Claude Code

Status: **validated spike, not production.** The goal is narrow: the provider
must never receive the raw values we send. Responses are never modified.

## What it is

`src/bin/gateway.rs` — a minimal Anthropic-compatible proxy on loopback:

1. Claude Code points at it with `ANTHROPIC_BASE_URL=http://127.0.0.1:7788`.
2. On `POST /v1/messages` it redacts text fields (`system`, `messages[].content`,
   `tool_result` content, `tool_use.input`, `document` blocks with a text source
   plus their `title` and `context`, `search_result` content, `title` and `source`)
   through the shared `Detector` (model + gitleaks + guards); spans become opaque
   numbered placeholders (`<private_email_1>`, `<secret_1>`, ...). Every block type
   is routed through `redact_block`; images, non-text documents and thinking
   blocks are passed through untouched.
3. The redacted request is forwarded to `PIIF_UPSTREAM` (required, no default
   provider) with the original auth headers.
4. The upstream response is streamed back **byte-for-byte, unbuffered and
   unmodified**: no SSE parsing, no vault, no placeholder rehydration.
5. `/health` responds `ok`; `/stats` returns redaction counters, a `values`
   counter of distinct placeholders, and metadata for recent first sightings (no
   raw values). Redaction errors fail closed (HTTP 502,
   the request is not forwarded). Other paths are passed through untouched
   (still streamed).

The Burn model is `!Sync`, so it lives on one worker thread; requests go through
a channel (`DetectJob`), serializing model calls.

Placeholders are one-way by design. The provider never sees the value; the agent
sees the placeholder. Each (category, value) pair gets one placeholder number for
the life of the gateway process, so the history Claude Code re-sends every turn is
rewritten byte-for-byte the same (provider prompt caching and thinking-block
signatures depend on that). Values are keyed by a per-process keyed hash, never
stored; a later scan of re-sent history skips existing placeholders through the placeholder guard, so
nothing is double-redacted.

Audit: `/tmp/piifence-audit.log` records only event metadata — field, label,
score, offsets, placeholder, engine — never raw values. `PIIF_AUDIT_BODY=1`
additionally writes the already-redacted request body for verification.

## Chunks: inputs vs responses

**Requests are not streamed.** An Anthropic Messages call is one JSON POST;
`stream: true` only controls the response. The gateway reads the complete body,
redacts it, and forwards one complete body — request scanning is complete before
anything leaves the machine.

**Responses are streamed.** The upstream body is piped with
`reqwest::Response::bytes_stream()` → `axum::body::Body::from_stream(...)`, so
SSE chunks reach Claude Code as they arrive. Measured against a mock upstream
that sends the first event, sleeps 2 s, then sends the rest:

| | time to first byte | total |
| --- | --- | --- |
| input-only proxy | 0.29 s | 2.29 s |

For comparison, the earlier buffered/rehydrating prototype had TTFB == total
(2.3 s). Buffering was removed together with rehydration: both only existed to
restore values the agent is no longer meant to see.

## Tradeoff (accepted)

The agent sees `<private_email_1>` instead of `alice@example.com` for the rest of
the session. Consequences:

- Tools that need the real value (e.g. `curl -H "Authorization: Bearer
  <secret_1>"`, editing a file whose path contained PII) will not work; there is
  no restore path by design.
- Anything the model generates itself is passed through unscrubbed — input-only
  protects the data *we send*, not model output.
- Local Claude Code history/transcripts store placeholders, not the raw values
  (the gateway never restores them).

## Label precedence

In prose like `"my key is AKIAIOSFODNN7EXAMPLE"` the model labels the key
`private_person` (0.678) while gitleaks knows it is a credential. A gitleaks
`secret` finding takes over every span it overlaps, so the placeholder is
`<secret_1>`, not `<private_person_1>`. Before replacement the gateway unions all
overlapping spans (so no part of a covering span stays visible), clamps spans that
start in the tool-call context to the tool output, and trims surrounding whitespace
(the model often includes a leading space). Every copy of a gitleaks secret in the
block is redacted, and findings gitleaks reports from decoded base64 redact the
encoded segment.

## Test evidence

Environment: Claude Code 2.1.283 on an OpenRouter Anthropic-compatible endpoint;
gateway upstream (`PIIF_UPSTREAM`, the provider used in that run); model
`~deepseek/deepseek-v4-flash-latest`; tools disabled (`--tools ""`) so only text
fields were exercised. A temporary `--settings` file (mode 0600, deleted
afterwards) overrode only `ANTHROPIC_BASE_URL`; the auth token was forwarded in
headers, never logged.

| run | provider received | Claude Code result |
| --- | --- | --- |
| email | `"My email is<private_email_1> ..."` — raw absent | `<private_email_1>` (not restored) |
| AWS key (with mock upstream) | `"my key is <secret_1>"` — raw absent | placeholders, streamed |

- Gateway stdout/stderr and audit log grepped for the raw email: 0 hits.
- Mock upstream verified the request body was redacted before forwarding and the
  response arrived incrementally (TTFB 0.29 s vs 2.29 s total).
- Latency per single-turn request: ~6–9 s wall clock on CPU, dominated by
  startup/model load; detection ~0.2–0.6 s for short text.

## User-visible notice (Claude Code plugin)

`plugin/piifence-notice/` is a Claude Code plugin that shows what was redacted.
`piifence claude` loads it for the session automatically via `--plugin-dir` when it
is not installed globally — no manual plugin install is required. If a copy exists at
`~/.claude/skills/piifence-notice`, that one is used instead (no duplicate hooks).
Hooks:

- `SessionStart` → `piifence: active — input redaction on (nothing redacted yet)`
  (or `… — N value(s) redacted so far`, N distinct values).
- `Stop` (after a turn in which a value was redacted for the first time) →
  `piifence: redacted 2 value(s) — private_email×2 (<private_email_1> al…om, <private_email_2> bo…io)`.

The preview is masked (first 4 + last 4 chars) and comes from the gateway `/stats`
metadata; the full value is never stored, logged, or sent to the plugin.

Evidence from a real Claude Code `--output-format stream-json` run:

```json
{"type":"system","subtype":"informational","content":"Stop says: piifence: redacted 2 value(s) — private_email×2 (<private_email_1>, <private_email_2>)","level":"notice"}
```

The script reads `/stats` and `/tmp/piifence-notice-state.json`, prints only
labels/counts/placeholders, and stays silent when the gateway is not running.
It counts `/stats` `values` (distinct placeholders assigned, each counted the first
time only), not `redactions` (every replaced span, which grows every turn because
Claude Code re-sends the history); `recent` holds only those first sightings, so a
value re-sent in later turns is not reported again.
It never reads the raw values (the gateway keeps none).

Optional persistent install (plain `claude` sessions, without the launcher):

```bash
cp -R plugin/piifence-notice ~/.claude/skills/piifence-notice
claude plugin disable piifence-notice@skills-dir   # or rm -rf ~/.claude/skills/piifence-notice
```

## One command: `piifence claude`

The CLI wrapper (`src/bin/piifence.rs`, symlinked at `/opt/homebrew/bin/piifence`)
does the whole setup per session:

```bash
piifence claude [claude arguments...]
```

1. If `127.0.0.1:7788` is not healthy, start `piifence-gateway` (weights resolved via
   `PIIF_MODEL_DIR`, else `<repo>/data`) and wait up to 45 s for `/health`.
   Gateway diagnostics go to a log file (`PIIF_GATEWAY_LOG`, default
   `<tmp>/piifence-gateway.log`), not to the terminal; on startup failure the last
   15 log lines are printed and Claude Code is not launched (fail closed).
2. Derive the upstream from the user's current Claude Code settings
   (`~/.claude/settings.json` `env.ANTHROPIC_BASE_URL`), so the gateway sits in front
   of whichever provider the user already uses (`PIIF_UPSTREAM` overrides).
3. Write a 0600 temporary `--settings` file overriding only `ANTHROPIC_BASE_URL`,
   load the notice plugin for this session with `--plugin-dir` if it is not already
   installed globally, launch `claude` with all user arguments, and delete the
   temporary settings afterwards. The user's settings file is never modified.
4. Pin the repository gitleaks config: `PIIF_GITLEAKS_CONFIG=<repo>/gitleaks.toml`
   and run the gateway with the repo as cwd. Without this, a launcher started from
   `$HOME` makes the gateway look for `./gitleaks.toml`, fall back to stock rules, and
   miss project rules such as bare `oc_sk_…` keys.
5. On normal exit, stop the gateway if this invocation started it; reuse an
   already-running one.

Example real run:

```bash
piifence claude -p "My email is alice@example.com. Reply with exactly my email." \
  --tools "" --system-prompt "You are terse. Repeat the user's email exactly." \
  --output-format stream-json --verbose --max-turns 1
```

Output (abridged):

```text
piifence: starting gateway on http://127.0.0.1:7788 (upstream <provider base URL>)
...
piifence: active — input redaction on (nothing redacted yet)        # SessionStart notice
Stop says: piifence: redacted 1 value(s) — private_email×1 (<private_email_1>)   # Stop notice
result: <private_email_1>
```

The upstream-visible request body contained `<private_email_1>`; grepping it for the
raw email returned 0 hits. The gateway process is gone after Claude Code exits.

Notes: do not pass `--settings` to `piifence claude` (it owns that flag); Ctrl-C may
leave the gateway running (next invocation reuses it); `piifence claude --version`
works as a smoke test.

## Prompt approval mod (native Claude Code dialog)

`plugin/piifence-approval` is a Claude Code **mod**, loaded by `piifence claude`. Its
`prompt.submit` hook asks the gateway for findings, then uses the mods API `$.ui.ask` —
Claude Code's own dialog — with options **Use $PIIF_<CATEGORY>_<N> / Redact / Send raw /
Block** (the env option is omitted when a value cannot be mapped, e.g. more than four
values of one category in a single prompt).

- **Use $PIIF_…** — the mod sets the raw value as an environment variable in the Claude
  Code session (`$.env.set`, names are literal), rewrites the prompt span to
  `$PIIF_SECRET_1` (or the category equivalent), and adds a Claude-only context note
  mapping the variable names. The gateway sees only the env reference (guard
  `$PIIF_[A-Z0-9_]+`), so the provider never receives the value; local Bash commands can
  expand it. Env vars live for the session and are never printed by the mod.
- **Redact** — prompt continues; the gateway replaces the spans as usual.
- **Send raw** — the mod calls `POST /control/allow-prompt-once`; the gateway lets the
  last user prompt through unmodified but still redacts tool results. Audit event
  `allowed_prompt`.
- **Block** — returns `{ drop: … }`: the prompt is not sent and the text returns to the
  input with `piifence: prompt blocked…`.

Tool results and Bash-mode command rows get the same treatment: the mod's
`session.append` hook rewrites `tool_result` content and `command` rows (Bash-mode output)
to `$PIIF_…` before they are stored and sent, with the same env counters. A `Read` of a
file containing a secret stores `$PIIF_SECRET_N` in the transcript, and a Bash-mode
`!echo $PIIF_SECRET_1` stores `$PIIF_SECRET_N` as `<bash-stdout>` content; the raw value
never reaches the provider.

Instruction files (`CLAUDE.md`, `@` imports) are env-replaced as well: the mod's
`prompt.context` hook rewrites the `claudeMd` / `attachedProject` context blocks to
`$PIIF_…` before the first request. `/scan` returns offsets in UTF-16 code units (what a
JS `String.prototype.slice` uses), so instruction files containing non-ASCII punctuation
rewrite cleanly instead of splitting the value.

The system prompt, assistant history and other request fields still use the gateway's
normal placeholder redaction: the gateway is a separate process and cannot set
`$.env`, and the mod has no hook that rewrites those arbitrary request fields (assistant
output is intentionally left alone). A secret there is replaced with an inert
placeholder, which is safe but not usable as a shell variable. The env variables are
available to Bash, so an agent can use them in commands (e.g.
`curl -H "Authorization: Bearer $PIIF_SECRET_1" ...`) without the value crossing the
gateway.
- **No interactive UI** (e.g. `claude -p`), a dismissed dialog, or an unreachable gateway
  → prompt continues and the gateway redacts (safe default). Hook errors are caught.

Gateway endpoints used by the mod:

- `POST /scan` `{text}` → `{findings: [{label, preview, start, end, engine, score}]}`;
  detection only, masked previews, no state change.
- `POST /control/allow-prompt-once` — one-shot flag consumed by the next
  `/v1/messages` request; only the last user message text is skipped (tool results and
  system content are still scanned/redacted).

No osascript or macOS dialog is involved. Mod files:
`plugin/piifence-approval/{.claude-plugin/plugin.json,hooks/hooks.json,hooks/register.js}`;
validate with `claude plugin validate plugin/piifence-approval`.

## Categories configuration

Only the configured categories are detected and redacted; everything else is sent to
the provider untouched. Sources, in priority order:

1. `PIIF_CATEGORIES` env var — comma or space separated names (overrides a file).
2. Config file: `PIIF_CONFIG`, else `~/.config/piifence/config.toml`, else `./piifence.toml`.
3. Default: all 8 categories.

File format (`piifence.toml.example` is tracked; a local `piifence.toml` is ignored):

```toml
categories = ["secret", "private_email"]
```

Valid names: `account_number`, `private_address`, `private_email`, `private_person`,
`private_phone`, `private_url`, `private_date`, `secret`. Unknown names are an error and
the gateway exits before loading the model — a typo cannot silently disable redaction.
Disabling `secret` also disables the gitleaks pre-pass.

`llm_filter` (default `true`) controls whether the neural model joins
secret detection:

- `true` — gitleaks **and** the neural model run for `secret`. Wider recall (novel
  formats, URL-embedded credentials the rules miss), costs model load + inference.
- `false` — rules-only fast path: the model is not loaded at all. Rules cover AWS keys
  (including the corpus EXAMPLE key), JWTs, OpenAI `sk-proj-…` keys, OpenCode
  `oc_sk_…` keys (including bare values in tool output), and URL-embedded credentials;
  novel secret formats may still be missed.

`piifence claude` resolves the same config path and passes `PIIF_CONFIG` to the gateway.
The chosen categories are logged at gateway startup (`categories: …`).

Verified with the gateway + mock upstream:

| `categories` | provider received |
| --- | --- |
| `["secret"]` | `"My email is alice@example.com and key <secret_1>"` (email raw, key redacted) |
| `["private_email"]` | `"My email is<private_email_1> and key AKIAIOSFODNN7EXAMPLE"` (email redacted, key raw) |

## Performance (measured 2026-10-25)

Setup: Claude Code 2.1.310 → OpenRouter (`deepseek-v4-flash`), short prompt, tools
disabled, Apple M4 CPU. Local overhead isolated with a captured 5.6 KB Claude Code
request and a mock upstream:

| path | per request |
| --- | --- |
| direct to upstream (no gateway) | ~0.3 ms |
| gateway, `["secret"]` + `llm_filter = false` (rules only) | ~95 ms |
| gateway, `["secret"]` + `llm_filter = true`, first unique text | ~4.4 s |
| gateway, `["secret"]` + `llm_filter = true`, repeated text (cache hit) | ~100 ms |

Cold startup of `piifence claude` (gateway + Claude Code version probe):

| setup | startup |
| --- | --- |
| plain `claude` | ~0.0 s |
| piifence, secret-only with `llm_filter = false` | 0.33 s |
| piifence, secret-only with `llm_filter = true` / all categories | 3.2 s |

End-to-end, same prompt and provider (provider latency varied 0.5–11 s across runs):

| run | wall | provider API | local (wall − api) |
| --- | --- | --- | --- |
| plain `claude` | 0.96–11.44 s | 0.47–11.07 s | ~0.41 s |
| `piifence claude`, cold, secret-only | 1.54–1.67 s | 0.82–0.90 s | ~0.73 s |
| `piifence claude`, warm gateway, secret-only | 1.34 s | 0.86 s | ~0.48 s |

Reading this: with rules-only secret mode the local cost is ~0.1 s/request plus 0.3 s
cold start — not the bottleneck. With the model enabled (llm_filter=true or any PII
category) the CPU model scans every *new* text block
(~4 s for a 1.2k-token prompt) and model load adds 3 s to cold start; repeated blocks
(same system prompt/history) hit the per-text cache. The earlier slowness was the
all-categories model path plus provider stalls, not the proxy hop.

`/stats` exposes `redact_ms_last`, `redact_ms_max`, `redact_ms_total` so this can be
checked live.

## Limitations

- Agent sees placeholders; tools needing real values break (accepted tradeoff).
- Model output is not scrubbed; only outbound input is.
- Placeholder numbers are per gateway process: stable for as long as it runs,
  reset by a restart. A restart mid-session renumbers the history once (one
  prompt-cache miss).
- Single detector worker: requests are serialized.
- No local auth on the loopback port.
- No chunking for oversized prompts (model context 128k).
- No adversarial tests: forged placeholder-shaped input, tool-arg injection.
- Only `/v1/messages` text-bearing fields are redacted; unknown future payload
  shapes are passed through (fail-open for unrecognized fields).
- Bare high-entropy credential values without a known prefix can be labelled
  `private_person` by the model instead of `secret`; rules cover the known formats
  above. If a key of an unknown format appeared in a session, treat it as exposed and
  rotate it.

## Reproduce

```bash
cargo build --release
PIIF_UPSTREAM=<provider base URL> ./target/release/piifence-gateway
curl http://127.0.0.1:7788/health
# point Claude Code at http://127.0.0.1:7788 via a temporary --settings env
```

Requires `gitleaks` on PATH (`brew install gitleaks`) and weights in `data/`.
