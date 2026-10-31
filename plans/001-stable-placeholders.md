# Plan 001: Give every redacted value the same placeholder on every turn

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving to the next step. If anything in the "STOP conditions" section occurs, stop and report — do not improvise. When done, update the status row for this plan in `plans/README.md` — unless a reviewer dispatched you and told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 39dd159..HEAD -- src/bin/gateway.rs docs/gateway-spike.md docs/labels.md`
> If any in-scope file changed since this plan was written, compare the "Current state" excerpts against the live code before proceeding; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S (about 2 hours including the end-to-end check)
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `39dd159`, 2026-10-30

## Why this matters

piifence is a local proxy between Claude Code and the model provider. It replaces secrets and personal data in each request with placeholders such as `<secret_1>` and `<private_email_2>`. Claude Code re-sends the whole conversation on every turn, with the original raw values, and the gateway numbers placeholders from one counter per category that only ever goes up. So the same value gets a new number on every turn. Measured at commit 39dd159: the first message of a 5-turn conversation went upstream as `<private_email_1>`, `_2`, `_4`, `_7`, `_11` on turns 1–5.

This costs three things:
1. **Prompt cache.** Claude Code turns on provider prompt caching by default, and a cache hit needs a byte-identical prefix. Because the history changes every turn, it is re-written to the cache (1.25× input price) instead of read (0.05× on Opus 5.5).
2. **Extended thinking.** On Claude 5.1+ models, a thinking block's signature is valid only while the messages before it are unchanged. Accounts created on or after 2026-08-31 get HTTP 400 on Opus/Sonnet/Haiku 5.5 when they change, and Claude Code then strips thinking and retries.
3. **Consistency.** The model sees `<secret_1>` in its own earlier reply and `<secret_4>` for the same value now.

After this plan, the same (category, value) pair always maps to the same number for the life of the gateway process. Re-sent history is then rewritten byte-for-byte the same on every turn.

## Current state

Files:
- `src/bin/gateway.rs` — the gateway: proxy handler, the JSON walker that finds text, and placeholder assignment. It has no `#[cfg(test)]` module today.
- `docs/gateway-spike.md` — design notes for the gateway; describes the counters and lists "numbers are not stable" as a limitation.
- `docs/labels.md` — an older proposal for hash-based placeholders (not implemented).

`src/bin/gateway.rs:67-77` — shared state. `counters` holds one running number per category:

```rust
struct AppState {
    detector_tx: std::sync::mpsc::Sender<DetectJob>,
    client: reqwest::Client,
    upstream: String,
    port: u16,
    audit: Arc<Mutex<std::fs::File>>,
    audit_body: Arc<Mutex<std::fs::File>>,
    counters: Arc<Mutex<HashMap<String, usize>>>,
    stats: Arc<Mutex<Stats>>,
    allow_prompt_until: Arc<Mutex<Option<Instant>>>,
}
```

`src/bin/gateway.rs:119` — `fn category_for(label: &str) -> &'static str` maps a model label to one of `private_email`, `private_person`, `private_phone`, `private_address`, `private_url`, `private_date`, `account_number`, `secret`, or `private_entity`.

`src/bin/gateway.rs:133-143` — the bug. The value is never consulted:

```rust
fn next_placeholder(state: &AppState, label: &str) -> String {
    let category = category_for(label);
    let mut counters = state.counters.lock().unwrap();
    let counter = counters.entry(category.to_string()).or_insert(0);
    *counter += 1;
    if category == "secret" {
        format!("<secret_{counter}>")
    } else {
        format!("<{category}_{counter}>")
    }
}
```

`src/bin/gateway.rs:299-327` (inside `redact_text_with_context`) — spans are selected and replaced right to left, so numbers are also handed out right to left:

```rust
    spans.sort_by_key(|s| s.start);
    // Greedy non-overlapping set; replace right-to-left so offsets stay valid.
    let mut out = text.to_string();
    let mut accepted = Vec::new();
    let mut last_start = usize::MAX;
    for span in spans.into_iter().rev() {
        if span.end > last_start {
            continue;
        }
        last_start = span.start;
        accepted.push(span);
    }

    let mut audit = Vec::new();
    for span in &accepted {
        let token = next_placeholder(state, &span.label);
        let preview = mask_value(&text[span.start..span.end]);
        out.replace_range(span.start..span.end, &token);
        audit.push(json!({
            ...
            "placeholder": token,
            ...
        }));
    }
    Ok((out, audit))
```

`src/bin/gateway.rs:847` — where `counters` is initialised in `main`: `counters: Arc::new(Mutex::new(HashMap::new())),`.

Design constraints from the docs (quote these when you update them):
- `docs/gateway-spike.md:27-30`: "Placeholders are one-way by design. The provider never sees the value; the agent sees the placeholder. Placeholder counters are per process; a later scan of re-sent history skips existing placeholders through the placeholder guard, so nothing is double-redacted."
- `docs/gateway-spike.md:324-325` (Limitations): "Placeholder counters are per process (no persistence); numbers are not stable across restarts (irrelevant without rehydration, but do not treat them as ids)."
- "No vault, no rehydration" (`src/bin/gateway.rs:17`). The gateway must never be able to map a placeholder back to its value. This plan keeps that: it stores a keyed hash of each value, not the value, and it has no placeholder→value lookup.
- `docs/labels.md:32` proposes `<PF_SECRET_{8 hex of sha256(category + value)}>`. Do NOT implement that. An unkeyed 8-hex hash of a short value such as an email or phone number can be reversed by trying candidate values, which would leak the value to the provider. The keyed per-process hash below avoids this.
- The placeholder format `<secret_N>` / `<{category}_N>` must not change: `src/guards.rs` recognises it, and the approval plugin `plugin/piifence-approval/hooks/register.js` relies on it.

Conventions: doc comments (`///`) on new items, explaining why rather than what; `HashMap` from `std::collections` (already imported at `gateway.rs:25`). Unit tests live in a `#[cfg(test)] mod tests` at the bottom of the file; see `src/detect.rs:279` onward for the style (plain `#[test]` functions with descriptive snake_case names, `assert_eq!`).

## Commands you will need

| Purpose | Command (run from repo root) | Expected on success |
|---|---|---|
| Build | `cargo build --release` | exit 0 |
| Unit tests | `cargo test --release` | all pass (19 existing + the new ones) |
| Gateway-only tests | `cargo test --release --bin piifence-gateway` | all pass |
| Corpus (needs model weights) | `PIIF_MODEL_DIR=<weights dir> cargo run --release` | ends with `15/15 passed` |

Model weights: if `data/config.json` does not exist, ask the operator for the weights directory (on the planning machine it is `/Users/alexs/piifence-trial/src/data`). gitleaks must be on PATH (`gitleaks version` prints a version).

## Scope

**In scope** (the only files you should modify):
- `src/bin/gateway.rs`
- `docs/gateway-spike.md`
- `docs/labels.md`

**Out of scope** (do NOT touch):
- `src/detect.rs` — its cache is plan 002.
- `src/guards.rs` and `plugin/` — they depend on the placeholder format, which does not change.
- The "Send raw" path (`allow_prompt_once`, `take_allow_prompt`) — a known separate issue.
- Trimming the leading space that model spans sometimes include — a separate finding; do not change span offsets here.
- Persisting the mapping across gateway restarts.

## Git workflow

- Branch: `fix/stable-placeholders` from `main`.
- Commit messages in this repo: imperative summary of 60 characters or less, blank line, then one bullet per change. Examples from `git log`: "Window long model input and keep secret spans whole", "Harden gateway and launcher against leaks and misuse". End each message with the trailer `Co-authored-by: Claude <noreply@anthropic.com>`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add a `Placeholders` type that numbers each value once

In `src/bin/gateway.rs`, directly above `fn next_placeholder`, add:

```rust
/// Placeholder numbers per (category, value), fixed for the life of the process.
/// Claude Code re-sends the raw history every turn, so numbering by value keeps the
/// rewritten history byte-identical across turns (prompt cache hits, valid thinking
/// signatures, consistent references). Values are keyed by a per-process keyed hash
/// and never stored, so there is no way back from a placeholder to its value.
#[derive(Default)]
struct Placeholders {
    hasher: std::collections::hash_map::RandomState,
    assigned: HashMap<(&'static str, u64), usize>,
    next: HashMap<&'static str, usize>,
}

impl Placeholders {
    /// The number for `value` in `category`, assigning the next free one on first sight.
    /// Surrounding whitespace is ignored: model spans sometimes include a leading space.
    fn number_for(&mut self, category: &'static str, value: &str) -> usize {
        use std::hash::BuildHasher;
        let key = (category, self.hasher.hash_one(value.trim()));
        if let Some(number) = self.assigned.get(&key) {
            return *number;
        }
        let next = self.next.entry(category).or_insert(0);
        *next += 1;
        self.assigned.insert(key, *next);
        *next
    }
}
```

**Verify**: `cargo build --release` → exit 0 (an "unused" warning for `Placeholders` is expected at this point).

### Step 2: Use it from `next_placeholder`

1. In `struct AppState`, replace `counters: Arc<Mutex<HashMap<String, usize>>>,` with `placeholders: Arc<Mutex<Placeholders>>,`.
2. In `main`, replace `counters: Arc::new(Mutex::new(HashMap::new())),` with `placeholders: Arc::new(Mutex::new(Placeholders::default())),`.
3. Change `next_placeholder` to take the value:

```rust
fn next_placeholder(state: &AppState, label: &str, value: &str) -> String {
    let category = category_for(label);
    let number = state.placeholders.lock().unwrap().number_for(category, value);
    if category == "secret" {
        format!("<secret_{number}>")
    } else {
        format!("<{category}_{number}>")
    }
}
```

4. Update its only caller in `redact_text_with_context` to pass `&text[span.start..span.end]` as `value`.

**Verify**: `cargo build --release` → exit 0 with no warnings mentioning `counters` or `Placeholders`. `grep -n "counters" src/bin/gateway.rs` → no matches.

### Step 3: Hand out numbers left to right

In `redact_text_with_context`, `accepted` is built right to left. Number the spans in document order, then replace right to left as before. Replace the loop that starts `let mut audit = Vec::new(); for span in &accepted {` with:

```rust
    // Number left to right so placeholders read in document order; replace right to
    // left so earlier offsets stay valid.
    let tokens: Vec<String> = accepted
        .iter()
        .rev()
        .map(|span| next_placeholder(state, &span.label, &text[span.start..span.end]))
        .collect();
    let mut audit = Vec::new();
    for (span, token) in accepted.iter().zip(tokens.iter().rev()) {
        let preview = mask_value(&text[span.start..span.end]);
        out.replace_range(span.start..span.end, token);
        audit.push(json!({
            // keep every existing field exactly as it is today
        }));
    }
```

Keep the body of `audit.push(json!({...}))` exactly as it is today (fields `field`, `label`, `score`, `start`, `end`, `placeholder` (now `token`), `preview`, `engine`). `accepted` is right-to-left, so `accepted.iter()` zipped with `tokens.iter().rev()` pairs each span with its own token.

**Verify**: `cargo build --release` → exit 0.

### Step 4: Unit tests

Add at the bottom of `src/bin/gateway.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_value_keeps_its_number() { ... }
    ...
}
```

Write these tests against `Placeholders::number_for` (no network, no model):
1. `same_value_keeps_its_number`: `number_for("secret", "abc")` twice returns 1 both times.
2. `new_values_get_the_next_number`: "abc" → 1, "def" → 2, "abc" again → 1.
3. `categories_count_independently`: `("secret","abc")` → 1 and `("private_email","x@example.org")` → 1.
4. `surrounding_whitespace_is_ignored`: `" abc"` and `"abc"` → the same number.
5. `same_text_in_two_categories_is_two_values`: `("secret","abc")` → 1, `("account_number","abc")` → 1, then `("secret","zzz")` → 2 (the categories do not share a counter).

**Verify**: `cargo test --release --bin piifence-gateway` → `test result: ok. 5 passed`. Then `cargo test --release` → all pass.

### Step 5: End-to-end check with a replayed conversation

This needs model weights and gitleaks (see "Commands you will need").

1. `rm -f /tmp/piifence-redacted-bodies.jsonl`
2. Start a test gateway on a spare port, in the background or a separate terminal, from the repo root:
   `PIIF_UPSTREAM=http://127.0.0.1:9 PIIF_PORT=7799 PIIF_AUDIT_BODY=1 PIIF_AUDIT_LOG=/tmp/piif-plan001-audit.log PIIF_MODEL_DIR=<weights dir> ./target/release/piifence-gateway`
   Wait until it prints `piifence gateway listening on http://127.0.0.1:7799` (20–60 s while the model loads).
3. `python3 -I plans/tools/measure_turns.py 7799 5`

**Verify**: the output contains `distinct renderings of message 1: 1`, and every turn line shows message 1 as `... to<private_email_1> and use token<secret_1> for the push.` (the missing space before the placeholder is a known separate issue; ignore it).

4. Stop the gateway. Then `rm -f /tmp/piifence-redacted-bodies.jsonl /tmp/piif-plan001-audit.log`.

### Step 6: Corpus still passes

**Verify**: `PIIF_MODEL_DIR=<weights dir> cargo run --release 2>&1 | tail -1` → `15/15 passed`.

### Step 7: Update the docs

1. `src/bin/gateway.rs` module doc (lines 9-10): after "spans become opaque numbered placeholders (`<private_email_1>`, `<secret_1>`, ...)", add "numbered once per value, so re-sent history is rewritten identically every turn".
2. `docs/gateway-spike.md:27-30`: replace "Placeholder counters are per process;" with "Each (category, value) pair gets one placeholder number for the life of the gateway process, so the history Claude Code re-sends every turn is rewritten byte-for-byte the same (provider prompt caching and thinking-block signatures depend on that). Values are keyed by a per-process keyed hash, never stored;".
3. `docs/gateway-spike.md:324-325`: replace that bullet with "Placeholder numbers are per gateway process: stable for as long as it runs, reset by a restart. A restart mid-session renumbers the history once (one prompt-cache miss)."
4. `docs/labels.md`, directly under the heading `## Placeholder mapping (M2 proposal)`: add one paragraph: "Not implemented as written. The gateway uses `<secret_N>` / `<{category}_N>`, numbered once per value through a per-process keyed hash (`Placeholders` in `src/bin/gateway.rs`). An unkeyed short hash of a low-entropy value such as an email can be reversed by guessing candidates, so it would leak the value."

**Verify**: `grep -n "keyed hash" docs/gateway-spike.md docs/labels.md src/bin/gateway.rs` → at least one match in each file.

## Test plan

- 5 new unit tests in `src/bin/gateway.rs` (step 4), modelled on the tests in `src/detect.rs:279-400`.
- End-to-end: `plans/tools/measure_turns.py` with 5 turns (step 5) shows one rendering of message 1.
- Regression: `cargo test --release` (all existing tests) and the corpus run (15/15).

## Done criteria

- [ ] `cargo build --release` exits 0 with no warnings from `src/bin/gateway.rs`
- [ ] `cargo test --release` exits 0; `cargo test --release --bin piifence-gateway` reports 5 passed
- [ ] `grep -n "counters" src/bin/gateway.rs` returns nothing
- [ ] `measure_turns.py 7799 5` prints `distinct renderings of message 1: 1`
- [ ] Corpus run ends with `15/15 passed`
- [ ] `git status` shows changes only in `src/bin/gateway.rs`, `docs/gateway-spike.md`, `docs/labels.md`, `plans/README.md`
- [ ] `plans/README.md` status row for 001 updated

## STOP conditions

Stop and report back if:
- The excerpts above do not match the live code (drift).
- `category_for` no longer returns `&'static str` (the `Placeholders` key type assumes it).
- After step 3, `measure_turns.py` still shows more than one rendering. The likely cause is that detection itself varies between turns. Report the differing lines; do not try to fix detection.
- The corpus drops below 15/15.
- Anything in `src/guards.rs` or `plugin/` seems to need changing.

## Maintenance notes

- Numbers are shared by every session using the same gateway process. That is fine: they only need to be stable, not to start at 1 per session.
- The map grows by one entry (about 40 bytes) per distinct value seen and is never pruned. That is acceptable for a developer-machine process. If gateways ever run for weeks, add a cap and accept one renumbering.
- Anything that makes detection non-deterministic across turns (for example a span found on turn 5 but not turn 4) still changes history. Plan 002's result cache makes repeat scans return the same spans.
- Reviewers: check that no code path stores or logs the raw value, and that `Placeholders` has no lookup from number to value.
