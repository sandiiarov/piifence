# Plan 002: Scan each text block once per gateway run, so long conversations stay fast

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving to the next step. If anything in the "STOP conditions" section occurs, stop and report — do not improvise. When done, update the status row for this plan in `plans/README.md` — unless a reviewer dispatched you and told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 39dd159..HEAD -- src/detect.rs src/bin/gateway.rs AGENTS.md docs/gateway-spike.md`
> Plan 001 is expected to have changed `src/bin/gateway.rs`, `docs/gateway-spike.md` and `docs/labels.md`; that is fine. Any change to `src/detect.rs` or `AGENTS.md` since `39dd159`: compare the "Current state" excerpts against the live code first. On a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S–M (about half a day)
- **Risk**: LOW
- **Depends on**: plans/001-stable-placeholders.md
- **Category**: perf
- **Planned at**: commit `39dd159`, 2026-10-30

## Why this matters

piifence is a local proxy that redacts secrets and personal data from Claude Code's requests before they reach the model provider. Claude Code re-sends the whole conversation on every turn, and the gateway runs detection on every text block of every request. Two things make re-scanning old blocks expensive:

1. The model-result cache in `src/detect.rs` holds 64 entries and is emptied completely when full. Once a conversation has more than about 64 blocks, every turn runs the model over the entire history again.
2. The gitleaks pre-pass is not cached at all. It starts one `gitleaks` process per block per request, about 20 ms each.

Measured at commit 39dd159, replaying a conversation with one new user message and one reply per turn (2 blocks per turn):

| Turn | Blocks | Time to redact the request |
|---|---|---|
| 3 | 5 | 90 ms |
| 33 | 65 | 1.6 s (cache hits; nearly all of it is gitleaks) |
| 34 | 67 | 13.8 s (cache emptied, model reran on everything) |
| 45 | 89 | 21 s |

Real Claude Code sessions add many blocks per turn through tool calls, so they reach this point within a few turns. After this plan, the final detection result (model + gitleaks + guards) for each exact text is cached. Least-recently-used entries are evicted one at a time under a byte budget, so each turn only scans the blocks that are new.

## Current state

Files:
- `src/detect.rs` — the shared detection pipeline (`Detector`): model inference, gitleaks pre-pass, guards, span merging. Used by the gateway and by the corpus harness `src/main.rs`.
- `src/bin/gateway.rs` — the gateway. It calls `detector.detect(&job.text)` on one worker thread (`gateway.rs:831-836`) and uses `detection.kept` only.
- `AGENTS.md` — contributor notes; line 71 describes the cache.

`src/detect.rs:28-46`:

```rust
#[derive(Debug, Default)]
pub struct Detection {
    pub kept: Vec<DetectedSpan>,
    pub suppressed: Vec<(DetectedSpan, Suppression)>,
}

pub struct Detector {
    engine: Option<PrivacyFilterInference<B>>,
    guards: Guards,
    use_gitleaks: bool,
    use_guards: bool,
    categories: Option<HashSet<String>>,
    /// Model output per exact text. Keyed on the full text, not a hash, so a hash
    /// collision cannot return another text's spans.
    cache: std::sync::Mutex<std::collections::HashMap<String, Vec<DetectedSpan>>>,
}

/// Entries kept in the model cache before it is cleared.
const CACHE_LIMIT: usize = 64;
```

`src/detect.rs:96-155` — `Detector::detect`. The model call sits inside the cache lookup; gitleaks and guards run on every call:

```rust
    pub fn detect(&self, text: &str) -> anyhow::Result<Detection> {
        let model_spans: Vec<DetectedSpan> = match &self.engine {
            Some(engine) => {
                let cached = {
                    let cache = self.cache.lock().unwrap();
                    cache.get(text).cloned()
                };
                match cached {
                    Some(spans) => spans,
                    None => {
                        let spans: Vec<DetectedSpan> = windowed(text, |chunk| { ... })?
                        .into_iter()
                        .map(|span| snap_to_char_boundaries(span, text))
                        .collect();
                        let mut cache = self.cache.lock().unwrap();
                        if cache.len() >= CACHE_LIMIT {
                            cache.clear();
                        }
                        cache.insert(text.to_string(), spans.clone());
                        spans
                    }
                }
            }
            None => Vec::new(),
        };

        let pre_spans = if self.use_gitleaks && self.category_enabled("secret") {
            gitleaks_spans(text)?
        } else {
            Vec::new()
        };

        let (model_kept, suppressed, pre_kept) = if self.use_guards { ... } else { ... };

        Ok(Detection {
            kept: merge_spans(model_kept, pre_kept),
            suppressed,
        })
    }
```

`src/detect.rs:79` — in `load_with_categories`: `cache: std::sync::Mutex::new(std::collections::HashMap::new()),`.

Facts that make caching the final result safe:
- Everything `detect` depends on besides `text` is fixed for the life of a `Detector`: the model, `categories`, `use_gitleaks`, `use_guards`, the guards, and the gitleaks config (read once from env/cwd). So the same text always gives the same `Detection`.
- The gateway passes context-prefixed text for tool results (`"Tool call: …\nTool output:\n" + text`, `gateway.rs:279-283`), so the cache key already includes the context.
- Keep the existing decision recorded in the comment above: keys are the full text, not a hash, because a hash collision would return another text's spans and could forward a secret raw.

Conventions: env switches are read where they are used and named `PIIF_*` (precedent: `src/gitleaks.rs:30` reads `PIIF_GITLEAKS_CONFIG`). Doc comments explain why. Unit tests are in `#[cfg(test)] mod tests` at `src/detect.rs:279`; match their style (a helper like `span(...)`, descriptive snake_case test names).

## Commands you will need

| Purpose | Command (run from repo root) | Expected on success |
|---|---|---|
| Build | `cargo build --release` | exit 0 |
| Unit tests | `cargo test --release` | all pass |
| Library tests only | `cargo test --release --lib` | all pass |
| Corpus (needs model weights) | `PIIF_MODEL_DIR=<weights dir> cargo run --release` | ends with `15/15 passed` |

Model weights: if `data/config.json` does not exist, ask the operator for the weights directory (on the planning machine it is `/Users/alexs/piifence-trial/src/data`). gitleaks must be on PATH.

## Scope

**In scope**:
- `src/detect.rs`
- `src/bin/gateway.rs` — module doc env list only (step 5)
- `AGENTS.md` — line 71 only

**Out of scope** (do NOT touch):
- `windowed`, `merge_spans`, `snap_to_char_boundaries`, `gitleaks_spans` — the detection logic stays exactly as is; only caching changes.
- `src/gitleaks.rs` — replacing the per-block process (e.g. with an in-process rules crate) is a separate decision.
- Placeholder numbering in `src/bin/gateway.rs` — that is plan 001.
- Adding new crates to `Cargo.toml`. The cache is about 60 lines with `std` only.

## Git workflow

- Branch: `fix/detection-cache` from `main` (after plan 001 is merged), or stacked on `fix/stable-placeholders`.
- Commit messages: imperative summary of 60 characters or less, blank line, one bullet per change, trailer `Co-authored-by: Claude <noreply@anthropic.com>`. Example from `git log`: "Window long model input and keep secret spans whole".
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Make `Detection` cloneable

Change `#[derive(Debug, Default)]` on `pub struct Detection` to `#[derive(Debug, Default, Clone)]`. `DetectedSpan` and `Suppression` already derive `Clone`.

**Verify**: `cargo build --release` → exit 0.

### Step 2: Add a byte-bounded LRU cache type

Add to `src/detect.rs`, after `impl Detector { ... }`:

```rust
/// Final detection results per exact text, bounded by the total bytes of cached text.
/// The least recently used entry is evicted first, so a long conversation keeps its
/// history cached instead of thrashing. Keyed on the full text, not a hash, so a hash
/// collision cannot return another text's spans.
struct DetectionCache {
    entries: std::collections::HashMap<String, (Detection, u64)>,
    bytes: usize,
    limit_bytes: usize,
    tick: u64,
}

impl DetectionCache {
    fn new(limit_bytes: usize) -> Self { ... }

    /// A copy of the cached detection, marking it most recently used.
    fn get(&mut self, text: &str) -> Option<Detection> { ... }

    /// Cache `detection` for `text`, evicting least recently used entries until it
    /// fits. A text larger than the whole budget is not cached.
    fn insert(&mut self, text: String, detection: Detection) { ... }
}
```

Implementation requirements:
- `tick` increases by 1 on every `get` hit and every `insert`; the entry stores the tick of its last use.
- `bytes` is the sum of `text.len()` over all keys. Count only key bytes; span vectors are small.
- `insert` of a key that already exists replaces it without double-counting its bytes.
- Eviction: while `bytes + text.len() > limit_bytes` and the map is not empty, remove the entry with the smallest tick. A linear scan for the minimum is fine: it only runs when the cache is full, and it is negligible next to a model call.
- If `text.len() > limit_bytes`, return without caching.

Add the budget function next to it:

```rust
/// Cache budget in bytes of text: `PIIF_CACHE_MB` (default 64). A Claude Code
/// session is a few MB of text, so the default holds several full sessions.
fn cache_limit_bytes() -> usize {
    std::env::var("PIIF_CACHE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(64)
        .saturating_mul(1024 * 1024)
}
```

**Verify**: `cargo build --release` → exit 0 (unused warnings are expected until step 3).

### Step 3: Cache the final `Detection` in `Detector::detect`

1. Change the `cache` field of `Detector` to `cache: std::sync::Mutex<DetectionCache>,` and remove its old doc comment (the new type carries it). Initialise it in `load_with_categories` with `std::sync::Mutex::new(DetectionCache::new(cache_limit_bytes()))`.
2. Delete `const CACHE_LIMIT` and its doc comment.
3. Restructure `detect`:
   - At the top: `if let Some(hit) = self.cache.lock().unwrap().get(text) { return Ok(hit); }`
   - The model step becomes the plain computation that is in the `None =>` arm today (call `windowed`, then `snap_to_char_boundaries`), with no cache access inside it. Keep `None => Vec::new()` for when there is no engine.
   - The gitleaks, guards and `merge_spans` code stays unchanged, except that the result goes into a local `let detection = Detection { kept: …, suppressed };`.
   - At the end: `self.cache.lock().unwrap().insert(text.to_string(), detection.clone()); Ok(detection)`.
   - Errors from `windowed` or `gitleaks_spans` must propagate with `?` before anything is cached. Never cache a failed or partial result.

**Verify**: `cargo build --release` → exit 0 with no warnings from `src/detect.rs`. `grep -n "CACHE_LIMIT" src/` → no matches.

### Step 4: Unit tests for `DetectionCache`

Add to the existing `mod tests` in `src/detect.rs` (no model needed). Build a small `Detection` with the existing `span(...)` helper, e.g. `Detection { kept: vec![span("secret", 0, 3, "model")], suppressed: vec![] }`.

1. `cache_returns_what_was_inserted`: insert "abc", `get("abc")` returns a detection with one kept span labelled "secret"; `get("zzz")` returns `None`.
2. `cache_evicts_least_recently_used_first`: limit 10 bytes. Insert "aaaa" and "bbbb" (8 bytes), `get("aaaa")`, then insert "cccc". Expect "bbbb" evicted; "aaaa" and "cccc" present.
3. `cache_skips_text_larger_than_budget`: limit 4, insert "abcdef", `get` returns `None`.
4. `cache_reinsert_does_not_double_count`: limit 8, insert "aaaa" twice, then insert "bbbb". Both present.

**Verify**: `cargo test --release --lib` → all pass, including the 4 new tests.

### Step 5: Docs

1. `AGENTS.md:71`: replace "inference results are cached per text block (<=256 entries) whenever it runs" with "final detection results (model + gitleaks + guards) are cached per exact text in a least-recently-used cache bounded by `PIIF_CACHE_MB` (default 64 MB of text), so re-sent history is not re-scanned".
2. `src/bin/gateway.rs` module doc, the `Env:` paragraph (lines 21-23): add `PIIF_CACHE_MB (64, detection cache budget)`.

**Verify**: `grep -n "PIIF_CACHE_MB" AGENTS.md src/bin/gateway.rs src/detect.rs` → at least one match in each file.

### Step 6: End-to-end measurement

1. `cargo build --release`
2. `rm -f /tmp/piifence-redacted-bodies.jsonl`
3. Start a test gateway from the repo root, in the background or a separate terminal:
   `PIIF_UPSTREAM=http://127.0.0.1:9 PIIF_PORT=7799 PIIF_AUDIT_BODY=1 PIIF_AUDIT_LOG=/tmp/piif-plan002-audit.log PIIF_MODEL_DIR=<weights dir> ./target/release/piifence-gateway`
   Wait for `piifence gateway listening on http://127.0.0.1:7799`.
4. `python3 -I plans/tools/measure_turns.py 7799 45 | tail -3`

**Verify**: `max turn ms` is below 1500 and `last turn ms` is below 500. Before this plan they were about 21000 and 21000. If plan 001 is merged, `distinct renderings of message 1: 1` must also hold.

5. Stop the gateway. Then `rm -f /tmp/piifence-redacted-bodies.jsonl /tmp/piif-plan002-audit.log`.

### Step 7: Corpus still passes

**Verify**: `PIIF_MODEL_DIR=<weights dir> cargo run --release 2>&1 | tail -1` → `15/15 passed`.

## Test plan

- 4 new unit tests for `DetectionCache` in `src/detect.rs` (step 4), following the existing tests in the same module.
- Performance regression check with `plans/tools/measure_turns.py` at 45 turns (step 6).
- Behaviour regression: the corpus (15/15) and all existing unit tests.

## Done criteria

- [ ] `cargo build --release` exits 0 with no warnings from `src/detect.rs`
- [ ] `cargo test --release` exits 0, including the 4 new cache tests
- [ ] `grep -rn "CACHE_LIMIT" src/` returns nothing
- [ ] `measure_turns.py 7799 45` reports `max turn ms` < 1500 and `last turn ms` < 500
- [ ] Corpus run ends with `15/15 passed`
- [ ] `git status` shows changes only in `src/detect.rs`, `src/bin/gateway.rs`, `AGENTS.md`, `plans/README.md`
- [ ] `plans/README.md` status row for 002 updated

## STOP conditions

Stop and report back if:
- `Detector::detect` no longer matches the excerpt (drift).
- `detect` turns out to depend on anything that can change during the process's life (for example a config reloaded per call). The cache would then return stale results.
- The 45-turn measurement still exceeds the thresholds. Report the per-turn times; do not tune other code.
- The corpus drops below 15/15, or an existing unit test fails.
- The work seems to need a new crate or changes to `src/gitleaks.rs`.

## Maintenance notes

- Any future per-request input to detection (per-session categories, a reloadable config, a "Send raw" flag passed into `detect`) must become part of the cache key or clear the cache. Otherwise stale results are returned.
- The cache holds raw text in process memory for as long as entries live. The old cache already did this, so it is not new exposure. Keep the budget modest; do not persist the cache to disk.
- Brand-new blocks still pay the full cost, about 20 ms of gitleaks per block plus the model. A large new tool result (hundreds of KB) can still take seconds. Running gitleaks in-process (for example the `kingfisher-scanner` crate, Apache-2.0) or once per request is the next step if that matters.
- Reviewers: check that nothing is cached on an error path and that `detect` returns exactly what it returned before for an uncached text.
