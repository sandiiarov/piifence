# Plan 008: Make the redaction notice report only values redacted for the first time

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat efdd25e..HEAD -- src/bin/gateway.rs plugin/piifence-notice tests/secrets/README.md docs/gateway-spike.md AGENTS.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition. Plans 004 and 005 change other
> parts of `src/bin/gateway.rs`; the excerpts below (`Stats`, `Placeholders`,
> `next_placeholder`, `record_stats`, the `/stats` handler and the
> placeholder loop) must still match, allowing for a renamed span vector in
> the loop.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW (counters and a hook script; no change to what is redacted)
- **Depends on**: plans/005-span-normalization-and-gitleaks-location.md (both edit the placeholder loop in `redact_text_with_context`; land 005 first to avoid a merge conflict)
- **Category**: bug
- **Planned at**: commit `efdd25e`, 2026-10-30

## Why this matters

Claude Code re-sends the whole conversation on every turn, so the gateway re-redacts every historical value every turn and its `redactions` counter grows by the size of the history each time. The notice hook computes "new = total − previous" from that counter, so once anything has been redacted, every later turn ends with "piifence: redacted N value(s)" listing the same placeholders again. Users learn to ignore the notice, which defeats its purpose: telling them a *new* value just left their machine as a placeholder. Since plan 001, the gateway already knows whether a placeholder number was assigned for the first time; exposing that makes the notice exact.

## Current state

Files:

- `src/bin/gateway.rs` — `Stats` (lines 48–58), `Placeholders::number_for` (150–160), `next_placeholder` (163–171), `record_stats` (179–195), the placeholder loop in `redact_text_with_context` (340–361), the `/stats` handler (582–599), unit tests for `Placeholders` (901–942).
- `plugin/piifence-notice/scripts/notice.py` — the hook script (97 lines). Runs on `SessionStart` and `Stop` (`plugin/piifence-notice/hooks/hooks.json`). Reads `/stats`, keeps the last seen count in `/tmp/piifence-notice-state.json`.
- `plugin/piifence-notice/README.md:34-47`, `docs/gateway-spike.md:107-125`, `AGENTS.md:102-104` — describe the notice; update them.
- `tests/secrets/run.py` — has reusable `Sink` (fake upstream), `Gateway` (starts `target/release/piifence-gateway` with a per-mode config) and `post` helpers; importing it is safe (its `main()` is under `if __name__ == "__main__"`).

`src/bin/gateway.rs:48-58`:

```rust
#[derive(Default)]
struct Stats {
    requests: usize,
    redactions: usize,
    allowed: usize,
    by_label: BTreeMap<String, usize>,
    recent: VecDeque<Value>,
    redact_ms_total: f64,
    redact_ms_last: f64,
    redact_ms_max: f64,
}
```

`src/bin/gateway.rs:150-171`:

```rust
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

`src/bin/gateway.rs:179-195`:

```rust
fn record_stats(state: &AppState, audit: &[Value], redact_ms: f64) {
    let mut stats = state.stats.lock().unwrap();
    stats.requests += 1;
    stats.redactions += audit.len();
    stats.redact_ms_total += redact_ms;
    stats.redact_ms_last = redact_ms;
    stats.redact_ms_max = stats.redact_ms_max.max(redact_ms);
    for entry in audit {
        if let Some(label) = entry.get("label").and_then(|v| v.as_str()) {
            *stats.by_label.entry(label.to_string()).or_insert(0) += 1;
        }
        stats.recent.push_back(entry.clone());
        while stats.recent.len() > 20 {
            stats.recent.pop_front();
        }
    }
}
```

The placeholder loop, `src/bin/gateway.rs:340-361` (after plan 005 the vector may no longer be called `accepted`; the structure is the same):

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
            "field": field,
            "label": span.label,
            "score": (span.score * 1000.0).round() / 1000.0,
            "start": span.start,
            "end": span.end,
            "placeholder": token,
            "preview": preview,
            "engine": span.source.split(':').next().unwrap_or(""),
        }));
    }
```

The `/stats` handler, `src/bin/gateway.rs:582-593`:

```rust
    if path == "/stats" {
        let stats = state.stats.lock().unwrap();
        let body = json!({
            "requests": stats.requests,
            "redactions": stats.redactions,
            "allowed": stats.allowed,
            "redact_ms_last": (stats.redact_ms_last * 100.0).round() / 100.0,
            "redact_ms_total": (stats.redact_ms_total * 100.0).round() / 100.0,
            "redact_ms_max": (stats.redact_ms_max * 100.0).round() / 100.0,
            "by_label": stats.by_label,
            "recent": stats.recent.iter().cloned().collect::<Vec<_>>(),
        });
```

`plugin/piifence-notice/scripts/notice.py:61-93`:

```python
    total = int(stats.get("redactions", 0))
    previous = int(load_state().get("redactions", 0))

    if hook == "SessionStart":
        save_state(total)
        if total:
            emit({"systemMessage": f"piifence: active — {total} value(s) redacted so far"})
        emit({"systemMessage": "piifence: active — input redaction on (nothing redacted yet)"})

    new = total - previous
    if new <= 0:
        if new < 0:
            # The gateway restarted, so its counter started over. Resync, or the
            # notices stay silent until the new count passes the old one.
            save_state(total)
        emit({})

    recent = stats.get("recent", [])[-new:]
    counts = {}
    samples = []
    for item in recent:
        label = item.get("label", "unknown")
        counts[label] = counts.get(label, 0) + 1
        placeholder = item.get("placeholder", "")
        preview = item.get("preview", "")
        if placeholder and preview:
            samples.append(f"{placeholder} {preview}")
        elif placeholder:
            samples.append(placeholder)
    breakdown = ", ".join(f"{label}×{n}" for label, n in sorted(counts.items()))
    sample = f" ({', '.join(samples[:4])})" if samples else ""
    save_state(total)
    emit({"systemMessage": f"piifence: redacted {new} value(s) — {breakdown}{sample}"})
```

Existing `Placeholders` tests, `src/bin/gateway.rs:905-910` (pattern for the test changes):

```rust
    #[test]
    fn same_value_keeps_its_number() {
        let mut p = Placeholders::default();
        assert_eq!(p.number_for("secret", "abc"), 1);
        assert_eq!(p.number_for("secret", "abc"), 1);
    }
```

Constraints to keep (`AGENTS.md:102-104`, `116-117`): `/stats` exposes "redaction counts and recent placeholder metadata only — including a masked first4+last4 `preview` for notice verification, never the raw value"; the notice plugin "must stay metadata-only, silent when the gateway is absent, and never read raw values". The approval mod (`plugin/piifence-approval`) does not read `/stats`; the launcher reads only `/health`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Build | `cargo build --release` | exit 0 |
| Unit tests | `cargo test --release` | exit 0 |
| Stats smoke test (new, Step 5) | `python3 -I tests/secrets/stats_check.py` | `stats ok`, exit 0 |
| Rules-only suite | `python3 -I tests/secrets/run.py --mode secret-rules` | exit 0 |
| Hook script by hand | `echo '{"hook_event_name":"Stop"}' \| PIIF_GATEWAY_URL=http://127.0.0.1:<port> PIIF_NOTICE_STATE=/tmp/piif-008-state.json python3 -I plugin/piifence-notice/scripts/notice.py` | a JSON line |

## Scope

**In scope** (the only files you should modify):
- `src/bin/gateway.rs`
- `plugin/piifence-notice/scripts/notice.py`
- `plugin/piifence-notice/README.md`
- `tests/secrets/stats_check.py` (create), `tests/secrets/README.md` (one line)
- `docs/gateway-spike.md`, `AGENTS.md` (notice and `/stats` lines)
- `plans/README.md` (status row)

**Out of scope** (do NOT touch, even though they look related):
- `plugin/piifence-approval/` — it does not use `/stats`.
- The audit log format beyond adding one boolean field (`new`) to each span entry.
- `src/detect.rs` — the detection cache is unrelated; the counting fix is in the gateway.
- `/tmp` state-file location (tracked separately in `plans/README.md`).
- `src/main.rs`, `tests/corpus-secrets.json` — owner's uncommitted work.

## Git workflow

- Branch: `fix/notice-reports-new-values` from `main`.
- One commit per step. Message style: summary of at most 60 characters, blank line, bullets, trailer `Co-authored-by: Claude <noreply@anthropic.com>` (see `git log --oneline -8`).
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Report first sight from the placeholder table

Change `Placeholders::number_for` to return `(usize, bool)`: `(existing, false)` when the key is already assigned, `(next, true)` when it is assigned now. Update the doc comment. Update the five existing tests to the tuple form, for example:

```rust
        assert_eq!(p.number_for("secret", "abc"), (1, true));
        assert_eq!(p.number_for("secret", "abc"), (1, false));
```

Change `next_placeholder` to return `(String, bool)` and pass the flag through.

**Verify**: `cargo test --release placeholders` (or run the five test names) → pass; `cargo build --release` → exit 0 after Step 2 (Step 1 alone will not compile until the caller is updated; do Steps 1 and 2 before building).

### Step 2: Record the flag in the audit entry

In the placeholder loop, make `tokens` a `Vec<(String, bool)>`, replace with `&token.0`, and add `"new": token.1` to the `json!` audit entry (after `"placeholder"`). Nothing else in the entry changes.

**Verify**: `cargo build --release` → exit 0; `cargo test --release` → pass.

### Step 3: Count distinct values and keep only new entries in `recent`

Add `values: usize` to `Stats` (distinct placeholders assigned since the gateway started). Move the body of `record_stats` into a method so it can be unit-tested without an `AppState`:

```rust
impl Stats {
    /// Fold one request's audit entries in. `redactions` counts every replaced
    /// span (history is re-sent every turn, so it grows fast); `values` counts a
    /// value only the first time it gets a placeholder, and `recent` keeps only
    /// those first sightings so the notice can show what is new.
    fn record(&mut self, audit: &[Value], redact_ms: f64) { ... }
}

fn record_stats(state: &AppState, audit: &[Value], redact_ms: f64) {
    state.stats.lock().unwrap().record(audit, redact_ms);
}
```

Inside `record`: keep `requests`, `redactions`, the three timings and `by_label` exactly as today; for entries where `entry.get("new").and_then(Value::as_bool) == Some(true)`, increment `values` and push to `recent` (cap 20). Entries without the flag or with `false` are not pushed.

Add `"values": stats.values` to the `/stats` JSON.

Add tests in `mod tests`:

- `record_counts_a_value_once`: two entries, `{"label":"secret","placeholder":"<secret_1>","new":true}` and the same with `"new":false` → `values == 1`, `redactions == 2`, `recent.len() == 1`, `by_label["secret"] == 2`.
- `recent_keeps_the_last_twenty_new_entries`: 25 entries all `new: true` with placeholders `<secret_1>` to `<secret_25>` → `values == 25`, `recent.len() == 20`, first `recent` placeholder is `<secret_6>`.

**Verify**: `cargo test --release record` → the two tests pass; `cargo test --release` → all pass.

### Step 4: Make the hook count values

In `notice.py`:

- `total = int(stats.get("values", stats.get("redactions", 0)))` (fallback keeps it working against an older gateway).
- Store and read the state under the key `values` (replace both `"redactions"` uses in `save_state`/`load_state` call sites; keep the file name).
- The SessionStart message keeps its wording; `total` now means distinct values.
- `recent[-new:]` stays: `recent` now contains only first sightings, so the slice is exactly the new ones (when `new` exceeds 20 the list is capped and the count in the message still says `new`).
- Update the module docstring (lines 2–6) to say "how many distinct values".

**Verify**: `python3 -I -m py_compile plugin/piifence-notice/scripts/notice.py` → exit 0.

### Step 5: Add an end-to-end stats check that needs no weights

Create `tests/secrets/stats_check.py`:

```python
"""Check that /stats counts a value once and the notice fires only for new values.
Starts the real gateway in secret-rules mode (no weights) against the suite's fake
upstream, sends the same prompt twice, then runs notice.py against it.

  python3 -I tests/secrets/stats_check.py      -> prints "stats ok", exit 0
"""
import json, os, subprocess, sys, tempfile, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__)); REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import contexts, formats, run  # noqa: E402

def stats(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=5) as r:
        return json.loads(r.read())

def notice(port, state_file, hook="Stop"):
    env = dict(os.environ, PIIF_GATEWAY_URL=f"http://127.0.0.1:{port}", PIIF_NOTICE_STATE=state_file)
    out = subprocess.run([sys.executable, "-I", os.path.join(REPO, "plugin/piifence-notice/scripts/notice.py")],
                         input=json.dumps({"hook_event_name": hook}).encode(), capture_output=True, env=env, check=True)
    return json.loads(out.stdout or b"{}")

def main():
    sink = run.Sink()
    with tempfile.TemporaryDirectory(prefix="piif-stats-") as tmp:
        gw = run.Gateway("secret-rules", "/nonexistent", sink.port, tmp)
        try:
            path, body, _ = contexts.prompt_text(formats.BY_ID["aws_access_key_id"].generate)
            state = os.path.join(tmp, "state.json")
            assert notice(gw.port, state, "SessionStart")["systemMessage"].startswith("piifence: active")
            assert run.post(gw.port, path, body, "one") == 200
            s = stats(gw.port)
            assert s["values"] == 1 and s["redactions"] == 1 and len(s["recent"]) == 1, s
            msg = notice(gw.port, state)["systemMessage"]
            assert "redacted 1 value(s)" in msg and "secret×1" in msg, msg
            assert run.post(gw.port, path, body, "two") == 200
            s = stats(gw.port)
            assert s["values"] == 1 and s["redactions"] == 2 and len(s["recent"]) == 1, s
            assert notice(gw.port, state) == {}, "second turn must be silent"
        finally:
            gw.stop(); sink.close()
    print("stats ok")

if __name__ == "__main__":
    main()
```

Add one line to `tests/secrets/README.md` under "Running it": `python3 -I tests/secrets/stats_check.py   # /stats counters and the notice, no weights`.

**Verify**: `cargo build --release && python3 -I tests/secrets/stats_check.py` → `stats ok`, exit 0. (The upstream is a fake that returns an empty message, which is enough for the gateway to count.)

### Step 6: Update the docs

- `plugin/piifence-notice/README.md:34-47`: "Stop (after a turn in which a value was redacted for the first time)"; state section: "stores the number of distinct values seen".
- `docs/gateway-spike.md:107-112` and `123-125`: same wording; mention the `values` counter and that `recent` holds first sightings.
- `AGENTS.md:102-104`: `/stats` exposes redaction counts, a `values` counter of distinct placeholders, and recent first-sighting metadata.

**Verify**: `grep -n "values" plugin/piifence-notice/README.md docs/gateway-spike.md AGENTS.md | grep -ic "distinct\|first"` → at least `3`.

## Test plan

- Unit: five updated `Placeholders` tests plus `record_counts_a_value_once` and `recent_keeps_the_last_twenty_new_entries` in `src/bin/gateway.rs`.
- End to end: `tests/secrets/stats_check.py` drives the real gateway and the real hook script, no weights.
- Regression: `python3 -I tests/secrets/run.py --mode secret-rules` still exits 0 (the audit entry gained a field; nothing else changed).

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo test --release` exits 0 and includes the two new `record_*` tests
- [ ] `python3 -I tests/secrets/stats_check.py` prints `stats ok` and exits 0
- [ ] `grep -c '"values"' src/bin/gateway.rs` → at least `1`; `grep -c '"new"' src/bin/gateway.rs` → at least `2`
- [ ] `grep -c "redactions" plugin/piifence-notice/scripts/notice.py` → `1` (only the fallback read remains)
- [ ] `python3 -I tests/secrets/run.py --mode secret-rules` exits 0
- [ ] `git status` shows no modified files outside the in-scope list
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- The excerpts in "Current state" do not match (apart from the span vector's name in the loop).
- `stats_check.py` fails because the gateway refuses to start in `secret-rules` mode without weights: that means plan 004's Step 1 behaviour is not what the gateway does; report the gateway log from the temp dir.
- Any raw value (not a masked preview) appears in `/stats` output or the notice text while testing.
- `redactions` would have to change meaning to make the notice work; it must keep counting every replaced span.

## Maintenance notes

- `values` is the number the notice should always use; `redactions` stays for throughput measurement (`tools`/measurement scripts and the audit log).
- `recent` now means "recent first sightings". Anything else that wants "recent spans" must read the audit log instead.
- A gateway restart resets `values`; the hook's existing negative-delta resync handles that.
- Deferred: the state file lives in `/tmp` and is shared by every session on the machine; two concurrent `piifence claude` sessions against one gateway would under-report. Tracked in `plans/README.md`.
