# Plan 005: Redact every copy of a gitleaks finding and the full extent of overlapping spans

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat efdd25e..HEAD -- src/gitleaks.rs src/detect.rs src/bin/gateway.rs tests/secrets/expectations.json tests/secrets/contexts.py docs/gateway-spike.md AGENTS.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition. Plan 004 is expected to have
> changed `src/bin/gateway.rs` around `redact_content`; that is fine as long
> as `redact_text_with_context` (lines 301–363) still matches the excerpt.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (changes which bytes get replaced; the secret suite and unit tests are the net)
- **Depends on**: plans/004-walk-every-content-block.md (only so the suite's gap diff stays readable; the code changes are independent)
- **Category**: security
- **Planned at**: commit `efdd25e`, 2026-10-30

## Why this matters

Four separate defects in how spans become placeholders each let part of a secret through, and all four live in the same two functions. (1) A gitleaks finding is located with `text.find`, so only the first copy of a repeated secret is redacted; the second copy in a `retry` log or a diff goes raw whenever the model does not also catch it. The suite records 11 such gaps in rules-only mode. (2) gitleaks decodes base64 by default and reports the decoded value as `Secret`, which never appears in the text, so the whole finding is dropped. (3) When two spans overlap, the gateway keeps the one that starts later and drops the one that covers it, so a model span that contains a gitleaks span is thrown away and the uncovered part stays visible. (4) A model span that starts inside the tool-call context prefix but ends inside the output is discarded rather than clamped. Fixing these in one pass, plus trimming the whitespace the model likes to include, makes the placeholder cover exactly the credential and every copy of it.

## Current state

Files:

- `src/gitleaks.rs` — runs `gitleaks stdin` per text block and turns the JSON report into byte ranges. `Finding` (lines 15–25) deserialises only `RuleID`, `Secret`, `StartColumn`, `EndColumn`; `locate` (lines 91–101) maps a finding to a range.
- `src/detect.rs` — `gitleaks_spans` (lines 512–528) turns findings into `DetectedSpan`s; `merge_spans` (lines 298–331) unions gitleaks spans with model spans; the `tests` module starts at line 333 (helper `span(label, start, end, source)` at line 337).
- `src/bin/gateway.rs` — `redact_text_with_context` (lines 301–363) filters spans to the text region, picks a non-overlapping set, and replaces right to left.
- `tests/secrets/expectations.json` — known gaps; 11 entries read "gitleaks findings are located with text.find, so copies after the first stay raw without the model" and 2 read "model spans swallow the newline and the next line's label between PEM copies".
- `docs/gateway-spike.md:73-79` and `AGENTS.md:62-65` describe span precedence; update them in the last step.

`src/gitleaks.rs:15-25` and `91-101` today:

```rust
#[derive(Debug, Deserialize)]
pub struct Finding {
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    #[serde(rename = "Secret")]
    pub secret: String,
    #[serde(rename = "StartColumn", default)]
    pub start_column: usize,
    #[serde(rename = "EndColumn", default)]
    pub end_column: usize,
}
...
/// Resolve a finding to a byte range in `text`.
///
/// gitleaks reports 1-based `StartColumn` and 0-based-exclusive `EndColumn` for
/// single-line findings; this is validated against the reported secret and
/// falls back to a literal search when columns are absent or disagree.
pub fn locate(finding: &Finding, text: &str) -> Option<(usize, usize)> {
    if finding.start_column > 0 && finding.end_column > finding.start_column {
        let start = finding.start_column - 1;
        let end = finding.end_column;
        if end <= text.len() && text.get(start..end) == Some(finding.secret.as_str()) {
            return Some((start, end));
        }
    }
    text.find(finding.secret.as_str())
        .map(|start| (start, start + finding.secret.len()))
}
```

`src/detect.rs:512-528`:

```rust
fn gitleaks_spans(text: &str) -> anyhow::Result<Vec<DetectedSpan>> {
    let findings = gitleaks::scan(text)?;
    let mut spans = Vec::new();
    for finding in &findings {
        if let Some((start, end)) = gitleaks::locate(finding, text) {
            spans.push(DetectedSpan {
                label: "secret".to_string(),
                score: 1.0,
                word: text[start..end].to_string(),
                start,
                end,
                source: format!("gitleaks:{}", finding.rule_id),
            });
        }
    }
    Ok(spans)
}
```

`src/bin/gateway.rs:301-363`:

```rust
async fn redact_text_with_context(
    state: &AppState,
    text: &str,
    field: &str,
    context: Option<&str>,
) -> anyhow::Result<(String, Vec<Value>)> {
    let (input, offset) = match context {
        Some(context) if !context.is_empty() => {
            (format!("{context}\n{text}"), context.len() + 1)
        }
        _ => (text.to_string(), 0),
    };
    let kept = detect_kept(state, &input).await?;
    let mut spans: Vec<DetectedSpan> = kept
        .into_iter()
        .filter(|span| span.start >= offset && span.end <= input.len())
        .map(|mut span| {
            span.start -= offset;
            span.end -= offset;
            span
        })
        .collect();
    if spans.is_empty() {
        return Ok((text.to_string(), Vec::new()));
    }

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
    Ok((out, audit))
}
```

`DetectedSpan` (`src/detect.rs:17-26`) has `label`, `score`, `word`, `start`, `end`, `source`. `merge_spans` (`src/detect.rs:298-331`) already unions a gitleaks span with every model span it overlaps; it does not union two model spans with each other, and it is not what drops covering spans (that is the greedy loop above).

Measured gitleaks 8.30.1 behaviour on `gitleaks stdin` (measure it again in Step 1 before relying on it):

- `StartLine` is 1-based. `StartColumn` is 1-based on line 1; on lines 2 and later it is one larger than that (the newline before the line is counted), so the in-line byte offset is `StartColumn - 1` on line 1 and `StartColumn - 2` afterwards. `EndColumn` equals `StartColumn + len(Secret) - 1`.
- The same secret repeated on three lines gives three findings, one per line. Two copies on one line give one finding.
- With the default `--max-decode-depth` (5), a base64-encoded credential produces a finding whose `Tags` contains `decoded:base64`, whose `Secret` is the decoded value, and whose columns point at the encoded segment in the original line. Both the raw and decoded findings can be present.
- Columns count bytes, not characters; a non-ASCII character earlier on the same line shifts them by its extra bytes.

Conventions: doc comments explain why; unit tests in `#[cfg(test)] mod tests` at the bottom of each file (`src/detect.rs:333`, `src/bin/gateway.rs:901`), plain `#[test]` functions with snake_case names and `assert_eq!`. `src/gitleaks.rs` has no tests yet; add a `mod tests` at the bottom in the same style. Keep the gateway "fail closed" rule (`AGENTS.md:100`): an error from detection blocks the request; it never forwards unredacted text.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Build | `cargo build --release` | exit 0 |
| Unit tests | `cargo test --release` | exit 0 |
| Rules-only suite (no model) | `python3 -I tests/secrets/run.py --mode secret-rules` | exit 0 |
| Full suite | `python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data` | exit 0; about 25 minutes |
| M1 corpus gate | `cargo run --release 2>&1 \| tail -3` with `PIIF_MODEL_DIR=/Users/alexs/piifence-trial/src/data` | `15/15`, exit 0 |
| Repo stays secret-free | `gitleaks dir tests/secrets --no-banner` | no leaks |

Weights on this machine: `/Users/alexs/piifence-trial/src/data`. Elsewhere, `scripts/fetch-weights.sh`.

## Scope

**In scope** (the only files you should modify):
- `src/gitleaks.rs`
- `src/detect.rs` (`gitleaks_spans` and tests only)
- `src/bin/gateway.rs` (`redact_text_with_context` and tests only)
- `tests/secrets/contexts.py` (one new context), `tests/secrets/expectations.json` (via `--record-gaps`)
- `docs/gateway-spike.md`, `AGENTS.md` (contract lines)
- `plans/README.md` (status row)

**Out of scope** (do NOT touch, even though they look related):
- `gitleaks.toml` and the gitleaks command line in `scan` (`src/gitleaks.rs:39-84`): do not add `--max-decode-depth`, `--ignore-gitleaks-allow` or other flags here; rule changes are plan 006.
- `merge_spans` in `src/detect.rs` — its union logic is correct; the covering-span bug is in the gateway.
- `Placeholders::number_for` and `next_placeholder` (`src/bin/gateway.rs:140-171`).
- The detection cache (`src/detect.rs:155-205`).
- `src/main.rs`, `tests/corpus-secrets.json` — the repository owner has uncommitted work there.

## Git workflow

- Branch: `fix/span-normalization` from `main`.
- One commit per step. Message style: summary of at most 60 characters, blank line, bullets, trailer `Co-authored-by: Claude <noreply@anthropic.com>` (see `git log --oneline -8`).
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Re-measure gitleaks column semantics

Write a throwaway script outside the repo (for example `/tmp/piif-plan-005/probe.py`; never commit it) that generates a value with the suite's own generator so no secret-shaped literal is written anywhere:

```python
import json, subprocess, sys
sys.path.insert(0, "tests/secrets")
import formats
g = formats.BY_ID["aws_access_key_id"].generate("probe")
def scan(text):
    out = subprocess.run(["gitleaks", "stdin", "--report-format", "json", "--report-path", "-",
                          "--exit-code", "0", "--no-banner", "--no-color", "-c", "gitleaks.toml"],
                         input=text.encode(), capture_output=True)
    raw = out.stdout.decode().strip()
    return json.loads(raw) if raw and raw != "null" else []
h = formats.BY_ID["hex32_with_keyword"].generate("probe")  # generic-api-key: capture group narrower than the match
for label, text in [("line1", g.line + "\n"),
                    ("line3 after non-ascii", "first\nsecond ünïcode\n" + g.line + "\n"),
                    ("three copies", "\n".join(f"retry {i}: {g.full}" for i in (1, 2, 3)) + "\n"),
                    ("two on one line", g.full + " and " + g.full + "\n"),
                    ("capture group on line 2", "first\n" + h.line + "\n")]:
    for f in scan(text):
        line_start = sum(len(l) + 1 for l in text.split("\n")[: f["StartLine"] - 1])
        print(label, {k: f[k] for k in ("RuleID", "StartLine", "StartColumn", "EndColumn", "Tags")},
              "col-1 ok:", text[line_start + f["StartColumn"] - 1:].startswith(f["Secret"]),
              "col-2 ok:", f["StartColumn"] >= 2 and text[line_start + f["StartColumn"] - 2:].startswith(f["Secret"]))
```

Run it from the repo root with `python3 -I /tmp/piif-plan-005/probe.py`. Record which of `col-1 ok` / `col-2 ok` is true on line 1 and on later lines, how many findings "three copies" and "two on one line" produce, and whether the "capture group" case (where gitleaks' `Secret` is only the value after `API_KEY=`, narrower than the regex match) reports columns for the value or for the whole match. If columns point at the whole match, neither `col-1` nor `col-2` will be ok; the in-line search in Step 2 handles that case, so just record it.

**Verify**: the output matches the measured behaviour listed under "Current state" (line 1: `col-1 ok`; later lines: `col-2 ok`; three copies → 3 findings; two on one line → 1 finding). If it does not, this is a STOP condition: the locate rules below assume it.

### Step 2: Locate findings by line and column, then every copy

In `src/gitleaks.rs`:

1. Extend `Finding` with `#[serde(rename = "StartLine", default)] pub start_line: usize` and `#[serde(rename = "Tags", default)] pub tags: Vec<String>`.
2. Add `pub fn is_decoded(&self) -> bool { self.tags.iter().any(|t| t.starts_with("decoded:")) }`.
3. Rewrite `locate` to return `Vec<(usize, usize)>` (every byte range to redact for this finding) with this order of attempts:
   - Compute `line_start`: the byte offset of line `start_line` (1-based; count `\n`). If `start_line` is 0 or past the end, use 0.
   - If `!is_decoded()`: try `line_start + start_column - 1` and `line_start + start_column - 2` (when `start_column >= 2`); the first candidate `c` with `text.get(c..c + secret.len()) == Some(secret)` is the anchor. If neither matches, search for `secret` inside that line only (`text[line_start..line_end].find`). Then add every other occurrence of `secret` in the whole text (`text.match_indices(secret)`), deduplicated and sorted. The result is the anchor plus all copies; if there is no anchor, it is all copies (which may be empty).
   - If `is_decoded()`: the secret is not in the text. Use the column range as reported: `start = line_start + start_column - k` where `k` is 1 on line 1 and 2 otherwise, `end = line_start + end_column - k + 1`, clamped to the line, then widened outward to char boundaries. Return that single range when it is non-empty and both ends are char boundaries; otherwise return an empty vector (never panic on a bad range).
4. Update the doc comment to state the measured semantics from Step 1 and that decoded findings redact the encoded segment.

Add `mod tests` at the bottom of `src/gitleaks.rs` with a helper that builds a `Finding` by hand (no gitleaks subprocess needed) and these tests:

- `first_line_uses_one_based_column`
- `later_lines_are_offset_by_one_more`
- `every_copy_is_returned`: secret on line 2 and again on line 4, finding reports line 2 → two ranges.
- `two_copies_on_one_line`: one finding, two ranges.
- `decoded_finding_redacts_encoded_segment`: tags `["decoded:base64"]`, secret absent from text, columns inside the text → one range equal to the column range.
- `bad_columns_do_not_panic`: `start_column` past the end of the text, secret absent → empty vector.
- `columns_after_multibyte_char`: line 1 contains `ü` before the secret and the finding's column counts bytes → anchor found.

Then in `src/detect.rs:512-528` change `gitleaks_spans` to loop over `locate(finding, text)`'s vector and push one `DetectedSpan` per range. For decoded findings, set `word` to the encoded text at that range (it is what gets replaced) and keep `source` as `gitleaks:<rule>`.

**Verify**: `cargo test --release gitleaks` → the new tests pass; `cargo test --release` → all pass; `cargo build --release` → exit 0.

### Step 3: Merge overlapping spans into their union and clamp to the text region

In `src/bin/gateway.rs`, extract the span selection out of `redact_text_with_context` into a pure function so it can be unit-tested without a detector:

```rust
/// Spans from one detection, mapped onto `text` (the region after the model-only
/// context) and made non-overlapping. Overlaps are unioned rather than picked:
/// keeping only the later span used to leave the covering span's extra bytes
/// visible. A span that starts in the context but ends in the text is clamped to
/// the text. Leading and trailing whitespace is trimmed so the placeholder does
/// not swallow the space before a value.
fn normalize_spans(spans: Vec<DetectedSpan>, text: &str, offset: usize) -> Vec<DetectedSpan>
```

Rules, applied in this order:

1. Keep a span only if `span.end > offset` and `span.start < offset + text.len()`. Clamp `start` to at least `offset` and `end` to at most `offset + text.len()`, then subtract `offset` from both.
2. Snap to char boundaries of `text` (widen outward, as `snap_to_char_boundaries` in `src/detect.rs:274-287` does; copy that logic rather than making it public, or make it `pub` and reuse it, either is fine).
3. Trim: move `start` forward past ASCII whitespace and `end` backward past ASCII whitespace; drop the span if it becomes empty.
4. Sort by `(start, end)`. Sweep once: if the next span starts before the current union ends (`next.start < current.end`), set `current.end = max(current.end, next.end)`; the label becomes `secret` if either is `secret`, otherwise the label of the longer original span; `score` is the max; `source` is the source of the span whose label won. Spans that merely touch (`next.start == current.end`) stay separate.

Then `redact_text_with_context` becomes: build `input` and `offset` as today, call `detect_kept`, call `normalize_spans`, and keep the existing numbering, replacement and audit code unchanged from the `// Number left to right` comment onward (with `accepted` replaced by the normalized vector).

Add to the gateway `tests` module (use the `span` helper pattern from `src/detect.rs:337-346`):

- `covering_span_is_kept_as_union`: spans (secret 10..30) and (model 12..20) → one span 10..30 labelled secret.
- `model_span_containing_secret_becomes_secret`: (private_person 8..32) and (secret 10..30) → one span 8..32 labelled secret.
- `span_starting_in_context_is_clamped`: offset 20, span 15..40 → span 0..20.
- `leading_space_is_trimmed`: text `"key: abc"`, span 4..8 → 5..8.
- `touching_spans_stay_separate`: 0..5 and 5..9 → two spans.
- `span_entirely_in_context_is_dropped`: offset 20, span 3..12 → no spans.

**Verify**: `cargo test --release normalize` → passes; `cargo test --release` → all pass.

### Step 4: Add a suite context that repeats a secret inside one line

In `tests/secrets/contexts.py`, add `repeated_on_one_line`: a `tool_turn("Bash", {"command": "grep -r TOKEN ."}, ...)` whose result text is `f"a.env:{g.line}  b.env:{g.line}\n"` with `keep = ["Let me check."]`. Append the function name to the list inside `CONTEXTS` (lines 408–421; the dict is built from `f.__name__`). The existing `repeated_lines` context already covers copies on separate lines.

**Verify**: `python3 -I tests/secrets/contexts.py` → `contexts ok:` with the count one higher than before this step.

### Step 5: Rebuild, run the suite, refresh the known gaps

```sh
cargo build --release
python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data --record-gaps
```

Expected removals: all 11 entries whose reason mentions `text.find`, and the 2 "model spans swallow the newline … between PEM copies" entries. Expected: no `FAIL` lines. `repeated_on_one_line` should pass in `secret-rules` for every format that passes in `repeated_lines`. For any new gap entry, replace the auto-generated reason with a one-line cause.

Also run the M1 gate: `PIIF_MODEL_DIR=/Users/alexs/piifence-trial/src/data cargo run --release 2>&1 | tail -3` → `15/15`.

**Verify**: `grep -c "text.find" tests/secrets/expectations.json` → `0`; the suite exits 0 with `0 regressions` and `0 fixed` on a second run without `--record-gaps`; `gitleaks dir tests/secrets --no-banner` → no leaks.

### Step 6: Update the contracts

- `docs/gateway-spike.md:73-79` ("Label precedence"): replace the ">=80%" sentence with: a gitleaks `secret` finding takes over every span it overlaps, overlapping spans are unioned, every copy of a gitleaks secret in the block is redacted, and findings gitleaks reports from decoded base64 redact the encoded segment.
- `AGENTS.md:62-65`: same change in one sentence (the ">=80%" wording there is already stale).

**Verify**: `grep -n "80%" docs/gateway-spike.md AGENTS.md` → no matches.

## Test plan

- `src/gitleaks.rs`: seven unit tests listed in Step 2, no subprocess.
- `src/bin/gateway.rs`: six unit tests listed in Step 3 on `normalize_spans`.
- `tests/secrets/contexts.py`: one new context, run by the suite in three modes.
- End to end: full suite exit 0, no `FAIL`, 13 entries removed from `expectations.json`; M1 corpus still 15/15.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo test --release` exits 0 and includes the 13 new tests
- [ ] `grep -c "fn locate" src/gitleaks.rs` → `1` and the function returns `Vec<(usize, usize)>`
- [ ] `grep -c "last_start" src/bin/gateway.rs` → `0` (the greedy loop is gone)
- [ ] `grep -c "text.find" tests/secrets/expectations.json` → `0`
- [ ] `python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data` exits 0 with `0 regressions`, `0 fixed` in all modes
- [ ] `PIIF_MODEL_DIR=/Users/alexs/piifence-trial/src/data cargo run --release` ends with `15/15` and exit 0
- [ ] `grep -n "80%" docs/gateway-spike.md AGENTS.md` → no matches
- [ ] `git status` shows no modified files outside the in-scope list
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- Step 1's measurement disagrees with the column semantics in "Current state" (then the `-1` / `-2` rule is wrong for this gitleaks version; report the observed numbers).
- The code at the locations in "Current state" does not match the excerpts.
- The suite reports `over-redaction` for any case that passed before (the union rule is eating a `keep` string; report the case id and the two spans involved).
- The M1 gate drops below 15/15.
- A fix seems to need `merge_spans`, the cache, or the gitleaks command line changed.
- `cargo test` panics with a byte-index error in any new test: the char-boundary snapping in Step 3 is incomplete; do not paper over it with `unwrap_or`.

## Maintenance notes

- `locate` encodes a measured quirk of gitleaks 8.30.1 (`StartColumn` is one larger on lines after the first). Re-run the Step 1 probe after any gitleaks upgrade; `scripts/install.sh` installs gitleaks from Homebrew, so the version floats.
- Decoded findings now redact the encoded segment. A reviewer should confirm the audit entry's `preview` for those shows the encoded text, never the decoded value.
- `normalize_spans` is the single place where span geometry is fixed; `merge_spans` in `src/detect.rs` stays about label precedence. Keep that split.
- Deferred: running gitleaks on the text only instead of the context + text concatenation. With every copy now located, a copy in the tool-call context no longer steals the finding, so the change was not needed for correctness; it would still cut one gitleaks subprocess per tool result if the context ever contains secrets that are redacted elsewhere.
- Deferred: the suite's `leak_window` (`tests/secrets/run.py:77-87`) checks a half-length window of each secret, which is why partial over-coverage is not reported; a stricter "placeholder must cover exactly the value" check belongs in a later test plan.
