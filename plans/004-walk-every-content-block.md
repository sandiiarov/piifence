# Plan 004: Redact every text-bearing content block through one dispatcher

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat efdd25e..HEAD -- src/bin/gateway.rs tests/secrets/run.py tests/secrets/contexts.py tests/secrets/expectations.json AGENTS.md docs/gateway-spike.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (touches the function that decides what gets redacted; the secret suite is the safety net)
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `efdd25e`, 2026-10-30

## Why this matters

The gateway walks a fixed list of block types (`text`, `tool_result`, `tool_use`) and silently forwards every other block raw. Two block types Claude Code can send carry user text: `document` blocks (a pasted or attached file with `source.type = "text"`) and `search_result` blocks (what an MCP search tool returns inside a `tool_result`). A secret inside either reaches the provider unredacted. The end-to-end secret suite already records this as 72 known gaps (24 per mode, contexts `document_text_source` and `search_result_in_tool_result`). A third hole is structural: when a `tool_result` has an originating tool call, non-text blocks nested in it are handed to a function that only understands strings and arrays, so a nested object is a no-op.

After this plan, one function decides how each content block is scanned, the two contexts above pass in all three suite modes, and the suite can run its rules-only mode without model weights (today it refuses to start without them even though that mode never loads the model).

## Current state

Files:

- `src/bin/gateway.rs` — the proxy. `redact_content` (lines 395–470) walks a message's content; `redact_tool_result_content` (lines 472–509) walks `tool_result` content with the tool call as model context; `redact_payload` (lines 511–558) builds the tool map and calls them.
- `tests/secrets/run.py` — the end-to-end suite (real gateway, fake upstream). `main` at line 415 refuses to run without weights.
- `tests/secrets/contexts.py` — request builders. `document_text_source` (line 320) and `search_result_in_tool_result` (line 327) are the two failing contexts; `CONTEXTS` (dict at lines 408–421) registers builders by id.
- `tests/secrets/expectations.json` — known gaps keyed `"<mode>|<context>/<format>"`. 72 entries for the two contexts above must disappear when this plan lands.
- `AGENTS.md`, `docs/gateway-spike.md` — contracts to update (see Step 6).

The block walker today, `src/bin/gateway.rs:395-470`:

```rust
#[async_recursion::async_recursion]
async fn redact_content(
    state: &AppState,
    content: &mut Value,
    tool_map: &HashMap<String, (String, String)>,
    skip_text: bool,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    match content {
        Value::String(text) => {
            if skip_text {
                return Ok(audit);
            }
            let (out, mut entries) = redact_text_smart(state, text, "content").await?;
            if !entries.is_empty() {
                *text = out;
                audit.append(&mut entries);
            }
        }
        Value::Array(blocks) => {
            for block in blocks {
                match block.get("type").and_then(|v| v.as_str()).unwrap_or("") {
                    "text" => {
                        if skip_text {
                            continue;
                        }
                        if let Some(Value::String(s)) = block.get_mut("text") {
                            let (out, mut entries) = redact_text_smart(state, s, "text").await?;
                            if !entries.is_empty() {
                                *s = out;
                                audit.append(&mut entries);
                            }
                        }
                    }
                    "tool_result" => {
                        let context = block
                            .get("tool_use_id")
                            .and_then(|v| v.as_str())
                            .and_then(|id| tool_map.get(id))
                            .map(|(name, input)| {
                                let mut input = input.clone();
                                if input.len() > 800 {
                                    // `truncate` panics off a char boundary, so back up to one.
                                    let mut cut = 800;
                                    while !input.is_char_boundary(cut) {
                                        cut -= 1;
                                    }
                                    input.truncate(cut);
                                }
                                format!("Tool call: {name} {input}\nTool output:")
                            });
                        if let Some(inner) = block.get_mut("content") {
                            if let Some(context) = context.as_deref() {
                                audit.extend(
                                    redact_tool_result_content(state, inner, context).await?,
                                );
                            } else {
                                audit.extend(redact_content(state, inner, tool_map, false).await?);
                            }
                        }
                    }
                    "tool_use" => {
                        if let Some(input) = block.get_mut("input") {
                            audit.extend(
                                redact_json_strings(state, input, "tool_use.input").await?,
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(audit)
}
```

The `tool_result` walker, `src/bin/gateway.rs:472-509`. Note line 502: a non-text block (an object) is passed to `redact_content`, which matches only `Value::String` and `Value::Array`, so nothing happens:

```rust
/// tool_result content: text blocks are scanned with the originating tool call
/// as context, so bare values (e.g. `echo $OPENCODE_API_KEY`) are recognised.
#[async_recursion::async_recursion]
async fn redact_tool_result_content(
    state: &AppState,
    content: &mut Value,
    context: &str,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    match content {
        Value::String(text) => {
            let (out, mut entries) = redact_text_with_context(state, text, "tool_result", Some(context)).await?;
            if !entries.is_empty() {
                *text = out;
                audit.append(&mut entries);
            }
        }
        Value::Array(blocks) => {
            for block in blocks {
                if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                    if let Some(Value::String(s)) = block.get_mut("text") {
                        let (out, mut entries) =
                            redact_text_with_context(state, s, "tool_result.text", Some(context))
                                .await?;
                        if !entries.is_empty() {
                            *s = out;
                            audit.append(&mut entries);
                        }
                    }
                } else {
                    audit.extend(redact_content(state, block, &HashMap::new(), false).await?);
                }
            }
        }
        _ => {}
    }
    Ok(audit)
}
```

The text-level helpers the walker calls (`src/bin/gateway.rs:220-229` and `289-296`). `redact_text_smart` also handles Claude Code bash-mode tags; `redact_text_with_context` (line 301) prepends a model-only context and keeps only spans inside `text`:

```rust
async fn redact_text_smart(
    state: &AppState,
    text: &str,
    field: &str,
) -> anyhow::Result<(String, Vec<Value>)> {
    let (bash_redacted, mut audit) = redact_bash_outputs(state, text, field).await?;
    let (out, mut more) = redact_text(state, &bash_redacted, field).await?;
    audit.append(&mut more);
    Ok((out, audit))
}
...
/// Redact one text block, returning the rewritten text and the audit entries.
async fn redact_text(
    state: &AppState,
    text: &str,
    field: &str,
) -> anyhow::Result<(String, Vec<Value>)> {
    redact_text_with_context(state, text, field, None).await
}
```

`redact_json_strings` (`src/bin/gateway.rs:365-393`) recursively redacts every string in a JSON value with `redact_text`; it is what `tool_use.input` goes through.

The two failing suite contexts, `tests/secrets/contexts.py:320-332`:

```python
def document_text_source(make):
    g = make("0")
    doc = {"type": "document", "title": "notes.txt",
           "source": {"type": "text", "media_type": "text/plain", "data": f"Ops notes\n{g.line}\nRotate monthly.\n"}}
    return "/v1/messages", request([user(doc, text("summarise these notes"))]), ["summarise these notes"]


def search_result_in_tool_result(make):
    g = make("0")
    result = [{"type": "search_result", "source": "https://wiki.internal/ops", "title": "Ops runbook",
               "content": [text(f"To deploy, export {g.line} first.")]}]
    body = conversation(tool_turn("search_wiki", {"query": "deploy"}, result))
    return "/v1/messages", body, ["Ops runbook"]
```

The suite's weights gate, `tests/secrets/run.py:428-434`:

```python
    if args.check_generators:
        return check_generators()
    if args.self_test:
        return self_test()
    if not os.path.exists(os.path.join(args.model_dir, "config.json")):
        print(f"setup error: no model weights in {args.model_dir} (pass --model-dir)", file=sys.stderr)
        return 2
```

and the mode table, `tests/secrets/run.py:41-45` (`secret-rules` sets `llm_filter` false, which makes the gateway skip loading the model — see `src/bin/gateway.rs:819-833`):

```python
MODES = {
    "all": {"categories": ALL_CATEGORIES, "llm_filter": True},
    "secret": {"categories": ["secret"], "llm_filter": True},
    "secret-rules": {"categories": ["secret"], "llm_filter": False},
}
```

Block shapes to handle (Anthropic Messages API; the suite's builders above are exact examples):

| Block `type` | Text-bearing fields | Treatment |
|---|---|---|
| `text` | `text` | existing behaviour |
| `tool_result` | `content` (string or array of blocks) | existing behaviour, context from the tool map |
| `tool_use` | `input` (any JSON) | existing behaviour |
| `document` | `source.data` only when `source.type == "text"`; also `title` and `context` strings if present | new: scan as plain text (`redact_text`, field names `document.source.data`, `document.title`, `document.context`) |
| `search_result` | `content` (array of `text` blocks), `title`, `source` (a URL string) | new: scan `content` like `tool_result` content (keeping the surrounding tool call as context when there is one); scan `title` and `source` with `redact_text` |
| `image`, `document` with `source.type` of `base64` or `url` | none scannable | skip |
| `thinking`, `redacted_thinking` | signed by the provider | never modify (the suite fails the case if a thinking block changes) |

Conventions: doc comments (`///`) explain why, not what. Unit tests live in `#[cfg(test)] mod tests` at the bottom of `src/bin/gateway.rs` (line 901 onward; plain `#[test]` functions with descriptive snake_case names and `assert_eq!`). Design constraints from `AGENTS.md:96-104`: input-only, "unknown payload shapes passed through", "fail closed on redaction errors". `docs/gateway-spike.md:12` lists what is redacted ("`tool_result` content, `tool_use.input`").

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Build | `cargo build --release` | exit 0 |
| Unit tests | `cargo test --release` | exit 0, all pass |
| Suite self-check | `python3 -I tests/secrets/run.py --self-test` | three `ok` lines, exit 0 |
| Context builders | `python3 -I tests/secrets/contexts.py` | `contexts ok: N` |
| Rules-only suite (no model) | `python3 -I tests/secrets/run.py --mode secret-rules` | exit 0 after Step 1; prints `FIXED (remove from expectations)` lines until Step 5 |
| Full suite | `python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data` | exit 0; about 25 minutes on an M-series laptop |
| Repo stays secret-free | `gitleaks dir tests/secrets --no-banner` | `no leaks found` |

Weights: on this machine they are at `/Users/alexs/piifence-trial/src/data`. Elsewhere run `scripts/fetch-weights.sh` (about 2.8 GB) and pass that directory with `--model-dir`.

## Scope

**In scope** (the only files you should modify):
- `src/bin/gateway.rs`
- `tests/secrets/run.py`
- `tests/secrets/contexts.py`
- `tests/secrets/expectations.json` (remove entries only via the suite's `--record-gaps`, see Step 5)
- `AGENTS.md`, `docs/gateway-spike.md` (one-line contract updates)
- `plans/README.md` (status row)

**Out of scope** (do NOT touch, even though they look related):
- `src/detect.rs`, `src/gitleaks.rs` — span merging and gitleaks location are plan 005.
- `gitleaks.toml`, `tests/secrets/formats.py` — new rules are plan 006.
- `redact_text_with_context` internals (`src/bin/gateway.rs:301-363`) — plan 005 rewrites them; this plan only calls it.
- `src/main.rs` and `tests/corpus-secrets.json` — the repository owner has uncommitted work there.
- Any change to `thinking` / `redacted_thinking` blocks.

## Git workflow

- Branch: `fix/walk-every-content-block` from `main` (the repo uses `fix/<slug>` and `feature/<slug>` branches, merged with `git merge` into `main`, see `git log --oneline -8`).
- One commit per step or logical unit. Message style from `git log`: a summary line of at most 60 characters, a blank line, bullets, and the trailer `Co-authored-by: Claude <noreply@anthropic.com>`. Example: `Number each redacted value once per gateway process`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Let the rules-only suite run without weights

In `tests/secrets/run.py`, replace the weights gate at lines 432–434 so it only applies when a selected mode needs the model:

```python
    modes = args.mode or list(MODES)
    if any(MODES[m]["llm_filter"] for m in modes) and not os.path.exists(os.path.join(args.model_dir, "config.json")):
        print(f"setup error: no model weights in {args.model_dir} (pass --model-dir, or use --mode secret-rules)", file=sys.stderr)
        return 2
```

and delete the later `modes = args.mode or list(MODES)` line (currently line 442) so `modes` is computed once. Update the docstring at the top of the file (line 3) and `tests/secrets/README.md` "Running it" with one line: `python3 -I tests/secrets/run.py --mode secret-rules   # no weights needed`.

**Verify**: `cargo build --release && python3 -I tests/secrets/run.py --mode secret-rules --model-dir /nonexistent` → runs 856 cases and exits 0 (every failure is a known gap). Then `python3 -I tests/secrets/run.py --mode secret --model-dir /nonexistent` → prints the setup error and exits 2.

### Step 2: Add a single block dispatcher

In `src/bin/gateway.rs`, add a new function next to `redact_content`:

```rust
/// Redact one content block in place. Every block type that can carry user text
/// is routed here, so a new block shape has exactly one place to be added.
/// `context` is the originating tool call for blocks nested in a tool_result;
/// it is shown to the model only, never redacted here.
#[async_recursion::async_recursion]
async fn redact_block(
    state: &AppState,
    block: &mut Value,
    tool_map: &HashMap<String, (String, String)>,
    context: Option<&str>,
    skip_text: bool,
) -> anyhow::Result<Vec<Value>>
```

Behaviour per `block["type"]`:

- `"text"`: as today. If `context` is `Some`, call `redact_text_with_context(state, s, "tool_result.text", context)`; otherwise `redact_text_smart(state, s, "text")`. Honour `skip_text`.
- `"tool_result"`: build the context string from `tool_map` exactly as lines 430–445 do today (keep the 800-byte char-boundary truncation). Then, if `content` is a `Value::String`, redact it with `redact_text_with_context(..., "tool_result", context)` when a context exists, else `redact_text_smart(..., "content")`. If `content` is an array, call `redact_block` on each element with the computed context. Nothing else is touched.
- `"tool_use"`: as today (`redact_json_strings` on `input`).
- `"document"`: if `source.type == "text"` and `source.data` is a string, redact it with `redact_text(state, data, "document.source.data")`. Also redact `title` and `context` if they are strings (fields `document.title`, `document.context`). Any other `source.type` is left alone.
- `"search_result"`: redact `title` and `source` if strings (fields `search_result.title`, `search_result.source`); then for each element of `content` call `redact_block` with the same `context` argument this call received.
- `"thinking"`, `"redacted_thinking"`, `"image"`, anything else: return an empty audit without touching the block.

Keep the "replace only when entries is non-empty" pattern (`if !entries.is_empty() { *s = out; audit.append(&mut entries); }`) so untouched strings stay byte-identical.

**Verify**: `cargo build --release` → exit 0 (the new function is not called yet; a dead-code warning is fine until Step 3).

### Step 3: Route both walkers through the dispatcher

Change `redact_content` so its `Value::Array` branch is only:

```rust
        Value::Array(blocks) => {
            for block in blocks {
                audit.extend(redact_block(state, block, tool_map, None, skip_text).await?);
            }
        }
```

Delete `redact_tool_result_content` entirely; its two callers are now inside `redact_block`. `redact_payload` keeps calling `redact_content` for `system` and each message's `content` (string or array), unchanged.

**Verify**: `cargo build --release 2>&1 | grep -c "warning: unused\|never used"` → `0`, and `cargo test --release` → all pass.

### Step 4: Unit-test the dispatcher's routing without the model

`redact_block` needs an `AppState`, which needs a detector worker. Add a test helper at the bottom of `src/bin/gateway.rs` inside `mod tests` that builds an `AppState` whose worker thread answers every job with a fixed span list, for example "every occurrence of the substring `TOKEN` is a `secret` span". The worker loop in `main` (`src/bin/gateway.rs:864-870`) shows the shape: an `std::sync::mpsc::channel::<DetectJob>()`, a thread that `recv()`s jobs and replies through `job.reply`. The audit and audit_body files can be `/dev/null` opened for writing; `client` can be `reqwest::Client::new()`; `upstream` any string; `port` 0.

Write these tests (model after `same_value_keeps_its_number` at line 905; use `#[tokio::test]` for async ones; `tokio` already has the `macros` feature):

1. `document_text_source_is_redacted`: a `document` block with `source.type = "text"` and `source.data = "a TOKEN b"` becomes `a <secret_1> b`; `title` with `TOKEN` is also replaced.
2. `document_base64_is_untouched`: a `document` with `source.type = "base64"` and `data` containing `TOKEN` is byte-identical after the call.
3. `search_result_inside_tool_result_is_redacted`: a `tool_result` whose `content` is `[ {type: search_result, title, source, content: [ {type: text, text: "x TOKEN y"} ]} ]` ends with `<secret_1>` in the nested text and the audit field equals `tool_result.text` when the tool map has the id (context present) and `text` when it does not.
4. `nested_object_in_tool_result_with_context_is_walked`: the exact shape of the old line-502 bug: a `tool_result` with a context (id present in the tool map) whose `content` array holds a `document` block; the document text is redacted.
5. `thinking_blocks_are_never_modified`: a `thinking` block whose `thinking` and `signature` strings contain `TOKEN` is byte-identical afterwards.

**Verify**: `cargo test --release walk 2>&1 | tail -3` (or by the test names) → the five new tests pass; `cargo test --release` → all pass.

### Step 5: Add suite contexts for the new shapes, then refresh the known gaps

In `tests/secrets/contexts.py` add three builder functions and append their names to the function list inside `CONTEXTS` (lines 408–421; the dict is built from `f.__name__`, so the function name is the context id):

- `document_with_title_and_context`: like `document_text_source`, but `title` is `"creds for " + g.line` and a top-level `"context": "pasted from " + g.line` field is present; `keep` is `["summarise these notes"]`.
- `search_result_top_level`: a `search_result` block directly inside a user message (not in a `tool_result`), `content: [text(g.line)]`, `title: "Ops runbook"`, `keep: ["Ops runbook"]`.
- `tool_result_document_block`: `tool_turn("fetch_doc", {"id": 7}, [doc])` where `doc` is a `document` block whose `source.data` contains `g.line`; `keep: ["Let me check."]`.

Run `python3 -I tests/secrets/contexts.py` → `contexts ok: 47`.

Then refresh the gap file. With the full suite (`--model-dir /Users/alexs/piifence-trial/src/data`):

```sh
python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data --record-gaps
```

Expected: every `document_text_source/*` and `search_result_in_tool_result/*` entry prints as `FIXED (remove from expectations)` and is removed; the new contexts gain entries only for formats that also fail in `prompt_text` (no rule and the model misses them). If a new context records a gap for a format that passes in `prompt_text`, that is a routing bug in Step 2, not a detection gap: fix it and rerun. `--record-gaps` writes reasons like `recorded 2026-10-30: leak (…)`; edit each new entry's `reason` to a one-line cause in the style of the existing ones (for example `no gitleaks rule or guard matches this format; only the model catches it`).

**Verify**: `jq -r 'keys[]' tests/secrets/expectations.json | grep -c "document_text_source\|search_result_in_tool_result"` → `0`; `python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data` → exit 0 with `0 regressions` and `0 fixed` in every mode; `gitleaks dir tests/secrets --no-banner` → no leaks.

### Step 6: Update the contracts

- `docs/gateway-spike.md:12`: extend the list of redacted fields to name `document` (text sources, title, context) and `search_result` (content, title, source) blocks, and state that `image`, non-text documents and thinking blocks are passed through untouched.
- `AGENTS.md`, Gateway spike contract (lines 96–121): add one sentence after "unknown payload shapes passed through": every block type that can carry text is routed through `redact_block`; add a new block type there.
- `AGENTS.md:152`: mention that `--mode secret-rules` runs without weights.

**Verify**: `grep -n "redact_block" AGENTS.md docs/gateway-spike.md` → at least one hit in each file.

## Test plan

- New unit tests in `src/bin/gateway.rs` (Step 4), five cases listed there, using a fixed-answer detector worker so no weights or gitleaks are needed.
- New suite contexts in `tests/secrets/contexts.py` (Step 5), exercised by `run.py` in all three modes.
- Regression check: the whole suite exits 0 with no `FAIL` and no `FIXED` lines; `cargo test --release` passes; the self-test still passes.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo build --release` exits 0 with no `unused`/`never used` warnings for `redact_block` or `redact_tool_result_content` (the latter no longer exists: `grep -c redact_tool_result_content src/bin/gateway.rs` → `0`)
- [ ] `cargo test --release` exits 0 and includes the five tests named in Step 4
- [ ] `python3 -I tests/secrets/run.py --mode secret-rules --model-dir /nonexistent` exits 0
- [ ] `python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data` exits 0 with `0 regressions` and `0 fixed` in all three modes
- [ ] `jq -r 'keys[]' tests/secrets/expectations.json | grep -c "document_text_source\|search_result_in_tool_result"` → `0`
- [ ] `python3 -I tests/secrets/contexts.py` → `contexts ok: 47`
- [ ] `gitleaks dir tests/secrets --no-banner` → no leaks
- [ ] `git status` shows no modified files outside the in-scope list
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- The code at the locations in "Current state" does not match the excerpts.
- A `thinking` or `redacted_thinking` block is modified in any suite case (the suite reports `thinking block modified`).
- The suite reports `structure changed` for any case after Step 3: the dispatcher must never add or remove JSON keys.
- A new context from Step 5 records a gap for a format that passes in the `prompt_text` context in the same mode, and you cannot find the routing cause within two attempts.
- Making the dispatcher work seems to require changing `redact_text_with_context`, `src/detect.rs` or `src/gitleaks.rs`.
- The full suite reports a `FAIL` outside the new contexts (a regression in a previously passing case).

## Maintenance notes

- Every future block type goes into `redact_block`; a reviewer should reject a new `match` on block type anywhere else in `gateway.rs`.
- Plan 005 changes `redact_text_with_context`; it does not need to touch `redact_block`, but its suite run will re-record gaps, so land this plan first to keep the gap diff readable.
- Deferred: `document` blocks with `source.type = "base64"` and a text `media_type` (base64-encoded plain text or PDF). Decoding, redacting and re-encoding changes the bytes the provider sees and the document's citations offsets; decide separately whether to block such requests instead.
- Deferred: top-level `role: "system"` messages are not part of the Messages API and are left as-is.
