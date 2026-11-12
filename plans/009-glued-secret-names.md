# Plan 009: Keep a secret's name from running into the text after it

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving to the next step. If anything in the "STOP conditions" section occurs, stop and report; do not improvise. When done, update the status row for this plan in `plans/README.md`, unless a reviewer dispatched you and told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat fc97e3d..HEAD -- src/bin/gateway.rs src/bin/piifence.rs src/guards.rs tests/secrets/run.py CLAUDE.md`
> If any of these files changed since this plan was written, compare the "Current state" excerpts against the live code before proceeding. On a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M (about 2–3 hours, plus one full suite run)
- **Risk**: MED (changes how every request is rewritten, and makes the `PreToolUse` hook stricter)
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `fc97e3d`, 2026-11-11

## Before you start: never type a literal name

This repo builds piifence, and piifence may be protecting your own Claude Code session. Your session is protected if your session-start context has a section titled "piifence environment variables". In a protected session, a `PreToolUse` hook rewrites the input of every tool except Bash, PowerShell and Monitor. Each dollar sign followed by `PIIF_SECRET_` and digits (or the same name inside `${…}`) is replaced with the real secret your session holds under that number, and a number your session does not have blocks the call. So an Edit or Write whose text contains a literal name either writes a real secret into a source file or fails.

Follow these rules whether or not your session is protected:

1. In new Rust tests, build names at run time with the `bare(n)` and `braced(n)` helpers this plan adds. Never write a name as a literal.
2. Do not edit any existing line that contains a literal name. No step needs to.
3. This plan never writes a name literally either. `$PIIF_SECRET_<N>`, `${PIIF_SECRET_<N>}` and `PIIF_SECRET_…` stand for a name with some number.

## Why this matters

piifence replaces each secret in what Claude Code sends to the model with a name made of a dollar sign, `PIIF_SECRET_` and a number. The agent then uses that name in shell commands, where the shell expands it, and in other tools, where the `piifence restore` hook puts the value back. Both readers take every letter, digit and `_` after the dollar sign as part of the name. The gateway writes the name without braces even when such a character follows, so the name merges with the text after it.

This happened in a real session on 2026-11-11, at commit `fc97e3d`:

1. README.md:116 shows a UUID's first group after `API_KEY=` as an example. The key rule named that 9-character value: 8 hex digits plus the hyphen. That part is by design.
2. The value ends in `-`, so the whole-token rule in `env_value_matches` did not protect it. The gateway then replaced it inside every full copy of that UUID, including a folder name and the comment at `src/guards.rs:94`.
3. The value's name had number 8, and the UUID's next characters were `25e8`. So the text read as name number 825 followed by `e8`. The restore hook looked up name 825 and blocked the tool call with "this session has no value for" name 825. A shell would read the unset variable `PIIF_SECRET_825e8` instead: an empty string, or "unbound variable" under `set -u`.
4. The same session named the 9-character prefix `piifence-`, which also ends in `-`. So `plugin/piifence-notice/scripts/notice.py` reached the model as `plugin/`, then the name, then `notice/…`. A shell reads that as the unset variable named `PIIF_SECRET_` + number + `notice`, so a command using that path fails.

The worst case is silent: if the merged digits form a name the session does have, the hook puts a different secret into the tool input. The 2026-10-30 audit flagged the same unbraced-name problem in the old JavaScript approval mod, so this is the second time it has shipped.

After this plan, three things are true. A short value whose first or last character is `-` or `_` is no longer replaced inside a longer token. A name is written in braces whenever a letter, digit or `_` follows it. And the hook refuses a bare name that runs into a letter or `_`, instead of guessing which name was meant.

## Current state

Files:

- `src/bin/gateway.rs`: the gateway (binary `piifence-gateway`). It names values, and rewrites requests before they go to the provider.
- `src/bin/piifence.rs`: the CLI (binary `piifence`). It includes the `restore` hook and `VARIABLES_NOTE`, the note the agent gets at session start.
- `src/guards.rs`: suppression rules shared by every detector. `env_ref` stops a detector from flagging an env reference, including a piifence name, as a secret.
- `tests/secrets/run.py`: the end-to-end secret suite. `SECRET_NAME` counts names in what the fake upstream received.
- `CLAUDE.md`: the developer notes. Lines 35 and 42 describe names and the restore hook.

`src/bin/gateway.rs:447-465`, the whole-token rule. Only a letter or digit at the value's own edge counts, so a value ending in `-` or `_` matches inside a longer token:

```rust
/// Below this many characters a known value is replaced only as a whole token: not where a letter or digit of the text runs into its own first or last letter or digit. A short value turns up inside other strings by chance (`2024` in `2024-10-30`); a long one does not, so it is replaced wherever it appears, which keeps a real secret covered inside a longer string.
const WHOLE_TOKEN_BELOW: usize = 16;

/// Where `value` is in `text`, by the rule of `WHOLE_TOKEN_BELOW`.
fn env_value_matches(text: &str, value: &str) -> Vec<usize> {
    let whole_token = value.chars().count() < WHOLE_TOKEN_BELOW;
    let joins = |outside: Option<char>, edge: Option<char>| matches!((outside, edge), (Some(o), Some(e)) if o.is_alphanumeric() && e.is_alphanumeric());
    text.match_indices(value)
        .map(|(start, _)| start)
        .filter(|&start| {
            !whole_token
                || !(joins(text[..start].chars().next_back(), value.chars().next())
                    || joins(
                        text[start + value.len()..].chars().next(),
                        value.chars().next_back(),
                    ))
        })
        .collect()
}
```

`src/bin/gateway.rs:497-519`, inside `replace_env_values`. This runs before detection on every text block, and `sweep_values` calls it again over the whole request. Line 501 builds the name without braces:

```rust
            let starts = env_value_matches(&out, &entry.value);
            if starts.is_empty() {
                continue;
            }
            let token = format!("${}", entry.name);
            let mut replaced = String::with_capacity(out.len());
            let mut copied = 0;
            for start in starts {
                audit.push(audit_entry(
                    field,
                    start,
                    start + entry.value.len(),
                    entry,
                    "env",
                    !entry.seen,
                ));
                entry.seen = true;
                replaced.push_str(&out[copied..start]);
                replaced.push_str(&token);
                copied = start + entry.value.len();
            }
            replaced.push_str(&out[copied..]);
```

`src/bin/gateway.rs:726-745`, inside `redact_text`, which names what the detectors found. Line 736 builds the name without braces. The loop replaces right to left, so when it replaces a span, the text after that span is already final:

```rust
    let mut out = text.clone();
    // Name left to right so numbers read in document order; replace right to left so earlier offsets stay valid.
    let named: Vec<(String, Value)> = accepted
        .iter()
        .map(|span| {
            with_session(state, |session| {
                let entry = session.env.entry_for(&span.word, span.kind());
                let new = !entry.seen;
                entry.seen = true;
                (
                    format!("${}", entry.name),
                    audit_entry(field, span.start, span.end, entry, span.engine(), new),
                )
            })
        })
        .collect();
    for (span, (token, entry)) in accepted.iter().zip(named).rev() {
        out.replace_range(span.start..span.end, &token);
        audit.push(entry);
    }
```

There is a third `format!("${}", entry.name)` at `src/bin/gateway.rs:482`, in `audit_entry`. It is metadata for the notice and the audit log, not provider-bound text. Leave it alone.

`src/bin/piifence.rs:484-486`, the restore hook's name pattern. `\d+` reads every digit, so a name followed by digits becomes a different name:

```rust
fn name_pattern() -> regex::Regex {
    regex::Regex::new(r"\$(?:\{PIIF_SECRET_(\d+)\}|PIIF_SECRET_(\d+))").expect("valid pattern")
}
```

`src/bin/piifence.rs:503-528`, the start of `fill_values`, which the hook calls on every string of the tool input:

```rust
/// Replace every name in every string of `value` with its value. A name this session does not have is an error.
fn fill_values(
    value: &mut serde_json::Value,
    values: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let pattern = name_pattern();
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::String(s) => {
                let mut missing = None;
                let filled = pattern.replace_all(s, |caps: &regex::Captures| {
                    let number = caps.get(1).or(caps.get(2)).map_or("", |m| m.as_str());
                    let name = format!("PIIF_SECRET_{number}");
                    match values.get(&name).and_then(|v| v.as_str()) {
                        Some(real) => real.to_string(),
                        None => {
                            missing.get_or_insert(name);
                            caps[0].to_string()
                        }
                    }
                });
                if let Some(name) = missing {
                    bail!("this session has no value for ${name}");
                }
                *s = filled.into_owned();
```

`src/bin/piifence.rs:349`, the `VARIABLES_NOTE` bullet the new bullet goes after. The note is one Rust string literal on lines 344-351:

```rust
- Everywhere else, write the name where the value belongs: in file contents (Write, Edit), in an edit's old text, and in arguments to other tools (MCP tools, for example). piifence puts the real value in before the tool runs, so a file you write holds the value and an edit matches the file.
```

`src/guards.rs:85-87`, the env-reference guard. Its last alternative does not match the braced form. It also runs on through any letters, digits or `_` glued after a bare name. `references` (`src/guards.rs:168-179`) drops every detector span that overlaps a match, so text glued after a name is hidden from every detector:

```rust
            env_ref: Regex::new(
                r#"os\.environ\.get\(\s*['"][A-Za-z0-9_]+['"]\s*\)|os\.environ\[\s*['"][A-Za-z0-9_]+['"]\s*\]|os\.getenv\(\s*['"][A-Za-z0-9_]+['"]\s*\)|process\.env\.[A-Za-z0-9_]+|\$PIIF_[A-Za-z0-9_]+"#,
            )?,
```

`tests/secrets/run.py:38`, which misses braced names. `evaluate` (line 156) counts a negative case as a false positive when it receives more names than it sent, so a braced false positive would go unnoticed:

```python
SECRET_NAME = re.compile(r"\$PIIF_SECRET_\d+")
```

Conventions to match:

- Every function and const has a `///` doc comment of one or two plain sentences that say what it does. Add no other comments.
- Test names are full sentences in snake_case, for example `short_values_are_replaced_only_as_whole_tokens` (`src/bin/gateway.rs:1520`). Tests live in the `mod tests` at the bottom of each file.
- Async gateway tests use `#[tokio::test]` and `fake_state()` (`src/bin/gateway.rs:1299`). Its detector marks every occurrence of `TOKEN` as a secret, and applies no guards. See `env_value_in_tool_output_becomes_its_name` at `src/bin/gateway.rs:1474` for how a test registers a known value with `with_session(&state, |session| { session.env.entry_for(…); })`.
- Errors in the CLI use `anyhow`: `bail!`, `.context(…)`.
- Edition 2021. `cargo fmt` and `cargo clippy -D warnings` must pass.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --check` | exit 0, no output |
| Lint | `cargo clippy --release --all-targets -- -D warnings` | exit 0 |
| Gateway tests | `cargo test --release --bin piifence-gateway` | `test result: ok.` with 0 failed |
| CLI tests | `cargo test --release --bin piifence` | `test result: ok.` with 0 failed |
| Library tests | `cargo test --release --lib` | `test result: ok.` with 0 failed |
| Fast checks | `scripts/check.sh --no-suite` | last line `check: all passed` |
| Full checks | `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh` | last line `check: all passed`; the suite's summary line ends `0 regressions, <n> fixed` |

The full checks need the model files. If `$HOME/.local/share/piifence/model/model.safetensors` does not exist, run `scripts/fetch-weights.sh /tmp/piifence-model` and use `PIIF_MODEL_DIR=/tmp/piifence-model` instead. CI does the same.

## Scope

**In scope** (the only files you should modify):

- `src/bin/gateway.rs`: `WHOLE_TOKEN_BELOW` doc, `env_value_matches`, a new `name_token`, `replace_env_values`, `redact_text`, new tests
- `src/bin/piifence.rs`: a new `glued_name`, `fill_values`, `VARIABLES_NOTE`, new tests
- `src/guards.rs`: the `env_ref` pattern, two new tests
- `tests/secrets/run.py`: `SECRET_NAME`
- `CLAUDE.md`: lines 35 and 42

**Out of scope** (do NOT touch, even though they look related):

- `README.md:116` and the UUID in the comment at `src/guards.rs:94`. The README example is correct, and replacing a value that follows `API_KEY=` is intended behavior.
- `audit_entry` in `src/bin/gateway.rs:482`. Its `name` field is metadata, and the notice plugin reads it.
- Detection itself: why a 9-character UUID prefix or `piifence-` got a name at all. That is a separate precision problem.
- Stored name tables (`save_names` and the encrypted per-conversation files). No migration is needed, because a stored value that ends in `-` stops matching inside longer tokens once Step 1 lands.
- `tests/secrets/expectations.json`. Remove an entry only if the suite prints `FIXED (remove from expectations)` for it.
- Every existing line that contains a literal name (see "Before you start").

## Git workflow

- Branch: `fix/glued-secret-names`, from `ghe-main`. The repo names branches `fix/<kebab-case>` and `feature/<kebab-case>`.
- One commit per step is fine. Message style, from `git log`: an imperative summary under 60 characters (for example "Add a Homebrew formula so the repo works as a tap"), a blank line, one bullet per change, then the trailer `Co-authored-by: Claude <noreply@anthropic.com>`.
- Do NOT push or open a PR unless the operator told you to.

## Steps

### Step 0: Record the baseline

Run `cargo test --release` and note the `passed` count on each `test result:` line. Run `scripts/check.sh --no-suite`.

**Verify**: every `test result:` line says `ok` with `0 failed`, and `scripts/check.sh --no-suite` ends with `check: all passed`. If not, STOP: the baseline is broken before any change.

### Step 1: Count `-` and `_` as part of a short value's edge

In `src/bin/gateway.rs`, change the `joins` closure in `env_value_matches` so that the value's own edge character counts when it is a letter, a digit, `-` or `_`. The character outside the value still has to be a letter or digit. Target shape:

```rust
    let joins = |outside: Option<char>, edge: Option<char>| {
        matches!((outside, edge), (Some(o), Some(e))
            if o.is_alphanumeric() && (e.is_alphanumeric() || e == '-' || e == '_'))
    };
```

Rewrite the doc comment on `WHOLE_TOKEN_BELOW` to match: a short value is not replaced where a letter or digit of the text runs into its first or last character, when that character is a letter, digit, `-` or `_`. Add that a value cut from a longer token often ends in `-` or `_`, like the first group of a UUID.

This keeps the existing rule that a value whose edge is other punctuation may touch a letter: the assertion `env_value_matches("a:pw!b", ":pw!") == vec![1]` at line 1533 must still pass. It also keeps replacing a whole short value that sits next to a hyphen, as in `a-hunter2 b`.

Add this test directly below `short_values_are_replaced_only_as_whole_tokens`:

```rust
    #[test]
    fn a_short_value_cut_at_a_hyphen_or_underscore_is_not_replaced_inside_a_longer_token() {
        let uuid = "12345678-abcd-4ef0-8123-456789abcdef";
        assert_eq!(env_value_matches(uuid, "12345678-"), Vec::<usize>::new());
        assert_eq!(env_value_matches("a-8123-4567", "-8123"), Vec::<usize>::new());
        assert_eq!(
            env_value_matches("plugin/piifence-notice", "piifence-"),
            Vec::<usize>::new()
        );
        assert_eq!(env_value_matches("MY_KEY_NAME", "KEY_"), Vec::<usize>::new());
        assert_eq!(env_value_matches("id: 12345678- end", "12345678-"), vec![4]);
        assert_eq!(env_value_matches("x KEY_ y", "KEY_"), vec![2]);
        assert_eq!(env_value_matches("a-hunter2 b", "hunter2"), vec![2]);
    }
```

**Verify**: `cargo test --release --bin piifence-gateway whole_token` → `test result: ok. 1 passed`. Then `cargo test --release --bin piifence-gateway inside_a_longer_token` → `test result: ok. 1 passed`.

### Step 2: Write a name in braces when a letter, digit or `_` follows it

In `src/bin/gateway.rs`, add this function directly above `replace_env_values`:

```rust
/// How a name is written into text: `$NAME`, or `${NAME}` when a letter, digit or `_` comes next, because a shell and `piifence restore` would read that character as part of the name.
fn name_token(name: &str, next: Option<char>) -> String {
    match next {
        Some(c) if c.is_alphanumeric() || c == '_' => format!("${{{name}}}"),
        _ => format!("${name}"),
    }
}
```

In `replace_env_values`, delete the line `let token = format!("${}", entry.name);`. Build the token per match from the character after the value:

```rust
            for start in starts {
                let end = start + entry.value.len();
                audit.push(audit_entry(field, start, end, entry, "env", !entry.seen));
                entry.seen = true;
                replaced.push_str(&out[copied..start]);
                replaced.push_str(&name_token(&entry.name, out[end..].chars().next()));
                copied = end;
            }
```

Change its doc comment from "with `$NAME`" to "with its name (see `name_token`)".

In `redact_text`, make `named` hold the bare name: replace `format!("${}", entry.name),` with `entry.name.clone(),`. Then build the token in the right-to-left loop from the text that follows the span:

```rust
    for (span, (name, entry)) in accepted.iter().zip(named).rev() {
        let token = name_token(&name, out[span.end..].chars().next());
        out.replace_range(span.start..span.end, &token);
        audit.push(entry);
    }
```

In `mod tests`, add these two helpers directly above `short_values_are_replaced_only_as_whole_tokens`:

```rust
    /// A bare name, built at run time so this file never holds one literally.
    fn bare(n: usize) -> String {
        format!("$PIIF_SECRET_{n}")
    }

    /// A braced name, built the same way.
    fn braced(n: usize) -> String {
        format!("${{PIIF_SECRET_{n}}}")
    }
```

Add this test below the Step 1 test:

```rust
    #[tokio::test]
    async fn a_name_is_braced_when_a_letter_digit_or_underscore_follows() {
        let state = fake_state();
        let long = "known-value-of-twenty";
        with_session(&state, |session| {
            session.env.entry_for(long, "PASSWORD");
            session.env.entry_for(":pw!", "PASSWORD");
        });
        let (out, _) = replace_env_values(&state, &format!("{long}7 {long}_x {long}-x {long}"), "text");
        assert_eq!(out, format!("{b}7 {b}_x {n}-x {n}", b = braced(1), n = bare(1)));
        let (out, _) = replace_env_values(&state, "a:pw!b", "text");
        assert_eq!(out, format!("a{}b", braced(2)));
        let (out, _) = redact_text(&state, "TOKENx TOKEN", "text", "").await.unwrap();
        assert_eq!(out, format!("{}x {}", braced(3), bare(3)));
    }
```

The test has three parts. The first covers the env pass with a value of 16 or more characters, which is replaced anywhere. The second covers a short value with punctuation edges, which may touch a letter and so needs braces too. The third covers the detection pass.

**Verify**:

- `cargo test --release --bin piifence-gateway braced` → `test result: ok. 1 passed`
- `cargo test --release --bin piifence-gateway` → `ok`, 0 failed, and the passed count is the Step 0 count plus 2
- `grep -c 'format!("\${}", entry.name)' src/bin/gateway.rs` → `1` (only `audit_entry` is left)

### Step 3: Make the restore hook refuse a bare name that runs into a letter or `_`

In `src/bin/piifence.rs`, add this function directly above `fill_values`:

```rust
/// The first bare name in `text` that a letter, digit or `_` follows directly. A shell reads such a name as a longer, different variable, so the hook refuses it instead of guessing.
fn glued_name(pattern: &regex::Regex, text: &str) -> Option<String> {
    pattern.captures_iter(text).find_map(|caps| {
        let number = caps.get(2)?;
        let end = caps.get(0)?.end();
        text[end..]
            .starts_with(|c: char| c.is_alphanumeric() || c == '_')
            .then(|| format!("PIIF_SECRET_{}", number.as_str()))
    })
}
```

In `fill_values`, at the top of the `serde_json::Value::String(s) =>` arm, before `let mut missing = None;`, add:

```rust
                if let Some(name) = glued_name(&pattern, s) {
                    bail!("${name} runs into the text after it, so a shell would read a longer variable name; write ${{{name}}} instead");
                }
```

Add this sentence to the doc comment of `fill_values`: "So is a bare name that runs into a letter or `_` (`glued_name`)."

In the `mod tests` of `src/bin/piifence.rs`, add the same `bare` and `braced` helpers as in Step 2, directly above `fill_values_replaces_names_in_every_string`. Then add this test below `fill_values_rejects_an_unknown_name`:

```rust
    #[test]
    fn fill_values_rejects_a_bare_name_that_runs_into_a_letter_or_underscore() {
        let values = serde_json::json!({"PIIF_SECRET_1": "one"});
        let values = values.as_object().unwrap();
        for text in [format!("{}x", bare(1)), format!("{}_old", bare(1))] {
            let mut input = serde_json::json!({ "content": text });
            let err = fill_values(&mut input, values).unwrap_err();
            assert!(err.to_string().contains(&braced(1)), "{err}");
        }
        let mut input =
            serde_json::json!({"content": format!("{}-x {}x", bare(1), braced(1))});
        fill_values(&mut input, values).unwrap();
        assert_eq!(input["content"], "one-x onex");
    }
```

**Verify**: `cargo test --release --bin piifence` → `ok`, 0 failed, and the passed count is the Step 0 count for that binary plus 1. The existing `fill_values_replaces_names_in_every_string` must still pass: it uses a braced name followed by `x`, which stays allowed.

### Step 4: Make the env-reference guard match exactly one name, braced or bare

In `src/guards.rs:86`, replace the last alternative of the `env_ref` pattern, `\$PIIF_[A-Za-z0-9_]+`, with these three alternatives, in this order:

```
\$\{PIIF_[A-Za-z0-9_]+\}|\$PIIF_SECRET_[0-9]+|\$PIIF_[A-Za-z0-9_]+
```

Change nothing else on that line. The order matters. At each position the `regex` crate takes the first alternative that matches, so a bare secret name now ends at its last digit, and text glued after it is no longer part of the reference. Other variables, such as `$PIIF_UPSTREAM`, still match through the third alternative.

Add these two tests below `pif_env_reference_is_suppressed`. The second one fails before the change, because the old pattern swallows `tail`:

```rust
    #[test]
    fn braced_pif_env_reference_is_suppressed() {
        let g = guards();
        let reference = format!("${{PIIF_SECRET_{}}}", 1);
        let text = format!("use this API key {reference}x");
        let start = text.find(&reference).unwrap();
        assert_eq!(
            g.suppress(&text, start, text.len()),
            Some(Suppression::EnvReference)
        );
    }

    #[test]
    fn text_glued_after_a_bare_name_is_not_part_of_the_reference() {
        let g = guards();
        let reference = format!("$PIIF_SECRET_{}", 7);
        let text = format!("use {reference}tail now");
        let start = text.find(&reference).unwrap();
        let tail = start + reference.len();
        assert_eq!(
            g.suppress(&text, start, tail),
            Some(Suppression::EnvReference)
        );
        assert_eq!(g.suppress(&text, tail, tail + 4), None);
    }
```

**Verify**: `cargo test --release --lib -- braced_pif_env_reference text_glued_after_a_bare_name` → `test result: ok. 2 passed`. Then `cargo test --release --lib` → 0 failed.

### Step 5: Count braced names in the secret suite

In `tests/secrets/run.py:38`, change the pattern to:

```python
SECRET_NAME = re.compile(r"\$(?:\{PIIF_SECRET_\d+\}|PIIF_SECRET_\d+)")
```

**Verify**:

- `python3 -I tests/secrets/run.py --self-test` → three lines that start with `ok `, exit 0
- `python3 -I -c 'import sys; sys.path.insert(0, "tests/secrets"); import run; print(len(run.SECRET_NAME.findall("$" + "{PIIF_SECRET_" + "7}x and $" + "PIIF_SECRET_8")))'` → `2`

The second command builds the names by joining strings, so neither the shell nor the hook sees a literal name. Keep the single quotes.

### Step 6: Tell the agent and the developer notes about braces

In `src/bin/piifence.rs`, add a new bullet to `VARIABLES_NOTE` directly after the bullet shown in "Current state" (line 349). It goes on its own line, inside the same string literal:

```text
- When a letter, digit or `_` comes right after a name, piifence writes the name in braces, as in `${PIIF_SECRET_…}_old`. Keep the braces when you use the name, in commands and in files: without them, the shell reads a longer variable name that does not exist.
```

In `CLAUDE.md:35`, replace "a value under 16 characters only as a whole token (`WHOLE_TOKEN_BELOW`)." with "a value under 16 characters only as a whole token (`WHOLE_TOKEN_BELOW`: no letter or digit of the text may run into its first or last character when that character is a letter, digit, `-` or `_`). A name is written `${PIIF_SECRET_<N>}` when a letter, digit or `_` follows it (`name_token`), so the shell and `piifence restore` read the same name."

In `CLAUDE.md:42`, after "An unknown name or a gateway that does not answer exits 2, which blocks the call.", add "So does a bare name that a letter or `_` follows directly (`glued_name`), because a shell would read it as a longer variable name."

**Verify**: `grep -c 'piifence writes the name in braces' src/bin/piifence.rs` → `1`. `grep -c 'name_token' CLAUDE.md` → `1`. `grep -c 'glued_name' CLAUDE.md` → `1`.

### Step 7: Run every check

Run `scripts/check.sh --no-suite`, then the full checks from "Commands you will need".

**Verify**: both end with `check: all passed`. In the full run, the suite's summary line ends with `0 regressions, <n> fixed`. If it lists `FIXED (remove from expectations): <case>` lines, remove exactly those keys from `tests/secrets/expectations.json` and run the full checks again.

## Test plan

New tests:

- `src/bin/gateway.rs`, `a_short_value_cut_at_a_hyphen_or_underscore_is_not_replaced_inside_a_longer_token`. It covers a UUID's first group with its hyphen, a `-` prefixed group, `piifence-` before a letter, and `KEY_` before a letter. It also checks that the same values are still replaced when they stand alone, and that a whole value next to a hyphen still is.
- `src/bin/gateway.rs`, `a_name_is_braced_when_a_letter_digit_or_underscore_follows`. It covers the env pass for long values and for short values with punctuation edges, and the detection pass.
- `src/bin/piifence.rs`, `fill_values_rejects_a_bare_name_that_runs_into_a_letter_or_underscore`. It checks the rejection, that the error suggests the braced form, and that a hyphen after a bare name and a letter after a braced name still pass.
- `src/guards.rs`, `braced_pif_env_reference_is_suppressed` and `text_glued_after_a_bare_name_is_not_part_of_the_reference`.

Pattern: `short_values_are_replaced_only_as_whole_tokens` (`src/bin/gateway.rs:1520`) for the pure tests, `env_value_in_tool_output_becomes_its_name` (`src/bin/gateway.rs:1474`) for the async one, `fill_values_rejects_an_unknown_name` (`src/bin/piifence.rs:613`), and `pif_env_reference_is_suppressed` (`src/guards.rs:499`).

Verification: `cargo test --release` reports 0 failed, with 5 more tests in total than at Step 0.

## Done criteria

ALL must hold:

- [ ] `cargo fmt --check` exits 0
- [ ] `cargo clippy --release --all-targets -- -D warnings` exits 0
- [ ] `cargo test --release` exits 0, with the 5 new tests listed in "Test plan" passing
- [ ] `grep -c 'format!("\${}", entry.name)' src/bin/gateway.rs` prints `1`
- [ ] `grep -c 'fn name_token' src/bin/gateway.rs` prints `1` and `grep -c 'fn glued_name' src/bin/piifence.rs` prints `1`
- [ ] `python3 -I tests/secrets/run.py --self-test` exits 0
- [ ] The full checks end with `check: all passed`, and the suite reports `0 regressions`
- [ ] `git status --short` lists only files from the in-scope list (and `tests/secrets/expectations.json`, if Step 7 removed fixed entries)
- [ ] `plans/README.md` status row for 009 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The code at the locations in "Current state" does not match the excerpts.
- Step 0 fails: the baseline is broken before any change.
- A tool call is blocked with "cannot put secret values back into this tool call". Do not retry with another number: re-read "Before you start" and report which text held a literal name.
- After Step 2, an existing test fails because it expected a bare name directly before a letter, digit or `_`. No such line existed at `fc97e3d`, so this means the code has drifted.
- The full suite reports a regression for a case whose secret starts or ends with `-` or `_`. Step 1 trades that recall for precision, and a human must decide. Report the case ids.
- `grep -n 'format!("\$' src/bin/gateway.rs` shows a place that writes a name into provider-bound text other than the ones this plan changes.

## Maintenance notes

- Any new code that writes a name into provider-bound text must call `name_token`. A bare `format!("${}", …)` brings this bug back.
- `glued_name` makes the hook stricter. If users report calls blocked with "runs into the text after it", some code path still emits a bare name before a letter or `_`; find that path and route it through `name_token`.
- Values already stored for a conversation are not changed. One that ends in `-` or `_` stays named for 30 days, but after Step 1 it is replaced only where it stands alone.
- Deferred: detection precision. Why did a 9-character UUID prefix, `piifence-`, and a 4-digit number get names at all? A value that short should rarely be named, and once named it rewrites every matching token for the rest of the conversation.
- Deferred: an agent in a piifence session cannot write a literal name into a file, because the hook always substitutes it. That matters for this repo's own docs and tests.
- Review focus: the right-to-left loop in `redact_text` must read `out[span.end..]` (the final text), not `text[span.end..]`. Otherwise a span directly before another span gets braces it does not need.
