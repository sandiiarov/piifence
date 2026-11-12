# Plan 013: A secret's name never lands in a file, a command or a commit as text

Written against commit `2cd321e` on `main`. Priority P1, effort M.

Notation: in this plan, `NAME` stands for a secret's name, the text `PIIF_SECRET_` followed by digits, so `$NAME` is a name as the agent writes it and `${NAME}` its braced form. The plan never spells out a numbered name, because a session running through piifence would replace it with a real value. Do the same in everything you write: build names at run time in tests, and never type `$` + `PIIF_SECRET_` + digits into a file or a command.

## Why this matters

The agent only sees names, never the values. Two things turn a name back into its value: the shell, which expands `$NAME` from the exported variables, and the `PreToolUse` restore hook (`piifence restore`), which replaces names in the input of every tool except shell tools.

A name that neither of them touches reaches the file system or git as literal text. A real case from a user's session: the model flagged a Jira key as a secret, and the agent wrote a script with `git commit -m "\$NAME: bla bla"`. The backslash stops the shell from expanding the name, so the commit message held the name followed by `: bla bla`. The user accepts false positives, but not a name in code or a commit message.

Today these forms reach disk as text, or with a stray backslash:

| What the agent writes | Tool | Result today | Result after this plan |
|---|---|---|---|
| `"\$NAME: x"` in a file | Write, Edit, MCP | `"\value: x"` (stray backslash) | `"value: x"` |
| `'$NAME'` | Bash, Monitor | the name as text | `'value'` |
| `"\$NAME"` or `\$NAME` | Bash, Monitor | the name as text | the value |
| `<<'EOF'` body with `$NAME` | Bash, Monitor | the name as text | the value |
| `$'…$NAME…'` | Bash, Monitor | the name as text | the value |
| `"$NAME"`, `$NAME`, unquoted heredoc body | Bash, Monitor | the value (the shell expands it) | unchanged |

## Current state

`src/bin/piifence.rs` (930 lines). The hook skips shell tools entirely:

```rust
const SHELL_TOOLS: &[&str] = &["Bash", "PowerShell", "Monitor"];
```

```rust
    if SHELL_TOOLS.contains(&tool) {
        return Ok(None);
    }
    let mut tool_input = hook
        .get("tool_input")
        .context("the hook input has no tool_input")?
        .clone();
    if !names_in(&tool_input) {
        return Ok(None);
    }
    let values = session_values(session, port)?;
    fill_values(&mut tool_input, &values)?;
    Ok(Some(tool_input))
```

`name_pattern()` is `r"\$(?:\{PIIF_SECRET_(\d+)\}|PIIF_SECRET_(\d+))"`. It ignores what comes before the `$`, so `\$NAME` becomes `\value`. `fill_values` replaces every match in every string of the tool input, refuses an unknown name, and refuses a bare name that a letter, digit or `_` follows (`glued_name`, from plan 009), telling the agent to write braces.

The tests module (`mod tests` near the end of the file) builds names at run time with `bare(n)` and `braced(n)`, so the source never holds a name literally. Follow that pattern in every new test; see `fill_values_rejects_a_bare_name_that_runs_into_a_letter_or_underscore`.

`VARIABLES_NOTE` (the text the agent gets at session start) currently ends its first bullet with: "Single quotes and quoted heredocs (`<<'EOF'`) stop the shell from expanding it."

## Decisions (already made; do not revisit)

1. A name the shell will expand is left alone. The shell already gives the right value, and a raw value would only add quoting risk.
2. A name the shell will not expand gets the value, escaped for the place it is in, so the command means what the agent meant.
3. A backslash that escapes the `$` of a name is part of the name's text: `\$NAME` and `\${NAME}` become the value, in every tool. An even number of backslashes does not escape the `$`; then the backslashes stay and only the name is replaced (Write/Edit/MCP), or the shell expands it (Bash).
4. When the hook cannot tell which kind of place a name is in (unclosed quote, unclosed heredoc, unbalanced `$(`), it blocks the call (exit 2) with a message that says to write the name in double quotes or an unquoted heredoc. It never lets a command run with a name it could not place.
5. A name without `$` (`NAME` alone) is left alone. Code legitimately reads the variables by key (`os.environ["…"]`), and the agent is told to always write the `$`.
6. PowerShell stays skipped. Out of scope.
7. A nested `claude -p` started from a Bash command inherits the parent's session header and has none of the launcher's hooks. Out of scope here; it is a follow-up in `plans/README.md`.

## Scope

In scope:
- New `src/shellfill.rs` (library module, exported from `src/lib.rs`): the shell scanner and its tests.
- `src/bin/piifence.rs`: `name_pattern`, `fill_values`, `glued_name`, `restored_input`, `SHELL_TOOLS`, `VARIABLES_NOTE`, and tests.
- Docs: `README.md`, `CLAUDE.md`, and the module doc at the top of `src/bin/piifence.rs`, wherever they say shell tools are skipped or that single quotes and quoted heredocs stop expansion. Find them with `git grep -n -i -E 'quoted heredoc|Shell tools|Bash, PowerShell|PowerShell and Monitor'`.

Out of scope: `src/bin/gateway.rs`, the detectors, the notice plugin, `tests/secrets`, `Cargo.toml` (no new crates).

## Steps

### Step 1: `\$NAME` in Write, Edit and MCP input

Change `name_pattern()` to capture the backslashes directly before the `$`: `r"(\\*)\$(?:\{PIIF_SECRET_(\d+)\}|PIIF_SECRET_(\d+))"`. Update every user of the capture groups (`fill_values`, `glued_name`; braced is now group 2, bare group 3). In `fill_values`, when the count of captured backslashes is odd, drop one of them and keep the rest. Keep the unknown-name and glued-name errors as they are.

Add tests, built with `bare`/`braced`:
- `\` + `bare(1)` + `: x` becomes `one: x`; the same with `braced(1)`.
- two backslashes + `bare(1)` becomes two backslashes + `one`; three backslashes + `bare(1)` becomes two backslashes + `one`.
- the existing tests still pass unchanged.

Verify: `cargo test --release --bin piifence fill_values` passes.

### Step 2: the shell scanner, `src/shellfill.rs`

Public API:

```rust
/// `command` with every name that the shell would not expand replaced by its value, escaped for the place it is in. `Ok(None)` when nothing changes.
pub fn fill_command(command: &str, value_of: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Option<String>>
```

`value_of` gets a variable name without the `$` (`PIIF_SECRET_` + digits) and returns its value. Keep the module free of I/O.

Scan the command once, left to right, with a stack of contexts. Rules, by context:

| Context | Starts at | Ends at | `$NAME` / `${NAME}` | `\$NAME` / `\${NAME}` (odd backslashes) |
|---|---|---|---|---|
| plain (top level, inside `$(…)` and backticks) | start | end, the `)` of its `$(`, the closing backtick | leave | the value in single quotes: `'` + v with each `'` → `'\''` + `'` |
| double quotes | `"` | unescaped `"` | leave | v with `\`, `$`, `` ` ``, `"` each preceded by `\` |
| single quotes | `'` | next `'` | v with each `'` → `'\''` | same, replacing the backslash too |
| ANSI-C `$'…'` | `$'` | unescaped `'` | v with `\` → `\\`, `'` → `\'` | same, replacing the backslash too |
| heredoc body, unquoted delimiter | the line after `<<WORD` / `<<-WORD` | a line equal to WORD (`<<-`: after stripping leading tabs) | leave | v with `\`, `$`, `` ` `` each preceded by `\` |
| heredoc body, quoted delimiter (`'EOF'`, `"EOF"`, `\EOF`, any quote in the word) | same | same | v raw | v raw, replacing the backslash too |
| comment (`#` at the start of a word in plain context) | `#` | newline | leave | leave |

More rules:
- Inside double quotes, `\` escapes the next character only if it is `$`, `` ` ``, `"`, `\` or a newline. In plain context `\` escapes any character. Inside single quotes `\` is literal.
- `$(` pushes a plain context in any context except single quotes, ANSI-C and quoted heredoc bodies; `$((` counts as `$(`. Inside it, count `(` and `)` (outside quotes) to find its end. A backtick pushes or pops a plain context the same way.
- `<<<` is a here-string, not a heredoc: its word is scanned as normal plain text.
- Several heredocs on one line are read in order after that line's newline.
- A bare name in a replacing context that a letter, digit or `_` follows directly is an error that tells the agent to write braces (same message as `glued_name`). A braced name may be followed by anything.
- A name in a replacing context whose value `value_of` does not know is an error naming it. A name in a leaving context is never looked up.
- A value containing a newline, in a quoted heredoc body, is an error.
- At the end of the command, an open quote, open `$(`, open backtick or a heredoc without its end line is an error, but only when the command holds at least one name. Without a name, return `Ok(None)`.

Keep it one function plus small helpers, about 200–300 lines without tests. If the scanner grows past 400 lines, STOP and report.

### Step 3: tests for the scanner, in `src/shellfill.rs`

Build names at run time, as `bare(n)`/`braced(n)` do in `src/bin/piifence.rs` (copy the two helpers). Below, `N` means `bare(1)`. Use a test value that needs escaping everywhere: a single quote, double quotes, a `$HOME`, backticks around `x` and a backslash, for example built as `format!("it's \"$HOME\" `x` \\ end")` with the backticks escaped as Rust needs.

1. **Run-it test (the main one).** For each command below, call `fill_command`, then run the result with `/bin/bash -c` (via `std::process::Command`), with an env holding `PIIF_SECRET_1` = the test value and `HOME=/nowhere`. Assert that stdout equals the expected text exactly, and that it never contains `PIIF_SECRET`. Commands:
   - `printf %s "N"` → the value (left alone; the shell expands it)
   - `printf %s 'N'` → the value
   - `printf %s "\N: bla"` → the value + `: bla` (the user's case)
   - `printf %s \N` → the value
   - `printf %s $'N'` → the value
   - `cat <<'EOF'`, a line `N: init`, `EOF` → the value + `: init` + newline; also with `<<"EOF"`, `<<\EOF`, and `<<-'EOF'` with a tab-indented body and end line
   - `cat <<EOF`, a line `\N`, `EOF` → the value + newline; and `cat <<EOF`, a line `N`, `EOF` left alone
   - `printf %s "$(printf %s 'N')"` → the value
   - ``printf %s "`printf %s 'N'`"`` → the value
   - `printf %s "a \" 'N' \""` → `a " '` + value + `' "` (the single quotes are inside double quotes, so the name is left alone)
   - `printf %s "\\N"` → `\` + value (two backslashes, so the shell expands the name)
   - `cat <<<'N'` → the value + newline
   - two quoted heredocs in one command, each with a name
   - a comment line `# it's 'N'`, then a line `printf %s 'N'` → the value (the comment's quote does not confuse the scanner)
2. **Exact-text tests**, no shell: `git commit -m "\N: bla bla"` becomes `git commit -m "` + the value escaped for double quotes + `: bla bla"`; a command without names returns `None`; `printf %s "N"` returns `None`.
3. **Errors:** an unknown name in single quotes; a glued name in single quotes (`'N_old'`) with the braces hint, while `'` + `braced(1)` + `_old'` is accepted; an unclosed `'` with a name; a heredoc without its end line, with a name; a newline in a value inside a quoted heredoc. An unknown name inside double quotes is not an error.

Verify: `cargo test --release --lib shellfill` passes.

### Step 4: use it in the hook

In `restored_input`: for `Bash` and `Monitor`, if `tool_input.command` is a string holding a name (the same check as `names_in`), fetch the values (`session_values`), call `shellfill::fill_command` with a closure over them, and return the tool input with only `command` replaced. Leave the other fields, such as `description`, unchanged. Return `None` when `fill_command` returns `None`. An error goes through the existing path: exit 2, message on stderr. `PowerShell` stays skipped. Update the doc comments of `SHELL_TOOLS`, `restore` and `restored_input` so they match what the hook now does.

Verify: `cargo test --release` passes, then `cargo clippy --release --all-targets -- -D warnings` and `cargo fmt --check`.

### Step 5: tell the agent

In `VARIABLES_NOTE`, replace the last sentence of the first bullet ("Single quotes and quoted heredocs (`<<'EOF'`) stop the shell from expanding it.") with:

"Where the shell would not expand a name (single quotes, quoted heredocs such as `<<'EOF'`), piifence puts the value in before the command runs, so a commit message or a file written from a command gets the value too. Never put a backslash before a name to keep it as text: the name stands for the value, and piifence fills in the value there as well."

Keep the bullet's other sentences. The note's existing lines hold example names; do not retype them. Edit with a Python script that matches the old sentence and swaps in the new one.

### Step 6: docs

Update the README, CLAUDE.md and the module doc in `src/bin/piifence.rs` (found with the grep in Scope) so they say: the restore hook also handles Bash and Monitor commands, filling values in only where the shell would not expand a name; PowerShell is skipped; a backslash before a name's `$` counts as part of the name. One or two sentences per place. Never hard-wrap prose.

### Step 7: full check

Run `scripts/check.sh` in the foreground (Bash timeout 600000) with `PIIF_MODEL_DIR` set to the model dir: `$(brew --prefix)/opt/piifence/share/piifence/model`. Expected last lines: `1119/1122 passed, 3 known gaps, 0 regressions, 0 fixed` and `check: all passed`.

## Done criteria

- `cargo fmt --check` exits 0.
- `cargo clippy --release --all-targets -- -D warnings` exits 0.
- `cargo test --release` exits 0, and the shellfill tests and the new `fill_values` tests are among those that ran.
- `scripts/check.sh` full run: `0 regressions`, `check: all passed`.
- `git grep -n 'stop the shell from expanding it' -- src` prints nothing.
- `git grep -n -E '\$\{?PIIF_SECRET_[0-9]' -- src/shellfill.rs` prints nothing (tests build names at run time).
- `git diff --stat` plus untracked files touch only: `src/shellfill.rs` (new), `src/lib.rs`, `src/bin/piifence.rs`, `README.md`, `CLAUDE.md`.

## STOP conditions

- The excerpts in "Current state" do not match the code.
- The scanner passes 400 lines, or a test case can only pass by special-casing that one command.
- A run-it test shows the shell expanding something inside a value the scanner put in (for example the `$HOME` in the test value). That means an escaping rule is wrong; report the case instead of loosening the test.
- `scripts/check.sh` reports a regression.

## Maintenance notes

- The scanner models bash quoting closely enough for commands an agent writes, not every bash construct. When a real command is blocked by the fallback, add it as a run-it test case first.
- If Claude Code adds another shell-like tool, add it next to Bash and Monitor.
- Follow-up (not this plan): a nested `claude -p` started from a Bash command inherits the parent's `x-piifence-session` header and has no hooks, so it writes names as text. Fixing it means checking how Claude Code passes its settings env to child processes.
