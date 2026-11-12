# Plan 014: A `claude` started from inside a piifence session gets piifence's hooks

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving to the next step. If anything in the "STOP conditions" section occurs, stop and report; do not improvise. When done, update the status row for this plan in `plans/README.md`, unless a reviewer dispatched you and told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat f6ce155..HEAD -- src/bin/piifence.rs README.md CLAUDE.md`
> If any in-scope file changed since this plan was written, compare the "Current state" excerpts against the live code before proceeding; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none (013 is DONE and this builds on it)
- **Category**: security
- **Planned at**: commit `f6ce155`, 2026-11-12
- **Finding**: NESTED-01 in `plans/README.md`

Notation: in this plan, `NAME` stands for a secret's name, the text `PIIF_SECRET_` followed by digits, so `$NAME` is a name as the agent writes it. The plan never spells out a numbered name, because a session running through piifence would replace it with a real value. Do the same in everything you write: build names at run time in tests (the tests module has `bare(n)` and `braced(n)` helpers), and never type `$` + `PIIF_SECRET_` + digits into a file or a command.

## Why this matters

`piifence claude` starts Claude Code with a `--settings` file that adds two hooks: `SessionStart` (tells the agent about names and makes Bash commands export the values) and `PreToolUse` (`piifence restore`, which puts the real value in place of a name in every tool's input). Those hooks are what stop a name from landing in a file or a commit as text.

An agent in a piifence session can start another Claude Code from a Bash command, for example `claude -p "…"` inside a script. That child inherits the parent's environment, including `ANTHROPIC_BASE_URL` (the gateway) and `ANTHROPIC_CUSTOM_HEADERS` (with the parent's `x-piifence-session` id). So the child talks to the gateway as the parent session and sees names instead of values. But it does not get the `--settings` file, so it has no hooks: when it writes a name with the Write tool, or in single quotes in a command, the name lands as text. That is the bug plan 013 fixed for the top-level session, and this plan fixes it for nested ones.

Checked on 2026-11-12 from a Bash command inside a piifence session: `ANTHROPIC_BASE_URL=http://127.0.0.1:7788`, `ANTHROPIC_CUSTOM_HEADERS=x-piifence-session: <32 hex digits>`, `PIIF_GATEWAY_SOCKET`, `PIIF_DATA_DIR` and the `PIIF_SECRET_<N>` variables are all set, and Claude Code ran the command as `zsh -c 'source <snapshot> && eval "$('<piifence>' env <session> <port>)" && <command>'`. So whatever `piifence env` prints is in force for the command, after the user's shell snapshot.

## Design (decided; do not revisit)

1. **A `claude` shim on `PATH`.** `piifence session-start` installs an executable `claude` script in `$PIIF_STATE_DIR/bin` (default `~/.local/state/piifence/bin`). `piifence env` prints a line that puts that directory first on `PATH`, once. So a command or script that runs `claude` by name runs the shim, which runs `piifence nested-claude <args>`.
2. **`piifence nested-claude` reuses the parent's session.** It reads the session id from `ANTHROPIC_CUSTOM_HEADERS` and the port from `ANTHROPIC_BASE_URL`, writes a settings file with the same `env` values and the same two hooks, and runs the real `claude` with `--settings` and `--plugin-dir`. It starts no gateway and takes no lease: the parent's launcher holds one. The nested session must use the parent's session, because the agent passes it names from the parent and those names must stand for the same values.
3. **The nested `SessionStart` hook does not bind.** Today `session-start` calls `bind_conversation`, and the gateway (`src/bin/gateway.rs:413`) then moves the session to that conversation id: it sets `session.conversation` to it and saves names under it from then on. A nested child doing that would take the parent's names table away from the parent's conversation. So the nested hook runs `session-start <session> <port> nested`, which does everything except `bind_conversation`.
4. **When the shim can't protect the child, the child does not run.** If the environment says a piifence session is active (both variables parse) but the gateway does not answer, or the arguments include `--settings` (piifence must supply its own), `nested-claude` exits non-zero with a message. If the environment does not name a piifence session at all, the shim runs the real `claude` unchanged.
5. **Not covered, and documented as a limitation:** a child started by absolute path (`/Users/x/.local/bin/claude`), by a shell alias or function that does not go through `PATH`, or by the Agent SDK with its own bundled executable.
6. `~/.claude/settings.json` is never edited. That is a documented promise in `CLAUDE.md` ("never edits `~/.claude/settings.json`").

## Current state

All code is in `src/bin/piifence.rs` (about 940 lines). Line numbers are from `f6ce155`.

Command dispatch, `main`, lines 30–47:

```rust
    let result = match args.first().map(String::as_str) {
        Some("claude") => run_claude(&args[1..]),
        // Run by Claude Code, not by people: the hook and the line it writes.
        Some("session-start") => session_start(&args[1..]),
        Some("env") => print_env(&args[1..]),
        Some("restore") => restore(&args[1..]),
```

`run_claude` (line 119) rejects a user `--settings`, resolves the upstream, makes a random 32-hex session id with `new_session_id()` (line 418), calls `ensure_gateway`, then `run_session`. `run_session`, lines 251–273:

```rust
fn run_session(
    gateway_url: &str,
    port: u16,
    plugin: &Path,
    args: &[String],
    session_id: &str,
) -> Result<i32> {
    let socket = control_socket(port)?;
    let settings_path = write_settings_override(gateway_url, port, session_id)
        .context("cannot write the session settings")?;
    let claude = env::var("CLAUDE_BIN").unwrap_or_else(|_| "claude".to_string());
    let status = Command::new(&claude)
        .arg("--settings")
        .arg(&settings_path)
        .arg("--plugin-dir")
        .arg(plugin)
        .args(args)
        .env("PIIF_GATEWAY_SOCKET", &socket)
        .status();
    let _ = fs::remove_file(&settings_path);
```

`session_hooks(port, session_id)`, line 440, builds `{"SessionStart": … "<exe> session-start <session> <port>" …, "PreToolUse": [{"matcher": "*", … "<exe> restore <session> <port>"}]}`, where `exe` is `shell_quote(&real_exe()?.to_string_lossy())`.

`write_settings_override(gateway_url, port, session_id)`, line 455, writes `env::temp_dir().join(format!("piifence-claude-settings-{session_id}.json"))` with `create_new(true)` and mode `0o600`, holding `{"env": {"ANTHROPIC_BASE_URL": gateway_url, "ANTHROPIC_CUSTOM_HEADERS": custom_headers(session_id)?}, "hooks": session_hooks(port, session_id)?}`. Because of `create_new` and a name that holds only the session id, a nested child using the same session id would fail to create its file while the parent's still exists. Step 1 fixes that.

`session_args(args)`, line 491, accepts exactly `[session, port]` and checks the session is 32 hex digits.

`session_start(args)`, line 505: reads the hook JSON from stdin (it has `session_id`, Claude Code's conversation id), builds the env line `eval "$('<exe>' env <session> <port>)"`, writes it into `CLAUDE_ENV_FILE` through `env_file_with` (which drops earlier piifence env lines), calls `bind_conversation(session, port, conversation)?`, and prints the hook answer with `VARIABLES_NOTE` as `additionalContext`.

`print_env(args)`, line 580:

```rust
fn print_env(args: &[String]) -> Result<i32> {
    let (session, port) = session_args(args)?;
    print!("{}", export_lines(&session_values(session, port)?));
    Ok(0)
}
```

`session_values(session, port)`, line 724, asks the gateway's control socket for the session's values and errors when the gateway does not answer. `control_socket(port)` uses `piifence::control::state_dir()` (`src/control.rs:10`: `$PIIF_STATE_DIR`, else `$HOME/.local/state/piifence`). `shell_quote(value)`, line 771, single-quotes a string for the shell. `existing(path, what)`, line 90, errors when a path does not exist. `data_dir()`, line 69, reads `PIIF_DATA_DIR`.

Conventions to match:

- Errors use `anyhow` with `.context(...)`/`.with_context(...)` and `bail!`; messages are lowercase sentences that say what to do. See `run_claude`.
- Every `fn` has a `///` doc comment of one or two sentences. Do not add other comments.
- Tests live in `mod tests` at the end of the file. Temporary files use `env::temp_dir()` with the process id in the name, as at about line 932 (`format!("piif-test-{}-{n}.sock", std::process::id())`). There is no `tempfile` crate; do not add one.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --check` | exit 0 |
| Lint | `cargo clippy --release --all-targets -- -D warnings` | exit 0 |
| Unit tests | `cargo test --release --bin piifence` | all pass |
| All tests | `cargo test --release` | all pass |

## Scope

**In scope** (the only files you should modify):

- `src/bin/piifence.rs`
- `README.md` (two bullets, Step 7)
- `CLAUDE.md` (two sentences, Step 7)
- `plans/README.md` (the status row and the NESTED-01 row)

**Out of scope** (do not touch):

- `src/bin/gateway.rs`: binding stays as it is; the nested hook simply does not call it.
- `src/shellfill.rs` and the `restore` logic: the nested session reuses them unchanged.
- `Formula/piifence.rb`, `scripts/install.sh`: the shim is created at run time, not at install time.
- `~/.claude/settings.json` and anything else under `~/.claude/`, except what Claude Code itself writes during the manual check.
- Leases (`ensure_gateway`, `lease`): a nested child takes none.

## Git workflow

- Work on the branch you were given, or `fix/nested-claude-hooks` if none.
- One commit for the code and tests, one for the docs and the plan index. Message style from `git log`: an imperative summary under 60 characters, such as "Keep hook and env paths stable across brew upgrade", then a bullet body, then `Co-authored-by: Claude <noreply@anthropic.com>`.
- Do not push unless told to.

## Steps

### Step 1: Give every settings file a name of its own

In `write_settings_override`, name the file with the session id plus a fresh random id, so two Claude Code processes on one session never collide:

```rust
let nonce = new_session_id().context("cannot create a settings file name")?;
let path = env::temp_dir().join(format!("piifence-claude-settings-{session_id}-{nonce}.json"));
```

**Verify**: `cargo test --release --bin piifence` → all pass.

### Step 2: Let the settings and hooks describe a nested session

1. Change `session_hooks(port, session_id)` to `session_hooks(port, session_id, nested: bool)`. When `nested` is true, the `SessionStart` command ends in ` nested`: `"{exe} session-start {session_id} {port} nested"`. `PreToolUse` is the same in both cases.
2. Change `write_settings_override(gateway_url, port, session_id)` to `write_settings_override(gateway_url, port, session_id, headers: &str, nested: bool)`. Use `headers` as the `ANTHROPIC_CUSTOM_HEADERS` value instead of calling `custom_headers` inside, and pass `nested` to `session_hooks`.
3. Change `run_session` to take `headers: &str` and `nested: bool` after `session_id`, and pass them to `write_settings_override`. Also give it a `claude: &OsStr` (or `&Path`) parameter instead of reading `CLAUDE_BIN` inside; `run_claude` passes `env::var_os("CLAUDE_BIN").unwrap_or_else(|| "claude".into())`, so its behaviour is unchanged.
4. In `run_claude`, call `run_session(&gateway_url, port, &plugin, args, &session_id, &custom_headers(&session_id)?, false, &claude)` (any argument order you like, as long as it is consistent).

**Verify**: `cargo clippy --release --all-targets -- -D warnings` → exit 0, and `cargo test --release --bin piifence` → all pass.

### Step 3: `session-start … nested` skips the bind

Add a pure helper and use it at the top of `session_start`:

```rust
/// `args` without a trailing `nested`, and whether it was there. The hook of a `claude` started inside a piifence session passes it, so that session does not take over the parent's conversation binding.
fn split_nested(args: &[String]) -> (&[String], bool) {
    match args {
        [rest @ .., last] if last == "nested" => (rest, true),
        _ => (args, false),
    }
}
```

In `session_start`, call `let (args, nested) = split_nested(args);` before `session_args(args)`, and call `bind_conversation(...)` only when `!nested`. Everything else (the env line, the shim from Step 4, the note) runs in both cases. Update `session_start`'s doc comment to say that a nested session does not bind.

**Verify**: `cargo test --release --bin piifence` → all pass (tests come in the Test plan).

### Step 4: Install the shim

Add:

```rust
/// Where `piifence session-start` puts the `claude` shim: `bin` in piifence's state directory.
fn shim_dir() -> Result<PathBuf> {
    Ok(piifence::control::state_dir()?.join("bin"))
}

/// The `claude` shim, which runs `piifence nested-claude` through `exe`.
fn shim_script(exe: &Path) -> String {
    format!("#!/bin/sh\nexec {} nested-claude \"$@\"\n", shell_quote(&exe.to_string_lossy()))
}
```

and `fn install_shim(dir: &Path, exe: &Path) -> Result<()>` that:

1. creates `dir` with `fs::DirBuilder::new().recursive(true).mode(0o700)` (`use std::os::unix::fs::DirBuilderExt;`),
2. returns `Ok(())` when `dir/claude` already holds exactly `shim_script(exe)`,
3. otherwise writes `shim_script(exe)` to `dir/claude.<process id>.tmp` with mode `0o755` (`OpenOptionsExt::mode`), then `fs::rename`s it to `dir/claude`. The rename makes the swap atomic when several sessions start at once.

Call `install_shim(&shim_dir()?, &real_exe()?)` in `session_start`, before the env file is written. An error there is an error of the hook (exits non-zero, Claude Code shows it).

**Verify**: `cargo test --release --bin piifence` → all pass.

### Step 5: `piifence env` puts the shim first on `PATH`

Add:

```rust
/// A shell line that puts `dir` first on `PATH` unless it is already there, so running it twice adds it once. `piifence env` prints it, so a `claude` that a command starts by name is the shim.
fn path_line(dir: &Path) -> String {
    let dir = shell_quote(&dir.to_string_lossy());
    format!("case \":$PATH:\" in *:{dir}:*) ;; *) PATH={dir}:\"$PATH\"; export PATH ;; esac\n")
}
```

In `print_env`, print `path_line(&shim_dir()?)` before the export lines, and before asking the gateway for values, so the line is there even when the gateway does not answer.

**Verify**: `cargo test --release --bin piifence` → all pass.

### Step 6: Add `piifence nested-claude`

1. A pure parser:

```rust
/// The session id and port of the piifence session named by `ANTHROPIC_CUSTOM_HEADERS` (`headers`) and `ANTHROPIC_BASE_URL` (`base_url`), or None when they do not name one.
fn nested_session(headers: Option<&str>, base_url: Option<&str>) -> Option<(String, u16)>
```

   - `headers` is newline-separated `Name: value` lines. Find the line whose name, trimmed and compared case-insensitively, is `x-piifence-session`. Its value, trimmed, must be 32 hex digits.
   - `base_url`, after removing one trailing `/`, must be `http://127.0.0.1:<port>` with a port that parses as `u16`.
   - Both are needed; otherwise return `None`.

2. A pure lookup of the real `claude`:

```rust
/// The first executable `claude` on `path` (a `PATH` value) that is not in `shim_dir`, comparing directories by their real paths.
fn find_claude(path: &OsStr, shim_dir: &Path) -> Option<PathBuf>
```

   Use `env::split_paths`. Skip an entry whose `fs::canonicalize` equals `fs::canonicalize(shim_dir)`. Also skip a candidate whose `fs::canonicalize` equals that of `shim_dir/claude`, so a symlink to the shim does not count. A candidate counts when it is a file and `metadata.permissions().mode() & 0o111 != 0`.

3. `fn run_nested_claude(args: &[String]) -> Result<i32>`:
   1. `let claude = match env::var_os("CLAUDE_BIN") { Some(bin) => PathBuf::from(bin), None => find_claude(&env::var_os("PATH").unwrap_or_default(), &shim_dir()?).context("cannot find the real `claude` on PATH")? };`
   2. If `nested_session(env::var("ANTHROPIC_CUSTOM_HEADERS").ok().as_deref(), env::var("ANTHROPIC_BASE_URL").ok().as_deref())` is `None`, run `claude` with `args` unchanged (`Command::new(&claude).args(args).status()`) and return its exit code (`code().unwrap_or(1)`).
   3. If `args` contains `--settings` or an argument starting with `--settings=`, `bail!("piifence cannot add its hooks to a claude that is given --settings inside a piifence session; drop --settings")`.
   4. Call `session_values(&session, port).context("the piifence gateway for this session does not answer, so a claude started here would run without piifence's hooks")?` to check the gateway knows the session. Discard the values.
   5. `let plugin = existing(data_dir()?.join("plugin/piifence-notice"), "the notice plugin")?;`
   6. Call `run_session(&format!("http://127.0.0.1:{port}"), port, &plugin, args, &session, &env::var("ANTHROPIC_CUSTOM_HEADERS")?, true, &claude)`. The headers go through unchanged, because they already hold the user's own headers plus the session header.

4. In `main`, under the "Run by Claude Code, not by people" comment, add `Some("nested-claude") => run_nested_claude(&args[1..]),`. Do not add it to `usage()`.

**Verify**: `cargo fmt --check` → exit 0; `cargo clippy --release --all-targets -- -D warnings` → exit 0; `cargo test --release` → all pass.

### Step 7: Document it

1. `README.md`, section "How it works": after the bullet that starts with `- **A \`PreToolUse\` hook**`, add:

   `- **A \`claude\` started inside the session gets the same hooks.** \`piifence env\` puts a small \`claude\` script from \`~/.local/state/piifence/bin\` first on \`PATH\`, so a command or script that runs \`claude -p …\` starts it with the session's hooks. That session shares the parent's names and does not take over the parent's saved names.`

2. `README.md`, section "Limitations": before the bullet that starts with `- **It runs on macOS only`, add:

   `- **A \`claude\` started some other way runs without the hooks.** That is a \`claude\` started by its full path, by a shell alias that doesn't go through \`PATH\`, or by the Agent SDK. It still goes through the gateway, but it writes a \`$PIIF_SECRET_<N>\` name in a file as text.`

3. `CLAUDE.md`: on the line listing the launcher's commands (it starts with `- Launcher (\`src/bin/piifence.rs\`, binary \`piifence\`)`), add `piifence nested-claude` to the list. At the end of the bullet that starts with `- \`piifence session-start <session> <port>\``, add: `It also installs the \`claude\` shim in \`$PIIF_STATE_DIR/bin\`, and \`piifence env\` prints a line that puts that directory first on \`PATH\`. The shim runs \`piifence nested-claude\`, which reads the session from \`ANTHROPIC_CUSTOM_HEADERS\` and the port from \`ANTHROPIC_BASE_URL\`, and runs the real \`claude\` (first on \`PATH\` outside the shim directory, or \`CLAUDE_BIN\`) with the same hooks, the \`SessionStart\` one as \`session-start <session> <port> nested\`, which skips the conversation binding. No lease is taken.`

Write each paragraph on one line; do not hard-wrap.

**Verify**: `grep -c 'nested-claude' CLAUDE.md` → at least 1; `grep -c 'started inside the session' README.md` → 1.

### Step 8: Update the index

In `plans/README.md`, set the status of the 014 row to DONE.

## Test plan

Add these tests to `mod tests` in `src/bin/piifence.rs`, modelled on `env_file_keeps_only_the_current_piifence_line`:

1. `split_nested_takes_a_trailing_nested`: `["s","p","nested"]` → (`["s","p"]`, true); `["s","p"]` → (same, false); `["nested","s","p"]` → (same, false).
2. `nested_hooks_skip_the_bind`: `session_hooks(7788, &"a".repeat(32), true)`'s `SessionStart` command ends with ` nested`; with `false` it ends with ` 7788`. The `PreToolUse` command is the same in both.
3. `nested_session_reads_the_parent_session`:
   - headers `"X-Other: 1\nx-piifence-session: <32 a's>"` and base url `"http://127.0.0.1:7788/"` → `Some((32 a's, 7788))`;
   - header name in another case (`X-Piifence-Session`) → still found;
   - 31 hex digits → `None`; a base url of `https://api.anthropic.com` → `None`; either side `None` → `None`.
4. `find_claude_skips_the_shim`: under `env::temp_dir().join(format!("piif-test-find-{}", std::process::id()))`, create `shim/claude` and `real/claude` (both mode 0o755) and `plain/claude` (mode 0o644). `find_claude` on `shim:plain:real` (joined with `env::join_paths`) → `real/claude`. Also make `link/claude` a symlink to `shim/claude`, and check that `link:real` → `real/claude`. Remove the directory at the end.
5. `install_shim_writes_once`: `install_shim` into a fresh temp dir writes `claude` with mode `0o755` and content `shim_script(exe)`. A second call leaves the modification time unchanged, and a call with a different `exe` replaces the content.
6. `path_line_adds_the_directory_once`: for a directory path containing a space (for example `/tmp/piif test/bin`), run `Command::new("/bin/sh").arg("-c").arg(format!("PATH=/usr/bin; {line}{line}printf %s \"$PATH\""))` and check the output is `/tmp/piif test/bin:/usr/bin`. Run the same with `/bin/zsh`, since Claude Code runs Bash commands through the user's shell.
7. `nested_settings_keep_the_headers`: `write_settings_override("http://127.0.0.1:7788", 7788, &"a".repeat(32), "X-Mine: 1\nx-piifence-session: …", true)`: read the file back as JSON, check `env.ANTHROPIC_CUSTOM_HEADERS` is the string passed in and the `SessionStart` command ends with ` nested`. Two calls with the same session id give two different paths. Delete the files.

**Verify**: `cargo test --release --bin piifence` → all pass, including the 7 new tests.

## Manual check (for the reviewer, inside a running `piifence claude` session)

These need a real Claude Code session and a model call, so they are not automated. Run each command from the session's Bash tool after installing the new build (for a Homebrew install, `brew upgrade --fetch-HEAD piifence`, then restart the session).

1. `bash -c 'command -v claude'` → `$HOME/.local/state/piifence/bin/claude`.
2. `claude -p 'Reply with the single word ok.'` → `ok`, with no error from a hook.
3. `ls -t ~/.claude/session-env | head -1` gives the nested conversation's id; `grep -c "' env " ~/.claude/session-env/<that id>/*.sh` → 1.
4. `ls ~/.local/state/piifence/names/<that id>` → "No such file or directory", which shows the nested session did not bind.
5. Pick a name `$NAME` that the parent session already has. Run `claude -p 'Use the Write tool to write exactly this text into /tmp/piif-nested-check.txt: $NAME' --allowedTools Write`, in single quotes so the parent's shell passes the name through. Then `grep -c PIIF_SECRET_ /tmp/piif-nested-check.txt` → 0, and remove the file.

## Done criteria

- [ ] `cargo fmt --check` exits 0
- [ ] `cargo clippy --release --all-targets -- -D warnings` exits 0
- [ ] `cargo test --release` exits 0, including the 7 new tests
- [ ] `grep -n '"nested-claude"' src/bin/piifence.rs` shows the dispatch line in `main`
- [ ] `git status` shows changes only to `src/bin/piifence.rs`, `README.md`, `CLAUDE.md` and `plans/README.md`
- [ ] `plans/README.md` shows 014 as DONE

## STOP conditions

Stop and report if:

- The excerpts in "Current state" do not match the code.
- Step 2 of the manual check shows that Claude Code does not run `SessionStart` or `PreToolUse` hooks from a `--settings` file in `-p` mode. The design depends on it.
- In the manual check, `command -v claude` from a Bash command does not print the shim, though `piifence env` prints the `PATH` line. That would mean Claude Code runs the command before the env file or resets `PATH` afterwards.
- `bind_conversation` turns out to be needed by something other than saving names (for example, the notice plugin needs it). Then skipping it in nested sessions may break that.
- A step's verification fails twice after a reasonable fix attempt, or the fix seems to need a change in `src/bin/gateway.rs`.

## Maintenance notes

- The shim's content holds the path of the `piifence` binary that wrote it. Since `f6ce155` that path is Homebrew's stable `opt` path, so it survives `brew upgrade`. If `real_exe` changes again, check that the shim still points at a path that survives upgrades.
- The shim directory is shared by every session of the user, and `install_shim` replaces it atomically. A user who uninstalls piifence keeps a stale `~/.local/state/piifence/bin/claude`, but nothing puts that directory on `PATH` outside a piifence session.
- A nested session takes no lease. If the parent session exits while a background child still runs, the gateway can stop under the child, and the child's next request fails. That is acceptable for `claude -p`. Revisit if long-lived nested sessions become common.
- Reviewers should check that the `nested-claude` path with no piifence variables runs the real `claude` unchanged, because the shim is first on `PATH` in every Bash command of a piifence session.
- Deferred: the Agent SDK and launches by absolute path (Design item 5). Covering them would need hooks in the user's own settings, which piifence promises not to edit.
