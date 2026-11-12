# Plan 010: Make gitleaks scan every line with the full rule set

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving to the next step. If anything in the "STOP conditions" section occurs, stop and report; do not improvise. When done, update the status row for this plan in `plans/README.md`, unless a reviewer dispatched you and told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat fc97e3d..HEAD -- src/gitleaks.rs src/detect.rs CLAUDE.md README.md`
> If any of these files changed since this plan was written, compare the "Current state" excerpts against the live code before proceeding. On a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S (about 1–2 hours, plus one full suite run)
- **Risk**: LOW (one subprocess call gains a flag and a working directory, and one file is written differently)
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `fc97e3d`, 2026-11-11

## Why this matters

piifence is a local gateway that replaces secrets in Claude Code's requests before they reach the model provider. One of its detectors runs the `gitleaks` CLI (`gitleaks stdin`) on every piece of text. gitleaks has three behaviours meant for developers scanning their own repositories, and the gateway inherits all three by accident:

1. **Inline markers.** gitleaks skips any line that contains the comment `gitleaks:allow`. Developers put that marker on lines holding real keys to get past pre-commit checks, so exactly those lines lose gitleaks coverage. On 2026-11-11 a throwaway gateway forwarded a random Slack webhook URL followed by `# gitleaks:allow` to its upstream unchanged, while the same line without the marker was replaced. A GitHub token and an AWS key with the marker were replaced only because the other detectors also caught them.
2. **The working directory's `.gitleaksignore`.** gitleaks reads `.gitleaksignore` from its working directory even when it scans stdin. The gateway, and every gitleaks process it starts, inherits the working directory of the project where the user ran `piifence claude`. A stdin finding's fingerprint is `:<rule id>:<line>`, for example `:github-pat:1`. So a cloned repository that ships a `.gitleaksignore` listing such entries switches those rules off, at those line numbers, for every text the session sends. Passing `--gitleaks-ignore-path` does not prevent this. Both facts were tested with gitleaks 8.30.1.
3. **A shared config file rewritten in place.** Every gateway start truncates and rewrites `<cache dir>/gitleaks.toml`. A scan by another running gateway at that moment can read an empty file. With an empty config, gitleaks finds nothing and exits 0, and the detection cache then stores that clean result for the text, so gitleaks never scans that text again while the same binary runs. Two different builds that share the cache dir, such as an installed one and a development one, also overwrite each other's rules.

After this plan, gitleaks ignores inline markers and runs in a directory that piifence owns. Its config file is written once, whole, under a name derived from its content. The `allow` list in the user's config file stays the only way to exempt a value. The plan also creates the cache directory with mode 0700. `CLAUDE.md:16` already promises that mode, but `~/.cache/piifence` was 0755 on the machine this plan was written on.

## Current state

Files:

- `src/gitleaks.rs`: the gitleaks pass. `write_config` writes the built-in rules into the cache dir, and `scan` runs `gitleaks stdin` on one text.
- `src/detect.rs`: `Detector::load` calls `gitleaks::write_config(cache_dir)` once at startup and keeps the path it returns. `detect` calls `gitleaks::scan(text, &self.gitleaks_config)`. No change is needed here.
- `src/bin/piifence.rs:154-162`: the launcher starts the gateway without setting a working directory. Read only; this plan does not change the launcher.
- `CLAUDE.md`: developer notes. Line 13 describes `src/gitleaks.rs`.
- `README.md`: user docs. Line 202 explains the `allow` list.

`src/gitleaks.rs:36-49`, `write_config`:

```rust
/// Write `CONFIG` to `dir/gitleaks.toml` (mode 0600) and return its path.
pub fn write_config(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("gitleaks.toml");
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(CONFIG.as_bytes()))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}
```

`src/gitleaks.rs:65-93`, the start of `scan`:

```rust
/// Scan one text block with `gitleaks stdin` and the rules in `config`, and parse the JSON report.
pub fn scan(text: &str, config: &Path) -> Result<Vec<Finding>> {
    let mut cmd = Command::new("gitleaks");
    cmd.args([
        "stdin",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
        "--no-banner",
        "--no-color",
    ]);
    cmd.arg("-c").arg(config);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("failed to run `gitleaks` (install it with `brew install gitleaks`)")?;
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(text.as_bytes())
        .context("writing text to gitleaks stdin")?;
    drop(child.stdin.take());
```

`src/gitleaks.rs:5-12`, the imports:

```rust
use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
```

`src/detect.rs:118-119`, in `Detector::load`. `write_config` runs before the cache opens at line 124:

```rust
        let gitleaks_config = gitleaks::write_config(cache_dir)?;
        let fingerprint = fingerprint(model_dirs, &allow)?;
```

`src/cache.rs:46-52`, where the cache creates the same directory. `DirBuilder` applies the mode only when it creates the directory, and by then `write_config` has already created it with the default mode:

```rust
        let dir = path.parent().context("cache path has no directory")?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
```

The detection cache needs no change. Its key includes the running binary's file stamp (`src/detect.rs:242-245`), so a rebuilt gateway starts with an empty cache and scans every text again with the new flags:

```rust
    fp.add_file_stamp(
        "exe",
        &std::env::current_exe().context("locate the running binary")?,
    )?;
```

`src/cache.rs:200-202` turns digest bytes into hex. Use the same expression, because it already passes clippy:

```rust
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
```

Conventions to match:

- Every function and const has a `///` doc comment of one or two plain sentences that say what it does. Add no other comments.
- Test names are full sentences in snake_case, for example `every_copy_is_returned` (`src/gitleaks.rs:215`). Tests live in `mod tests` at the bottom of the file, which starts with `use super::*;`.
- Tests that need a directory follow `src/cache.rs:226-230`: `std::env::temp_dir().join(format!("piif-cache-{name}-{}", std::process::id()))`, removed first with `let _ = std::fs::remove_dir_all(&dir);`.
- Errors use `anyhow`: `.context(…)`, `.with_context(|| …)`, `anyhow::ensure!`.
- `sha2` 0.10 is already a dependency (`Cargo.toml:24`). `src/cache.rs:15` imports it as `use sha2::{Digest, Sha256};`.
- Edition 2021. `cargo fmt --check` and clippy with `-D warnings` must pass.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| gitleaks has the flag | `gitleaks stdin --help \| grep -c ignore-gitleaks-allow` | `1` |
| Format | `cargo fmt --check` | exit 0 |
| Lint | `cargo clippy --release --all-targets -- -D warnings` | exit 0 |
| Library tests | `cargo test --release --lib` | `test result: ok`, 0 failed |
| All Rust tests | `cargo test --release` | 0 failed |
| Fast checks | `scripts/check.sh --no-suite` | last line `check: all passed` |
| Full checks, with the secret suite | `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh` | last line `check: all passed`, and the suite summary says `0 regressions` |

gitleaks must be on `PATH` (`brew install gitleaks`). The full checks need the model in `~/.local/share/piifence/model`. If it is missing, `scripts/fetch-weights.sh "$HOME/.local/share/piifence/model"` downloads it.

## Scope

**In scope** (the only files you should modify):

- `src/gitleaks.rs`: `write_config`, `scan`, a new private function `command`, the imports, and three new tests
- `CLAUDE.md`: line 13, the `src/gitleaks.rs` bullet
- `README.md`: one new paragraph after line 202

**Out of scope** (do NOT touch, even though they look related):

- `src/bin/piifence.rs`: do not set the gateway's working directory in the launcher. Setting it on the gitleaks process is enough, and another plan changes the launcher's lifecycle code.
- `src/detect.rs` and `src/cache.rs`: no change is needed. `Detector::load` keeps calling `write_config(cache_dir)` and storing the path it returns.
- `gitleaks.toml` at the repository root (the rules), `tests/secrets/run.py:376` and `bench/models/shootout.py:46`. Those two scripts read the repository's `gitleaks.toml`, not the copy in the cache dir.
- `.gitleaksignore` at the repository root. It is for scanning this repository's own files, not for the gateway.
- Deleting the old `<cache dir>/gitleaks.toml`. A gateway built before this change may still be running and reading it.

## Git workflow

- Branch: `fix/gitleaks-full-coverage`. The repo names branches `fix/<kebab>`, `feature/<kebab>` and `docs/<kebab>`.
- One commit is enough. Message style: an imperative summary under 60 characters (for example `Add a Homebrew formula so the repo works as a tap` from `git log`), a blank line, a bullet body, then the trailer `Co-authored-by: Claude <noreply@anthropic.com>`.
- Do NOT push or open a PR unless the operator told you to.

## Steps

### Step 0: Record the baseline

Run `gitleaks stdin --help | grep -c ignore-gitleaks-allow`, then `cargo test --release --lib 2>&1 | grep 'test result'`, and write down the passed count. Then run `scripts/check.sh --no-suite`.

**Verify**: the grep prints `1`, the test line shows `0 failed`, and `check.sh` ends with `check: all passed`. If any of these fails before you change anything, STOP.

### Step 1: Write the config whole, under a content-derived name, in a private directory

In `src/gitleaks.rs`, change the import `use std::os::unix::fs::OpenOptionsExt;` to `use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};`, and add `use sha2::{Digest, Sha256};` after `use serde::Deserialize;`.

Replace the whole of `write_config` (its doc comment and body) with:

```rust
/// Write `CONFIG` to `dir/gitleaks-<hash>.toml` (mode 0600), named after a hash of its content, and return the absolute path; `dir` is created or narrowed to mode 0700. The file is written under a temporary name and renamed, so a scan never reads half of it, and builds with different rules can share `dir`.
pub fn write_config(dir: &Path) -> Result<PathBuf> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("make {} private", dir.display()))?;
    let dir = std::fs::canonicalize(dir).with_context(|| format!("resolve {}", dir.display()))?;
    let hash: String = Sha256::digest(CONFIG.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let path = dir.join(format!("gitleaks-{hash}.toml"));
    let temp = dir.join(format!("gitleaks-{}.tmp", std::process::id()));
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| file.write_all(CONFIG.as_bytes()))
        .with_context(|| format!("write {}", temp.display()))?;
    std::fs::rename(&temp, &path).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}
```

The path must be absolute because Step 2 runs gitleaks inside this directory, and a relative `-c` path would then point somewhere else.

**Verify**: `cargo build --release` exits 0, and `grep -c 'dir.join("gitleaks.toml")' src/gitleaks.rs` prints `0`.

### Step 2: Run gitleaks with inline markers ignored, inside the config's directory

Add this function directly above `scan`:

```rust
/// The `gitleaks stdin` command for one scan with the rules in `config`. `--ignore-gitleaks-allow` makes gitleaks scan lines that carry a `gitleaks:allow` comment, and the command runs in the directory that holds `config`, so a `.gitleaksignore` where the gateway was started does not apply.
fn command(config: &Path) -> Result<Command> {
    let dir = config
        .parent()
        .context("the gitleaks config path has no directory")?;
    let mut cmd = Command::new("gitleaks");
    cmd.args([
        "stdin",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
        "--no-banner",
        "--no-color",
        "--ignore-gitleaks-allow",
    ]);
    cmd.arg("-c").arg(config).current_dir(dir);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(cmd)
}
```

In `scan`, delete everything from `let mut cmd = Command::new("gitleaks");` through `.stderr(Stdio::piped());`, which is lines 67–82 at `fc97e3d`. Then change the spawn to:

```rust
    let mut child = command(config)?
        .spawn()
        .context("failed to run `gitleaks` (install it with `brew install gitleaks`)")?;
```

Leave the rest of `scan` unchanged.

**Verify**: `cargo build --release` exits 0. `grep -c '"--ignore-gitleaks-allow",' src/gitleaks.rs` prints `1`. `grep -n 'Command::new("gitleaks")' src/gitleaks.rs` prints exactly two lines, one in `version` and one in `command`.

### Step 3: Add the tests

Add these to `mod tests` at the bottom of `src/gitleaks.rs`, after the existing tests:

```rust
    /// A fresh path under the system temp dir for one test; the directory itself is not created.
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("piif-gitleaks-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_config_is_written_whole_under_its_content_name_in_a_private_dir() {
        let dir = test_dir("config");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let first = write_config(&dir).unwrap();
        let second = write_config(&dir).unwrap();
        assert_eq!(first, second);
        assert!(first.is_absolute());
        let name = first.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("gitleaks-") && name.ends_with(".toml"));
        assert_eq!(std::fs::read_to_string(&first).unwrap(), CONFIG);
        let file_mode = std::fs::metadata(&first).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().path().extension().is_some_and(|ext| ext == "tmp"))
            .count();
        assert_eq!(leftovers, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scan_ignores_allow_comments_and_runs_in_the_config_dir() {
        let dir = test_dir("command");
        let config = write_config(&dir).unwrap();
        let cmd = command(&config).unwrap();
        assert!(cmd.get_args().any(|arg| arg == "--ignore-gitleaks-allow"));
        assert_eq!(cmd.get_current_dir(), config.parent());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_gitleaks_allow_comment_does_not_hide_a_finding() {
        let dir = test_dir("marker");
        let config = write_config(&dir).unwrap();
        let hex: String = Sha256::digest(b"piifence gitleaks:allow test")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let token = format!("ghp_{}", &hex[..36]);
        let plain = scan(&format!("value = \"{token}\"\n"), &config).unwrap();
        let marked = scan(&format!("value = \"{token}\"  # gitleaks:allow\n"), &config).unwrap();
        assert!(!plain.is_empty());
        assert_eq!(marked.len(), plain.len());
        std::fs::remove_dir_all(&dir).unwrap();
    }
```

The token in the last test is built at run time from a hash, so no token-shaped text sits in the source file. With gitleaks 8.30.1 and this repository's rules, that line gave 1 finding without the marker. With the marker it gave 0 findings, and 1 again once `--ignore-gitleaks-allow` was passed.

Run `cargo fmt` after adding the tests; rustfmt will rewrap the long lines.

**Verify**:

1. `cargo test --release --lib -- the_config_is_written_whole a_scan_ignores_allow_comments a_gitleaks_allow_comment` → `test result: ok. 3 passed`.
2. Prove the last test catches the bug. Delete the line `"--ignore-gitleaks-allow",` from `command`, then run `cargo test --release --lib a_gitleaks_allow_comment` → `1 failed`. Put the line back exactly as it was, and run the same command again → `1 passed`.
3. `cargo test --release --lib` → 0 failed, with 3 more passed than at Step 0.

### Step 4: Update the docs

In `CLAUDE.md:13`, the `src/gitleaks.rs` bullet, replace the words `and written to the cache dir at startup.` with:

```
and written whole to `gitleaks-<hash>.toml` in the cache dir at startup. gitleaks runs in that directory with `--ignore-gitleaks-allow`, so inline `gitleaks:allow` comments and a `.gitleaksignore` where the gateway was started have no effect.
```

In `README.md`, directly after the paragraph at line 202 that starts with "`allow` is the only key.", add one blank line and this paragraph:

```
Inline `gitleaks:allow` comments and `.gitleaksignore` files have no effect on the gateway. A line is scanned whatever it says about itself, and only your `allow` list makes exceptions.
```

**Verify**: `grep -c 'ignore-gitleaks-allow' CLAUDE.md` prints `1`, and `grep -c 'list makes exceptions' README.md` prints `1`.

### Step 5: Run every check

Run `scripts/check.sh --no-suite`, then `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh`.

**Verify**: both end with `check: all passed`, and the suite summary says `0 regressions`. No suite case contains `gitleaks:allow`, so the suite's counts should match a run before this change.

## Test plan

New tests, all in `src/gitleaks.rs`:

- `the_config_is_written_whole_under_its_content_name_in_a_private_dir`: two writes give the same absolute path with the built-in rules; the file is 0600; a directory that started as 0755 ends as 0700; no `.tmp` file is left.
- `a_scan_ignores_allow_comments_and_runs_in_the_config_dir`: the command carries `--ignore-gitleaks-allow` and runs in the config's directory.
- `a_gitleaks_allow_comment_does_not_hide_a_finding`: runs the real gitleaks. A marked line gives as many findings as the same line without the marker. This needs gitleaks on `PATH`; CI installs it with `brew install gitleaks` before `scripts/check.sh` (`.github/workflows/ci.yml:25`).

Pattern: `every_copy_is_returned` (`src/gitleaks.rs:215`) for layout, and `temp_dir` in `src/cache.rs:226-230` for test directories.

Verification: `cargo test --release` reports 0 failed, with 3 more tests than at Step 0.

## Done criteria

ALL must hold:

- [ ] `cargo fmt --check` exits 0
- [ ] `cargo clippy --release --all-targets -- -D warnings` exits 0
- [ ] `cargo test --release` exits 0, and the 3 new tests pass
- [ ] `grep -c '"--ignore-gitleaks-allow"' src/gitleaks.rs` prints `2` (the command and its test)
- [ ] `grep -c 'current_dir(dir)' src/gitleaks.rs` prints `1`
- [ ] `grep -c 'dir.join("gitleaks.toml")' src/gitleaks.rs` prints `0`
- [ ] The full checks end with `check: all passed`, and the suite reports `0 regressions`
- [ ] `git status --short` lists only `src/gitleaks.rs`, `CLAUDE.md`, `README.md` and `plans/README.md`
- [ ] `plans/README.md` status row for 010 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The code at the locations in "Current state" does not match the excerpts.
- `gitleaks stdin --help` does not list `--ignore-gitleaks-allow`. Report the output of `gitleaks version`.
- In `a_gitleaks_allow_comment_does_not_hide_a_finding`, `plain` is empty: the installed gitleaks or the repository's rules no longer report a `ghp_` token built this way. Report `gitleaks version`. Do not change the token or loosen the assertion to make the test pass.
- `grep -rn 'Command::new("gitleaks")' src` finds a call outside `src/gitleaks.rs`. That call would need the same flag and working directory, so report where it is.
- The full suite reports a regression. The flag, the working directory and the file name should not change any suite case, so a regression means something else is wrong. Report the case ids.
- `write_config` fails in the suite or in CI with "make … private". Report the directory it names. Do not drop the `set_permissions` call.

## Maintenance notes

- The `allow` list in the user's config is meant to be the only exception mechanism. A request to "support `gitleaks:allow`" is a request to weaken the gateway; point it at `allow`.
- Cache dirs created before this change keep an old `gitleaks.toml` that new builds no longer read. It is harmless. Delete it only when no older gateway build can still be running.
- The cache dir gains one `gitleaks-<hash>.toml` file, about 12 KB, per rules version. If that ever matters, prune the files whose name is not the current hash at startup.
- On every gitleaks upgrade, check `gitleaks stdin --help` for new ways to read project files, such as a new ignore file or a default baseline. Running in the cache dir covers anything gitleaks reads relative to its working directory, but not new absolute defaults.
- Review focus: `command` must keep both `--ignore-gitleaks-allow` and `current_dir`, and `write_config` must write a temporary file and rename it, never truncate the final path.
