# Plan 007: Make every check runnable with one command, locally and in CI

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat efdd25e..HEAD -- Cargo.toml src examples scripts AGENTS.md README.md`
> This plan is meant to run LAST (after 004, 005, 006 and 008), so `src/`
> will have changed. The excerpts below describe warnings, not code; re-run
> `cargo clippy --release --all-targets` and `cargo fmt --check` and work
> from their live output. Treat the `Cargo.toml` excerpt as the one that must
> still match.

## Status

- **Priority**: P1
- **Effort**: S–M
- **Risk**: LOW (formatting, lint fixes, a script and a workflow file; behaviour unchanged)
- **Depends on**: plans/004-walk-every-content-block.md (the weights-free `--mode secret-rules` run that CI uses); run after 005, 006 and 008 because `cargo fmt` moves lines those plans quote
- **Category**: dx
- **Planned at**: commit `efdd25e`, 2026-10-30

## Why this matters

The repo has no CI and no single command that runs its checks. Today `cargo clippy` prints warnings in three files, `cargo fmt --check` reports differences in eight files, and `Cargo.toml` declares a dependency (`burn`) and a tokio feature (`process`) that nothing in `src/` or `examples/` uses. Each plan in `plans/` lists six to eight verification commands; without a script, executors and reviewers run different subsets. After this plan, `scripts/check.sh` runs everything that does not need the 2.8 GB model, the same script runs in GitHub Actions on every push, and lint and formatting are clean so a regression stands out.

## Current state

Files:

- `Cargo.toml` — dependencies at lines 21–39; `burn` at line 30, tokio features at line 38.
- `src/detect.rs`, `src/bin/gateway.rs`, `src/main.rs` — the three files with clippy warnings.
- `scripts/` — holds `fetch-weights.sh` and `install.sh` (bash). No check script. No `.github/` directory. `Cargo.lock` is tracked.
- `AGENTS.md:143-157` ("Verification") and `README.md:52-56` ("Status") — describe how to verify; update them.
- Toolchain on the development machine: `rustc 1.99.1` and `cargo 1.99.1` (Homebrew stable), `gitleaks 8.30.1`, Python 3. The crate uses `privacy-filter-rs` with the `blas-accelerate` feature, which needs Apple's Accelerate framework, so builds run on macOS only.

`cargo clippy --release --all-targets` at `efdd25e` (the lines will differ after plans 004–008; the kinds will not unless those plans fixed them):

```
warning: items after a test module
   --> src/detect.rs:334:1
warning: in a `match` scrutinee, avoid complex blocks or closures with blocks; instead, move the block or closure higher and bind it with a `let`
   --> src/bin/gateway.rs:667:32
warning: doc list item without indentation
 --> src/main.rs:8:5   (and :9, :10)
```

`cargo fmt --check` at `efdd25e` reports differences in `examples/probe.rs`, `src/bin/gateway.rs` (12 places), `src/bin/piifence.rs`, `src/detect.rs`, `src/guards.rs`, `src/main.rs`.

`Cargo.toml:29-39`:

```toml
privacy-filter-rs = { version = "0.1", features = ["blas-accelerate"] }
burn = { version = "0.20", default-features = false, features = ["std"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"
toml = "0.8"
regex = "1"
async-recursion = "1"
axum = "0.8"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "process"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream"] }
```

`grep -rn "burn\|tokio::process" src examples` returns nothing at `efdd25e`: the model backend types come from `privacy_filter_rs::backend`, and the gateway spawns gitleaks with `std::process::Command`.

The gateway's `match` scrutinee clippy complains about, `src/bin/gateway.rs:666-671` at `efdd25e`:

```rust
        match serde_json::from_slice::<Value>(&outgoing) {
            Ok(mut payload) => match {
                let started = std::time::Instant::now();
                let result = redact_payload(&state, &mut payload, allow_prompt_once).await;
                (result, started.elapsed().as_secs_f64() * 1000.0)
            } {
                (Ok(audit), redact_ms) => {
```

The checks the repo already has (from `AGENTS.md:143-157`, `tests/secrets/README.md:25-37`, and plans 004–008):

| Check | Command | Needs |
|---|---|---|
| Format | `cargo fmt --check` | — |
| Lint | `cargo clippy --release --all-targets -- -D warnings` | — |
| Build | `cargo build --release` | — |
| Unit tests | `cargo test --release` | — |
| Suite self-check | `python3 -I tests/secrets/run.py --self-test` | — |
| Rules match formats | `python3 -I tests/secrets/run.py --check-generators` | gitleaks |
| Context builders | `python3 -I tests/secrets/contexts.py` | — |
| Fixtures secret-free | `gitleaks dir tests/secrets --no-banner` | gitleaks |
| Stats and notice (plan 008) | `python3 -I tests/secrets/stats_check.py` | release build, gitleaks |
| Rules-only suite (plan 004) | `python3 -I tests/secrets/run.py --mode secret-rules` | release build, gitleaks |
| Model suite | `python3 -I tests/secrets/run.py --model-dir <weights> --mode all --mode secret` | weights (about 25 min) |
| M1 corpus gate | `PIIF_MODEL_DIR=<weights> cargo run --release` → `15/15` | weights |

Weights on this machine: `/Users/alexs/piifence-trial/src/data`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Lint clean | `cargo clippy --release --all-targets -- -D warnings` | exit 0 |
| Format clean | `cargo fmt --check` | exit 0, no output |
| Tests | `cargo test --release` | exit 0 |
| Whole script | `scripts/check.sh` | exit 0, last line `check: all passed` |
| Workflow parses | `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); puts "yaml ok"'` | `yaml ok` |
| Workflow lint (if installed) | `command -v actionlint && actionlint` | exit 0 or "not installed" |

## Scope

**In scope** (the only files you should modify):
- `src/detect.rs`, `src/bin/gateway.rs`, `src/main.rs` — lint fixes only, no behaviour change
- Every `.rs` file under `src/` and `examples/` — `cargo fmt` only
- `Cargo.toml`, `Cargo.lock` (the lock changes only by dropping the direct `burn` edge)
- `scripts/check.sh` (create)
- `.github/workflows/ci.yml` (create)
- `AGENTS.md`, `README.md`
- `plans/README.md` (status row)

**Out of scope** (do NOT touch, even though they look related):
- Any logic change while fixing lints. If clippy wants a behaviour change (not a restructuring), allow the lint with a comment and report it.
- `scripts/install.sh`, `scripts/fetch-weights.sh`.
- Switching the model backend or making the crate build on Linux.
- The Python files' style (no formatter is configured for them; do not add one).
- `tests/corpus-secrets.json` and the owner's uncommitted edit to `src/main.rs` (see Step 1).

## Git workflow

- Start from a clean checkout of `main` in a separate worktree: `git worktree add ../piifence-007 -b fix/verification-baseline main` and work there. The owner's working tree has uncommitted changes in `src/main.rs`; this plan also edits that file (doc comment and formatting), so it must not run in the owner's tree.
- Commits, in this order so each is reviewable: lint fixes; `cargo fmt`; dependency cleanup; check script; workflow; docs. Message style: summary of at most 60 characters, blank line, bullets, trailer `Co-authored-by: Claude <noreply@anthropic.com>` (see `git log --oneline -8`).
- Do NOT push or open a PR unless the operator instructed it. The workflow cannot be verified end to end without a push; say so in your report.

## Steps

### Step 1: Confirm a clean start

**Verify**: in the worktree, `git status --short` → empty, and `git log --oneline -1` shows the current `main` head (after plans 004, 005, 006 and 008 were merged). If `src/main.rs` shows as modified, you are in the owner's tree: STOP.

### Step 2: Fix the clippy warnings

Run `cargo clippy --release --all-targets 2>&1 | grep -E "^warning|-->"` and fix each kind:

- `items after a test module` (`src/detect.rs`): move the free functions that sit below `#[cfg(test)] mod tests` (at `efdd25e`: `apply_guards` and `gitleaks_spans`) to just above the test module. No edits inside them.
- `in a match scrutinee, avoid complex blocks` (`src/bin/gateway.rs`): bind first, then match:

  ```rust
            Ok(mut payload) => {
                let started = std::time::Instant::now();
                let result = redact_payload(&state, &mut payload, allow_prompt_once).await;
                let redact_ms = started.elapsed().as_secs_f64() * 1000.0;
                match (result, redact_ms) {
                    (Ok(audit), redact_ms) => { ... unchanged ... }
                    (Err(err), _) => { ... unchanged ... }
                }
            }
  ```

- `doc list item without indentation` (`src/main.rs` module doc): indent the continuation lines of each `//!` list item by two spaces so they attach to the item.
- Any warning introduced by plans 004–008: fix in the same spirit (restructure, never change behaviour). If a fix needs a behaviour change, add `#[allow(clippy::<lint>)]` with a one-line reason and list it in your report.

**Verify**: `cargo clippy --release --all-targets -- -D warnings` → exit 0; `cargo test --release` → exit 0.

### Step 3: Format

Run `cargo fmt`. Review the diff: it must contain whitespace and line-wrapping changes only (`git diff --stat` and a skim of `git diff`).

**Verify**: `cargo fmt --check` → exit 0, no output; `cargo test --release` → exit 0.

### Step 4: Drop the unused dependency declarations

In `Cargo.toml`, delete the `burn = …` line and remove `"process"` from the tokio feature list. Leave the comment block above `privacy-filter-rs` (it documents why the backend is CPU) untouched.

**Verify**: `grep -rn "burn\|tokio::process" src examples` → no output; `cargo build --release` → exit 0; `cargo test --release` → exit 0; `git diff --stat Cargo.lock` shows a small change (the `piifence-m1` entry loses `burn`) or none. If the build fails without `burn`, restore the line and STOP: something in the tree now uses it.

### Step 5: Write `scripts/check.sh`

Create `scripts/check.sh`, executable (`chmod +x`), using the same shebang and `set` options as `scripts/install.sh`:

```bash
#!/usr/bin/env bash
# One command for every check. Fast checks first; the model-backed suite modes and
# the M1 corpus gate only when weights are present (PIIF_MODEL_DIR, default data/).
# Usage: scripts/check.sh [--no-suite]   (--no-suite skips the gateway-backed suites)
set -euo pipefail
cd "$(dirname "$0")/.."

run() { echo "==> $*"; "$@"; }

run cargo fmt --check
run cargo clippy --release --all-targets -- -D warnings
run cargo build --release
run cargo test --release
run python3 -I tests/secrets/run.py --self-test
run python3 -I tests/secrets/run.py --check-generators
run python3 -I tests/secrets/contexts.py
run gitleaks dir tests/secrets --no-banner

if [ "${1:-}" != "--no-suite" ]; then
  run python3 -I tests/secrets/stats_check.py
  run python3 -I tests/secrets/run.py --mode secret-rules
  model_dir="${PIIF_MODEL_DIR:-data}"
  if [ -f "$model_dir/config.json" ]; then
    run python3 -I tests/secrets/run.py --model-dir "$model_dir" --mode all --mode secret
    PIIF_MODEL_DIR="$model_dir" run cargo run --release
  else
    echo "==> skipping model-backed checks (no weights at $model_dir; set PIIF_MODEL_DIR)"
  fi
fi
echo "check: all passed"
```

If `tests/secrets/stats_check.py` does not exist (plan 008 not merged), leave that line out and say so in the report.

**Verify**: `scripts/check.sh --no-suite` → `check: all passed`, exit 0. Then `PIIF_MODEL_DIR=/Users/alexs/piifence-trial/src/data scripts/check.sh` → `check: all passed` (about 30 minutes). Then `scripts/check.sh` with `PIIF_MODEL_DIR` unset and no `data/` dir → the skip line is printed and the exit code is 0.

### Step 6: Add the GitHub Actions workflow

Create `.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  check:
    # privacy-filter-rs is built with Apple's Accelerate BLAS, so this must be macOS.
    runs-on: macos-latest
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: brew install gitleaks
      - run: scripts/check.sh
```

Notes for the executor: the weights are never fetched in CI, so the script's model-backed section is skipped there by design. The first run compiles the model crate from scratch; later runs hit the cache. The repository's visibility could not be checked from the planning session; on a private repository, macOS runner minutes cost ten times Linux minutes, which the owner should know before enabling this.

**Verify**: `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); puts "yaml ok"'` → `yaml ok`; if `actionlint` is installed, `actionlint` → exit 0.

### Step 7: Update the docs

- `AGENTS.md` "Verification" (lines 143–157): first bullet becomes "`scripts/check.sh` runs every check; CI runs it on every push (`.github/workflows/ci.yml`). It skips the model-backed suite modes and the M1 gate when no weights are present." Keep the existing bullets as the description of what the script runs.
- `README.md` "Quick start" or "Status": one line, `scripts/check.sh` runs the checks.
- `AGENTS.md` "Work Guidance" (line 133): the dependency list says "privacy-filter-rs + serde + anyhow + regex"; it is already wider (toml, axum, tokio, reqwest); reword to "keep the dependency list to what `Cargo.toml` has; justify additions".

**Verify**: `grep -c "check.sh" AGENTS.md README.md` → at least `1` each.

## Test plan

- No new unit tests: this plan changes no behaviour. The gate is that every existing test and suite passes after the lint, format and dependency changes.
- `scripts/check.sh` itself is tested by running it in both modes (Step 5).
- The workflow is tested by YAML parsing (and `actionlint` if present); its first real run happens when the owner pushes.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo clippy --release --all-targets -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0
- [ ] `grep -c "^burn" Cargo.toml` → `0`; `grep -c '"process"' Cargo.toml` → `0`
- [ ] `scripts/check.sh --no-suite` exits 0 with `check: all passed`
- [ ] `PIIF_MODEL_DIR=/Users/alexs/piifence-trial/src/data scripts/check.sh` exits 0 (on a machine with weights)
- [ ] `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml")'` exits 0
- [ ] `git status` shows no modified files outside the in-scope list
- [ ] `plans/README.md` status row updated, with a note that CI has not yet run

## STOP conditions

Stop and report back (do not improvise) if:

- You are not in a clean worktree (Step 1).
- A clippy fix requires changing what the code does, and the lint cannot be allowed with a reason.
- `cargo build --release` fails after removing `burn` (restore it first, then report).
- `cargo fmt` produces a diff that is not purely whitespace and line wrapping (for example it reorders imports and a test starts failing).
- `scripts/check.sh` fails on a check that passed before this plan started: that is a regression from plans 004–008, not from this plan; report which.

## Maintenance notes

- `scripts/check.sh` is the one list of checks; when a plan adds a check, it adds a line here, and CI picks it up without a workflow change.
- `macos-latest` moves between macOS versions; if the Accelerate build breaks on a new image, pin `runs-on` to the last working `macos-NN`.
- Deferred: caching the model weights in CI to run the model-backed suite modes (2.8 GB per run; GitHub's cache limit is 10 GB per repository, so it is possible but would evict the Rust build cache).
- Deferred: a `rust-toolchain.toml` to pin the compiler; today the local toolchain is Homebrew stable and CI uses `stable`, which can differ by a minor version.
