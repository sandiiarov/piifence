# Plan 011: Keep a shared gateway running until the last `piifence claude` that uses it exits

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving to the next step. If anything in the "STOP conditions" section occurs, stop and report; do not improvise. When done, update the status row for this plan in `plans/README.md`, unless a reviewer dispatched you and told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat fc97e3d..HEAD -- src/bin/piifence.rs src/bin/gateway.rs Cargo.toml Cargo.lock scripts/check.sh tests/secrets/README.md README.md CLAUDE.md`
> If any of these files changed since this plan was written, compare the "Current state" excerpts against the live code before proceeding. On a mismatch, treat it as a STOP condition. Plans 009 and 010 edit other paragraphs of `README.md` and `CLAUDE.md`; if they landed first, the README line numbers below may be a few lines off, so find each README and CLAUDE.md edit by its quoted text, not by its line number.

## Status

- **Priority**: P1
- **Effort**: M (about 4–6 hours: about 150 lines of Rust, one new Python check, two suite runs)
- **Risk**: MED (it changes when the gateway process starts and stops. A mistake either leaves a gateway running or stops one that a session still needs. The second case fails closed: Claude Code's requests are refused, not sent unredacted)
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `fc97e3d`, 2026-11-11

## Why this matters

piifence is a local gateway that replaces secrets in Claude Code's requests before they reach the model provider. `piifence claude` (the launcher, `src/bin/piifence.rs`) starts the gateway (`src/bin/gateway.rs`) on port 7788 when nothing answers there, and reuses a running gateway that forwards to the same upstream. Three things go wrong when two sessions share a gateway:

1. **The first launcher stops the gateway under the second session.** The launcher that started the gateway kills it as soon as its own Claude Code exits (`src/bin/piifence.rs:130-134`), even when a second `piifence claude` reused that gateway and is still running. The second session then loses its gateway mid-conversation. Every request fails with "connection refused". `piifence env` fails, so Bash commands run without the `PIIF_SECRET_<N>` values. `piifence restore` blocks every tool call that uses a name. Nothing restarts the gateway, so the user has to quit and start again.
2. **A start race can pick a gateway with the wrong upstream.** `wait_healthy` (`src/bin/piifence.rs:265-280`) returns as soon as any gateway answers `/health`, before it checks whether its own child exited, and it does not compare the upstream. When two launchers with different upstreams start at the same moment, only one gateway gets the port. The other launcher then silently uses that gateway, so its requests and credentials go to the other provider.
3. **Closing a terminal stops a shared gateway.** The gateway runs in the launcher's process group, so closing the terminal that started it sends it SIGHUP, whichever sessions still use it.

After this plan, each launcher takes a lease on the gateway before it starts Claude Code, made of its session id and its process id. The launcher never stops a gateway. A gateway that the launcher started gets `PIIF_EXIT_WHEN_UNUSED=<seconds>` (10 by default). Once a second it checks whether each lease's process still exists, and it exits by itself once no lease has been held for that many seconds. A gateway started by hand or by the test suite does not get the variable, so it runs until stopped, as today.

## Current state

Files:

- `src/bin/piifence.rs`: the launcher. `run_claude` finds or starts the gateway and kills it at exit. `start_gateway` spawns it, `wait_healthy` waits for it, `run_session` runs Claude Code, and `http_get` (lines 234-249) sends one raw HTTP GET over loopback TCP and returns the whole response as a string.
- `src/bin/gateway.rs`: the gateway, an axum server. `proxy` is the one handler for every path. `main` reads the environment, loads the detector, binds `127.0.0.1:<port>` and serves.
- `Cargo.toml`: tokio is built with `["rt-multi-thread", "macros", "net"]` (line 31). `libc` is not a direct dependency, but `Cargo.lock` already has `libc` 0.2.191 through other crates. The locked axum is 0.8.9, which has `Serve::with_graceful_shutdown`.
- `scripts/check.sh`: runs every check. Lines 18-22 run the end-to-end checks that need the model.
- `tests/secrets/stats_check.py`: the pattern for a small end-to-end check. It imports `run` (`tests/secrets/run.py`) for `run.Sink()`, a fake upstream on a free port, and `run.free_port()`.

`src/bin/piifence.rs:102-136`, `run_claude`. The kill at exit is lines 130-134:

```rust
fn run_claude(args: &[String]) -> Result<i32> {
    if args
        .iter()
        .any(|a| a == "--settings" || a.starts_with("--settings="))
    {
        bail!("do not pass --settings to `piifence claude`; piifence supplies the gateway override itself");
    }

    let port = port()?;
    let gateway_url = format!("http://127.0.0.1:{port}");
    let data = data_dir()?;
    let plugin = existing(data.join("plugin/piifence-notice"), "the notice plugin")?;
    let upstream = resolve_upstream(&gateway_url)?.context(
        "no upstream configured: set PIIF_UPSTREAM to your provider's base URL, or ANTHROPIC_BASE_URL in your shell or Claude settings",
    )?;

    let mut gateway_child: Option<Child> = None;
    match running_gateway_upstream(port) {
        // Reuse only a gateway that forwards to the same place this launch would. Reusing another one would send this session's credentials elsewhere.
        Some(running) if running == upstream => {
            eprintln!("piifence: using existing gateway on {gateway_url} (upstream {upstream})");
        }
        Some(running) => bail!(
            "a gateway on {gateway_url} forwards to {running:?}, but this launch wants {upstream}. Stop that gateway or set PIIF_PORT to a free port."
        ),
        None => gateway_child = Some(start_gateway(&data, port, &upstream)?),
    }

    let result = run_session(&gateway_url, port, &plugin, args);
    if let Some(mut child) = gateway_child {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
```

`src/bin/piifence.rs:138-181`, `start_gateway`:

```rust
/// Start the gateway and wait until it is healthy. Claude Code is never launched without one (fail closed).
fn start_gateway(data: &Path, port: u16, upstream: &str) -> Result<Child> {
    let exe = real_exe()?;
    let gateway_bin = existing(exe.with_file_name("piifence-gateway"), "the gateway binary")?;
    let model_dir = existing(data.join("model"), "the secret model")?;
    let gateway_log = match env::var("PIIF_GATEWAY_LOG") {
        Ok(path) => PathBuf::from(path),
        Err(_) => env::temp_dir().join("piifence-gateway.log"),
    };
    let gateway_url = format!("http://127.0.0.1:{port}");
    eprintln!("piifence: starting gateway on {gateway_url} (upstream {upstream})");
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gateway_log)
        .with_context(|| format!("cannot open the gateway log {}", gateway_log.display()))?;
    let mut child = Command::new(&gateway_bin)
        .env("PIIF_UPSTREAM", upstream)
        .env("PIIF_MODEL_DIR", &model_dir)
        .env("PIIF_PORT", port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .with_context(|| format!("could not start the gateway {}", gateway_bin.display()))?;

    if let Err(err) = wait_healthy(port, &mut child) {
        let _ = child.kill();
        let _ = child.wait();
        let lines = match fs::read_to_string(&gateway_log) {
            Ok(text) => {
                let lines: Vec<&str> = text.lines().collect();
                lines[lines.len().saturating_sub(15)..].join("\n  ")
            }
            Err(read) => format!("cannot read it: {read}"),
        };
        bail!(
            "{err}; refusing to launch Claude Code (fail closed). Last gateway log lines ({}):\n  {lines}",
            gateway_log.display()
        );
    }
    eprintln!("piifence: gateway ready (log: {})", gateway_log.display());
    Ok(child)
}
```

`src/bin/piifence.rs:183-200`, `run_session`. It creates the session id itself, on line 185:

```rust
/// Run Claude Code against the gateway with the session's settings override and the notice plugin. Returns Claude Code's exit code.
fn run_session(gateway_url: &str, port: u16, plugin: &Path, args: &[String]) -> Result<i32> {
    let session_id = new_session_id().context("cannot create a session id")?;
    let settings_path = write_settings_override(gateway_url, port, &session_id)
        .context("cannot write the session settings")?;
```

`src/bin/piifence.rs:251-280`, `running_gateway_upstream` and `wait_healthy`:

```rust
/// The upstream a healthy gateway on `port` reports, or None when nothing healthy answers there.
fn running_gateway_upstream(port: u16) -> Option<String> {
    let response = http_get(port, "/health", "", Duration::from_millis(500)).ok()?;
    if !response.starts_with("HTTP/1.1 200") {
        return None;
    }
    response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("x-piifence-upstream")
            .then(|| value.trim().to_string())
    })
}

fn wait_healthy(port: u16, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while Instant::now() < deadline {
        if running_gateway_upstream(port).is_some() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!("the gateway exited during startup ({status})");
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!(
        "the gateway did not become healthy in {} s",
        GATEWAY_START_TIMEOUT.as_secs()
    )
}
```

`src/bin/gateway.rs:48-62`, `AppState`:

```rust
#[derive(Clone)]
struct AppState {
    detector_tx: std::sync::mpsc::Sender<DetectJob>,
    client: reqwest::Client,
    upstream: String,
    port: u16,
    audit: Arc<Mutex<std::fs::File>>,
    /// The rewritten request bodies, when `PIIF_AUDIT_BODY=1`.
    audit_body: Option<Arc<Mutex<std::fs::File>>>,
    stats: Arc<Mutex<Stats>>,
    /// Per-session `$PIIF_…` values (see `Session`).
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    /// This request's session id (`x-piifence-session`), `""` outside a request or without one.
    session: String,
}
```

`src/bin/gateway.rs:1095-1121`, the end of the routing in `proxy`. A `/control/` path other than these two falls through to the forwarding code below and is sent to the provider:

```rust
    // Secrets become the session's `$PIIF_…` names, so a scanned request and the control endpoint need a session.
    if (is_scanned || path.starts_with("/control/")) && state.session.is_empty() {
        return error_response(
            StatusCode::FORBIDDEN,
            "missing x-piifence-session: run Claude Code with `piifence claude`",
        );
    }
    // `piifence env` runs before every Bash command (Claude Code sources the line the session-start hook wrote) and exports these, so commands get the real values behind the `$PIIF_…` names. Values go only to the session they belong to.
    if path == "/control/env" && method == Method::GET {
        let values = with_session(&state, |session| session.env.all());
        return json_response(StatusCode::OK, json!({"values": values}));
    }
    // The session-start hook sends Claude Code's conversation id, so a resumed conversation gets back the names it already uses.
    if path == "/control/conversation" && method == Method::GET {
        let Some(conversation) = conversation_id(&headers) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "missing or malformed x-piifence-conversation",
            );
        };
        return match bind_conversation(&state, &conversation) {
            Ok(loaded) => json_response(StatusCode::OK, json!({"loaded": loaded})),
            Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{err:#}")),
        };
    }

    let outgoing = if is_scanned {
```

`src/bin/gateway.rs:1266-1292`, the end of `main`:

```rust
    let state = AppState {
        detector_tx,
        client: reqwest::Client::builder()
            .build()
            .context("build the HTTP client")?,
        upstream,
        port,
        audit: Arc::new(Mutex::new(audit)),
        audit_body: audit_body.map(|file| Arc::new(Mutex::new(file))),
        stats: Arc::new(Mutex::new(Stats::default())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        session: String::new(),
    };

    let app = Router::new()
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("piifence gateway listening on http://127.0.0.1:{port}");
    eprintln!(
        "audit log: {audit_path} (body log: {})",
        audit_body_path.as_deref().unwrap_or("off")
    );
    axum::serve(listener, app).await?;
    Ok(())
}
```

Conventions to match:

- Every function and constant has a `///` doc comment that says what it does; see `session_id` at `src/bin/gateway.rs:431-439`. Test names are full sentences, such as `fill_values_replaces_names_in_every_string`. Errors use `anyhow` (`bail!`, `.context(...)`). Code comments are rare.
- `CLAUDE.md:27` says: "**No fallbacks.** A missing file, an unset required variable, an unparsable value, a failed write or a finding that cannot be placed is an error, never a silent default or a degraded mode. Defaults are allowed only for optional settings with one documented value (`PIIF_PORT` 7788, …), and a set value that does not parse is an error." `PIIF_EXIT_WHEN_UNUSED` follows this rule: 10 when unset, and an error when it is set but is not a whole number.
- The launcher reads optional settings like `port()` (`src/bin/piifence.rs:92-100`). The gateway reads them with `env_or` (`src/bin/gateway.rs:1202`), for example `let port: u16 = env_or("PIIF_PORT", 7788)?;` on line 1220.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format check | `cargo fmt --check` | exit 0, no output |
| Format (fix) | `cargo fmt` | exit 0 |
| Lint | `cargo clippy --release --all-targets -- -D warnings` | exit 0 |
| Build | `cargo build --release` | exit 0 |
| Gateway unit tests | `cargo test --release --bin piifence-gateway` | all pass |
| Launcher unit tests | `cargo test --release --bin piifence` | all pass |
| All unit tests | `cargo test --release` | all pass |
| Lifecycle check | `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/lifecycle_check.py` | prints `lifecycle ok`, exit 0 (about 30–60 s) |
| Fast checks | `scripts/check.sh --no-suite` | last line `check: all passed` |
| Full checks | `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh` | last line `check: all passed` (several minutes) |

## Scope

**In scope** (the only files you should modify):

- `src/bin/piifence.rs`
- `src/bin/gateway.rs`
- `Cargo.toml`, and `Cargo.lock` as cargo updates it (exactly one added line)
- `tests/secrets/lifecycle_check.py` (create)
- `scripts/check.sh`
- `tests/secrets/README.md`, `README.md`, `CLAUDE.md`
- `plans/README.md` (your status row only)

**Out of scope** (do NOT touch, even though they look related):

- `tests/secrets/run.py` and `tests/secrets/stats_check.py`. Their gateways must keep running until the check stops them, and they do, because they never set `PIIF_EXIT_WHEN_UNUSED`.
- `/health`, `/stats`, `/control/env`, `/control/conversation` and the saved-names and Keychain code. They stay as they are.
- The notice plugin (`plugin/piifence-notice`).
- Moving the control endpoints off loopback TCP. That is plan 012, which builds on this plan.
- Any gateway already running on port 7788. It may serve the operator's own Claude Code session. Never send it a request, never stop or restart it, and never run `pkill` or `killall` on gateway processes during this work.

## Git workflow

- Branch: `fix/shared-gateway-lifetime`. The repo uses `fix/<kebab>`, `feature/<kebab>` and `docs/<kebab>`.
- Commit messages: an imperative summary under 60 characters, a blank line, one bullet per change, and the trailer `Co-authored-by: Claude <noreply@anthropic.com>`. An example from `git log`: "Add a Homebrew formula so the repo works as a tap". Suggested commits: "Lease the gateway instead of stopping it on exit" for Steps 1–6, and "Document the gateway's lease and exit timer" for Step 7.
- Do NOT push or open a PR unless the operator told you to.

## Steps

### Step 1: Write the lifecycle check and watch it fail on the current code

Create `tests/secrets/lifecycle_check.py` with exactly this content. It starts two real launchers against a substitute for Claude Code. The first launcher starts the gateway and the second reuses it. The check then lets the first one exit and asserts that the second one still has its gateway, and that the gateway exits once both are gone. It always uses a free port, never 7788.

```python
"""Check that a gateway shared by two `piifence claude` launchers outlives the one that started it, and exits once neither uses it.

Starts two real launchers with a substitute for Claude Code, against the suite's fake upstream, on a free port (never 7788).

  PIIF_MODEL_DIR=<model> python3 -I tests/secrets/lifecycle_check.py      -> prints "lifecycle ok", exit 0
"""

import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import run  # noqa: E402

# Stands in for Claude Code: waits for its go file, then exits 0 only if the gateway still answers.
FAKE_CLAUDE = """import os, sys, time, urllib.request
while not os.path.exists(os.environ["LIFECYCLE_GO"]):
    time.sleep(0.1)
try:
    urllib.request.urlopen(os.environ["PIIF_GATEWAY_URL"] + "/health", timeout=5).read()
except OSError:
    sys.exit(3)
"""


def healthy(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


def control(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"x-piifence-session": "0" * 32})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as err:
        return err.code


def read(path):
    with open(path) as f:
        return f.read()


def wait_for(condition, seconds, what):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return
        time.sleep(0.2)
    raise AssertionError(f"timed out after {seconds} s waiting for {what}")


def stop_listener(port):
    """Stop whatever still listens on this check's own port, if the gateway failed to exit by itself."""
    pids = subprocess.run(["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True).stdout
    for pid in pids.split():
        os.kill(int(pid), signal.SIGTERM)


def main():
    model_dir = os.path.abspath(os.environ["PIIF_MODEL_DIR"].split(":")[0])
    target = os.environ.get("CARGO_TARGET_DIR", os.path.join(REPO, "target"))
    launcher = os.path.join(target, "release", "piifence")
    port = run.free_port()
    assert port != 7788, "the check must never touch the default port"
    sink = run.Sink()
    started = []
    with tempfile.TemporaryDirectory(prefix="piif-life-") as tmp:
        data = os.path.join(tmp, "data")
        os.makedirs(os.path.join(data, "plugin"))
        os.symlink(model_dir, os.path.join(data, "model"))
        os.symlink(os.path.join(REPO, "plugin", "piifence-notice"), os.path.join(data, "plugin", "piifence-notice"))
        script = os.path.join(tmp, "fake_claude.py")
        with open(script, "w") as f:
            f.write(FAKE_CLAUDE)
        fake = os.path.join(tmp, "claude")
        with open(fake, "w") as f:
            f.write(f'#!/bin/sh\nexec "{sys.executable}" -I "{script}"\n')
        os.chmod(fake, stat.S_IRWXU)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PIIF_", "ANTHROPIC_"))}
        env.update({
            "PIIF_DATA_DIR": data,
            "PIIF_UPSTREAM": f"http://127.0.0.1:{sink.port}",
            "PIIF_PORT": str(port),
            "PIIF_EXIT_WHEN_UNUSED": "1",
            "PIIF_GATEWAY_LOG": os.path.join(tmp, "gateway.log"),
            "PIIF_AUDIT_LOG": os.path.join(tmp, "audit.log"),
            "PIIF_CACHE_DIR": os.path.join(tmp, "cache"),
            "PIIF_STATE_DIR": os.path.join(tmp, "state"),
            "PIIF_CONFIG": os.path.join(tmp, "config.toml"),
            "CLAUDE_BIN": fake,
            "CLAUDE_CONFIG_DIR": os.path.join(tmp, "claude-config"),
        })

        def start(name):
            go = os.path.join(tmp, name + ".go")
            log = open(os.path.join(tmp, name + ".log"), "w")
            proc = subprocess.Popen([launcher, "claude"], env=dict(env, LIFECYCLE_GO=go),
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            started.append((proc, go, log))
            return proc, go

        try:
            first, first_go = start("first")
            wait_for(lambda: healthy(port), 180, "the gateway the first launcher starts")
            second, second_go = start("second")
            wait_for(lambda: "using existing gateway" in read(os.path.join(tmp, "second.log")), 30,
                     "the second launcher to reuse that gateway")
            open(first_go, "w").close()
            assert first.wait(timeout=30) == 0, read(os.path.join(tmp, "first.log"))
            time.sleep(3)
            assert healthy(port), "the gateway stopped while the second launcher still used it"
            assert control(port, "/control/lease") == 400, "a lease without a launcher pid must be refused"
            assert control(port, "/control/no-such-endpoint") == 404, "an unknown control path must not be forwarded"
            open(second_go, "w").close()
            assert second.wait(timeout=30) == 0, "the second session lost its gateway"
            wait_for(lambda: not healthy(port), 15, "the gateway to exit after the last launcher")
        finally:
            for proc, go, log in started:
                open(go, "w").close()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                log.close()
            if healthy(port):
                stop_listener(port)
            sink.close()
    print("lifecycle ok")


if __name__ == "__main__":
    main()
```

How it fits the launcher: `PIIF_DATA_DIR` holds the `model` and `plugin/piifence-notice` links that `run_claude` and `start_gateway` require. `CLAUDE_BIN` points the launcher at the substitute. `PIIF_UPSTREAM` means the user's Claude Code settings are never read. `PIIF_EXIT_WHEN_UNUSED=1` keeps the check fast; the launcher passes it through to the gateway after Step 4. `stop_listener` only runs on this check's own free port, and only if the gateway failed to exit.

**Verify**: `cargo build --release && PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/lifecycle_check.py` → exit 1, and the last line of the output is `AssertionError: the gateway stopped while the second launcher still used it`. That assertion is the bug this plan fixes. If the check fails anywhere else, STOP (see "STOP conditions").

### Step 2: Give the gateway a lease endpoint and an exit timer

2a. In `Cargo.toml`, change line 31 to:

```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time"] }
```

and add this line as the last line of `[dependencies]`, after the `chacha20poly1305` line:

```toml
libc = "0.2"
```

2b. In `src/bin/gateway.rs`, add this import after `use std::sync::{Arc, Mutex};` (line 15):

```rust
use std::time::{Duration, Instant};
```

The existing fully qualified uses (`std::time::Instant::now()` on line 1018 and `std::time::Duration::from_secs` on line 396) keep working; leave them.

2c. In `src/bin/gateway.rs`, directly after the `session_id` function (it ends on line 439), add:

```rust
/// The header carrying the process id of the `piifence claude` launcher that takes a lease.
const LAUNCHER_HEADER: &str = "x-piifence-launcher-pid";

/// How often a gateway started with `PIIF_EXIT_WHEN_UNUSED` checks that its launchers are still running.
const LEASE_CHECK: Duration = Duration::from_secs(1);

/// The `piifence claude` launchers using this gateway, as process ids by session id, and whether the gateway has started to shut down.
#[derive(Default)]
struct Leases {
    pids: HashMap<String, i32>,
    empty_since: Option<Instant>,
    closing: bool,
}

/// The launcher process id in `headers`, or None when it is missing or not a positive number.
fn launcher_pid(headers: &HeaderMap) -> Option<i32> {
    headers
        .get(LAUNCHER_HEADER)?
        .to_str()
        .ok()?
        .parse()
        .ok()
        .filter(|pid| *pid > 0)
}

/// Record that launcher `pid` runs `session` on this gateway. False when the gateway is shutting down: the launcher then waits for it to close and starts a new one.
fn take_lease(leases: &mut Leases, session: &str, pid: i32) -> bool {
    if leases.closing {
        return false;
    }
    leases.pids.insert(session.to_string(), pid);
    leases.empty_since = None;
    true
}

/// Drop the leases whose launcher process is gone, and mark the gateway as closing once no lease has been held for `grace`. Returns whether it is closing.
fn expire_leases(
    leases: &mut Leases,
    now: Instant,
    grace: Duration,
    alive: impl Fn(i32) -> bool,
) -> bool {
    leases.pids.retain(|_, pid| alive(*pid));
    if !leases.pids.is_empty() {
        leases.empty_since = None;
        return false;
    }
    let since = *leases.empty_since.get_or_insert(now);
    if now.duration_since(since) >= grace {
        leases.closing = true;
    }
    leases.closing
}

/// Whether process `pid` exists. Signal 0 is never delivered: `kill` only checks the process, and EPERM means it exists but belongs to another user.
fn process_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Finish once no launcher has held a lease for `grace`. `axum::serve` then stops accepting connections, finishes the open ones and returns, so the gateway exits.
async fn until_unused(leases: Arc<Mutex<Leases>>, grace: Duration) {
    loop {
        tokio::time::sleep(LEASE_CHECK).await;
        if expire_leases(&mut leases.lock().unwrap(), Instant::now(), grace, process_alive) {
            eprintln!(
                "no piifence claude session has used this gateway for {} s; shutting down",
                grace.as_secs()
            );
            return;
        }
    }
}
```

The mutex guard in `until_unused` is a temporary of the `if` condition, so it is released before the next `.await`. Keep it that way: never hold `leases` across an `.await`.

2d. In `AppState` (`src/bin/gateway.rs:48-62`), add this field directly after `sessions`:

```rust
    /// The launchers using this gateway (see `Leases`).
    leases: Arc<Mutex<Leases>>,
```

2e. In `proxy`, directly after the closing `}` of the `/control/conversation` block (line 1119) and before the blank line and `let outgoing = if is_scanned {`, add:

```rust
    // `piifence claude` takes a lease before it starts Claude Code. A gateway started with `PIIF_EXIT_WHEN_UNUSED` runs while a live launcher holds one.
    if path == "/control/lease" && method == Method::GET {
        let Some(pid) = launcher_pid(&headers) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "missing or malformed x-piifence-launcher-pid",
            );
        };
        return if take_lease(&mut state.leases.lock().unwrap(), &state.session, pid) {
            json_response(StatusCode::OK, json!({"leased": true}))
        } else {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "this gateway is shutting down")
        };
    }
    // Control paths are for the launcher and its hooks, so none is ever forwarded to the provider.
    if path.starts_with("/control/") {
        return error_response(StatusCode::NOT_FOUND, "no such control endpoint");
    }
```

The existing session check (line 1096) already answers 403 to a `/control/` request without a valid session id, so `/control/lease` needs no check of its own for that.

2f. In `main`:

- Directly after `let port: u16 = env_or("PIIF_PORT", 7788)?;` (line 1220), add:

```rust
    let exit_when_unused: u64 = env_or("PIIF_EXIT_WHEN_UNUSED", 0)?;
```

- Directly before `let state = AppState {` (line 1266), add:

```rust
    let leases = Arc::new(Mutex::new(Leases::default()));
```

- In that `AppState { ... }` literal, add `leases: leases.clone(),` directly after `sessions: Arc::new(Mutex::new(HashMap::new())),`.
- Replace the line `    axum::serve(listener, app).await?;` (line 1290) with:

```rust
    let serve = axum::serve(listener, app);
    if exit_when_unused > 0 {
        eprintln!("exits {exit_when_unused} s after the last piifence claude session ends");
        serve
            .with_graceful_shutdown(until_unused(leases, Duration::from_secs(exit_when_unused)))
            .await?;
    } else {
        serve.await?;
    }
```

The `Ok(())` after it stays.

2g. In `fake_state` in the tests module (`src/bin/gateway.rs:1316-1331`), add `leases: Arc::new(Mutex::new(Leases::default())),` directly after `sessions: Arc::new(Mutex::new(HashMap::new())),`. Without it the tests do not compile.

2h. Update the module doc at the top of `src/bin/gateway.rs`:

- After line 7 (the item that starts `//!   5. The session-start hook sends`), add one line:

```rust
//!   6. `piifence claude` takes a lease on `/control/lease` (its session id and process id) before it starts Claude Code. Started with `PIIF_EXIT_WHEN_UNUSED=<seconds>`, as the launcher does, the gateway exits once no live launcher has held a lease for that long. Any other `/control/` path is answered 404 and never forwarded.
```

- In the `//! Env:` line, insert `PIIF_EXIT_WHEN_UNUSED (seconds; above 0, exit once no launcher has held a lease that long; unset or 0, run until stopped), ` directly after `PIIF_PORT (7788), `.

**Verify**:
- `cargo build --release` → exit 0.
- `git diff Cargo.lock | grep '^[+-] '` → exactly one line: `+ "libc",`. (Adding the tokio feature does not change the lock.)
- `cargo clippy --release --all-targets -- -D warnings` → exit 0.

### Step 3: Test the lease logic in the gateway

Append these tests at the end of `mod tests` in `src/bin/gateway.rs`, before its final closing `}`:

```rust
    #[test]
    fn a_closing_gateway_refuses_a_lease() {
        let mut leases = Leases::default();
        assert!(take_lease(&mut leases, "a", 10));
        leases.closing = true;
        assert!(!take_lease(&mut leases, "b", 11));
        assert_eq!(leases.pids.len(), 1);
    }

    #[test]
    fn leases_of_launchers_that_exited_are_dropped() {
        let mut leases = Leases::default();
        take_lease(&mut leases, "a", 10);
        take_lease(&mut leases, "b", 11);
        let closing = expire_leases(&mut leases, Instant::now(), Duration::from_secs(10), |pid| pid == 11);
        assert!(!closing);
        assert_eq!(leases.pids.len(), 1);
        assert!(leases.pids.contains_key("b"));
    }

    #[test]
    fn the_gateway_closes_only_after_the_grace_passes_with_no_lease() {
        let grace = Duration::from_secs(10);
        let start = Instant::now();
        let mut leases = Leases::default();
        assert!(!expire_leases(&mut leases, start, grace, |_| true));
        assert!(!expire_leases(&mut leases, start + grace - Duration::from_millis(1), grace, |_| true));
        assert!(expire_leases(&mut leases, start + grace, grace, |_| true));
        assert!(leases.closing);
    }

    #[test]
    fn a_new_lease_restarts_the_grace() {
        let grace = Duration::from_secs(10);
        let start = Instant::now();
        let mut leases = Leases::default();
        expire_leases(&mut leases, start, grace, |_| true);
        take_lease(&mut leases, "a", 10);
        assert!(!expire_leases(&mut leases, start + grace, grace, |_| true));
        leases.pids.clear();
        assert!(!expire_leases(&mut leases, start + grace, grace, |_| true));
        assert!(!expire_leases(&mut leases, start + grace * 2 - Duration::from_millis(1), grace, |_| true));
        assert!(expire_leases(&mut leases, start + grace * 2, grace, |_| true));
    }

    #[test]
    fn this_process_is_alive_and_a_reaped_child_is_not() {
        assert!(process_alive(std::process::id() as i32));
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as i32;
        child.wait().unwrap();
        assert!(!process_alive(pid));
    }

    #[test]
    fn the_launcher_pid_header_must_be_a_positive_number() {
        let mut headers = HeaderMap::new();
        assert_eq!(launcher_pid(&headers), None);
        for (value, expected) in [("4242", Some(4242)), ("0", None), ("-5", None), ("12x", None)] {
            headers.insert(LAUNCHER_HEADER, value.parse().unwrap());
            assert_eq!(launcher_pid(&headers), expected, "{value}");
        }
    }
```

**Verify**: `cargo test --release --bin piifence-gateway -- lease grace process_is_alive launcher_pid` → `6 passed`, 0 failed. (No existing test name contains these words, so exactly these 6 run.)

### Step 4: Make the launcher lease the gateway instead of stopping it

All edits are in `src/bin/piifence.rs`.

4a. In the module doc, line 6, replace `runs Claude Code, then tears the gateway down if this process started it.` with:

```text
takes a lease on the gateway, and runs Claude Code. It never stops a gateway: one it started exits by itself once no `piifence claude` has held a lease for `PIIF_EXIT_WHEN_UNUSED` seconds (10 by default).
```

4b. Add this import after `use std::net::TcpStream;` (line 15):

```rust
use std::os::unix::process::CommandExt;
```

4c. Add this constant after `GATEWAY_START_TIMEOUT` (line 24):

```rust
/// Seconds a gateway started by `piifence claude` keeps running after the last lease ends, unless `PIIF_EXIT_WHEN_UNUSED` is set.
const DEFAULT_EXIT_WHEN_UNUSED: u64 = 10;
```

4d. Add this function directly after `port()` (it ends on line 100), following its pattern:

```rust
/// `PIIF_EXIT_WHEN_UNUSED`: the seconds a gateway this launcher starts keeps running without a lease (0: until stopped).
fn exit_when_unused() -> Result<u64> {
    match env::var("PIIF_EXIT_WHEN_UNUSED") {
        Ok(raw) => raw
            .parse()
            .with_context(|| format!("PIIF_EXIT_WHEN_UNUSED={raw:?} is not a whole number of seconds")),
        Err(_) => Ok(DEFAULT_EXIT_WHEN_UNUSED),
    }
}
```

4e. In `run_claude`, replace everything from `let mut gateway_child: Option<Child> = None;` (line 118) to the end of the function with:

```rust
    let session_id = new_session_id().context("cannot create a session id")?;
    ensure_gateway(&data, port, &upstream, &session_id)?;
    run_session(&gateway_url, port, &plugin, args, &session_id)
}
```

The lease ends when this process exits: the gateway notices within a second that the process is gone. So there is no release call and no cleanup code.

4f. Add these three functions directly after `run_claude`:

```rust
/// Make sure a gateway that forwards to `upstream` runs on `port`, starting one if none answers, and lease it so it keeps running while this launcher does. A gateway that is shutting down is waited out and replaced. The launcher never stops a gateway: one it started exits by itself after the last lease ends.
fn ensure_gateway(data: &Path, port: u16, upstream: &str, session_id: &str) -> Result<()> {
    let gateway_url = format!("http://127.0.0.1:{port}");
    for _ in 0..2 {
        match running_gateway_upstream(port) {
            // Reuse only a gateway that forwards to the same place this launch would. Reusing another one would send this session's credentials elsewhere.
            Some(running) if running == upstream => {
                eprintln!("piifence: using existing gateway on {gateway_url} (upstream {upstream})");
            }
            Some(running) => bail!(
                "a gateway on {gateway_url} forwards to {running:?}, but this launch wants {upstream}. Stop that gateway or set PIIF_PORT to a free port."
            ),
            None => start_gateway(data, port, upstream)?,
        }
        if lease(port, session_id)? {
            return Ok(());
        }
        wait_until_closed(port)?;
    }
    bail!("the gateway on {gateway_url} shut down twice while this launch tried to use it; refusing to launch Claude Code (fail closed)")
}

/// Ask the gateway on `port` to keep running while this process runs session `session_id`. False when the gateway is shutting down (503) or no longer answers. Any other answer means the gateway predates leases.
fn lease(port: u16, session_id: &str) -> Result<bool> {
    let headers = format!(
        "x-piifence-session: {session_id}\r\nx-piifence-launcher-pid: {}\r\n",
        std::process::id()
    );
    let Ok(response) = http_get(port, "/control/lease", &headers, Duration::from_secs(5)) else {
        return Ok(false);
    };
    if response.starts_with("HTTP/1.1 200") {
        return Ok(true);
    }
    if response.starts_with("HTTP/1.1 503") {
        return Ok(false);
    }
    let status = response.lines().next().unwrap_or_default();
    bail!(
        "the gateway on port {port} cannot hold a lease ({status}); it is probably from an older piifence. Quit the sessions that use it, or stop it with `pkill -f piifence-gateway`, and run again."
    )
}

/// Wait until the gateway on `port`, which is shutting down, stops answering.
fn wait_until_closed(port: u16) -> Result<()> {
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while running_gateway_upstream(port).is_some() {
        if Instant::now() >= deadline {
            bail!(
                "the gateway on port {port} did not shut down in {} s",
                GATEWAY_START_TIMEOUT.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}
```

A gateway that is shutting down stops accepting connections at once (axum drops its listener when the shutdown starts), so `wait_until_closed` normally returns within one poll.

4g. Change `start_gateway` as follows. Everything not mentioned stays.

- Replace its doc comment and signature with:

```rust
/// Start a gateway that exits by itself once no launcher holds a lease, and wait until a gateway that forwards to `upstream` is healthy. Claude Code is never launched without one (fail closed).
fn start_gateway(data: &Path, port: u16, upstream: &str) -> Result<()> {
```

- Directly after the `gateway_log` match, add:

```rust
    let exit_when_unused = exit_when_unused()?;
```

- Replace the `let mut child = Command::new(&gateway_bin)` statement with:

```rust
    // Its own process group, so closing this terminal does not stop a gateway that other sessions use.
    let mut child = Command::new(&gateway_bin)
        .env("PIIF_UPSTREAM", upstream)
        .env("PIIF_MODEL_DIR", &model_dir)
        .env("PIIF_PORT", port.to_string())
        .env("PIIF_EXIT_WHEN_UNUSED", exit_when_unused.to_string())
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .with_context(|| format!("could not start the gateway {}", gateway_bin.display()))?;
```

- Change `if let Err(err) = wait_healthy(port, &mut child) {` to `if let Err(err) = wait_healthy(port, upstream, &mut child) {`. The kill inside that error branch stays: it only stops this launcher's own child, which never became healthy.
- Change the last line, `Ok(child)`, to `Ok(())`. Dropping the `Child` handle neither stops nor waits for the gateway.

4h. Replace `wait_healthy` (lines 265-280) with:

```rust
/// Wait until a gateway that forwards to `upstream` answers on `port`. Another launcher may start a gateway at the same moment, and only one of the two gets the port; the other one's gateway is used when it forwards to the same upstream.
fn wait_healthy(port: u16, upstream: &str, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while Instant::now() < deadline {
        let exited = child.try_wait()?;
        match running_gateway_upstream(port) {
            Some(running) if running == upstream => return Ok(()),
            Some(running) => bail!(
                "a gateway that forwards to {running:?} took port {port} first, but this launch wants {upstream}. Set PIIF_PORT to a free port."
            ),
            None => {}
        }
        if let Some(status) = exited {
            bail!("the gateway exited during startup ({status})");
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!(
        "the gateway did not become healthy in {} s",
        GATEWAY_START_TIMEOUT.as_secs()
    )
}
```

4i. In `run_session`, take the session id as a parameter instead of creating it:

- Change the signature to `fn run_session(gateway_url: &str, port: u16, plugin: &Path, args: &[String], session_id: &str) -> Result<i32> {`.
- Delete the line `let session_id = new_session_id().context("cannot create a session id")?;`.
- Change `write_settings_override(gateway_url, port, &session_id)` to `write_settings_override(gateway_url, port, session_id)`.

**Verify**:
- `cargo build --release` → exit 0.
- `cargo clippy --release --all-targets -- -D warnings` → exit 0.
- `grep -c 'child.kill()' src/bin/piifence.rs` → `1` (only the error branch in `start_gateway`).
- `grep -c 'new_session_id()' src/bin/piifence.rs` → `1` (only in `run_claude`).

### Step 5: Test the launcher's lease answers

Append to `mod tests` in `src/bin/piifence.rs`, before its final closing `}`:

```rust
    /// The port of a one-request HTTP server on loopback that reads a whole request and answers `status` with an empty body.
    fn answer_once(status: &'static str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            let reply = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            stream.write_all(reply.as_bytes()).unwrap();
        });
        port
    }

    #[test]
    fn a_lease_is_held_on_200_and_refused_on_503_or_no_answer() {
        let session = "0".repeat(32);
        assert!(lease(answer_once("200 OK"), &session).unwrap());
        assert!(!lease(answer_once("503 Service Unavailable"), &session).unwrap());
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(!lease(closed, &session).unwrap());
    }

    #[test]
    fn a_lease_on_a_gateway_that_predates_leases_is_an_error() {
        let err = lease(answer_once("404 Not Found"), &"0".repeat(32)).unwrap_err();
        assert!(format!("{err:#}").contains("older piifence"), "{err:#}");
    }
```

The server reads until the blank line that ends the request before it answers. Answering earlier can reset the connection and make the test flaky.

**Verify**: `cargo test --release --bin piifence -- a_lease` → `2 passed`, 0 failed.

### Step 6: Run the lifecycle check and add it to the suite

Run the check from Step 1 again, now against the fixed binaries.

Then add it to `scripts/check.sh`, directly after line 20 (`  run python3 -I tests/secrets/stats_check.py`):

```bash
  run python3 -I tests/secrets/lifecycle_check.py
```

**Verify**:
- `cargo build --release && PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/lifecycle_check.py` → the last line is `lifecycle ok`, exit 0.
- `grep -c 'lifecycle_check.py' scripts/check.sh` → `1`.

### Step 7: Update the docs

Make these edits. Find each one by its quoted text.

1. `README.md`, the "Upgrading" section, step 1. Replace `` `piifence claude` reuses a gateway that is already running, so an old gateway keeps serving until it stops. `` with:

```text
A gateway that `piifence claude` started exits by itself about 10 seconds after its last session ends; until then, a new `piifence claude` reuses it.
```

2. `README.md`, the environment variable table. Add this row directly below the `PIIF_GATEWAY_LOG` row:

```text
| `PIIF_EXIT_WHEN_UNUSED` | `10` | Seconds a gateway started by `piifence claude` keeps running after the last `piifence claude` that used it exits. `0` keeps it running until you stop it. |
```

3. `README.md`, "The gateway doesn't start". Add this bullet directly below the bullet that starts `` - **`a gateway on … forwards to …`** ``:

```text
- **`cannot hold a lease`**: a gateway from an older piifence is still running on the port. Quit the sessions that use it, or stop it with `pkill -f piifence-gateway`.
```

4. `CLAUDE.md:27`. Replace ``(`PIIF_PORT` 7788, `` with ``(`PIIF_PORT` 7788, `PIIF_EXIT_WHEN_UNUSED` 10 for a gateway the launcher starts, ``.

5. `CLAUDE.md:30`. Replace `` `PIIF_PORT`, `PIIF_AUDIT_LOG` `` with:

```text
`PIIF_PORT`, `PIIF_EXIT_WHEN_UNUSED` (seconds; above 0 the gateway exits once no live launcher has held a lease that long), `PIIF_AUDIT_LOG`
```

6. `CLAUDE.md:40`. Directly after the sentence `It reuses a running gateway only when its `/health` reports the same upstream.`, insert:

```text
 Before Claude Code starts, it takes a lease (`GET /control/lease` with the session id and `x-piifence-launcher-pid`), and it never stops a gateway: one it started runs with `PIIF_EXIT_WHEN_UNUSED` (10 unless set) and exits once no live launcher has held a lease that long. A 503 answer means that gateway is shutting down, so the launcher waits for it to close and starts a new one.
```

7. `tests/secrets/README.md`, inside the code block, directly after line 34 (the `stats_check.py` line), add:

```text
PIIF_MODEL_DIR=<model dir> python3 -I tests/secrets/lifecycle_check.py   # a shared gateway outlives the launcher that started it
```

**Verify**:
- `grep -c 'PIIF_EXIT_WHEN_UNUSED' README.md` → `1`.
- `grep -c 'cannot hold a lease' README.md` → `1`.
- `grep -c 'PIIF_EXIT_WHEN_UNUSED' CLAUDE.md` → `3`.
- `grep -c 'lifecycle_check.py' tests/secrets/README.md` → `1`.
- `grep -c 'tears the gateway down' src/bin/piifence.rs` → `0`.

### Step 8: Run every check

**Verify**:
- `cargo fmt --check` → exit 0. If it fails, run `cargo fmt` and check again.
- `scripts/check.sh --no-suite` → the last line is `check: all passed`.
- `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh` → the last line is `check: all passed`.

## Test plan

- Gateway unit tests (6 new), in `mod tests` of `src/bin/gateway.rs`, as plain `#[test]` functions like the existing ones there:
  - a closing gateway refuses a lease;
  - leases of launchers that exited are dropped;
  - the gateway closes only after the grace passes with no lease, and not one millisecond earlier;
  - a new lease restarts the grace;
  - `process_alive` is true for this process and false for a child that was reaped;
  - the launcher pid header must be a positive number.
- Launcher unit tests (2 new), in `mod tests` of `src/bin/piifence.rs`, using a one-request loopback server:
  - a lease is held on 200, and refused on 503 or when nothing listens;
  - any other answer, such as an older gateway's 404, is an error that names the cause.
- End to end: `tests/secrets/lifecycle_check.py`, modeled on `tests/secrets/stats_check.py`, in the suite block of `scripts/check.sh`. It fails on the code at `fc97e3d` (Step 1) and passes after Step 4.
- Verification: `cargo test --release` passes, including the 8 new tests, and the lifecycle check prints `lifecycle ok`.

## Done criteria

ALL must hold:

- [ ] `cargo fmt --check` exits 0
- [ ] `cargo clippy --release --all-targets -- -D warnings` exits 0
- [ ] `cargo test --release` exits 0
- [ ] `cargo test --release --bin piifence-gateway -- lease grace process_is_alive launcher_pid` reports `6 passed`
- [ ] `cargo test --release --bin piifence -- a_lease` reports `2 passed`
- [ ] `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/lifecycle_check.py` prints `lifecycle ok`
- [ ] `grep -c 'child.kill()' src/bin/piifence.rs` prints `1`
- [ ] `git diff fc97e3d -- Cargo.lock | grep '^[+-] '` prints only `+ "libc",`
- [ ] `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh` ends with `check: all passed`
- [ ] `git status --short` lists only files from the in-scope list
- [ ] `plans/README.md` status row for 011 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The code at the locations in "Current state" does not match the excerpts.
- The model directory `$HOME/.local/share/piifence/model` does not exist. The lifecycle check and the full suite need it. Ask the operator for the path; do not download the model without their approval.
- In Step 1, the check fails with any message other than `the gateway stopped while the second launcher still used it`. That means the check's setup (the substitute, the links or the environment) is wrong, and a pass later would prove nothing.
- `Cargo.lock` changes in any way other than the one added `"libc",` line, for example a version bump.
- The lifecycle check fails twice after a reasonable fix attempt. Do not raise its timeouts or sleeps to make it pass; report the output and the gateway log instead.
- Any step would need you to send a request to port 7788, stop or restart a process there, or run `pkill` or `killall` on gateway processes.
- `cargo test --release` hangs, or takes more than 10 s longer than before your change.

## Maintenance notes

- Plan 012 moves every `/control/` endpoint, `/control/lease` included, to a private Unix socket. Whoever changes the lease protocol must change the gateway, the launcher and `tests/secrets/lifecycle_check.py` together.
- A lease is a process id. If a launcher dies and a new process gets its id within a second, the gateway stays up until that new process exits. That is harmless: a gateway that runs longer is today's behaviour.
- If a launcher is killed with SIGKILL while its Claude Code keeps running, the gateway exits after the grace period and that Claude Code's requests fail. This fails closed: nothing is sent unredacted.
- When two launchers start a gateway at the same moment, the gateway that loses the port writes "Address already in use" to the shared gateway log and exits. That line is expected.
- The gateway now exits by returning from `main` while the detector thread is still running. The detection cache writes one whole line per append (`src/cache.rs:130-133`), so nothing buffered is lost. A future buffered writer would have to be flushed before `main` returns.
- Reviewers should check three things: no path in the launcher stops a gateway that it did not just start and fail to reach, `wait_healthy` compares the upstream, and the `/control/` 404 comes after every real control route in `proxy`.
