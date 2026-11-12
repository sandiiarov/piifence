# Plan 012: Serve the gateway's control endpoints and `/stats` only on a private Unix socket

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving to the next step. If anything in the "STOP conditions" section occurs, stop and report; do not improvise. When done, update the status row for this plan in `plans/README.md`, unless a reviewer dispatched you and told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat fc97e3d..HEAD -- src/lib.rs src/bin/piifence.rs src/bin/gateway.rs plugin/piifence-notice/scripts/notice.py tests/secrets/run.py tests/secrets/stats_check.py tests/secrets/lifecycle_check.py tests/secrets/README.md README.md CLAUDE.md plugin/piifence-notice/README.md Cargo.toml Cargo.lock`
> This plan builds on plan 011, so most of these files have changed since `fc97e3d`: by plan 011, and in places by plans 009 and 010. That is expected. The "Current state" excerpts show the code as plan 011 leaves it; compare them against the live code before proceeding, and on a mismatch, treat it as a STOP condition. Find every edit by its quoted text, not by its line number: line numbers below are from `fc97e3d` and are only a guide.

## Status

- **Priority**: P1
- **Effort**: M (about 5–7 hours: a 30-line library module, about 150 lines of Rust across both binaries, about 60 lines of Python, two end-to-end runs)
- **Risk**: MED (every hook and the notice plugin reach the gateway a new way. A mistake makes `piifence env`, the `PreToolUse` hook or the notice fail. That fails closed: Bash commands run without the values and tool calls that hold a name are blocked; no value is sent anywhere)
- **Depends on**: plans/011-shared-gateway-lifetime.md
- **Category**: security
- **Planned at**: commit `fc97e3d`, 2026-11-11

## Why this matters

piifence is a local gateway (`src/bin/gateway.rs`) that replaces secrets in Claude Code's requests with names such as `PIIF_SECRET_<N>` and keeps the real values in memory. It listens on `127.0.0.1:7788`, and every account on the Mac can connect to a loopback TCP port, not only the user who started it. Today the gateway serves everything on that port, including `GET /control/env`, which returns a session's names and real values to any caller that sends the session's id in the `x-piifence-session` header.

That id is not hidden from other accounts. The launcher passes Claude Code a settings file named after it (`$TMPDIR/piifence-claude-settings-<id>.json`, `src/bin/piifence.rs:322`), the hooks get it as a command-line argument, and macOS `ps` shows every process's arguments to every account. So any other local account (another person, a service account, or malware running as one) can read every secret of every running session with one `ps` and one HTTP request. Two more endpoints are exposed the same way: `/control/conversation` accepts any made-up session id and loads a saved conversation's decrypted names into it, given the conversation id, and `/stats` gives masked previews of recent secrets to any caller, with no session at all.

After this plan, `/stats`, every `/control/` path, and the `/health` answer that names the upstream are served only on a Unix socket, `<state dir>/run/<port>.sock`, in a directory that only the user can open (mode 0700). The TCP port serves the proxy and a bare `/health`, and answers 404 for the rest. The launcher, its hooks and the notice plugin talk to the gateway over the socket. As a side effect, the launcher stops trusting a port that answers on TCP without that socket, so a program or another account that holds the port can no longer pass for the gateway.

## Current state

Files:

- `src/bin/gateway.rs`: the gateway, an axum server. `proxy` is the one handler for every path. `main` reads the environment, binds `127.0.0.1:<port>` and serves.
- `src/bin/piifence.rs`: the launcher (`piifence claude`) and the hook commands `piifence session-start`, `piifence env` and `piifence restore`. Each hook gets `<session> <port>` as its arguments (`session_args`, lines 354-365). All of them reach the gateway through `http_get`, one raw HTTP GET over loopback TCP.
- `src/lib.rs`: the library crate, which both binaries can use. The gateway already calls `piifence::config::load()`. `src/config.rs:23-30` is the pattern for a path that comes from an environment variable with a documented default.
- `plugin/piifence-notice/scripts/notice.py`: the notice plugin's hook. It reads `/stats` over TCP from `PIIF_GATEWAY_URL`.
- `tests/secrets/run.py`: the suite's helpers: `Sink` (a fake upstream), `free_port()`, `post()`, `session_for()` (a case's session id, the md5 hex of the case id) and `Gateway` (starts the real gateway on a free port, with files in a temp dir).
- `tests/secrets/stats_check.py`: an end-to-end check of `/stats` and the notice.
- `tests/secrets/lifecycle_check.py`: added by plan 011. Two real launchers share one gateway.
- `plugin/piifence-notice/README.md`: the plugin's README. Line 7 says that `piifence claude` sets `PIIF_GATEWAY_URL`.

The notice plugin is the only reader of `PIIF_GATEWAY_URL` in the product. `git grep -n PIIF_GATEWAY_URL` finds it only in `run_session` (which sets it), the notice plugin and its README, `CLAUDE.md:44`, `stats_check.py`, and plan 011's `lifecycle_check.py`.

`src/bin/gateway.rs:1042-1068` and `1095-1106`, parts of `proxy`:

```rust
async fn proxy(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !is_local_request(&state, &headers) {
        return error_response(
            StatusCode::FORBIDDEN,
            "piifence only accepts local, non-browser requests",
        );
    }
    let state = AppState {
        session: session_id(&headers),
        ..state
    };
    let path = uri.path();
    if path == "/health" {
        // The launcher compares this header to its own upstream before reusing a gateway.
        return Response::builder()
            .status(StatusCode::OK)
            .header("x-piifence-upstream", state.upstream.as_str())
            .body(Body::from("ok"))
            .expect("valid response");
    }
    if path == "/stats" {
```

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
```

After `/control/env` come `/control/conversation`, plan 011's `/control/lease`, and plan 011's catch-all that answers 404 `no such control endpoint` for any other `/control/` path. `is_local_request` (`src/bin/gateway.rs:64-80`) refuses a request with an `Origin` header, and accepts only the Host values `127.0.0.1:<port>`, `localhost:<port>` and `127.0.0.1`.

`src/bin/gateway.rs:1231-1238`, the state directory in `main`:

```rust
    let names_dir = match std::env::var("PIIF_STATE_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from(std::env::var("HOME").context("HOME is not set")?)
            .join(".local/state/piifence"),
    }
    .join("names");
    prepare_names_dir(&names_dir)?;
    NAMES_DIR.set(names_dir).expect("set once");
```

The end of `main`, as plan 011 leaves it:

```rust
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
    let serve = axum::serve(listener, app);
    if exit_when_unused > 0 {
        eprintln!("exits {exit_when_unused} s after the last piifence claude session ends");
        serve
            .with_graceful_shutdown(until_unused(leases, Duration::from_secs(exit_when_unused)))
            .await?;
    } else {
        serve.await?;
    }
    Ok(())
}
```

Plan 011 also added, after `session_id` in `src/bin/gateway.rs`, the lease code: `LAUNCHER_HEADER`, `LEASE_CHECK`, `Leases`, `launcher_pid`, `take_lease`, `expire_leases`, `process_alive` and, last, `async fn until_unused(leases: Arc<Mutex<Leases>>, grace: Duration)`, whose doc comment reads: "Finish once no launcher has held a lease for `grace`. `axum::serve` then stops accepting connections, finishes the open ones and returns, so the gateway exits."

`src/bin/piifence.rs:234-263`, `http_get` and `running_gateway_upstream`:

```rust
/// Raw HTTP response to `GET path` on the loopback port, with `headers` (`Name: value` lines).
fn http_get(port: u16, path: &str, headers: &str, timeout: Duration) -> std::io::Result<String> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(300))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{headers}Connection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;
    // The gateway closes the connection after the response (Connection: close), so reading to the end gets the whole reply.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

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
```

The two hook calls that carry a session id, `src/bin/piifence.rs:411-418` (`bind_conversation`) and `539-546` (`session_values`):

```rust
fn bind_conversation(session: &str, port: u16, conversation: &str) -> Result<()> {
    let response = http_get(
        port,
        "/control/conversation",
        &format!("x-piifence-session: {session}\r\nx-piifence-conversation: {conversation}\r\n"),
        Duration::from_secs(30),
    )
    .with_context(|| format!("the gateway on port {port} did not answer"))?;
```

```rust
fn session_values(session: &str, port: u16) -> Result<serde_json::Map<String, serde_json::Value>> {
    let response = http_get(
        port,
        "/control/env",
        &format!("x-piifence-session: {session}\r\n"),
        Duration::from_secs(2),
    )
    .with_context(|| format!("the gateway on port {port} did not answer"))?;
```

Plan 011's launcher functions, in `src/bin/piifence.rs` directly after `run_claude` and at the old places of `start_gateway` and `wait_healthy`. Only the lines this plan changes are shown in full:

```rust
fn ensure_gateway(data: &Path, port: u16, upstream: &str, session_id: &str) -> Result<()> {
    let gateway_url = format!("http://127.0.0.1:{port}");
    for _ in 0..2 {
        match running_gateway_upstream(port) {
            // ... the `Some(running) if running == upstream` and `Some(running)` arms ...
            None => start_gateway(data, port, upstream)?,
        }
        if lease(port, session_id)? {
            return Ok(());
        }
        wait_until_closed(port)?;
    }
    // ... bail!: the gateway shut down twice ...
}

fn lease(port: u16, session_id: &str) -> Result<bool> {
    // ... `let headers = format!(...)` with the session and launcher-pid headers ...
    let Ok(response) = http_get(port, "/control/lease", &headers, Duration::from_secs(5)) else {
        return Ok(false);
    };
    // ... 200 → Ok(true), 503 → Ok(false) ...
    let status = response.lines().next().unwrap_or_default();
    bail!(
        "the gateway on port {port} cannot hold a lease ({status}); it is probably from an older piifence. Quit the sessions that use it, or stop it with `pkill -f piifence-gateway`, and run again."
    )
}

fn wait_until_closed(port: u16) -> Result<()> {
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while running_gateway_upstream(port).is_some() {
    // ...
}

fn start_gateway(data: &Path, port: u16, upstream: &str) -> Result<()> {
    // ...
    if let Err(err) = wait_healthy(port, upstream, &mut child) {
    // ...
}

fn wait_healthy(port: u16, upstream: &str, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while Instant::now() < deadline {
        let exited = child.try_wait()?;
        match running_gateway_upstream(port) {
        // ...
}
```

`run_session`, as plan 011 leaves it, takes `session_id: &str` as its last parameter, and its `Command::new(&claude)` chain sets `.env("PIIF_GATEWAY_URL", gateway_url)`.

`plugin/piifence-notice/scripts/notice.py`, lines 6, 9, 13-20 and 38-39:

```python
`piifence claude` loads this plugin and sets PIIF_GATEWAY_URL. A gateway that does not answer is an error: the hook exits non-zero, so Claude Code shows it.
```

```python
  PIIF_GATEWAY_URL   required, e.g. http://127.0.0.1:7788
```

```python
import json
import os
import pathlib
import sys
import urllib.request

GATEWAY = os.environ["PIIF_GATEWAY_URL"].rstrip("/")
STATE = pathlib.Path(os.environ.get("PIIF_NOTICE_STATE", "/tmp/piifence-notice-state.json"))
```

```python
    with urllib.request.urlopen(GATEWAY + "/stats", timeout=1.5) as resp:
        stats = json.loads(resp.read())
```

`tests/secrets/stats_check.py:26-35`:

```python
def stats(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=5) as r:
        return json.loads(r.read())


def notice(port, state_file, hook="Stop"):
    env = dict(os.environ, PIIF_GATEWAY_URL=f"http://127.0.0.1:{port}", PIIF_NOTICE_STATE=state_file)
    out = subprocess.run([sys.executable, "-I", NOTICE], input=json.dumps({"hook_event_name": hook}).encode(),
                         capture_output=True, env=env, check=True)
    return json.loads(out.stdout or b"{}")
```

Its `main` (lines 38-59) starts `gw = run.Gateway(...)` in a `tempfile.TemporaryDirectory(prefix="piif-stats-")`, then calls `notice(gw.port, ...)` three times, `stats(gw.port)` twice and `run.post(gw.port, path, body, "turn")` twice. Line 46 is the first `assert run.post(gw.port, path, body, "turn") == 200`.

`tests/secrets/run.py:225-238`, the start of `Gateway`:

```python
class Gateway:
    def __init__(self, model_dir, sink_port, tmp):
        self.port = free_port()
        env = {k: v for k, v in os.environ.items() if not k.startswith("PIIF_")}
        env.update({
            "PIIF_UPSTREAM": f"http://127.0.0.1:{sink_port}",
            "PIIF_PORT": str(self.port),
            "PIIF_AUDIT_LOG": os.path.join(tmp, "audit.log"),
            "PIIF_MODEL_DIR": model_dir,
            # No config file: no `allow` exceptions, whatever the user has configured.
            "PIIF_CONFIG": os.path.join(tmp, "config.toml"),
            # A fresh detection cache, so every run measures detection itself.
            "PIIF_CACHE_DIR": os.path.join(tmp, "cache"),
        })
```

`run.py` sets no `PIIF_STATE_DIR`, so today the suite's gateway uses the user's real `~/.local/state/piifence`. `run.py` imports `http.server` (line 14) and `socket` (line 19), but not `http.client`.

`tests/secrets/lifecycle_check.py`, as plan 011 writes it (its Step 1), has these parts this plan changes:

```python
import urllib.error
```

```python
# Stands in for Claude Code: waits for its go file, then exits 0 only if the gateway still answers.
FAKE_CLAUDE = """import os, sys, time, urllib.request
while not os.path.exists(os.environ["LIFECYCLE_GO"]):
    time.sleep(0.1)
try:
    urllib.request.urlopen(os.environ["PIIF_GATEWAY_URL"] + "/health", timeout=5).read()
except OSError:
    sys.exit(3)
"""
```

```python
def control(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"x-piifence-session": "0" * 32})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as err:
        return err.code
```

In its `main`, the environment sets `"PIIF_STATE_DIR": os.path.join(tmp, "state")`, and the `try:` block starts with `first, first_go = start("first")`, asserts `control(port, "/control/lease") == 400` and `control(port, "/control/no-such-endpoint") == 404`, and ends with `wait_for(lambda: not healthy(port), 15, "the gateway to exit after the last launcher")`.

Conventions to match:

- Every function and constant has a `///` doc comment (`//!` for a module). Test names are full sentences, such as `a_lease_is_held_on_200_and_refused_on_503_or_no_answer`. Errors use `anyhow`: `bail!`, `.context(...)`, `.with_context(|| format!(...))`.
- `CLAUDE.md:27`: "**No fallbacks.** A missing file, an unset required variable, an unparsable value, a failed write or a finding that cannot be placed is an error, never a silent default or a degraded mode. Defaults are allowed only for optional settings with one documented value". `PIIF_STATE_DIR`'s default, `~/.local/state/piifence`, is already documented in `README.md`'s environment table.

Platform facts, checked for this plan:

- axum 0.8.9 serves a `tokio::net::UnixListener` with the same `axum::serve` call it uses for TCP. `Router::layer` also wraps the fallback handler, so a middleware layered on the router sees every request that `proxy` gets.
- `tokio::select!` in tokio 1.54.1 takes an `axum::serve(...)` value directly as a branch (it calls `IntoFuture::into_future` on it).
- No new crate or feature is needed: tokio's `net` feature, already on, includes `UnixListener`, and the launcher uses `std::os::unix::net::UnixStream`.
- macOS limits a Unix socket path to 104 bytes. The default path, `~/.local/state/piifence/run/7788.sock`, is about 55 bytes with a typical home directory. The suite's temp dirs give about 90 bytes.
- The installed copies that the user's running sessions use are in `~/.local/libexec/piifence/`, copied there by `scripts/install.sh`. Building in `target/` does not touch them.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Build | `cargo build --release` | exit 0 |
| Lint | `cargo clippy --release --all-targets -- -D warnings` | exit 0 |
| Format | `cargo fmt --check` | exit 0 |
| Library test | `cargo test --release --lib -- control::tests` | `1 passed` |
| Gateway tests | `cargo test --release --bin piifence-gateway -- control_socket` | `2 passed` |
| Launcher tests | `cargo test --release --bin piifence -- a_lease control_socket` | `3 passed` |
| All Rust tests | `cargo test --release` | exit 0 |
| Stats check | `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/stats_check.py` | last line `stats ok` |
| Lifecycle check | `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/lifecycle_check.py` | last line `lifecycle ok` |
| Every check | `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh` | last line `check: all passed` |

## Scope

**In scope** (the only files you should modify):

- `src/control.rs` (create)
- `src/lib.rs`
- `src/bin/gateway.rs`
- `src/bin/piifence.rs`
- `plugin/piifence-notice/scripts/notice.py`
- `tests/secrets/run.py`
- `tests/secrets/stats_check.py`
- `tests/secrets/lifecycle_check.py`
- `README.md`, `CLAUDE.md`, `tests/secrets/README.md`, `plugin/piifence-notice/README.md`

**Out of scope** (do NOT touch, even though they look related):

- `Cargo.toml` and `Cargo.lock`. No new dependency or feature is needed; if the build says otherwise, STOP.
- The proxy itself. It stays on TCP, because Claude Code reaches the gateway through `ANTHROPIC_BASE_URL`, which is an `http://` URL.
- The hook arguments (`<session> <port>`) and the settings override file. The session id stays visible in `ps`; after this plan it no longer unlocks anything on TCP but the proxy, which never returns a value.
- What `/control/env`, `/control/conversation`, `/control/lease` and `/stats` return. Only where they are served changes.
- Per-session `/stats` and the notice's shared state file. Those are a separate finding.
- `scripts/check.sh`: plan 011 already runs both checks this plan changes.
- `scripts/install.sh`, Homebrew, and everything under `~/.local/libexec/piifence/`, `~/.local/share/piifence/` and `~/.local/state/piifence/`. The checks use temp state dirs; never create, change or delete anything in the real ones.
- Port 7788. Never send it a request, and never stop or restart a process there.

## Git workflow

- Branch: `fix/private-control-socket`, created from a commit that has plan 011. The repo uses `fix/<kebab>`, `feature/<kebab>` and `docs/<kebab>`.
- Before Step 1, record the commit you start from with `git rev-parse HEAD`. The done criteria call it `BASE`.
- Commit messages: an imperative summary under 60 characters, a blank line, one bullet per change, and the trailer `Co-authored-by: Claude <noreply@anthropic.com>`. An example from `git log`: "Add a Homebrew formula so the repo works as a tap". Suggested commits: "Serve control endpoints only on a private socket" for Steps 1–8, and "Document the gateway's control socket" for Step 9.
- Do NOT push or open a PR unless the operator told you to.

## Steps

### Step 1: Make the stats check prove the leak, and watch it fail

1a. In `tests/secrets/run.py`:

- Add `import http.client` directly before `import http.server` (line 14).
- Directly after the `free_port` function (it ends on line 208), add:

```python
class SocketConnection(http.client.HTTPConnection):
    """HTTP over a gateway's control socket, a Unix socket, instead of TCP."""

    def __init__(self, path, timeout=5):
        super().__init__("127.0.0.1", timeout=timeout)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def socket_get(socket_path, path, headers=None):
    """Status, headers and body of `GET path` on a gateway's control socket; an error status is returned, not raised."""
    conn = SocketConnection(socket_path)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.headers, resp.read()
    finally:
        conn.close()
```

- In `Gateway.__init__`, directly after `self.port = free_port()`, add:

```python
        self.socket = os.path.join(tmp, "state", "run", f"{self.port}.sock")
```

- In the same method's `env.update({...})`, directly after the line `"PIIF_CACHE_DIR": os.path.join(tmp, "cache"),`, add:

```python
            # A temp state dir, so the gateway's names and its control socket (run/<port>.sock) stay out of the user's own.
            "PIIF_STATE_DIR": os.path.join(tmp, "state"),
```

`SocketConnection` connects to the socket and sends the Host header `127.0.0.1`, which `is_local_request` accepts. The new `PIIF_STATE_DIR` also stops the suite from using the user's real state directory, which it does today.

1b. In `tests/secrets/stats_check.py`:

- Add `import urllib.error` directly before `import urllib.request`.
- Directly after the `notice` function, add:

```python
def tcp_get(port, path, headers=None):
    """Status and headers of `GET path` on the gateway's TCP port; an error status is returned, not raised."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.headers
    except urllib.error.HTTPError as err:
        return err.code, err.headers
```

- In `main`, directly after the first `assert run.post(gw.port, path, body, "turn") == 200` (line 46), add these lines at the same indentation:

```python
            # Any account on this machine can connect to the TCP port, so nothing there may hand out a session's values or previews, or name the upstream.
            session = {"x-piifence-session": run.session_for("turn")}
            assert tcp_get(gw.port, "/control/env", session)[0] == 404, "TCP must not hand out a session's values"
            assert tcp_get(gw.port, "/stats")[0] == 404, "TCP must not serve /stats"
            status, headers = tcp_get(gw.port, "/health")
            assert status == 200 and headers.get("x-piifence-upstream") is None, "TCP /health must not name the upstream"
```

`run.session_for("turn")` is the session that `run.post(..., "turn")` just used, so the gateway holds one value for it. Today `/control/env` answers 200 on TCP with that value, which is the leak this plan closes.

**Verify**: `cargo build --release && PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/stats_check.py` → exit 1, and the last line of the output is `AssertionError: TCP must not hand out a session's values`. If it fails anywhere else, STOP.

### Step 2: Add the socket's path to the library

2a. Create `src/control.rs` with exactly this content:

```rust
//! The gateway's control socket: a Unix socket in a directory only the user can open.
//!
//! The gateway serves its proxy on `127.0.0.1:<port>`, which every account on the machine can connect to. So `/stats`, every `/control/` path and the `/health` answer that names the upstream are served only on `<state dir>/run/<port>.sock`. The gateway creates `run/` with mode 0700; the launcher, its hooks and the notice plugin connect there.

use std::path::{Path, PathBuf};

use anyhow::Context;

/// `$PIIF_STATE_DIR`, or `~/.local/state/piifence` when that is unset.
pub fn state_dir() -> anyhow::Result<PathBuf> {
    if let Ok(dir) = std::env::var("PIIF_STATE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/state/piifence"))
}

/// The control socket of the gateway on `port`: `run/<port>.sock` in `state_dir`.
pub fn socket_path(state_dir: &Path, port: u16) -> PathBuf {
    state_dir.join("run").join(format!("{port}.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socket_for_a_port_is_in_the_run_directory_of_the_state_dir() {
        assert_eq!(
            socket_path(Path::new("/state"), 7788),
            Path::new("/state/run/7788.sock")
        );
    }
}
```

`state_dir` gives exactly the directory the gateway uses today (the `match` at `src/bin/gateway.rs:1231-1235`); Step 3 makes the gateway call it, so the gateway and the launcher can never disagree.

2b. In `src/lib.rs`:

- Add `pub mod control;` directly after `pub mod config;`.
- At the end of line 3 (the crate doc paragraph that ends `Used by the gateway (`src/bin/gateway.rs`).`), append this sentence after a space: `` `control` says where the gateway's private control socket is, for the gateway and the launcher (`src/bin/piifence.rs`). ``

**Verify**: `cargo test --release --lib -- control::tests` → `1 passed`, 0 failed.

### Step 3: Serve the control paths only on the socket

All edits are in `src/bin/gateway.rs`.

3a. Directly after plan 011's `until_unused` function (the last function of the lease code), add:

```rust
/// The listener a request came in on.
#[derive(Clone, Copy)]
enum Via {
    /// `127.0.0.1:<port>`, which every account on this machine can connect to.
    Tcp,
    /// The control socket, in a directory only this user can open (see `piifence::control`).
    Socket,
}

/// Whether `path` is served on `via`. `/stats` and every `/control/` path are served only on the control socket, because they hand out a session's values and previews of them, and any account on this machine can connect to a loopback TCP port. The proxy is served only on TCP, where Claude Code sends its requests. `/health` is served on both.
fn served_on(via: Via, path: &str) -> bool {
    let control = path == "/stats" || path.starts_with("/control/");
    match via {
        Via::Tcp => !control,
        Via::Socket => control || path == "/health",
    }
}

/// The header in which `/health` names the upstream. Only the answer on the control socket keeps it.
const UPSTREAM_HEADER: &str = "x-piifence-upstream";

/// Middleware for the TCP listener: a path served only on the control socket gets 404, and the upstream is removed from the answer to `/health`.
async fn tcp_only(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if !served_on(Via::Tcp, request.uri().path()) {
        return error_response(
            StatusCode::NOT_FOUND,
            "this path is served only on the gateway's control socket",
        );
    }
    let mut response = next.run(request).await;
    response.headers_mut().remove(UPSTREAM_HEADER);
    response
}

/// Middleware for the control socket: anything but `/health`, `/stats` and the `/control/` paths gets 404, so nothing sent there is forwarded to the provider.
async fn socket_only(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if !served_on(Via::Socket, request.uri().path()) {
        return error_response(
            StatusCode::NOT_FOUND,
            "the control socket serves only /health, /stats and /control/",
        );
    }
    next.run(request).await
}

/// Bind the control socket at `path`, in a directory only this user can open: mode 0700, set again when the directory already exists. Call it only after binding the TCP port. Holding the port means no other gateway serves this socket, so a socket file that a killed gateway left behind is removed.
fn bind_control_socket(path: &std::path::Path) -> anyhow::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = path
        .parent()
        .context("the control socket path has no directory")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("make {} private (mode 0700)", dir.display()))?;
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err)
                .with_context(|| format!("remove the old control socket {}", path.display()));
        }
    }
    tokio::net::UnixListener::bind(path)
        .with_context(|| format!("bind the control socket {}", path.display()))
}
```

`served_on` compares the raw `uri.path()`, exactly as `proxy` does, so the two never disagree about a path: `/control` and `/stats/` are not control paths for `proxy` either, and are forwarded like any other path.

3b. In `proxy`, in the `if path == "/health" {` block, replace the comment line and the `.header(...)` line:

```rust
        // The launcher compares this header to its own upstream before reusing a gateway.
```

```rust
            .header("x-piifence-upstream", state.upstream.as_str())
```

with:

```rust
        // The launcher reads this header on the control socket and compares it to its own upstream before reusing a gateway. `tcp_only` removes it from the answer on TCP.
```

```rust
            .header(UPSTREAM_HEADER, state.upstream.as_str())
```

3c. Replace the doc comment of `until_unused` (one line) with:

```rust
/// Finish once no launcher has held a lease for `grace`. `main` then removes the control socket and returns, which closes both listeners and ends the gateway.
```

3d. In `main`:

- Replace the 8 lines that set up the names directory (from `let names_dir = match std::env::var("PIIF_STATE_DIR") {` to `NAMES_DIR.set(names_dir).expect("set once");`, shown in "Current state") with:

```rust
    let state_dir = piifence::control::state_dir()?;
    let names_dir = state_dir.join("names");
    prepare_names_dir(&names_dir)?;
    NAMES_DIR.set(names_dir).expect("set once");
```

- Replace everything from `let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;` to the end of `main` (the `let app = Router::new()...` statement before it stays) with:

```rust
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let socket_path = piifence::control::socket_path(&state_dir, port);
    let control_listener = bind_control_socket(&socket_path)?;
    eprintln!("piifence gateway listening on http://127.0.0.1:{port}");
    eprintln!("control socket: {}", socket_path.display());
    eprintln!(
        "audit log: {audit_path} (body log: {})",
        audit_body_path.as_deref().unwrap_or("off")
    );
    let tcp_server = axum::serve(
        listener,
        app.clone().layer(axum::middleware::from_fn(tcp_only)),
    );
    let socket_server = axum::serve(
        control_listener,
        app.layer(axum::middleware::from_fn(socket_only)),
    );
    let unused = async move {
        if exit_when_unused == 0 {
            return std::future::pending::<anyhow::Result<()>>().await;
        }
        eprintln!("exits {exit_when_unused} s after the last piifence claude session ends");
        until_unused(leases, Duration::from_secs(exit_when_unused)).await;
        // Removed while both listeners still run: once the TCP port is free, another gateway may take it and bind this same path.
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("remove the control socket {}", socket_path.display()))
    };
    tokio::select! {
        served = tcp_server => served.context("serve on TCP")?,
        served = socket_server => served.context("serve on the control socket")?,
        removed = unused => removed?,
    }
    Ok(())
}
```

Why the order matters: the socket is bound only after the TCP port, so a gateway that loses the race for the port never touches the socket of the one that won. When the last lease ends, the socket file is removed first, and the TCP port is released only when `tokio::select!` returns. This replaces plan 011's graceful shutdown: at that point no `piifence claude` has held a lease for the whole grace period, so no Claude Code session is using the gateway, and both listeners can close at once. A gateway run without `PIIF_EXIT_WHEN_UNUSED` (by hand, or by the suite) still runs until it is stopped.

3e. Update the module doc at the top of the file:

- Directly after the line that starts `//!   6. `piifence claude` takes a lease` (added by plan 011), add:

```rust
//!   7. `/stats`, every `/control/` path and the `/health` answer that names the upstream are served only on the control socket, `$PIIF_STATE_DIR/run/<port>.sock`, in a directory only the user can open (see `piifence::control`). Any account on the machine can connect to the TCP port, so there those paths get 404 and `/health` leaves the upstream out.
```

- At the end of the `//! Env:` line, replace `encrypted with a key kept in the macOS Keychain).` with `encrypted with a key kept in the macOS Keychain, and `run/<port>.sock` is the control socket).`

**Verify**:
- `cargo build --release` → exit 0.
- `grep -c 'served_on(Via::' src/bin/gateway.rs` → `2` (one in each middleware).
- `grep -c 'with_graceful_shutdown' src/bin/gateway.rs` → `0`.

Clippy runs in Step 6, after the launcher's tests compile again.

### Step 4: Test the split and the socket's directory

Append these two tests at the end of `mod tests` in `src/bin/gateway.rs`, before its final closing `}`:

```rust
    #[test]
    fn paths_are_split_between_tcp_and_the_control_socket() {
        for path in [
            "/stats",
            "/control/env",
            "/control/conversation",
            "/control/lease",
            "/control/other",
        ] {
            assert!(!served_on(Via::Tcp, path), "{path} must not be served on TCP");
            assert!(
                served_on(Via::Socket, path),
                "{path} must be served on the control socket"
            );
        }
        for path in [
            "/v1/messages",
            "/v1/messages/count_tokens",
            "/v1/models",
            "/control",
            "/stats/",
        ] {
            assert!(served_on(Via::Tcp, path), "{path} must be served on TCP");
            assert!(
                !served_on(Via::Socket, path),
                "{path} must not be served on the control socket"
            );
        }
        assert!(served_on(Via::Tcp, "/health"));
        assert!(served_on(Via::Socket, "/health"));
    }

    #[tokio::test]
    async fn binding_the_control_socket_makes_its_directory_private_and_replaces_a_stale_socket() {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let state = std::env::temp_dir().join(format!("piif-gw-{}", std::process::id()));
        let path = piifence::control::socket_path(&state, 7);
        let dir = path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&path, "left behind").unwrap();

        let listener = bind_control_socket(&path).unwrap();

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the socket's directory must be private");
        assert!(std::fs::metadata(&path).unwrap().file_type().is_socket());
        drop(listener);
        std::fs::remove_dir_all(&state).unwrap();
    }
```

The second test is a `#[tokio::test]` because `tokio::net::UnixListener::bind` needs a running tokio runtime. Its path is about 75 bytes long, well under the 104-byte limit.

**Verify**: `cargo test --release --bin piifence-gateway -- control_socket` → `2 passed`, 0 failed.

### Step 5: Make the launcher and the hooks use the socket

All edits are in `src/bin/piifence.rs`.

5a. Add this import directly after `use std::net::TcpStream;`, before plan 011's `use std::os::unix::process::CommandExt;`:

```rust
use std::os::unix::net::UnixStream;
```

5b. Replace `http_get` (the whole function and its doc comment, shown in "Current state") with these five functions:

```rust
/// Raw HTTP response to `GET path` on the loopback port, with `headers` (`Name: value` lines).
fn http_get(port: u16, path: &str, headers: &str, timeout: Duration) -> std::io::Result<String> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(300))?;
    stream.set_read_timeout(Some(timeout))?;
    send_get(stream, &format!("127.0.0.1:{port}"), path, headers)
}

/// The control socket of the gateway on `port` (see `piifence::control`).
fn control_socket(port: u16) -> Result<PathBuf> {
    Ok(piifence::control::socket_path(
        &piifence::control::state_dir()?,
        port,
    ))
}

/// Raw HTTP response to `GET path` on the gateway's control socket `socket`, with `headers` (`Name: value` lines).
fn control_get(
    socket: &Path,
    path: &str,
    headers: &str,
    timeout: Duration,
) -> std::io::Result<String> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    send_get(stream, "127.0.0.1", path, headers)
}

/// Send `GET path` with the Host `host` and `headers` over `stream`, and return the whole raw response.
fn send_get(
    mut stream: impl Read + Write,
    host: &str,
    path: &str,
    headers: &str,
) -> std::io::Result<String> {
    stream.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{headers}Connection: close\r\n\r\n")
            .as_bytes(),
    )?;
    // The gateway closes the connection after the response (Connection: close), so reading to the end gets the whole reply.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Whether anything on the loopback port answers `GET /health` with an HTTP response. A gateway answers there only once it serves both its TCP port and its control socket.
fn tcp_answers(port: u16) -> bool {
    http_get(port, "/health", "", Duration::from_millis(500))
        .is_ok_and(|response| response.starts_with("HTTP/"))
}
```

5c. Replace `running_gateway_upstream` (the whole function and its doc comment, shown in "Current state") with:

```rust
/// The upstream of the gateway on `port`, or None when nothing answers there. The upstream comes from `/health` on the gateway's control socket, which only this user's processes can reach. So a port that answers on TCP while its control socket does not is an error, never reused: another program, another account's gateway, a gateway from an older piifence or one started with a different `PIIF_STATE_DIR` holds it. TCP is asked first because a gateway answers there only once its socket is bound.
fn running_gateway_upstream(port: u16, socket: &Path) -> Result<Option<String>> {
    if !tcp_answers(port) {
        return Ok(None);
    }
    let response = control_get(socket, "/health", "", Duration::from_millis(500)).with_context(|| {
        format!(
            "something answers on 127.0.0.1:{port}, but no piifence gateway answers on {}. Another program, another account's gateway, a gateway from an older piifence or one started with a different PIIF_STATE_DIR holds the port. Stop it, or set PIIF_PORT to a free port.",
            socket.display()
        )
    })?;
    if !response.starts_with("HTTP/1.1 200") {
        bail!(
            "the gateway's control socket {} answered /health with {}",
            socket.display(),
            response.lines().next().unwrap_or_default()
        );
    }
    let upstream = response
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("x-piifence-upstream")
                .then(|| value.trim().to_string())
        })
        .with_context(|| {
            format!(
                "the gateway's control socket {} did not name its upstream",
                socket.display()
            )
        })?;
    Ok(Some(upstream))
}
```

5d. In `ensure_gateway` (plan 011):

- Directly after `let gateway_url = format!("http://127.0.0.1:{port}");`, add `let socket = control_socket(port)?;`.
- Change `match running_gateway_upstream(port) {` to `match running_gateway_upstream(port, &socket)? {`.
- Change `None => start_gateway(data, port, upstream)?,` to `None => start_gateway(data, port, &socket, upstream)?,`.
- Change `if lease(port, session_id)? {` to `if lease(&socket, session_id)? {`.

5e. In `lease` (plan 011):

- In its doc comment, replace `Ask the gateway on `port` to keep running` with `Ask the gateway whose control socket is `socket` to keep running`.
- Change the signature to `fn lease(socket: &Path, session_id: &str) -> Result<bool> {`.
- Change `let Ok(response) = http_get(port, "/control/lease", &headers, Duration::from_secs(5)) else {` to `let Ok(response) = control_get(socket, "/control/lease", &headers, Duration::from_secs(5)) else {`.
- Directly before the final `bail!(`, add `let socket = socket.display();`, and in that `bail!` message replace `the gateway on port {port} cannot hold a lease` with `the gateway at {socket} cannot hold a lease`. Leave the rest of the message as it is; the launcher tests look for its words `older piifence`.

5f. In `wait_until_closed` (plan 011), change `while running_gateway_upstream(port).is_some() {` to `while tcp_answers(port) {`.

5g. In `start_gateway`:

- Change its signature to `fn start_gateway(data: &Path, port: u16, socket: &Path, upstream: &str) -> Result<()> {`.
- Change `if let Err(err) = wait_healthy(port, upstream, &mut child) {` to `if let Err(err) = wait_healthy(port, socket, upstream, &mut child) {`.

5h. In `wait_healthy`:

- Change its signature to `fn wait_healthy(port: u16, socket: &Path, upstream: &str, child: &mut Child) -> Result<()> {`.
- Change `match running_gateway_upstream(port) {` to `match running_gateway_upstream(port, socket)? {`. An error here (the port answers on TCP but the socket does not) ends the wait, and `start_gateway`'s error branch then stops its own child and prints the gateway log, as for any start failure.

5i. In `run_session`:

- Add `let socket = control_socket(port)?;` as the first line of the function body.
- Replace `.env("PIIF_GATEWAY_URL", gateway_url)` with `.env("PIIF_GATEWAY_SOCKET", &socket)`. The notice plugin was the only reader of `PIIF_GATEWAY_URL`, and after Step 7 it reads `PIIF_GATEWAY_SOCKET` instead. The hooks find the socket themselves, from `PIIF_STATE_DIR` and their `<port>` argument. `gateway_url` stays a parameter, because `write_settings_override` uses it to point Claude Code at the proxy.

5j. In `bind_conversation` and in `session_values`, make the same three changes:

- Add `let socket = control_socket(port)?;` as the first line of the function body.
- In the call that follows, change `http_get(` to `control_get(` and its first argument `port,` to `&socket,`.
- Change `.with_context(|| format!("the gateway on port {port} did not answer"))?;` to `.with_context(|| format!("the gateway's control socket {} did not answer", socket.display()))?;`.

5k. In the module doc, at the end of line 10 (it ends with `The gateway binary sits next to this one.`), append after a space: `` The hooks and the notice plugin reach the gateway on its control socket, `$PIIF_STATE_DIR/run/<port>.sock` (state dir `~/.local/state/piifence` by default), in a directory only the user can open; the gateway hands out no session data on TCP. ``

**Verify**:
- `cargo build --release` → exit 0. (`cargo build` does not compile tests. Plan 011's lease tests still call `lease` with a port, so `cargo test` and clippy only compile again after Step 6.)
- `grep -n 'http_get(' src/bin/piifence.rs` → exactly two lines: the `fn http_get(` line and the call inside `tcp_answers`.
- `grep -c 'control_get(' src/bin/piifence.rs` → `5` (its definition, `running_gateway_upstream`, `lease`, `bind_conversation`, `session_values`).
- `grep -c 'running_gateway_upstream(port)' src/bin/piifence.rs` → `0`.
- `grep -c 'PIIF_GATEWAY_URL' src/bin/piifence.rs` → `0`.

### Step 6: Move the launcher's tests to the socket

In `mod tests` of `src/bin/piifence.rs`, replace plan 011's helper `answer_once` and its two tests, `a_lease_is_held_on_200_and_refused_on_503_or_no_answer` and `a_lease_on_a_gateway_that_predates_leases_is_an_error`, with:

```rust
    /// Read one whole HTTP request from `stream`, then answer with `head` (a status line, optionally followed by header lines, joined by `\r\n`) and an empty body. Answering before the request is read can reset the connection and make a test flaky.
    fn answer(mut stream: impl Read + Write, head: &str) {
        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
        }
        let reply = format!("{head}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(reply.as_bytes()).unwrap();
    }

    /// The port of a loopback TCP server that answers one request with `head`.
    fn tcp_answering(head: &'static str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || answer(listener.accept().unwrap().0, head));
        port
    }

    /// A Unix socket path in the temp dir that no other test uses, with nothing listening on it.
    fn unused_socket_path() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = env::temp_dir().join(format!("piif-test-{}-{n}.sock", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    /// The path of a Unix socket whose server answers one request with `head`, then removes the socket file.
    fn socket_answering(head: &'static str) -> PathBuf {
        let path = unused_socket_path();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let file = path.clone();
        thread::spawn(move || {
            answer(listener.accept().unwrap().0, head);
            fs::remove_file(file).unwrap();
        });
        path
    }

    #[test]
    fn a_lease_is_held_on_200_and_refused_on_503_or_no_answer() {
        let session = "0".repeat(32);
        assert!(lease(&socket_answering("HTTP/1.1 200 OK"), &session).unwrap());
        assert!(!lease(&socket_answering("HTTP/1.1 503 Service Unavailable"), &session).unwrap());
        assert!(!lease(&unused_socket_path(), &session).unwrap());
    }

    #[test]
    fn a_lease_on_a_gateway_that_predates_leases_is_an_error() {
        let err = lease(&socket_answering("HTTP/1.1 404 Not Found"), &"0".repeat(32)).unwrap_err();
        assert!(format!("{err:#}").contains("older piifence"), "{err:#}");
    }

    #[test]
    fn a_gateway_is_trusted_only_when_its_control_socket_answers() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(
            running_gateway_upstream(closed, &unused_socket_path()).unwrap(),
            None
        );

        let squatted = tcp_answering("HTTP/1.1 200 OK");
        let err = running_gateway_upstream(squatted, &unused_socket_path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("no piifence gateway answers"),
            "{err:#}"
        );

        let port = tcp_answering("HTTP/1.1 200 OK");
        let socket =
            socket_answering("HTTP/1.1 200 OK\r\nx-piifence-upstream: http://upstream.test");
        assert_eq!(
            running_gateway_upstream(port, &socket).unwrap().as_deref(),
            Some("http://upstream.test")
        );
    }
```

Each test server answers exactly one request, and each test sends each server exactly one, so no server thread waits forever. `closed` is the port of a listener that is dropped at once, so nothing answers there.

**Verify**:
- `cargo test --release --bin piifence -- a_lease control_socket` → `3 passed`, 0 failed.
- `cargo clippy --release --all-targets -- -D warnings` → exit 0.

### Step 7: Read `/stats` over the socket in the notice plugin

Edit `plugin/piifence-notice/scripts/notice.py`:

- Line 6: replace `sets PIIF_GATEWAY_URL.` with `sets PIIF_GATEWAY_SOCKET, the gateway's control socket: a Unix socket in a directory only the user can open, and the only place the gateway serves /stats.`
- Line 9: replace the whole line `  PIIF_GATEWAY_URL   required, e.g. http://127.0.0.1:7788` with `  PIIF_GATEWAY_SOCKET  required, e.g. ~/.local/state/piifence/run/7788.sock`.
- Replace the imports (lines 13-17) with:

```python
import http.client
import json
import os
import pathlib
import socket
import sys
```

- Replace line 19, `GATEWAY = os.environ["PIIF_GATEWAY_URL"].rstrip("/")`, with `SOCKET = os.environ["PIIF_GATEWAY_SOCKET"]`.
- Directly after the `STATE = ...` line (line 20), add:

```python


class SocketConnection(http.client.HTTPConnection):
    """HTTP over the gateway's control socket, a Unix socket, instead of TCP."""

    def __init__(self, path, timeout):
        super().__init__("127.0.0.1", timeout=timeout)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def fetch_stats():
    """The gateway's /stats, read on its control socket. An answer other than 200 is an error."""
    conn = SocketConnection(SOCKET, 1.5)
    try:
        conn.request("GET", "/stats")
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    if resp.status != 200:
        raise RuntimeError(f"the gateway answered /stats with {resp.status}")
    return json.loads(body)
```

- In `main`, replace the two lines `with urllib.request.urlopen(GATEWAY + "/stats", timeout=1.5) as resp:` and `stats = json.loads(resp.read())` with the single line `    stats = fetch_stats()` (4 spaces of indentation, like the lines around it).

A socket that does not exist or does not answer raises, so the hook exits non-zero and Claude Code shows the error, as before.

**Verify**:
- `python3 -I -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' plugin/piifence-notice/scripts/notice.py` → exit 0, no output.
- `grep -c -E 'PIIF_GATEWAY_URL|urllib' plugin/piifence-notice/scripts/notice.py` → `0`.

### Step 8: Move the end-to-end checks to the socket, and run them

8a. In `tests/secrets/stats_check.py`:

- Replace line 1 of the docstring, `"""Check that /stats counts a value once and the notice fires only for new values.`, with `"""Check that /stats counts a value once, the notice fires only for new values, and only the control socket serves /stats and /control/.`
- Replace the `stats` and `notice` functions (shown in "Current state") with:

```python
def stats(gw):
    status, _, body = run.socket_get(gw.socket, "/stats")
    assert status == 200, (status, body)
    return json.loads(body)


def notice(gw, state_file, hook="Stop"):
    env = dict(os.environ, PIIF_GATEWAY_SOCKET=gw.socket, PIIF_NOTICE_STATE=state_file)
    out = subprocess.run([sys.executable, "-I", NOTICE], input=json.dumps({"hook_event_name": hook}).encode(),
                         capture_output=True, env=env, check=True)
    return json.loads(out.stdout or b"{}")
```

- In `main`, change every `notice(gw.port,` to `notice(gw,` (3 places) and every `stats(gw.port)` to `stats(gw)` (2 places). Leave the `run.post(gw.port, ...)` calls and the assertions on the notice's messages as they are.
- Directly after the TCP lines you added in Step 1b (after the line that ends `"TCP /health must not name the upstream"`), add:

```python
            status, _, body = run.socket_get(gw.socket, "/control/env", session)
            assert status == 200 and "PIIF_SECRET_1" in json.loads(body)["values"], "the control socket must hand the session its values"
            status, headers, _ = run.socket_get(gw.socket, "/health")
            assert status == 200 and headers.get("x-piifence-upstream"), "/health on the control socket must name the upstream"
            assert run.socket_get(gw.socket, "/v1/messages")[0] == 404, "the control socket must not forward to the provider"
```

8b. In `tests/secrets/lifecycle_check.py`:

- In the docstring's first line, replace `outlives the one that started it, and exits once neither uses it.` with `outlives the one that started it and exits once neither uses it, and that a launcher never uses a port without a piifence control socket.`
- Delete the line `import urllib.error`; nothing uses it after the `control` change below.
- Replace the comment line above `FAKE_CLAUDE` and the whole `FAKE_CLAUDE` string, 9 lines in all (shown in "Current state"), with:

```python
# Stands in for Claude Code: waits for its go file, then exits 0 only if the launcher passed it the gateway's control socket and the gateway still answers on its port.
FAKE_CLAUDE = """import os, sys, time, urllib.request
while not os.path.exists(os.environ["LIFECYCLE_GO"]):
    time.sleep(0.1)
if not os.path.exists(os.environ["PIIF_GATEWAY_SOCKET"]):
    sys.exit(4)
try:
    urllib.request.urlopen("http://127.0.0.1:" + os.environ["PIIF_PORT"] + "/health", timeout=5).read()
except OSError:
    sys.exit(3)
"""
```

The launcher no longer sets `PIIF_GATEWAY_URL` (Step 5i), so the fake builds the URL from `PIIF_PORT`, which it inherits from the launcher.

- Replace the `control` function with:

```python
def control(sock, path):
    return run.socket_get(sock, path, {"x-piifence-session": "0" * 32})[0]
```

- In `main`, directly after the `env.update({...})` statement closes (the line `        })`), add, at the same indentation as `env.update`:

```python
        sock = os.path.join(tmp, "state", "run", f"{port}.sock")
```

- As the first statement inside the `try:` block, before `first, first_go = start("first")`, add:

```python
            # The fake upstream answers HTTP on its port but has no piifence control socket, so a launcher pointed at it must refuse to start Claude Code. The go file exists, so a fake Claude Code started by mistake exits at once instead of waiting forever.
            squat_go = os.path.join(tmp, "squat.go")
            open(squat_go, "w").close()
            squat = subprocess.run([launcher, "claude"], env=dict(env, PIIF_PORT=str(sink.port), LIFECYCLE_GO=squat_go),
                                   stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
            assert squat.returncode == 1 and "no piifence gateway answers" in squat.stderr, squat.stderr
```

- Change `control(port, "/control/lease")` to `control(sock, "/control/lease")` and `control(port, "/control/no-such-endpoint")` to `control(sock, "/control/no-such-endpoint")`.
- Directly after the line `wait_for(lambda: not healthy(port), 15, "the gateway to exit after the last launcher")`, add at the same indentation:

```python
            wait_for(lambda: not os.path.exists(sock), 5, "the gateway to remove its control socket")
```

The fake upstream (`run.Sink`) answers a GET with `501 Unsupported method`, an HTTP response, so the launcher sees "something answers" there; no gateway is started for that run, and nothing is left to clean up.

**Verify**:
- `cargo build --release && PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/stats_check.py` → the last line is `stats ok`, exit 0.
- `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/lifecycle_check.py` → the last line is `lifecycle ok`, exit 0.
- `grep -c -E 'urllib\.error|PIIF_GATEWAY_URL' tests/secrets/lifecycle_check.py` → `0`.

### Step 9: Update the docs

Make these edits. Find each one by its quoted text.

1. `README.md`, the `> [!IMPORTANT]` box after the "What changes" table (line 87). Directly after the line `> The gateway serves only `piifence claude` sessions. Plain `claude` pointed at the gateway is refused, because its requests lack the session id that `piifence claude` adds.`, add these two lines:

```text
>
> The gateway hands a session's values only to your own account. `piifence env`, the `PreToolUse` hook and the notice reach it on a Unix socket in `~/.local/state/piifence/run/`, a directory only you can open. Its TCP port, which every account on the Mac can reach, serves only the proxy and a health check.
```

2. `README.md`, the bullet that starts `- **The gateway** is a proxy on`. Replace `It keeps the values in memory and hands them only to the session they belong to.` with `It keeps the values in memory and hands them only to the session they belong to, and only on its control socket, `~/.local/state/piifence/run/7788.sock`, never on its TCP port.`

3. `README.md`, the environment table. In the `PIIF_STATE_DIR` row, replace `Where each conversation's encrypted names are kept, in `names/`.` with `Where each conversation's encrypted names are kept, in `names/`, and the gateway's control socket, in `run/`.`

4. `README.md`, "Guarantees". Directly after the bullet that starts `- 🙈 **No raw values are written in the clear.**`, add:

```text
- 👤 **Other accounts on your Mac can't read the values.** Any account can connect to the gateway's TCP port, so the gateway serves only the proxy there. It hands out values, saved names and the notice's previews only on a Unix socket in `~/.local/state/piifence/run/`, a directory only you can open.
```

5. `README.md`, "The gateway doesn't start". Add this bullet directly after the bullet about `a gateway on … forwards to …`, which is the last bullet of that list:

```text
- **`no piifence gateway answers on …`**: something answers on the port, but it is not a gateway this piifence can reach: another program, another account's gateway, a gateway from a piifence older than the control socket, or one started with a different `PIIF_STATE_DIR`. Stop it, or set `PIIF_PORT` to a free port.
```

6. `CLAUDE.md:27`. Replace `` `PIIF_CACHE_DIR` `~/.cache/piifence`, `` with `` `PIIF_CACHE_DIR` `~/.cache/piifence`, `PIIF_STATE_DIR` `~/.local/state/piifence`, ``.

7. `CLAUDE.md:30`. Replace `` `PIIF_CACHE_DIR`. `` (with the period) with `` `PIIF_CACHE_DIR`, `PIIF_STATE_DIR` (`names/`, and `run/<port>.sock`, the control socket). ``

8. `CLAUDE.md:34`. Directly after the sentence `The header is stripped before forwarding.`, insert:

```text
 `/stats`, every `/control/` path and the `/health` answer that names the upstream are served only on the control socket `$PIIF_STATE_DIR/run/<port>.sock`, whose directory the gateway creates 0700, because any account can connect to a loopback port; on TCP they get 404 and `/health` leaves the upstream out.
```

9. `CLAUDE.md:40`. Replace the sentence `It reuses a running gateway only when its `/health` reports the same upstream.` with `It reuses a running gateway only when `/health` on its control socket reports the same upstream; a port that answers on TCP without that socket is an error, never reused.`

10. `CLAUDE.md:44`. Replace `` `PIIF_GATEWAY_URL` is required; `` with `` `PIIF_GATEWAY_SOCKET` (the control socket, set by `piifence claude`) is required; ``.

11. `tests/secrets/README.md:34`. Replace `# /stats counters and the notice` with `# /stats and the notice over the control socket; TCP refuses them`.

12. `plugin/piifence-notice/README.md:7`. Replace `` and sets `PIIF_GATEWAY_URL`. `` with `` and sets `PIIF_GATEWAY_SOCKET`, the gateway's control socket: a Unix socket in a directory only you can open, and the only place the gateway serves `/stats`. ``

**Verify**:
- `grep -c 'piifence/run/' README.md` → `3`.
- `grep -c 'no piifence gateway answers' README.md` → `1`.
- `grep -c 'run/<port>.sock' CLAUDE.md` → `2`.
- `grep -c 'PIIF_GATEWAY_SOCKET' CLAUDE.md` → `1`.
- `grep -c 'PIIF_GATEWAY_URL' CLAUDE.md` → `0`.
- `grep -c 'control socket' tests/secrets/README.md` → `1`.
- `grep -c 'PIIF_GATEWAY_SOCKET' plugin/piifence-notice/README.md` → `1`.
- `git grep -n PIIF_GATEWAY_URL -- ':!plans'` → no output.

### Step 10: Run every check

**Verify**:
- `cargo fmt --check` → exit 0. If it fails, run `cargo fmt` and check again.
- `cargo clippy --release --all-targets -- -D warnings` → exit 0.
- `cargo test --release` → exit 0.
- `scripts/check.sh --no-suite` → the last line is `check: all passed`.
- `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh` → the last line is `check: all passed`.

## Test plan

- Library (1 new), in `src/control.rs`: the socket for a port is `run/<port>.sock` in the state dir. Pattern: `src/config.rs:55-72`.
- Gateway (2 new), in `mod tests` of `src/bin/gateway.rs`:
  - which paths each listener serves: `/stats` and `/control/*` only on the socket, the proxy paths only on TCP, `/health` on both, and the near-misses `/control` and `/stats/` treated as proxy paths, as `proxy` treats them;
  - binding the socket sets its directory to 0700 even when it existed with 0755, and replaces a file left at the socket's path.
- Launcher (3), in `mod tests` of `src/bin/piifence.rs`, with one-request servers on TCP and on Unix sockets:
  - plan 011's two lease tests, now over the socket;
  - a gateway is trusted only when its control socket answers: nothing on TCP gives None, TCP without a socket is an error, and TCP plus the socket gives the upstream the socket names.
- End to end, both already run by `scripts/check.sh`:
  - `tests/secrets/stats_check.py`: TCP answers 404 to `/control/env` with a valid session id and to `/stats`, and its `/health` names no upstream; the socket hands the session its value, names the upstream and refuses `/v1/messages`; the notice reads `/stats` on the socket. Step 1 shows the first assertion failing on the old code.
  - `tests/secrets/lifecycle_check.py`: a launcher pointed at a port without a control socket exits 1 with `no piifence gateway answers`; the fake Claude Code gets `PIIF_GATEWAY_SOCKET` pointing at an existing socket; the lease answers come from the socket; the gateway removes its socket when it exits.

## Done criteria

ALL must hold:

- [ ] `cargo fmt --check` exits 0
- [ ] `cargo clippy --release --all-targets -- -D warnings` exits 0
- [ ] `cargo test --release` exits 0
- [ ] `cargo test --release --lib -- control::tests` reports `1 passed`
- [ ] `cargo test --release --bin piifence-gateway -- control_socket` reports `2 passed`
- [ ] `cargo test --release --bin piifence -- a_lease control_socket` reports `3 passed`
- [ ] `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/stats_check.py` prints `stats ok`
- [ ] `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" python3 -I tests/secrets/lifecycle_check.py` prints `lifecycle ok`
- [ ] `git diff BASE -- Cargo.toml Cargo.lock` prints nothing
- [ ] `git grep -n PIIF_GATEWAY_URL -- ':!plans'` prints nothing, and `grep -c 'PIIF_GATEWAY_URL' plugin/piifence-notice/scripts/notice.py` prints `0`
- [ ] `PIIF_MODEL_DIR="$HOME/.local/share/piifence/model" scripts/check.sh` ends with `check: all passed`
- [ ] `git status --short` lists only files from the in-scope list
- [ ] `plans/README.md` status row for 012 updated

## STOP conditions

Stop and report back (do not improvise) if:

- Plan 011 is not in the code: `grep -c 'fn ensure_gateway' src/bin/piifence.rs` prints `0`, or `tests/secrets/lifecycle_check.py` does not exist. This plan edits plan 011's code and cannot be applied without it.
- The code at a location in "Current state" does not match the excerpts, or a quoted text that an edit replaces is not found exactly once.
- The model directory `$HOME/.local/share/piifence/model` does not exist. Ask the operator for the path; do not download the model without their approval.
- In Step 1, the stats check fails with any message other than `TCP must not hand out a session's values`. That means the check's setup is wrong, and a pass later would prove nothing.
- The gateway fails to start with an error about the socket path's length (such as `path must be shorter than SUN_LEN`). Report the value of `$TMPDIR` and the path; do not move the socket or shorten paths on your own.
- The build needs a change to `Cargo.toml` or `Cargo.lock`.
- Any step would need you to send a request to port 7788, stop or restart a process there, run `pkill` or `killall`, run `scripts/install.sh`, `brew upgrade` or `brew reinstall`, or change anything under `~/.local/libexec/piifence/`, `~/.local/share/piifence/` or `~/.local/state/piifence/`. The user's running sessions use those. A launcher or hook from this plan cannot reach a gateway that predates it, so installing it while sessions run breaks their `piifence env` and `PreToolUse` hook until they are restarted.
- A check fails twice after a reasonable fix attempt. Do not loosen an assertion or raise a timeout to make it pass; report the output and the gateway log instead.
- `cargo test --release` hangs, or takes more than 10 s longer than before your change. A test server thread that waits forever on `accept` is the likely cause.

## Maintenance notes

- `served_on` is the only gate between the two listeners. A new endpoint that returns session data (values, names, previews, conversation ids) must live under `/control/` or be added to `served_on`'s socket list, and a reviewer must check that `served_on` and `proxy` compare the same raw path (`uri.path()`, never percent-decoded).
- The launcher, its hooks and the notice plugin find the socket from `PIIF_STATE_DIR` and the port, so all of them must see the same `PIIF_STATE_DIR`. A gateway started with a different one shows up as `no piifence gateway answers on …`.
- Upgrades: a launcher or hook from this plan cannot talk to a gateway that predates it, and the other way round. The README's "Upgrading" section already says to quit every session before upgrading; keep it that way.
- What this plan does not stop: if the gateway dies while a session runs, another account could bind the free port and receive that Claude Code's raw requests, credentials included. Closing that needs the launcher to watch the gateway and stop Claude Code when it dies; deferred.
- The session id stays visible in `ps`, in the settings file's name and in the hook arguments. On TCP it now only picks which session's names a proxied request uses, and the proxy never returns a value. Moving it out of the arguments would need the hooks to read it from the environment; deferred.
- macOS limits a socket path to 104 bytes, so a `PIIF_STATE_DIR` longer than about 85 bytes makes the gateway fail at start with the bind error. The suite's temp dirs use about 90 of the 104.
- A rare race at shutdown: the gateway removes its socket just before it stops answering on TCP. A launcher whose TCP check lands in that gap gets `no piifence gateway answers on …`, and running it again works. A retry in `running_gateway_upstream` would close the gap; it was left out because the gap lasts only from the socket's removal to the end of `main`, and it opens only after the grace period has passed with no session.
- The socket is private only because the user owns every directory on its path. A `PIIF_STATE_DIR` inside a directory that another account owns would let that account replace `run/`. The default, under the user's home, is safe.
- Reviewers should check four things: no TCP path returns a value (the stats check covers `/control/env` and `/stats`), the socket's directory is set to 0700 even when it already exists, the socket file is removed before the TCP port is released, and every launcher call that carries a session id goes through `control_get`.
