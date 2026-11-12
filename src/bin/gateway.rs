//! piifence gateway — keeps secrets out of what Claude Code sends to the model provider.
//!
//!   1. `piifence claude` points Claude Code at it (`ANTHROPIC_BASE_URL=http://127.0.0.1:7788`) and gives the session an id, sent on every request in the `x-piifence-session` header.
//!   2. `POST /v1/messages` and `/v1/messages/count_tokens` bodies are scanned (system, tool descriptions, message text, tool_result, tool_use / server_tool_use / mcp_tool_use input, mcp_tool_result, web fetch results, documents, search results) by the shared Detector (secret model + key rule + gitleaks + guards). Each secret becomes an environment variable name, `$PIIF_SECRET_<N>`, numbered once per value per session, so re-sent history is rewritten identically every turn.
//!   3. The rewritten request is forwarded to `PIIF_UPSTREAM` with the original auth headers.
//!   4. The response is streamed back byte for byte. Names are never replaced back: the provider never sees the value, and the agent uses the name. `piifence env` hands the values to the session's Bash commands, so `$PIIF_SECRET_1` expands to the real value on the user's machine.
//!   5. The session-start hook sends Claude Code's conversation id to `/control/conversation`. The gateway then keeps that conversation's names in a file encrypted with a key from the macOS Keychain, and loads them back when the conversation is resumed, so names the agent already wrote keep their values across restarts.
//!   6. `piifence claude` takes a lease on `/control/lease` (its session id and process id) before it starts Claude Code. Started with `PIIF_EXIT_WHEN_UNUSED=<seconds>`, as the launcher does, the gateway exits once no live launcher has held a lease for that long. Any other `/control/` path is answered 404 and never forwarded.
//!   7. `/stats`, every `/control/` path and the `/health` answer that names the upstream are served only on the control socket, `$PIIF_STATE_DIR/run/<port>.sock`, in a directory only the user can open (see `piifence::control`). Any account on the machine can connect to the TCP port, so there those paths get 404 and `/health` leaves the upstream out.
//!
//! Env: PIIF_UPSTREAM (required: provider base URL), PIIF_MODEL_DIR (required: the model directory, or several joined with ':', each a Scrub or cbx model), PIIF_PORT (7788), PIIF_EXIT_WHEN_UNUSED (seconds; above 0, exit once no launcher has held a lease that long; unset or 0, run until stopped), PIIF_AUDIT_LOG (/tmp/piifence-audit.log), PIIF_AUDIT_BODY=1 (also log the rewritten request bodies), PIIF_CACHE_DIR (~/.cache/piifence: detection results kept across restarts, as offsets per text hash, never the text or values), PIIF_STATE_DIR (~/.local/state/piifence: `names/` holds each conversation's names, encrypted with a key kept in the macOS Keychain, and `run/<port>.sock` is the control socket).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use axum::Router;
use piifence::detect::{DetectedSpan, Detector};
use regex::Regex;
use serde_json::{json, Value};

struct DetectJob {
    text: String,
    reply: tokio::sync::oneshot::Sender<anyhow::Result<Vec<DetectedSpan>>>,
}

#[derive(Default)]
struct Stats {
    requests: usize,
    redactions: usize,
    /// Distinct values named since the gateway started.
    values: usize,
    by_kind: BTreeMap<String, usize>,
    recent: VecDeque<Value>,
    redact_ms_total: f64,
    redact_ms_last: f64,
    redact_ms_max: f64,
}

/// Largest request body the gateway accepts. Claude Code sends the whole conversation on every turn, which can exceed axum's 2 MB default.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

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
    /// The launchers using this gateway (see `Leases`).
    leases: Arc<Mutex<Leases>>,
    /// This request's session id (`x-piifence-session`), `""` outside a request or without one.
    session: String,
}

/// Reject requests a browser page or a DNS-rebinding site could make. Claude Code and the launcher send no `Origin` header and use `127.0.0.1` / `localhost` as Host.
fn is_local_request(state: &AppState, headers: &HeaderMap) -> bool {
    if headers.contains_key("origin") {
        return false;
    }
    let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let port = state.port;
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        "127.0.0.1".to_string(),
    ]
    .iter()
    .any(|allowed| host == allowed)
}

/// Masked preview for notices: first 4 + last 4 characters, never the full value.
fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "••••".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// One secret with a `$PIIF_SECRET_<N>` name.
struct EnvValue {
    value: String,
    name: String,
    /// What found it first: the model's secret type, the gitleaks rule, or `keyrule`.
    kind: String,
    /// Whether the value has been replaced in a request yet, so the notice reports it once.
    seen: bool,
}

/// One session's secrets and their names. Commands run with the real value, so their output can contain it (`echo $PIIF_SECRET_1`); the gateway replaces every copy of a named value with `$NAME` in all provider-bound text before detection runs, so it never leaves even when detection would miss it. Never logged or written in the clear; once the session is bound to a Claude Code conversation, the table is also kept encrypted under `NAMES_DIR`, so a resumed conversation's names still work after the gateway restarts.
#[derive(Default)]
struct EnvValues {
    /// Longest value first, so a value that contains another is replaced whole.
    entries: Vec<EnvValue>,
    /// Highest number used.
    counter: usize,
}

impl EnvValues {
    /// The entry for `value`, named `PIIF_SECRET_<next number>` the first time it is seen.
    fn entry_for(&mut self, value: &str, kind: &str) -> &mut EnvValue {
        let index = match self.entries.iter().position(|entry| entry.value == value) {
            Some(index) => index,
            None => {
                self.counter += 1;
                self.entries.push(EnvValue {
                    value: value.to_string(),
                    name: format!("PIIF_SECRET_{}", self.counter),
                    kind: kind.to_string(),
                    seen: false,
                });
                self.entries
                    .sort_by_key(|entry| std::cmp::Reverse(entry.value.len()));
                self.entries
                    .iter()
                    .position(|entry| entry.value == value)
                    .expect("the entry was just added")
            }
        };
        &mut self.entries[index]
    }

    /// Every name and its value, for `piifence env`.
    fn all(&self) -> serde_json::Map<String, Value> {
        self.entries
            .iter()
            .map(|entry| (entry.name.clone(), Value::String(entry.value.clone())))
            .collect()
    }

    /// The table as stored in the Keychain.
    fn stored(&self) -> Value {
        json!(self
            .entries
            .iter()
            .map(|e| json!({"name": e.name, "value": e.value, "kind": e.kind}))
            .collect::<Vec<_>>())
    }

    /// Take in a conversation's stored table. A stored value keeps its name, since the conversation already uses it; a value named only here keeps its name unless a stored entry has it, and is renumbered then.
    fn merge(&mut self, stored: &[(String, String, String)]) {
        let current = std::mem::take(&mut self.entries);
        let number = |name: &str| {
            name.strip_prefix("PIIF_SECRET_")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0)
        };
        for (name, value, kind) in stored {
            self.counter = self.counter.max(number(name));
            self.entries.push(EnvValue {
                value: value.clone(),
                name: name.clone(),
                kind: kind.clone(),
                seen: true,
            });
        }
        for mut entry in current {
            if self.entries.iter().any(|e| e.value == entry.value) {
                continue;
            }
            if self.entries.iter().any(|e| e.name == entry.name) {
                self.counter += 1;
                entry.name = format!("PIIF_SECRET_{}", self.counter);
            }
            self.counter = self.counter.max(number(&entry.name));
            self.entries.push(entry);
        }
        self.entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.value.len()));
    }
}

/// Per-session state, keyed by the `x-piifence-session` id the launcher gives each Claude Code session.
#[derive(Default)]
struct Session {
    env: EnvValues,
    /// Claude Code's conversation id, once the session-start hook has sent it. Only then is the table stored.
    conversation: Option<String>,
    /// The table's `counter` when it was last saved; None when it must be saved.
    saved: Option<usize>,
}

/// Where each conversation's table is kept, one encrypted file per conversation id, set once in `main`. The agent's own messages and the files it wrote hold `$PIIF_SECRET_<N>` names, and `claude --resume` or `-c` can bring them back after this gateway has stopped, so the names must outlive it.
static NAMES_DIR: OnceLock<PathBuf> = OnceLock::new();

/// A table nobody has resumed for this long is deleted when a gateway starts.
const NAMES_KEPT_DAYS: u64 = 30;

/// The header the session-start hook sends Claude Code's conversation id in.
const CONVERSATION_HEADER: &str = "x-piifence-conversation";

/// Apple's Keychain tool, which holds the key the tables are encrypted with. The gateway goes through it rather than the Keychain API so the item belongs to a program that does not change when piifence is updated; otherwise macOS asks for access after every update.
const SECURITY_TOOL: &str = "/usr/bin/security";

/// The Keychain item (service and account) holding the key.
const KEY_SERVICE: &str = "piifence";
const KEY_ACCOUNT: &str = "names-key";

/// `security`'s exit code when no item matches.
const KEYCHAIN_NOT_FOUND: i32 = 44;

static NAMES_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(text.len().is_multiple_of(2) && text.is_ascii(), "not hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("not hex"))
        .collect()
}

fn random_bytes<const N: usize>() -> anyhow::Result<[u8; N]> {
    use std::io::Read;
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .context("read /dev/urandom")?;
    Ok(bytes)
}

/// The key as stored, or None when there is none yet.
fn read_key() -> anyhow::Result<Option<[u8; 32]>> {
    let out = std::process::Command::new(SECURITY_TOOL)
        .args([
            "find-generic-password",
            "-s",
            KEY_SERVICE,
            "-a",
            KEY_ACCOUNT,
            "-w",
        ])
        .output()
        .context("run security")?;
    if out.status.code() == Some(KEYCHAIN_NOT_FOUND) {
        return Ok(None);
    }
    anyhow::ensure!(
        out.status.success(),
        "read piifence's key from the Keychain: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let key = unhex(String::from_utf8_lossy(&out.stdout).trim())?;
    Ok(Some(key.try_into().map_err(|_| {
        anyhow::anyhow!("piifence's Keychain key is not 32 bytes")
    })?))
}

/// The key the tables are encrypted with, created in the Keychain on first use. It is added without `-U`, so when two gateways race the second add fails and both read the one that won.
fn names_key() -> anyhow::Result<[u8; 32]> {
    let mut cached = NAMES_KEY.lock().unwrap();
    if let Some(key) = *cached {
        return Ok(key);
    }
    let key = match read_key()? {
        Some(key) => key,
        None => {
            // `security -i` reads the command on stdin, so the key never shows in the process list.
            let mut child = std::process::Command::new(SECURITY_TOOL)
                .arg("-i")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .context("run security")?;
            let fresh = hex(hex(&random_bytes::<32>()?).as_bytes());
            writeln!(
                child.stdin.take().context("security's stdin")?,
                "add-generic-password -s {KEY_SERVICE} -a {KEY_ACCOUNT} -X {fresh}"
            )
            .context("write to security")?;
            child.wait().context("wait for security")?;
            read_key()?.context("piifence's key is not in the Keychain after adding it")?
        }
    };
    *cached = Some(key);
    Ok(key)
}

fn names_path(conversation: &str) -> anyhow::Result<PathBuf> {
    Ok(NAMES_DIR
        .get()
        .context("the names directory is not set")?
        .join(conversation))
}

/// The stored `(name, value, kind)` table of `conversation`, empty when it has none.
fn load_names(conversation: &str) -> anyhow::Result<Vec<(String, String, String)>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let path = names_path(conversation)?;
    let sealed = match std::fs::read(&path) {
        Ok(sealed) => sealed,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    anyhow::ensure!(sealed.len() > 24, "{} is cut short", path.display());
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&names_key()?.into());
    let (nonce, data) = sealed.split_at(24);
    let plain = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: data,
                aad: conversation.as_bytes(),
            },
        )
        .map_err(|_| {
            anyhow::anyhow!(
                "{} does not decrypt with piifence's Keychain key",
                path.display()
            )
        })?;
    let entries: Vec<Value> =
        serde_json::from_slice(&plain).context("the stored table is not a JSON list")?;
    entries
        .iter()
        .map(|e| {
            let field = |key: &str| {
                e[key]
                    .as_str()
                    .map(str::to_string)
                    .with_context(|| format!("a stored entry has no {key}"))
            };
            Ok((field("name")?, field("value")?, field("kind")?))
        })
        .collect()
}

/// Save the session's table when it is bound to a conversation and has changed since the last save. The file is written whole under a temporary name and renamed, so a reader never sees half of it.
fn save_names(state: &AppState) -> anyhow::Result<()> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use std::os::unix::fs::OpenOptionsExt;
    let pending = with_session(state, |session| {
        let conversation = session.conversation.clone()?;
        (session.saved != Some(session.env.counter))
            .then(|| (conversation, session.env.stored(), session.env.counter))
    });
    let Some((conversation, table, counter)) = pending else {
        return Ok(());
    };
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&names_key()?.into());
    let nonce = random_bytes::<24>()?;
    let plain = table.to_string();
    let mut sealed = nonce.to_vec();
    sealed.extend(
        cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: plain.as_bytes(),
                    aad: conversation.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt the names"))?,
    );
    let path = names_path(&conversation)?;
    let temp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| file.write_all(&sealed))
        .with_context(|| format!("write {}", temp.display()))?;
    std::fs::rename(&temp, &path).with_context(|| format!("write {}", path.display()))?;
    with_session(state, |session| session.saved = Some(counter));
    Ok(())
}

/// Create the names directory (owner only) and delete tables older than `NAMES_KEPT_DAYS`.
fn prepare_names_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let cutoff =
        std::time::SystemTime::now() - std::time::Duration::from_secs(NAMES_KEPT_DAYS * 24 * 3600);
    for entry in std::fs::read_dir(dir).with_context(|| format!("list {}", dir.display()))? {
        let entry = entry?;
        if entry.metadata()?.modified()? < cutoff {
            std::fs::remove_file(entry.path())
                .with_context(|| format!("delete {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Bind this session to Claude Code's conversation: merge in the names the conversation already uses and save the result. Returns how many were stored.
fn bind_conversation(state: &AppState, conversation: &str) -> anyhow::Result<usize> {
    let stored = load_names(conversation)?;
    with_session(state, |session| {
        session.env.merge(&stored);
        session.conversation = Some(conversation.to_string());
        session.saved = None;
    });
    save_names(state)?;
    Ok(stored.len())
}

/// The conversation id in `headers`: Claude Code's session UUID, so 36 hex digits and dashes.
fn conversation_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CONVERSATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|id| id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
        .map(str::to_string)
}

/// The header carrying the session id: Claude Code sends it on every request (the launcher sets `ANTHROPIC_CUSTOM_HEADERS`), and `piifence env` on its call for the values. It is stripped before forwarding.
const SESSION_HEADER: &str = "x-piifence-session";

/// The session id in `headers`, or `""` when it is missing or not 32 hex digits. The id is also what lets `piifence env` fetch values, so only a well-formed one counts.
fn session_id(headers: &HeaderMap) -> String {
    headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string)
        .unwrap_or_default()
}

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
    (unsafe { libc::kill(pid, 0) == 0 })
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Finish once no launcher has held a lease for `grace`. `main` then removes the control socket and returns, which closes both listeners and ends the gateway.
async fn until_unused(leases: Arc<Mutex<Leases>>, grace: Duration) {
    loop {
        tokio::time::sleep(LEASE_CHECK).await;
        if expire_leases(
            &mut leases.lock().unwrap(),
            Instant::now(),
            grace,
            process_alive,
        ) {
            eprintln!(
                "no piifence claude session has used this gateway for {} s; shutting down",
                grace.as_secs()
            );
            return;
        }
    }
}

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

/// Run `f` on this request's session, creating it on first use.
fn with_session<T>(state: &AppState, f: impl FnOnce(&mut Session) -> T) -> T {
    let mut sessions = state.sessions.lock().unwrap();
    f(sessions.entry(state.session.clone()).or_default())
}

/// Below this many characters a known value is replaced only as a whole token: not where a letter or digit of the text runs into its first or last character, when that character is a letter, digit, `-` or `_`. A value cut from a longer token often ends in `-` or `_`, like the first group of a UUID. A short value turns up inside other strings by chance (`2024` in `2024-10-30`); a long one does not, so it is replaced wherever it appears, which keeps a real secret covered inside a longer string.
const WHOLE_TOKEN_BELOW: usize = 16;

/// Where `value` is in `text`, by the rule of `WHOLE_TOKEN_BELOW`.
fn env_value_matches(text: &str, value: &str) -> Vec<usize> {
    let whole_token = value.chars().count() < WHOLE_TOKEN_BELOW;
    let joins = |outside: Option<char>, edge: Option<char>| {
        matches!((outside, edge), (Some(o), Some(e))
            if o.is_alphanumeric() && (e.is_alphanumeric() || e == '-' || e == '_'))
    };
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

/// One audit entry: where a value was replaced, what found it, and its name. Never the value, only a masked preview.
fn audit_entry(
    field: &str,
    start: usize,
    end: usize,
    entry: &EnvValue,
    engine: &str,
    new: bool,
) -> Value {
    json!({
        "field": field,
        "kind": entry.kind,
        "engine": engine,
        "start": start,
        "end": end,
        "name": format!("${}", entry.name),
        "new": new,
        "preview": mask_value(&entry.value),
    })
}

/// How a name is written into text: `$NAME`, or `${NAME}` when a letter, digit or `_` comes next, because a shell and `piifence restore` would read that character as part of the name.
fn name_token(name: &str, next: Option<char>) -> String {
    match next {
        Some(c) if c.is_alphanumeric() || c == '_' => format!("${{{name}}}"),
        _ => format!("${name}"),
    }
}

/// Replace every named value in `text` with its name (see `name_token`), returning the new text and one audit entry per replacement. Offsets are into the text as it stood when that value was replaced, after any longer values.
fn replace_env_values(state: &AppState, text: &str, field: &str) -> (String, Vec<Value>) {
    with_session(state, |session| {
        let mut out = text.to_string();
        let mut audit = Vec::new();
        for entry in session.env.entries.iter_mut() {
            if !out.contains(&entry.value) {
                continue;
            }
            let starts = env_value_matches(&out, &entry.value);
            if starts.is_empty() {
                continue;
            }
            let mut replaced = String::with_capacity(out.len());
            let mut copied = 0;
            for start in starts {
                let end = start + entry.value.len();
                audit.push(audit_entry(field, start, end, entry, "env", !entry.seen));
                entry.seen = true;
                replaced.push_str(&out[copied..start]);
                replaced.push_str(&name_token(&entry.name, out[end..].chars().next()));
                copied = end;
            }
            replaced.push_str(&out[copied..]);
            out = replaced;
        }
        (out, audit)
    })
}

impl Stats {
    /// Fold one request's audit entries in. `redactions` counts every replaced span (history is re-sent every turn, so it grows fast); `values` counts a value only the first time it is named, and `recent` keeps only those first sightings so the notice can show what is new.
    fn record(&mut self, audit: &[Value], redact_ms: f64) {
        self.requests += 1;
        self.redactions += audit.len();
        self.redact_ms_total += redact_ms;
        self.redact_ms_last = redact_ms;
        self.redact_ms_max = self.redact_ms_max.max(redact_ms);
        for entry in audit {
            if let Some(kind) = entry["kind"].as_str() {
                *self.by_kind.entry(kind.to_string()).or_insert(0) += 1;
            }
            if entry["new"] != true {
                continue;
            }
            self.values += 1;
            self.recent.push_back(entry.clone());
            while self.recent.len() > 20 {
                self.recent.pop_front();
            }
        }
    }
}

fn record_stats(state: &AppState, audit: &[Value], redact_ms: f64) {
    state.stats.lock().unwrap().record(audit, redact_ms);
}

fn audit_line(state: &AppState, entry: Value) -> anyhow::Result<()> {
    let mut file = state.audit.lock().unwrap();
    writeln!(file, "{entry}").context("write the audit log")
}

async fn detect_kept(state: &AppState, text: &str) -> anyhow::Result<Vec<DetectedSpan>> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    state
        .detector_tx
        .send(DetectJob {
            text: text.to_string(),
            reply: reply_tx,
        })
        .map_err(|_| anyhow::anyhow!("detector worker stopped"))?;
    reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("detector worker dropped the job"))?
}

fn echo_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^\s*echo\s+"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?\s*$"#).expect("echo regex")
    })
}

/// Longest tool input shown to the model as context.
const CONTEXT_INPUT_BYTES: usize = 800;

/// `text` cut to at most `CONTEXT_INPUT_BYTES`, on a char boundary.
fn cut(text: &str) -> &str {
    let mut end = text.len().min(CONTEXT_INPUT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The model-only context for the output of a shell command: a shell transcript, the kind of text the model reads best. `echo $VAR` output reads as `VAR=<output>`, so the variable's name sits right before its value; any other command reads as `$ <command>` on the line above.
fn shell_context(command: &str) -> String {
    match echo_var_re().captures(command) {
        Some(m) => format!("{}=", &m[1]),
        None => format!("$ {}\n", cut(command)),
    }
}

/// The model-only context for a tool_result: the tool call that produced it, so a bare value (`echo $OPENCODE_API_KEY`) is recognised. Bash reads as a shell transcript (`shell_context`), Read as `$ cat <path>`, any other tool as `Tool call: <name> <input JSON>` / `Tool output:`.
fn tool_result_context(name: &str, input: &Value) -> anyhow::Result<String> {
    if let ("Bash", Some(command)) = (name, input["command"].as_str()) {
        return Ok(shell_context(command));
    }
    if let ("Read", Some(path)) = (name, input["file_path"].as_str()) {
        return Ok(format!("$ cat {}\n", cut(path)));
    }
    let raw = serde_json::to_string(input).context("serialize a tool input")?;
    Ok(format!("Tool call: {name} {}\nTool output:\n", cut(&raw)))
}

/// Claude Code bash-mode output (`!command`) arrives as `<bash-input>` / `<bash-stdout>` tags in message text, without a tool_use/tool_result pair. Scan the stdout with the shell command as model context, then run the normal scan over the rest of the text.
async fn redact_text_smart(
    state: &AppState,
    text: &str,
    field: &str,
) -> anyhow::Result<(String, Vec<Value>)> {
    let (bash_redacted, mut audit) = redact_bash_outputs(state, text, field).await?;
    let (out, mut more) = redact_text(state, &bash_redacted, field, "").await?;
    audit.append(&mut more);
    Ok((out, audit))
}

fn bash_input_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<bash-input>(.*?)</bash-input>").expect("bash-input regex"))
}

fn bash_output_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)<(?:bash-stdout|local-command-stdout)>(.*?)</(?:bash-stdout|local-command-stdout)>")
            .expect("bash-stdout regex")
    })
}

async fn redact_bash_outputs(
    state: &AppState,
    text: &str,
    field: &str,
) -> anyhow::Result<(String, Vec<Value>)> {
    let commands: Vec<(usize, &str)> = bash_input_re()
        .captures_iter(text)
        .filter_map(|cap| Some((cap.get(0)?.start(), cap.get(1)?.as_str())))
        .collect();
    let mut replacements: Vec<(usize, usize, String, Vec<Value>)> = Vec::new();
    for cap in bash_output_re().captures_iter(text) {
        let (Some(full), Some(inner)) = (cap.get(0), cap.get(1)) else {
            continue;
        };
        let context = commands
            .iter()
            .rev()
            .find(|(start, _)| *start < full.start())
            .map_or(String::new(), |(_, command)| shell_context(command));
        let (redacted, audit) = redact_text(state, inner.as_str(), field, &context).await?;
        if !audit.is_empty() {
            replacements.push((inner.start(), inner.end(), redacted, audit));
        }
    }
    let mut out = text.to_string();
    let mut audit = Vec::new();
    for (start, end, redacted, mut entries) in replacements.into_iter().rev() {
        out.replace_range(start..end, &redacted);
        audit.append(&mut entries);
    }
    Ok((out, audit))
}

/// Spans from one detection, mapped onto `text` (the region after the model-only context of `offset` bytes) and made non-overlapping, sorted by start. Overlaps are unioned, so no part of either span is left visible. A span that starts in the context but ends in the text is clamped to the text. Surrounding ASCII whitespace is trimmed so a name does not swallow the space before a value.
fn normalize_spans(spans: Vec<DetectedSpan>, text: &str, offset: usize) -> Vec<DetectedSpan> {
    let text_end = offset + text.len();
    let bytes = text.as_bytes();
    let mut mapped: Vec<DetectedSpan> = spans
        .into_iter()
        .filter(|span| span.end > offset && span.start < text_end)
        .filter_map(|mut span| {
            let mut start = span.start.max(offset) - offset;
            let mut end = span.end.min(text_end) - offset;
            while start > 0 && !text.is_char_boundary(start) {
                start -= 1;
            }
            while end < text.len() && !text.is_char_boundary(end) {
                end += 1;
            }
            while start < end && bytes[start].is_ascii_whitespace() {
                start += 1;
            }
            while end > start && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            if start >= end {
                return None;
            }
            span.start = start;
            span.end = end;
            Some(span)
        })
        .collect();
    mapped.sort_by_key(|span| (span.start, span.end));

    let mut out: Vec<DetectedSpan> = Vec::new();
    for span in mapped {
        match out.last_mut() {
            Some(current) if span.start < current.end => current.end = current.end.max(span.end),
            _ => out.push(span),
        }
    }
    for span in &mut out {
        span.word = text[span.start..span.end].to_string();
    }
    out
}

/// Redact one text block. `context` (may be empty) is shown to the model before `text`, never rewritten: the tool call that produced a tool_result, or the command before bash-mode output. Spans wholly in the context are dropped and spans crossing into `text` are clamped to it (see `normalize_spans`).
async fn redact_text(
    state: &AppState,
    text: &str,
    field: &str,
    context: &str,
) -> anyhow::Result<(String, Vec<Value>)> {
    // Known values go first, so detection sees `$PIIF_SECRET_1` (which the env-ref guard skips) and never the value itself.
    let (text, mut audit) = replace_env_values(state, text, field);
    let kept = detect_kept(state, &format!("{context}{text}")).await?;
    // Sorted, non-overlapping, so replacing right to left keeps offsets valid.
    let accepted = normalize_spans(kept, &text, context.len());
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
                    entry.name.clone(),
                    audit_entry(field, span.start, span.end, entry, span.engine(), new),
                )
            })
        })
        .collect();
    for (span, (name, entry)) in accepted.iter().zip(named).rev() {
        let token = name_token(&name, out[span.end..].chars().next());
        out.replace_range(span.start..span.end, &token);
        audit.push(entry);
    }
    Ok((out, audit))
}

#[async_recursion::async_recursion]
async fn redact_json_strings(
    state: &AppState,
    value: &mut Value,
    field: &str,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    match value {
        Value::String(text) => {
            let (out, mut entries) = redact_text(state, text, field, "").await?;
            *text = out;
            audit.append(&mut entries);
        }
        Value::Array(items) => {
            for item in items {
                audit.extend(redact_json_strings(state, item, field).await?);
            }
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                audit.extend(redact_json_strings(state, item, field).await?);
            }
        }
        _ => {}
    }
    Ok(audit)
}

/// tool_use id → the model-only context for its result (`tool_result_context`).
type ToolContexts = HashMap<String, String>;

#[async_recursion::async_recursion]
async fn redact_content(
    state: &AppState,
    content: &mut Value,
    tools: &ToolContexts,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    match content {
        Value::String(text) => {
            let (out, mut entries) = redact_text_smart(state, text, "content").await?;
            *text = out;
            audit.append(&mut entries);
        }
        Value::Array(blocks) => {
            for block in blocks {
                audit.extend(redact_block(state, block, tools, None).await?);
            }
        }
        _ => {}
    }
    Ok(audit)
}

/// Redact the string at `block[key]` in place, if it is a string.
async fn redact_string_field(
    state: &AppState,
    block: &mut Value,
    key: &str,
    field: &str,
) -> anyhow::Result<Vec<Value>> {
    let Some(Value::String(s)) = block.get_mut(key) else {
        return Ok(Vec::new());
    };
    let (out, entries) = redact_text(state, s, field, "").await?;
    *s = out;
    Ok(entries)
}

/// Redact one content block in place. Every block type that can carry user text is routed here, so a new block shape has exactly one place to be added. `context` is the model-only context of the tool_result a block sits in. Thinking blocks are signed by the provider and images carry no text, so those and unknown types are left untouched.
#[async_recursion::async_recursion]
async fn redact_block(
    state: &AppState,
    block: &mut Value,
    tools: &ToolContexts,
    context: Option<&str>,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    let kind = block["type"].as_str().map(str::to_string);
    match kind.as_deref() {
        Some("text") => {
            if let Some(Value::String(s)) = block.get_mut("text") {
                let (out, mut entries) = match context {
                    Some(context) => redact_text(state, s, "tool_result.text", context).await?,
                    None => redact_text_smart(state, s, "text").await?,
                };
                *s = out;
                audit.append(&mut entries);
            }
        }
        Some("tool_result" | "mcp_tool_result") => {
            let context = block["tool_use_id"]
                .as_str()
                .and_then(|id| tools.get(id))
                .cloned();
            match block.get_mut("content") {
                Some(Value::String(text)) => {
                    let (out, mut entries) = match context.as_deref() {
                        Some(context) => redact_text(state, text, "tool_result", context).await?,
                        None => redact_text_smart(state, text, "content").await?,
                    };
                    *text = out;
                    audit.append(&mut entries);
                }
                Some(Value::Array(inner)) => {
                    for item in inner {
                        audit.extend(redact_block(state, item, tools, context.as_deref()).await?);
                    }
                }
                _ => {}
            }
        }
        Some(kind @ ("tool_use" | "server_tool_use" | "mcp_tool_use")) => {
            let field = format!("{kind}.input");
            if let Some(input) = block.get_mut("input") {
                audit.extend(redact_json_strings(state, input, &field).await?);
            }
        }
        Some("web_fetch_tool_result") => {
            if let Some(result) = block.get_mut("content") {
                audit.extend(redact_block(state, result, tools, context).await?);
            }
        }
        Some("web_fetch_result") => {
            audit.extend(redact_string_field(state, block, "url", "web_fetch_result.url").await?);
            if let Some(document) = block.get_mut("content") {
                audit.extend(redact_block(state, document, tools, context).await?);
            }
        }
        Some("document") => {
            if block["source"]["type"] == "text" {
                if let Some(source) = block.get_mut("source") {
                    audit.extend(
                        redact_string_field(state, source, "data", "document.source.data").await?,
                    );
                }
            }
            audit.extend(redact_string_field(state, block, "title", "document.title").await?);
            audit.extend(redact_string_field(state, block, "context", "document.context").await?);
        }
        Some("search_result") => {
            audit.extend(redact_string_field(state, block, "title", "search_result.title").await?);
            audit
                .extend(redact_string_field(state, block, "source", "search_result.source").await?);
            if let Some(Value::Array(inner)) = block.get_mut("content") {
                for item in inner {
                    audit.extend(redact_block(state, item, tools, context).await?);
                }
            }
        }
        _ => {}
    }
    Ok(audit)
}

async fn redact_payload(state: &AppState, body: &mut Value) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    // The context each tool_result is scanned with comes from the tool call that produced it.
    let mut tools = ToolContexts::new();
    for message in body["messages"].as_array().into_iter().flatten() {
        for block in message["content"].as_array().into_iter().flatten() {
            if let ("tool_use" | "mcp_tool_use", Some(id), Some(name)) = (
                block["type"].as_str().unwrap_or_default(),
                block["id"].as_str(),
                block["name"].as_str(),
            ) {
                tools.insert(id.to_string(), tool_result_context(name, &block["input"])?);
            }
        }
    }
    if let Some(system) = body.get_mut("system") {
        audit.extend(redact_content(state, system, &tools).await?);
    }
    for tool in body
        .get_mut("tools")
        .and_then(|t| t.as_array_mut())
        .into_iter()
        .flatten()
    {
        audit.extend(redact_string_field(state, tool, "description", "tools.description").await?);
    }
    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages.iter_mut() {
            if let Some(content) = message.get_mut("content") {
                audit.extend(redact_content(state, content, &tools).await?);
            }
        }
    }
    Ok(audit)
}

fn json_response(status: StatusCode, body: Value) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("valid response")
}

fn error_response(status: StatusCode, message: &str) -> Response {
    json_response(
        status,
        json!({"type":"error","error":{"type":"piifence_error","message":message}}),
    )
}

/// Replace the session's named values wherever they are still in `payload` after redaction, by the rule of `WHOLE_TOKEN_BELOW`. A value can be named in a later field after an earlier one was already rewritten, or sit in a field the walker does not scan. Thinking blocks are signed and cannot be rewritten, base64 sources hold no text, and `metadata` holds the client's ids, so those are skipped.
fn sweep_values(state: &AppState, payload: &mut Value) -> anyhow::Result<Vec<Value>> {
    let values: Vec<String> = with_session(state, |session| {
        session
            .env
            .entries
            .iter()
            .map(|e| e.value.clone())
            .collect()
    });
    let mut audit = Vec::new();
    if values.is_empty() {
        return Ok(audit);
    }
    let finder = aho_corasick::AhoCorasick::new(&values).context("index the named values")?;
    sweep(state, payload, &finder, &values, "$", &mut audit);
    Ok(audit)
}

fn sweep(
    state: &AppState,
    value: &mut Value,
    finder: &aho_corasick::AhoCorasick,
    values: &[String],
    path: &str,
    audit: &mut Vec<Value>,
) {
    match value {
        Value::String(text) => {
            let hit = finder
                .find_overlapping_iter(text.as_str())
                .any(|m| !env_value_matches(text, &values[m.pattern().as_usize()]).is_empty());
            if hit {
                let (out, mut entries) = replace_env_values(state, text, path);
                *text = out;
                audit.append(&mut entries);
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                sweep(state, item, finder, values, &format!("{path}[{i}]"), audit);
            }
        }
        Value::Object(map) => {
            if matches!(
                map.get("type").and_then(Value::as_str),
                Some("thinking" | "redacted_thinking" | "base64")
            ) {
                return;
            }
            for (key, item) in map.iter_mut() {
                if !(path == "$" && key.as_str() == "metadata") {
                    sweep(state, item, finder, values, &format!("{path}.{key}"), audit);
                }
            }
        }
        _ => {}
    }
}

/// Scan a messages request and return its rewritten body.
async fn redact_request(state: &AppState, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut payload: Value = serde_json::from_slice(body).context("request body is not JSON")?;
    let started = std::time::Instant::now();
    let mut audit = redact_payload(state, &mut payload).await?;
    audit.append(&mut sweep_values(state, &mut payload)?);
    save_names(state)?;
    let redact_ms = started.elapsed().as_secs_f64() * 1000.0;
    let redacted = serde_json::to_vec(&payload)?;
    if !audit.is_empty() {
        audit_line(
            state,
            json!({"event":"redacted","spans":audit.len(),"details":audit}),
        )?;
        if let Some(file) = &state.audit_body {
            writeln!(
                file.lock().unwrap(),
                "{}",
                String::from_utf8_lossy(&redacted)
            )
            .context("write the body log")?;
        }
        record_stats(state, &audit, redact_ms);
    }
    Ok(redacted)
}

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
        // The launcher reads this header on the control socket and compares it to its own upstream before reusing a gateway. `tcp_only` removes it from the answer on TCP.
        return Response::builder()
            .status(StatusCode::OK)
            .header(UPSTREAM_HEADER, state.upstream.as_str())
            .body(Body::from("ok"))
            .expect("valid response");
    }
    if path == "/stats" {
        let stats = state.stats.lock().unwrap();
        return json_response(
            StatusCode::OK,
            json!({
                "requests": stats.requests,
                "redactions": stats.redactions,
                "values": stats.values,
                "redact_ms_last": (stats.redact_ms_last * 100.0).round() / 100.0,
                "redact_ms_total": (stats.redact_ms_total * 100.0).round() / 100.0,
                "redact_ms_max": (stats.redact_ms_max * 100.0).round() / 100.0,
                "by_kind": stats.by_kind,
                "recent": stats.recent.iter().cloned().collect::<Vec<_>>(),
            }),
        );
    }
    // Every POST under /v1/messages carries conversation text. Scan the two shapes that share the Messages body and refuse any other, such as batches, and the legacy /v1/complete prompt, rather than forwarding their text unscanned.
    let is_messages = matches!(path, "/v1/messages" | "/v1/messages/count_tokens");
    let is_scanned = is_messages && method == Method::POST;
    if (path == "/v1/complete" || path.starts_with("/v1/messages/") && !is_messages)
        && method == Method::POST
    {
        return error_response(
            StatusCode::FORBIDDEN,
            "this endpoint is not redacted; request blocked",
        );
    }
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
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "this gateway is shutting down",
            )
        };
    }
    // Control paths are for the launcher and its hooks, so none is ever forwarded to the provider.
    if path.starts_with("/control/") {
        return error_response(StatusCode::NOT_FOUND, "no such control endpoint");
    }

    let outgoing = if is_scanned {
        match redact_request(&state, &body).await {
            Ok(redacted) => redacted,
            Err(err) => {
                // Fail closed: never forward a payload that was not fully scanned.
                let _ = audit_line(
                    &state,
                    json!({"event":"redact_error","error":format!("{err:#}")}),
                );
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("piifence could not scan this request, so it was not sent: {err:#}"),
                );
            }
        }
    } else {
        body.to_vec()
    };

    let upstream_url = format!(
        "{}{}",
        state.upstream.trim_end_matches('/'),
        uri.path_and_query().map_or(path, |p| p.as_str())
    );
    let mut forward_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        if matches!(
            name.as_str(),
            "host" | "content-length" | "accept-encoding" | "connection" | SESSION_HEADER
        ) {
            continue;
        }
        forward_headers.insert(name.clone(), value.clone());
    }
    let upstream = match state
        .client
        .request(method.clone(), &upstream_url)
        .headers(forward_headers)
        .body(outgoing)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            let _ = audit_line(
                &state,
                json!({"event":"upstream_error","error":err.to_string()}),
            );
            return error_response(StatusCode::BAD_GATEWAY, &format!("upstream error: {err}"));
        }
    };

    // Response: byte-for-byte passthrough, streamed as it arrives. No parsing, no buffering, no replacing names back.
    let status = upstream.status();
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream.headers().iter() {
        if matches!(
            name.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from_stream(upstream.bytes_stream()))
        .expect("valid response")
}

/// Open a log for appending with owner-only permissions. The mode applies when the file is created, so an existing log keeps its current mode.
fn open_private_append(path: &str) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {path}"))
}

/// `name` from the environment, or `default` when it is unset. A set value that does not parse is an error.
fn env_or<T: std::str::FromStr>(name: &str, default: T) -> anyhow::Result<T> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse()
            .map_err(|_| anyhow::anyhow!("{name}={raw:?} is not valid")),
        Err(_) => Ok(default),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let upstream = std::env::var("PIIF_UPSTREAM")
        .context("PIIF_UPSTREAM is required: set it to the provider's base URL")?;
    let model_dirs: Vec<PathBuf> =
        std::env::split_paths(&std::env::var_os("PIIF_MODEL_DIR").context(
            "PIIF_MODEL_DIR is required: the model directory, or several joined with ':'",
        )?)
        .collect();
    let port: u16 = env_or("PIIF_PORT", 7788)?;
    let exit_when_unused: u64 = env_or("PIIF_EXIT_WHEN_UNUSED", 0)?;
    let audit_path: String = env_or("PIIF_AUDIT_LOG", "/tmp/piifence-audit.log".to_string())?;
    let audit_body_path = (env_or("PIIF_AUDIT_BODY", 0u8)? == 1)
        .then(|| "/tmp/piifence-redacted-bodies.jsonl".to_string());
    let cache_dir = match std::env::var("PIIF_CACHE_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => {
            PathBuf::from(std::env::var("HOME").context("HOME is not set")?).join(".cache/piifence")
        }
    };

    let state_dir = piifence::control::state_dir()?;
    let names_dir = state_dir.join("names");
    prepare_names_dir(&names_dir)?;
    NAMES_DIR.set(names_dir).expect("set once");

    let audit = open_private_append(&audit_path)?;
    let audit_body = audit_body_path
        .as_deref()
        .map(open_private_append)
        .transpose()?;
    let allow = piifence::config::load()?.allow_patterns()?;
    eprintln!(
        "loading the secret models from {} (upstream {upstream}, port {port})",
        std::env::join_paths(&model_dirs)?.to_string_lossy()
    );
    let detector = Detector::load(&model_dirs, allow, &cache_dir)?;
    eprintln!(
        "detection cache: {} ({} entries)",
        cache_dir.join("detections.jsonl").display(),
        detector.cached()
    );

    // Detection runs on one worker thread, one text at a time; requests reach it through a channel.
    let (detector_tx, detector_rx) = std::sync::mpsc::channel::<DetectJob>();
    std::thread::spawn(move || {
        while let Ok(job) = detector_rx.recv() {
            let result = detector.detect(&job.text).map(|detection| detection.kept);
            let _ = job.reply.send(result);
        }
    });

    let leases = Arc::new(Mutex::new(Leases::default()));
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
        leases: leases.clone(),
        session: String::new(),
    };

    let app = Router::new()
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An AppState in a session whose detector marks every `TOKEN` as a secret, so the block walker can be tested without model weights or gitleaks.
    fn fake_state() -> AppState {
        let (detector_tx, detector_rx) = std::sync::mpsc::channel::<DetectJob>();
        std::thread::spawn(move || {
            while let Ok(job) = detector_rx.recv() {
                let spans = job
                    .text
                    .match_indices("TOKEN")
                    .map(|(start, word)| DetectedSpan {
                        word: word.to_string(),
                        start,
                        end: start + word.len(),
                        source: "model:API_KEY".to_string(),
                    })
                    .collect();
                let _ = job.reply.send(Ok(spans));
            }
        });
        AppState {
            detector_tx,
            client: reqwest::Client::new(),
            upstream: "http://127.0.0.1:1".to_string(),
            port: 0,
            audit: Arc::new(Mutex::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/null")
                    .unwrap(),
            )),
            audit_body: None,
            stats: Arc::new(Mutex::new(Stats::default())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            leases: Arc::new(Mutex::new(Leases::default())),
            session: "0123456789abcdef0123456789abcdef".to_string(),
        }
    }

    fn span(start: usize, end: usize) -> DetectedSpan {
        DetectedSpan {
            word: String::new(),
            start,
            end,
            source: "model:PASSWORD".to_string(),
        }
    }

    fn ranges(spans: &[DetectedSpan]) -> Vec<(usize, usize)> {
        spans.iter().map(|s| (s.start, s.end)).collect()
    }

    const TEXT40: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";

    #[test]
    fn overlapping_spans_are_unioned() {
        let out = normalize_spans(vec![span(10, 30), span(12, 20), span(25, 35)], TEXT40, 0);
        assert_eq!(ranges(&out), vec![(10, 35)]);
        assert_eq!(out[0].word, &TEXT40[10..35]);
    }

    #[test]
    fn span_starting_in_context_is_clamped() {
        let out = normalize_spans(vec![span(15, 40)], &TEXT40[..20], 20);
        assert_eq!(ranges(&out), vec![(0, 20)]);
    }

    #[test]
    fn leading_space_is_trimmed() {
        let out = normalize_spans(vec![span(4, 8)], "key: abc", 0);
        assert_eq!(ranges(&out), vec![(5, 8)]);
    }

    #[test]
    fn touching_spans_stay_separate() {
        let out = normalize_spans(vec![span(0, 5), span(5, 9)], TEXT40, 0);
        assert_eq!(ranges(&out), vec![(0, 5), (5, 9)]);
    }

    #[test]
    fn span_entirely_in_context_is_dropped() {
        let out = normalize_spans(vec![span(3, 12)], &TEXT40[..20], 20);
        assert!(out.is_empty());
    }

    #[test]
    fn multibyte_edges_are_widened() {
        // "é" is two bytes; a span ending inside it is widened to cover it.
        let out = normalize_spans(vec![span(0, 5)], "abcdé xyz", 0);
        assert_eq!(ranges(&out), vec![(0, 6)]);
    }

    #[test]
    fn tool_results_are_framed_as_a_shell_transcript() {
        let context = |name: &str, input: Value| tool_result_context(name, &input).unwrap();
        assert_eq!(
            context("Bash", json!({"command": "echo $API_KEY"})),
            "API_KEY="
        );
        assert_eq!(
            context("Bash", json!({"command": "echo \"${DB_PASSWORD}\""})),
            "DB_PASSWORD="
        );
        assert_eq!(
            context("Bash", json!({"command": "tail -1 access.log"})),
            "$ tail -1 access.log\n"
        );
        assert_eq!(
            context("Read", json!({"file_path": "/repo/.env"})),
            "$ cat /repo/.env\n"
        );
        assert_eq!(
            context("search", json!({"q": "x"})),
            "Tool call: search {\"q\":\"x\"}\nTool output:\n"
        );
        // Long input is cut on a char boundary.
        let long = format!("echo {}", "é".repeat(600));
        assert!(context("Bash", json!({ "command": long })).len() <= CONTEXT_INPUT_BYTES + 3);
    }

    #[tokio::test]
    async fn document_text_source_is_redacted() {
        let state = fake_state();
        let mut content = json!([{"type": "document", "title": "TOKEN notes",
            "source": {"type": "text", "media_type": "text/plain", "data": "a TOKEN b"}}]);
        let audit = redact_content(&state, &mut content, &ToolContexts::new())
            .await
            .unwrap();
        assert_eq!(content[0]["source"]["data"], "a $PIIF_SECRET_1 b");
        assert_eq!(content[0]["title"], "$PIIF_SECRET_1 notes");
        assert_eq!(audit.len(), 2);
    }

    #[tokio::test]
    async fn document_base64_is_untouched() {
        let state = fake_state();
        let mut content = json!([{"type": "document",
            "source": {"type": "base64", "media_type": "application/pdf", "data": "TOKEN"}}]);
        let before = content.clone();
        redact_content(&state, &mut content, &ToolContexts::new())
            .await
            .unwrap();
        assert_eq!(content, before);
    }

    #[tokio::test]
    async fn search_result_inside_tool_result_is_redacted() {
        let state = fake_state();
        let mut tools = ToolContexts::new();
        tools.insert(
            "t1".to_string(),
            "Tool call: search {}\nTool output:\n".to_string(),
        );
        let block = json!([{"type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "search_result", "title": "Ops", "source": "https://wiki/ops",
             "content": [{"type": "text", "text": "x TOKEN y"}]}]}]);

        let mut with_context = block.clone();
        let audit = redact_content(&state, &mut with_context, &tools)
            .await
            .unwrap();
        assert_eq!(
            with_context[0]["content"][0]["content"][0]["text"],
            "x $PIIF_SECRET_1 y"
        );
        assert_eq!(audit[0]["field"], "tool_result.text");

        let mut without_context = block;
        let audit = redact_content(&state, &mut without_context, &ToolContexts::new())
            .await
            .unwrap();
        assert_eq!(
            without_context[0]["content"][0]["content"][0]["text"],
            "x $PIIF_SECRET_1 y"
        );
        assert_eq!(audit[0]["field"], "text");
    }

    #[tokio::test]
    async fn env_value_in_tool_output_becomes_its_name() {
        let state = fake_state();
        // The value was named in an earlier request.
        with_session(&state, |session| {
            session.env.entry_for("if-ajsdlk231lj", "PASSWORD");
        });
        // `echo $PIIF_SECRET_1` printed the value, which detection would miss; TOKEN is still detected and gets the next name.
        let mut content = json!([{"type": "tool_result", "tool_use_id": "t1",
            "content": "if-ajsdlk231lj\nTOKEN"}]);
        let audit = redact_content(&state, &mut content, &ToolContexts::new())
            .await
            .unwrap();
        assert_eq!(content[0]["content"], "$PIIF_SECRET_1\n$PIIF_SECRET_2");
        assert_eq!(audit[0]["engine"], "env");
        assert_eq!(audit[0]["kind"], "PASSWORD");
        assert_eq!(audit[0]["name"], "$PIIF_SECRET_1");
        assert_eq!(audit[0]["new"], true);
        assert_eq!(audit[1]["kind"], "API_KEY");

        // Anywhere in the request, and reported as new only once.
        let mut content = json!([{"type": "tool_use", "id": "t2", "name": "Bash",
            "input": {"command": "curl -H 'X-Key: if-ajsdlk231lj' x"}}]);
        let audit = redact_content(&state, &mut content, &ToolContexts::new())
            .await
            .unwrap();
        assert_eq!(
            content[0]["input"]["command"],
            "curl -H 'X-Key: $PIIF_SECRET_1' x"
        );
        assert_eq!(audit[0]["new"], false);

        // Another session neither sees the value replaced nor can look it up.
        let other = AppState {
            session: "ffffffffffffffffffffffffffffffff".to_string(),
            ..state.clone()
        };
        let (out, _) = replace_env_values(&other, "if-ajsdlk231lj", "text");
        assert_eq!(out, "if-ajsdlk231lj");
        assert!(with_session(&other, |s| s.env.all()).is_empty());
        assert_eq!(
            with_session(&state, |s| s.env.all())["PIIF_SECRET_1"],
            "if-ajsdlk231lj"
        );
    }

    /// A bare name, built at run time so this file never holds one literally.
    fn bare(n: usize) -> String {
        format!("$PIIF_SECRET_{n}")
    }

    /// A braced name, built the same way.
    fn braced(n: usize) -> String {
        format!("${{PIIF_SECRET_{n}}}")
    }

    #[test]
    fn short_values_are_replaced_only_as_whole_tokens() {
        // Short: not inside a longer run of letters and digits, but next to punctuation.
        assert_eq!(env_value_matches("885,1150p", "1150"), Vec::<usize>::new());
        assert_eq!(
            env_value_matches("pw hunter2x", "hunter2"),
            Vec::<usize>::new()
        );
        assert_eq!(env_value_matches("PW=hunter2;", "hunter2"), vec![3]);
        assert_eq!(
            env_value_matches("'hunter2' hunter2", "hunter2"),
            vec![1, 10]
        );
        // A value whose edge is punctuation may touch a letter there.
        assert_eq!(env_value_matches("a:pw!b", ":pw!"), vec![1]);
        // Long: replaced wherever it appears.
        let long = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(env_value_matches(&format!("x{long}y"), long), vec![1]);
    }

    #[test]
    fn a_short_value_cut_at_a_hyphen_or_underscore_is_not_replaced_inside_a_longer_token() {
        let uuid = "12345678-abcd-4ef0-8123-456789abcdef";
        assert_eq!(env_value_matches(uuid, "12345678-"), Vec::<usize>::new());
        assert_eq!(
            env_value_matches("a-8123-4567", "-8123"),
            Vec::<usize>::new()
        );
        assert_eq!(
            env_value_matches("plugin/piifence-notice", "piifence-"),
            Vec::<usize>::new()
        );
        assert_eq!(
            env_value_matches("MY_KEY_NAME", "KEY_"),
            Vec::<usize>::new()
        );
        assert_eq!(env_value_matches("id: 12345678- end", "12345678-"), vec![4]);
        assert_eq!(env_value_matches("x KEY_ y", "KEY_"), vec![2]);
        assert_eq!(env_value_matches("a-hunter2 b", "hunter2"), vec![2]);
    }

    #[tokio::test]
    async fn a_name_is_braced_when_a_letter_digit_or_underscore_follows() {
        let state = fake_state();
        let long = "known-value-of-twenty";
        with_session(&state, |session| {
            session.env.entry_for(long, "PASSWORD");
            session.env.entry_for(":pw!", "PASSWORD");
        });
        let (out, _) =
            replace_env_values(&state, &format!("{long}7 {long}_x {long}-x {long}"), "text");
        assert_eq!(
            out,
            format!("{b}7 {b}_x {n}-x {n}", b = braced(1), n = bare(1))
        );
        let (out, _) = replace_env_values(&state, "a:pw!b", "text");
        assert_eq!(out, format!("a{}b", braced(2)));
        let (out, _) = redact_text(&state, "TOKENx TOKEN", "text", "")
            .await
            .unwrap();
        assert_eq!(out, format!("{}x {}", braced(3), bare(3)));
    }

    #[test]
    fn a_resumed_conversation_keeps_its_stored_names() {
        let mut env = EnvValues::default();
        env.entry_for("seen-before-bind", "PASSWORD");
        env.entry_for("stored-too", "API_KEY");
        let stored = [
            (
                "PIIF_SECRET_1".to_string(),
                "old-one".to_string(),
                "PASSWORD".to_string(),
            ),
            (
                "PIIF_SECRET_7".to_string(),
                "stored-too".to_string(),
                "API_KEY".to_string(),
            ),
        ];
        env.merge(&stored);
        let all = env.all();
        assert_eq!(all["PIIF_SECRET_1"], "old-one");
        assert_eq!(all["PIIF_SECRET_7"], "stored-too");
        assert_eq!(all["PIIF_SECRET_8"], "seen-before-bind");
        assert_eq!(all.len(), 3);
        assert_eq!(env.entry_for("new", "API_KEY").name, "PIIF_SECRET_9");

        let round_trip: Vec<(String, String, String)> = env
            .stored()
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["name"].as_str().unwrap().into(),
                    e["value"].as_str().unwrap().into(),
                    e["kind"].as_str().unwrap().into(),
                )
            })
            .collect();
        let mut again = EnvValues::default();
        again.merge(&round_trip);
        assert_eq!(again.all(), env.all());
        assert_eq!(again.counter, 9);
    }

    #[test]
    fn names_count_up_and_a_value_keeps_its_name() {
        let mut env = EnvValues::default();
        assert_eq!(env.entry_for("abcd", "PASSWORD").name, "PIIF_SECRET_1");
        assert_eq!(env.entry_for("efgh", "API_KEY").name, "PIIF_SECRET_2");
        assert_eq!(env.entry_for("abcd", "API_KEY").name, "PIIF_SECRET_1");
        assert_eq!(env.entry_for("abcd", "API_KEY").kind, "PASSWORD");
        for n in 3..=120 {
            assert_eq!(
                env.entry_for(&format!("value-{n}"), "keyrule").name,
                format!("PIIF_SECRET_{n}")
            );
        }
        assert_eq!(env.all().len(), 120);
    }

    #[tokio::test]
    async fn thinking_blocks_are_never_modified() {
        let state = fake_state();
        let mut content = json!([
            {"type": "thinking", "thinking": "TOKEN", "signature": "TOKEN"},
            {"type": "redacted_thinking", "data": "TOKEN"}]);
        let before = content.clone();
        let audit = redact_content(&state, &mut content, &ToolContexts::new())
            .await
            .unwrap();
        assert_eq!(content, before);
        assert!(audit.is_empty());
    }

    #[tokio::test]
    async fn server_and_mcp_blocks_and_tool_descriptions_are_redacted() {
        let state = fake_state();
        let mut body = json!({
            "tools": [{"name": "deploy", "description": "Uses TOKEN.", "input_schema": {"type": "object"}}],
            "messages": [{"role": "assistant", "content": [
                {"type": "server_tool_use", "id": "s1", "name": "web_fetch",
                 "input": {"url": "https://example.com/?access_token=TOKEN"}},
                {"type": "web_fetch_tool_result", "tool_use_id": "s1", "content": {
                    "type": "web_fetch_result", "url": "https://example.com/TOKEN",
                    "content": {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "key TOKEN"}}}},
                {"type": "mcp_tool_use", "id": "m1", "name": "set", "server_name": "vault", "input": {"value": "TOKEN"}},
                {"type": "mcp_tool_result", "tool_use_id": "m1", "content": [{"type": "text", "text": "saved TOKEN"}]}
            ]}]
        });
        redact_payload(&state, &mut body).await.unwrap();
        let text = body.to_string();
        assert!(!text.contains("TOKEN"), "{text}");
        assert_eq!(body["tools"][0]["description"], "Uses $PIIF_SECRET_1.");
        assert_eq!(
            body["messages"][0]["content"][2]["input"]["value"],
            "$PIIF_SECRET_1"
        );
    }

    #[tokio::test]
    async fn a_named_value_left_anywhere_is_replaced() {
        let state = fake_state();
        with_session(&state, |session| {
            session.env.entry_for("if-ajsdlk231lj", "PASSWORD");
        });
        let leaked = json!({"messages": [{"role": "user", "content": "hi"}],
            "container": {"note": "pw if-ajsdlk231lj"}});
        let out = redact_request(&state, leaked.to_string().as_bytes())
            .await
            .unwrap();
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["container"]["note"], "pw $PIIF_SECRET_1");

        // Thinking, base64 data and metadata are not rewritten; a short value inside a longer word is not a copy.
        let allowed = json!({"metadata": {"user_id": "if-ajsdlk231lj"},
            "messages": [{"role": "assistant", "content": [
                {"type": "thinking", "thinking": "if-ajsdlk231lj", "signature": "s"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "if-ajsdlk231lj"}},
                {"type": "text", "text": "the value if-ajsdlk231lj"}]}],
            "tool_choice": {"name": "xif-ajsdlk231ljx"}});
        let out = redact_request(&state, allowed.to_string().as_bytes())
            .await
            .unwrap();
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            out["messages"][0]["content"][2]["text"],
            "the value $PIIF_SECRET_1"
        );
    }

    #[test]
    fn record_counts_a_value_once() {
        let mut stats = Stats::default();
        let first = json!({"kind": "API_KEY", "name": "$PIIF_SECRET_1", "new": true});
        let again = json!({"kind": "API_KEY", "name": "$PIIF_SECRET_1", "new": false});
        stats.record(&[first, again], 1.0);
        assert_eq!(stats.values, 1);
        assert_eq!(stats.redactions, 2);
        assert_eq!(stats.recent.len(), 1);
        assert_eq!(stats.by_kind["API_KEY"], 2);
    }

    #[test]
    fn recent_keeps_the_last_twenty_new_entries() {
        let mut stats = Stats::default();
        let audit: Vec<Value> = (1..=25)
            .map(|n| json!({"kind": "API_KEY", "name": format!("$PIIF_SECRET_{n}"), "new": true}))
            .collect();
        stats.record(&audit, 1.0);
        assert_eq!(stats.values, 25);
        assert_eq!(stats.recent.len(), 20);
        assert_eq!(stats.recent[0]["name"], "$PIIF_SECRET_6");
    }

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
        let closing = expire_leases(
            &mut leases,
            Instant::now(),
            Duration::from_secs(10),
            |pid| pid == 11,
        );
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
        assert!(!expire_leases(
            &mut leases,
            start + grace - Duration::from_millis(1),
            grace,
            |_| true
        ));
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
        assert!(!expire_leases(
            &mut leases,
            start + grace * 2 - Duration::from_millis(1),
            grace,
            |_| true
        ));
        assert!(expire_leases(&mut leases, start + grace * 2, grace, |_| {
            true
        }));
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
        for (value, expected) in [
            ("4242", Some(4242)),
            ("0", None),
            ("-5", None),
            ("12x", None),
        ] {
            headers.insert(LAUNCHER_HEADER, value.parse().unwrap());
            assert_eq!(launcher_pid(&headers), expected, "{value}");
        }
    }

    #[test]
    fn paths_are_split_between_tcp_and_the_control_socket() {
        for path in [
            "/stats",
            "/control/env",
            "/control/conversation",
            "/control/lease",
            "/control/other",
        ] {
            assert!(
                !served_on(Via::Tcp, path),
                "{path} must not be served on TCP"
            );
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
}
