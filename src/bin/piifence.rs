//! piifence CLI — launch Claude Code through the secret-redaction gateway.
//!
//! Usage:
//!   piifence claude [claude arguments...]
//!
//! It starts the gateway if it is not already healthy (upstream derived from the user's current Claude Code settings), points this Claude Code session at it with a temporary `--settings` override, takes a lease on the gateway, and runs Claude Code. It never stops a gateway: one it started exits by itself once no `piifence claude` has held a lease for `PIIF_EXIT_WHEN_UNUSED` seconds (10 by default). The user's settings file is never modified.
//!
//! The override also adds two hooks. `SessionStart` runs `piifence session-start`: it tells the agent what `$PIIF_SECRET_<N>` names are, sends the gateway Claude Code's conversation id so a resumed conversation gets its old names back, and adds a line to Claude Code's `CLAUDE_ENV_FILE`, which Claude Code sources before every Bash command. That line runs `piifence env`, which exports this session's values from the gateway, so a command that names `$PIIF_SECRET_1` gets the real value. `PreToolUse` runs `piifence restore` on every tool call: it puts the real values into the tool's input, so a file the agent writes or an MCP argument holds the value, not the name; a backslash before a name's `$` counts as part of the name. In Bash and Monitor commands it fills in only the names the shell would not expand (single quotes, quoted heredocs, an escaped `$`), escaped for where they stand; PowerShell is skipped.
//!
//! Files: `$PIIF_DATA_DIR` (default `~/.local/share/piifence`, which `scripts/install.sh` sets) holds `model/` (the secret model) and `plugin/piifence-notice` (the notice plugin). The gateway binary sits next to this one. The hooks and the notice plugin reach the gateway on its control socket, `$PIIF_STATE_DIR/run/<port>.sock` (state dir `~/.local/state/piifence` by default), in a directory only the user can open; the gateway hands out no session data on TCP.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const DEFAULT_PORT: u16 = 7788;
const GATEWAY_START_TIMEOUT: Duration = Duration::from_secs(45);
/// Seconds a gateway started by `piifence claude` keeps running after the last lease ends, unless `PIIF_EXIT_WHEN_UNUSED` is set.
const DEFAULT_EXIT_WHEN_UNUSED: u64 = 10;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("claude") => run_claude(&args[1..]),
        // Run by Claude Code, not by people: the hook and the line it writes.
        Some("session-start") => session_start(&args[1..]),
        Some("env") => print_env(&args[1..]),
        Some("restore") => restore(&args[1..]),
        Some("-h") | Some("--help") | Some("help") | None => {
            usage();
            Ok(0)
        }
        Some(other) => {
            eprintln!("piifence: unknown command `{other}`\n");
            usage();
            Ok(2)
        }
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("piifence: {err:#}");
            std::process::exit(1);
        }
    }
}

fn usage() {
    println!(
        "piifence — run Claude Code with local secret redaction\n\n\
         Usage:\n  piifence claude [claude arguments...]\n\n\
         Starts the redaction gateway if needed, points this Claude Code session at\n\
         it, and streams responses back untouched. The gateway forwards redacted requests\n\
         to PIIF_UPSTREAM, else the ANTHROPIC_BASE_URL set in your shell or Claude Code\n\
         settings. No default provider is assumed; one of these must be set."
    );
}

/// `$PIIF_DATA_DIR`, default `~/.local/share/piifence`.
fn data_dir() -> Result<PathBuf> {
    match env::var("PIIF_DATA_DIR") {
        Ok(dir) => Ok(PathBuf::from(dir)),
        Err(_) => Ok(home()?.join(".local/share/piifence")),
    }
}

fn home() -> Result<PathBuf> {
    Ok(PathBuf::from(env::var("HOME").context("HOME is not set")?))
}

/// This binary's path as it was started, when the gateway binary sits next to it there, so a stable path such as Homebrew's `opt/piifence` survives an upgrade in the hooks and the env file. Otherwise its real path, through any symlink.
fn real_exe() -> Result<PathBuf> {
    let exe = env::current_exe().context("cannot find the piifence binary's path")?;
    if exe.is_absolute() && exe.with_file_name("piifence-gateway").exists() {
        return Ok(exe);
    }
    fs::canonicalize(&exe).with_context(|| format!("cannot resolve {}", exe.display()))
}

/// `path`, which must exist.
fn existing(path: PathBuf, what: &str) -> Result<PathBuf> {
    if !path.exists() {
        bail!(
            "{what} is missing: nothing at {} (run scripts/install.sh)",
            path.display()
        );
    }
    Ok(path)
}

fn port() -> Result<u16> {
    match env::var("PIIF_PORT") {
        Ok(raw) => raw
            .parse()
            .with_context(|| format!("PIIF_PORT={raw:?} is not a port")),
        Err(_) => Ok(DEFAULT_PORT),
    }
}

/// `PIIF_EXIT_WHEN_UNUSED`: the seconds a gateway this launcher starts keeps running without a lease (0: until stopped).
fn exit_when_unused() -> Result<u64> {
    match env::var("PIIF_EXIT_WHEN_UNUSED") {
        Ok(raw) => raw.parse().with_context(|| {
            format!("PIIF_EXIT_WHEN_UNUSED={raw:?} is not a whole number of seconds")
        }),
        Err(_) => Ok(DEFAULT_EXIT_WHEN_UNUSED),
    }
}

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

    let session_id = new_session_id().context("cannot create a session id")?;
    ensure_gateway(&data, port, &upstream, &session_id)?;
    run_session(&gateway_url, port, &plugin, args, &session_id)
}

/// Make sure a gateway that forwards to `upstream` runs on `port`, starting one if none answers, and lease it so it keeps running while this launcher does. A gateway that is shutting down is waited out and replaced. The launcher never stops a gateway: one it started exits by itself after the last lease ends.
fn ensure_gateway(data: &Path, port: u16, upstream: &str, session_id: &str) -> Result<()> {
    let gateway_url = format!("http://127.0.0.1:{port}");
    let socket = control_socket(port)?;
    for _ in 0..2 {
        match running_gateway_upstream(port, &socket)? {
            // Reuse only a gateway that forwards to the same place this launch would. Reusing another one would send this session's credentials elsewhere.
            Some(running) if running == upstream => {
                eprintln!("piifence: using existing gateway on {gateway_url} (upstream {upstream})");
            }
            Some(running) => bail!(
                "a gateway on {gateway_url} forwards to {running:?}, but this launch wants {upstream}. Stop that gateway or set PIIF_PORT to a free port."
            ),
            None => start_gateway(data, port, &socket, upstream)?,
        }
        if lease(&socket, session_id)? {
            return Ok(());
        }
        wait_until_closed(port)?;
    }
    bail!("the gateway on {gateway_url} shut down twice while this launch tried to use it; refusing to launch Claude Code (fail closed)")
}

/// Ask the gateway whose control socket is `socket` to keep running while this process runs session `session_id`. False when the gateway is shutting down (503) or no longer answers. Any other answer means the gateway predates leases.
fn lease(socket: &Path, session_id: &str) -> Result<bool> {
    let headers = format!(
        "x-piifence-session: {session_id}\r\nx-piifence-launcher-pid: {}\r\n",
        std::process::id()
    );
    let Ok(response) = control_get(socket, "/control/lease", &headers, Duration::from_secs(5))
    else {
        return Ok(false);
    };
    if response.starts_with("HTTP/1.1 200") {
        return Ok(true);
    }
    if response.starts_with("HTTP/1.1 503") {
        return Ok(false);
    }
    let status = response.lines().next().unwrap_or_default();
    let socket = socket.display();
    bail!(
        "the gateway at {socket} cannot hold a lease ({status}); it is probably from an older piifence. Quit the sessions that use it, or stop it with `pkill -f piifence-gateway`, and run again."
    )
}

/// Wait until the gateway on `port`, which is shutting down, stops answering.
fn wait_until_closed(port: u16) -> Result<()> {
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while tcp_answers(port) {
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

/// Start a gateway that exits by itself once no launcher holds a lease, and wait until a gateway that forwards to `upstream` is healthy. Claude Code is never launched without one (fail closed).
fn start_gateway(data: &Path, port: u16, socket: &Path, upstream: &str) -> Result<()> {
    let exe = real_exe()?;
    let gateway_bin = existing(exe.with_file_name("piifence-gateway"), "the gateway binary")?;
    let model_dir = existing(data.join("model"), "the secret model")?;
    let gateway_log = match env::var("PIIF_GATEWAY_LOG") {
        Ok(path) => PathBuf::from(path),
        Err(_) => env::temp_dir().join("piifence-gateway.log"),
    };
    let exit_when_unused = exit_when_unused()?;
    let gateway_url = format!("http://127.0.0.1:{port}");
    eprintln!("piifence: starting gateway on {gateway_url} (upstream {upstream})");
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gateway_log)
        .with_context(|| format!("cannot open the gateway log {}", gateway_log.display()))?;
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

    if let Err(err) = wait_healthy(port, socket, upstream, &mut child) {
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
    Ok(())
}

/// Run Claude Code against the gateway with the session's settings override and the notice plugin. Returns Claude Code's exit code.
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
    let status = status.with_context(|| format!("failed to run `{claude}`"))?;
    Ok(status.code().unwrap_or(1))
}

/// Upstream = the provider Claude Code is already configured for, so the gateway is a drop-in hop in front of the user's real endpoint. Order: PIIF_UPSTREAM, the shell's ANTHROPIC_BASE_URL, then the Claude settings file. None when nothing is set: no provider is assumed, so the launcher refuses to run. A value that already points at a gateway (ours, from an earlier run) is ignored.
fn resolve_upstream(gateway_url: &str) -> Result<Option<String>> {
    if let Ok(upstream) = env::var("PIIF_UPSTREAM") {
        return Ok((!upstream.is_empty()).then_some(upstream));
    }
    let settings_base = user_settings_env("ANTHROPIC_BASE_URL")?;
    Ok([env::var("ANTHROPIC_BASE_URL").ok(), settings_base]
        .into_iter()
        .flatten()
        .find(|base| !base.is_empty() && !base.starts_with(gateway_url)))
}

fn claude_settings_path() -> Result<PathBuf> {
    if let Ok(dir) = env::var("CLAUDE_CONFIG_DIR") {
        return Ok(Path::new(&dir).join("settings.json"));
    }
    Ok(home()?.join(".claude/settings.json"))
}

/// `env.<name>` in the user's Claude Code settings. None when the file or the key is absent; a file that cannot be read or parsed is an error.
fn user_settings_env(name: &str) -> Result<Option<String>> {
    let path = claude_settings_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&data)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    Ok(json["env"][name].as_str().map(str::to_string))
}

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

/// Wait until a gateway that forwards to `upstream` answers on `port`. Another launcher may start a gateway at the same moment, and only one of the two gets the port; the other one's gateway is used when it forwards to the same upstream.
fn wait_healthy(port: u16, socket: &Path, upstream: &str, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while Instant::now() < deadline {
        let exited = child.try_wait()?;
        match running_gateway_upstream(port, socket)? {
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

/// A random 32-hex-digit id for this Claude Code session. The gateway keys the session's `$PIIF_…` values on it, and hands values only to a caller that knows it, so it comes from the OS random source.
fn new_session_id() -> std::io::Result<String> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// `ANTHROPIC_CUSTOM_HEADERS` for the session: the user's own (shell, else Claude Code settings, the order Claude Code uses) plus the session id header. The override replaces the user's value, so theirs is carried over.
fn custom_headers(session_id: &str) -> Result<String> {
    let existing = match env::var("ANTHROPIC_CUSTOM_HEADERS") {
        Ok(headers) => Some(headers),
        Err(_) => user_settings_env("ANTHROPIC_CUSTOM_HEADERS")?,
    };
    let ours = format!("x-piifence-session: {session_id}");
    Ok(
        match existing.filter(|headers| !headers.trim().is_empty()) {
            Some(existing) => format!("{}\n{ours}", existing.trim_end()),
            None => ours,
        },
    )
}

/// The session's hooks, run by this binary's real path: `SessionStart` (`piifence session-start <session> <port>`) sets the session up, and `PreToolUse` (`piifence restore <session> <port>`, every tool) puts real values back into tool input.
fn session_hooks(port: u16, session_id: &str) -> Result<serde_json::Value> {
    let exe = shell_quote(&real_exe()?.to_string_lossy());
    Ok(serde_json::json!({
        "SessionStart": [{"hooks": [{
            "type": "command",
            "command": format!("{exe} session-start {session_id} {port}"),
        }]}],
        "PreToolUse": [{"matcher": "*", "hooks": [{
            "type": "command",
            "command": format!("{exe} restore {session_id} {port}"),
        }]}]
    }))
}

/// Write the per-session settings override. The name holds the random session id and the file is created with `create_new`, so a file or symlink planted at a guessable /tmp path cannot make this write land somewhere else. Mode 0600 is set at creation.
fn write_settings_override(gateway_url: &str, port: u16, session_id: &str) -> Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = env::temp_dir().join(format!("piifence-claude-settings-{session_id}.json"));
    let content = format!(
        "{}\n",
        serde_json::json!({
            "env": {
                "ANTHROPIC_BASE_URL": gateway_url,
                "ANTHROPIC_CUSTOM_HEADERS": custom_headers(session_id)?,
            },
            "hooks": session_hooks(port, session_id)?,
        })
    );
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(content.as_bytes()))
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(path)
}

/// What `$PIIF_SECRET_<N>` names are, given to the agent when the session starts (and again after `/clear` or a compaction, which start it again). Without it the agent meets a name in tool output with no idea what it is: it warns that a secret leaked, or decides the variable holds its own name, and does not know it can use it.
const VARIABLES_NOTE: &str = "# piifence environment variables

This session runs through piifence, which keeps secrets (API keys, tokens, passwords, private keys) from reaching you. Before anything is sent to you (the user's prompts, command output, file contents), piifence replaces each secret with an environment variable name such as `$PIIF_SECRET_1`. The real value stays on the user's machine.

- Use the name in Bash commands, inside double quotes, where you would use the value: `curl -H \"Authorization: Bearer $PIIF_SECRET_1\" …`. piifence exports the variables before each command runs, so the shell expands the name, and scripts the command starts can read the variable too. Where the shell would not expand a name (single quotes, quoted heredocs such as `<<'EOF'`), piifence puts the value in before the command runs, so a commit message or a file written from a command gets the value too. Never put a backslash before a name to keep it as text: the name stands for the value, and piifence fills in the value there as well.
- Everywhere else, write the name where the value belongs: in file contents (Write, Edit), in an edit's old text, and in arguments to other tools (MCP tools, for example). piifence puts the real value in before the tool runs, so a file you write holds the value and an edit matches the file.
- A name can stand for text that is not a secret, such as a ticket key, a hostname or a version string. Treat it as that text: write the name wherever the text belongs, in a commit message, a branch name or a file, and piifence puts the text in.
- When a letter, digit or `_` comes right after a name, piifence writes the name in braces, as in `${PIIF_SECRET_…}_old`. Keep the braces when you use the name, in commands and in files: without them, the shell reads a longer variable name that does not exist.
- Files, environment variables and command output on the user's machine hold the real value; only what is sent to you shows the name. A value you see as a `$PIIF_…` name was not exposed to you or the provider: do not warn that it leaked or suggest rotating it on that account.
- When a command prints a value, you see its name again: `echo $PIIF_SECRET_1` shows you `$PIIF_SECRET_1` although the variable holds the real value. Do not conclude from that that the variable is wrong or holds its own name, and do not try to print, decode or otherwise reveal the values.";

/// `<session> <port>` from a hook's or `env`'s arguments.
fn session_args(args: &[String]) -> Result<(&str, u16)> {
    let [session, port] = args else {
        bail!("expected <session> <port>");
    };
    if session.len() != 32 || !session.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("the session id is not 32 hex digits");
    }
    let port = port
        .parse()
        .with_context(|| format!("{port:?} is not a port"))?;
    Ok((session.as_str(), port))
}

/// `piifence session-start <session> <port>`, the `SessionStart` hook. Adds the line that runs `piifence env` to `CLAUDE_ENV_FILE` (once per file), binds the session to Claude Code's conversation id (see `bind_conversation`), and answers with VARIABLES_NOTE as context for the agent. A failure exits non-zero, so Claude Code shows it.
fn session_start(args: &[String]) -> Result<i32> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("read the hook input")?;
    let (session, port) = session_args(args)?;
    let hook: serde_json::Value =
        serde_json::from_str(&input).context("the hook input is not JSON")?;
    let conversation = hook["session_id"]
        .as_str()
        .context("the hook input has no session_id")?;
    let line = format!(
        "eval \"$({} env {session} {port})\"\n",
        shell_quote(&real_exe()?.to_string_lossy())
    );
    let path = env::var("CLAUDE_ENV_FILE")
        .context("CLAUDE_ENV_FILE is not set, so Bash commands cannot get $PIIF_* values")?;
    let existing = if Path::new(&path).exists() {
        fs::read_to_string(&path).with_context(|| format!("cannot read {path}"))?
    } else {
        String::new()
    };
    let updated = env_file_with(&existing, &line);
    if updated != existing {
        fs::write(&path, updated).with_context(|| format!("cannot write {path}"))?;
    }
    bind_conversation(session, port, conversation)?;
    println!(
        "{}",
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": VARIABLES_NOTE,
            }
        })
    );
    Ok(0)
}

/// `existing` env file content with every earlier `piifence env` line dropped and `line` added. A resumed conversation keeps its env file, so without this it would also run the lines of its earlier sessions, some through a binary an upgrade has removed.
fn env_file_with(existing: &str, line: &str) -> String {
    let ours = regex::Regex::new(r#"^eval "\$\('[^']*' env [0-9a-f]{32} [0-9]+\)"$"#)
        .expect("valid pattern");
    let mut kept: String = existing
        .lines()
        .filter(|l| !ours.is_match(l))
        .map(|l| format!("{l}\n"))
        .collect();
    kept.push_str(line);
    kept
}

/// Tell the gateway which Claude Code conversation this session is, so it loads the names a resumed conversation already uses and stores new ones (encrypted, with a key kept in the Keychain).
fn bind_conversation(session: &str, port: u16, conversation: &str) -> Result<()> {
    let socket = control_socket(port)?;
    let response = control_get(
        &socket,
        "/control/conversation",
        &format!("x-piifence-session: {session}\r\nx-piifence-conversation: {conversation}\r\n"),
        Duration::from_secs(30),
    )
    .with_context(|| {
        format!(
            "the gateway's control socket {} did not answer",
            socket.display()
        )
    })?;
    if !response.starts_with("HTTP/1.1 200") {
        let body = response.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        bail!("the gateway could not load this conversation's names: {body}");
    }
    Ok(())
}

/// `piifence env <session> <port>`: this session's values from the gateway as `export NAME='value'` lines, for the `eval` Claude Code runs before every Bash command. A gateway that does not answer is an error on stderr; the command then runs without the values.
fn print_env(args: &[String]) -> Result<i32> {
    let (session, port) = session_args(args)?;
    print!("{}", export_lines(&session_values(session, port)?));
    Ok(0)
}

/// Tools whose input a shell reads, which expands `$PIIF_SECRET_<N>` itself from the exported variables, so the hook fills in only the names the shell would not expand (`piifence::shellfill`). The hook leaves `PowerShell` commands alone.
const SHELL_TOOLS: &[&str] = &["Bash", "Monitor"];

/// `piifence restore <session> <port>`, the `PreToolUse` hook. The agent only ever sees names, so it writes `$PIIF_SECRET_<N>` into file contents, edits, and MCP tool arguments, where no shell expands it. This puts each known name's real value back into the tool's input before the tool runs. A backslash that escapes a name's `$` goes with the name. In `Bash` and `Monitor` commands only the names the shell would not expand are filled in, escaped for where they stand (`SHELL_TOOLS`). `PowerShell` and inputs without a name are left alone. A failure exits 2, which blocks the call, so a tool never runs with a name where a value belongs.
fn restore(args: &[String]) -> Result<i32> {
    match restored_input(args) {
        Ok(Some(input)) => {
            println!(
                "{}",
                serde_json::json!({
                    "hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": input}
                })
            );
            Ok(0)
        }
        Ok(None) => Ok(0),
        Err(err) => {
            eprintln!("piifence: cannot put secret values back into this tool call: {err:#}");
            Ok(2)
        }
    }
}

/// The hook's tool input with names replaced by values (in a shell command, only the names the shell would not expand), or None when nothing changes.
fn restored_input(args: &[String]) -> Result<Option<serde_json::Value>> {
    let (session, port) = session_args(args)?;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("read the hook input")?;
    let hook: serde_json::Value =
        serde_json::from_str(&input).context("the hook input is not JSON")?;
    let tool = hook["tool_name"]
        .as_str()
        .context("the hook input has no tool_name")?;
    if tool == "PowerShell" {
        return Ok(None);
    }
    let mut tool_input = hook
        .get("tool_input")
        .context("the hook input has no tool_input")?
        .clone();
    if SHELL_TOOLS.contains(&tool) {
        let Some(command) = tool_input["command"].as_str() else {
            return Ok(None);
        };
        if !name_pattern().is_match(command) {
            return Ok(None);
        }
        let values = session_values(session, port)?;
        let value_of = |var: &str| values.get(var).and_then(|v| v.as_str()).map(str::to_string);
        let Some(command) = piifence::shellfill::fill_command(command, &value_of)? else {
            return Ok(None);
        };
        tool_input["command"] = command.into();
        return Ok(Some(tool_input));
    }
    if !names_in(&tool_input) {
        return Ok(None);
    }
    let values = session_values(session, port)?;
    fill_values(&mut tool_input, &values)?;
    Ok(Some(tool_input))
}

/// `$PIIF_SECRET_12` or `${PIIF_SECRET_12}`; the number is read whole, so `_1` never matches inside `_12`. Group 1 holds the backslashes right before the `$`: an odd count escapes the `$`, so the escaping backslash belongs to the name.
fn name_pattern() -> regex::Regex {
    regex::Regex::new(r"(\\*)\$(?:\{PIIF_SECRET_(\d+)\}|PIIF_SECRET_(\d+))").expect("valid pattern")
}

/// Whether any string in `value` holds a name.
fn names_in(value: &serde_json::Value) -> bool {
    let pattern = name_pattern();
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::String(s) if pattern.is_match(s) => return true,
            serde_json::Value::Array(items) => stack.extend(items),
            serde_json::Value::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    false
}

/// The first bare name in `text` that a letter, digit or `_` follows directly. A shell reads such a name as a longer, different variable, so the hook refuses it instead of guessing.
fn glued_name(pattern: &regex::Regex, text: &str) -> Option<String> {
    pattern.captures_iter(text).find_map(|caps| {
        let number = caps.get(3)?;
        let end = caps.get(0)?.end();
        text[end..]
            .starts_with(|c: char| c.is_alphanumeric() || c == '_')
            .then(|| format!("PIIF_SECRET_{}", number.as_str()))
    })
}

/// Replace every name in every string of `value` with its value. A name this session does not have is an error. So is a bare name that runs into a letter or `_` (`glued_name`).
fn fill_values(
    value: &mut serde_json::Value,
    values: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let pattern = name_pattern();
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::String(s) => {
                if let Some(name) = glued_name(&pattern, s) {
                    bail!("${name} runs into the text after it, so a shell would read a longer variable name; write ${{{name}}} instead");
                }
                let mut missing = None;
                let filled = pattern.replace_all(s, |caps: &regex::Captures| {
                    let number = caps.get(2).or(caps.get(3)).map_or("", |m| m.as_str());
                    let name = format!("PIIF_SECRET_{number}");
                    match values.get(&name).and_then(|v| v.as_str()) {
                        Some(real) => {
                            let slashes = &caps[1];
                            format!("{}{real}", &slashes[..slashes.len() / 2 * 2])
                        }
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
            }
            serde_json::Value::Array(items) => stack.extend(items.iter_mut()),
            serde_json::Value::Object(map) => stack.extend(map.values_mut()),
            _ => {}
        }
    }
    Ok(())
}

/// This session's `{name: value}` map from the gateway's `/control/env`.
fn session_values(session: &str, port: u16) -> Result<serde_json::Map<String, serde_json::Value>> {
    let socket = control_socket(port)?;
    let response = control_get(
        &socket,
        "/control/env",
        &format!("x-piifence-session: {session}\r\n"),
        Duration::from_secs(2),
    )
    .with_context(|| {
        format!(
            "the gateway's control socket {} did not answer",
            socket.display()
        )
    })?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("the gateway sent a malformed response")?;
    if !head.starts_with("HTTP/1.1 200") {
        bail!(
            "the gateway refused: {}",
            head.lines().next().unwrap_or_default()
        );
    }
    let json: serde_json::Value =
        serde_json::from_str(body).context("the gateway sent invalid JSON")?;
    json["values"]
        .as_object()
        .cloned()
        .context("the gateway's reply has no `values`")
}

/// `export NAME='value'` for each `PIIF_SECRET_<N>` name; anything else is skipped, as is a value with a NUL byte, which a shell variable cannot hold.
fn export_lines(values: &serde_json::Map<String, serde_json::Value>) -> String {
    values
        .iter()
        .filter(|(name, _)| {
            name.strip_prefix("PIIF_SECRET_")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter_map(|(name, value)| {
            let value = value.as_str().filter(|value| !value.contains('\0'))?;
            Some(format!("export {name}={}\n", shell_quote(value)))
        })
        .collect()
}

/// `value` in single quotes for a POSIX shell, with each `'` written as `'\''`.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare name, built at run time so this file never holds one literally.
    fn bare(n: usize) -> String {
        format!("$PIIF_SECRET_{n}")
    }

    /// A braced name, built the same way.
    fn braced(n: usize) -> String {
        format!("${{PIIF_SECRET_{n}}}")
    }

    #[test]
    fn fill_values_replaces_names_in_every_string() {
        let values = serde_json::json!({"PIIF_SECRET_1": "one", "PIIF_SECRET_12": "twelve"});
        let values = values.as_object().unwrap();
        let mut input = serde_json::json!({
            "file_path": "/tmp/a.py",
            "content": "a = \"$PIIF_SECRET_1\"\nb = \"$PIIF_SECRET_12\"\nc = \"${PIIF_SECRET_1}x\"",
            "edits": [{"old_string": "k=$PIIF_SECRET_12", "replace_all": false}],
            "n": 3,
        });
        assert!(names_in(&input));
        fill_values(&mut input, values).unwrap();
        assert_eq!(
            input,
            serde_json::json!({
                "file_path": "/tmp/a.py",
                "content": "a = \"one\"\nb = \"twelve\"\nc = \"onex\"",
                "edits": [{"old_string": "k=twelve", "replace_all": false}],
                "n": 3,
            })
        );
        assert!(!names_in(&input));
    }

    #[test]
    fn fill_values_rejects_an_unknown_name() {
        let values = serde_json::json!({"PIIF_SECRET_1": "one"});
        let mut input = serde_json::json!({"content": "$PIIF_SECRET_1 $PIIF_SECRET_2"});
        let err = fill_values(&mut input, values.as_object().unwrap()).unwrap_err();
        assert!(err.to_string().contains("PIIF_SECRET_2"));
    }

    #[test]
    fn fill_values_rejects_a_bare_name_that_runs_into_a_letter_or_underscore() {
        let values = serde_json::json!({"PIIF_SECRET_1": "one"});
        let values = values.as_object().unwrap();
        for text in [format!("{}x", bare(1)), format!("{}_old", bare(1))] {
            let mut input = serde_json::json!({ "content": text });
            let err = fill_values(&mut input, values).unwrap_err();
            assert!(err.to_string().contains(&braced(1)), "{err}");
        }
        let mut input = serde_json::json!({"content": format!("{}-x {}x", bare(1), braced(1))});
        fill_values(&mut input, values).unwrap();
        assert_eq!(input["content"], "one-x onex");
    }

    #[test]
    fn fill_values_takes_an_escaping_backslash_with_the_name() {
        let values = serde_json::json!({"PIIF_SECRET_1": "one"});
        let values = values.as_object().unwrap();
        for (text, want) in [
            (format!("\\{}: x", bare(1)), "one: x"),
            (format!("\\{}: x", braced(1)), "one: x"),
            (format!("\\\\{}", bare(1)), "\\\\one"),
            (format!("\\\\\\{}", bare(1)), "\\\\one"),
        ] {
            let mut input = serde_json::json!({ "content": text });
            fill_values(&mut input, values).unwrap();
            assert_eq!(input["content"], want, "{text}");
        }
    }

    #[test]
    fn env_file_keeps_only_the_current_piifence_line() {
        let old = format!("eval \"$('/gone/piifence' env {} 7788)\"\n", "a".repeat(32));
        let line = format!("eval \"$('/opt/piifence' env {} 7788)\"\n", "b".repeat(32));
        let existing = format!("export OTHER=1\n{old}{old}");
        assert_eq!(
            env_file_with(&existing, &line),
            format!("export OTHER=1\n{line}")
        );
        assert_eq!(
            env_file_with(&format!("export OTHER=1\n{line}"), &line),
            format!("export OTHER=1\n{line}")
        );
        assert_eq!(env_file_with("", &line), line);
    }

    #[test]
    fn names_in_ignores_other_variables() {
        assert!(!names_in(
            &serde_json::json!({"command": "echo $HOME $PIIF_SECRET_X"})
        ));
    }

    #[test]
    fn export_lines_quote_values_and_skip_other_names() {
        let values = serde_json::json!({
            "PIIF_SECRET_1": "it's $HOME `x`",
            "PIIF_SECRET_12": "a@b.io",
            "PIIF_EMAIL_3": "x",
            "PATH": "/tmp/evil",
            "PIIF_SECRET_2": "nul\u{0}byte",
            "PIIF_SECRET_X": "nope",
        });
        let out = export_lines(values.as_object().unwrap());
        assert_eq!(
            out,
            "export PIIF_SECRET_1='it'\\''s $HOME `x`'\nexport PIIF_SECRET_12='a@b.io'\n"
        );
    }

    #[test]
    fn session_args_are_checked() {
        let ok = vec![
            "0123456789abcdef0123456789abcdef".to_string(),
            "7788".to_string(),
        ];
        assert_eq!(
            session_args(&ok).unwrap(),
            ("0123456789abcdef0123456789abcdef", 7788)
        );
        assert!(session_args(&["x; rm -rf /".to_string(), "7788".to_string()]).is_err());
        assert!(session_args(&ok[..1]).is_err());
    }

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
        assert!(!lease(
            &socket_answering("HTTP/1.1 503 Service Unavailable"),
            &session
        )
        .unwrap());
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
}
