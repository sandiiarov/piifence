//! piifence CLI — launch Claude Code through the secret-redaction gateway.
//!
//! Usage:
//!   piifence claude [claude arguments...]
//!
//! It starts the gateway if it is not already healthy (upstream derived from the user's current Claude Code settings), points this Claude Code session at it with a temporary `--settings` override, runs Claude Code, then tears the gateway down if this process started it. The user's settings file is never modified.
//!
//! The override also adds a `SessionStart` hook, `piifence session-start`. It tells the agent what `$PIIF_SECRET_<N>` names are, and adds a line to Claude Code's `CLAUDE_ENV_FILE`, which Claude Code sources before every Bash command. That line runs `piifence env`, which exports this session's values from the gateway, so a command that names `$PIIF_SECRET_1` gets the real value.
//!
//! Files: `$PIIF_DATA_DIR` (default `~/.local/share/piifence`, which `scripts/install.sh` sets) holds `model/` (the secret model) and `plugin/piifence-notice` (the notice plugin). The gateway binary sits next to this one.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const DEFAULT_PORT: u16 = 7788;
const GATEWAY_START_TIMEOUT: Duration = Duration::from_secs(45);

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("claude") => run_claude(&args[1..]),
        // Run by Claude Code, not by people: the hook and the line it writes.
        Some("session-start") => session_start(&args[1..]),
        Some("env") => print_env(&args[1..]),
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

/// This binary's real path, through any symlink.
fn real_exe() -> Result<PathBuf> {
    let exe = env::current_exe().context("cannot find the piifence binary's path")?;
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

/// Run Claude Code against the gateway with the session's settings override and the notice plugin. Returns Claude Code's exit code.
fn run_session(gateway_url: &str, port: u16, plugin: &Path, args: &[String]) -> Result<i32> {
    let session_id = new_session_id().context("cannot create a session id")?;
    let settings_path = write_settings_override(gateway_url, port, &session_id)
        .context("cannot write the session settings")?;
    let claude = env::var("CLAUDE_BIN").unwrap_or_else(|_| "claude".to_string());
    let status = Command::new(&claude)
        .arg("--settings")
        .arg(&settings_path)
        .arg("--plugin-dir")
        .arg(plugin)
        .args(args)
        .env("PIIF_GATEWAY_URL", gateway_url)
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

/// The `SessionStart` hook that sets the session up: `piifence session-start <session> <port>`, by this binary's real path.
fn session_start_hook(port: u16, session_id: &str) -> Result<serde_json::Value> {
    let exe = real_exe()?;
    Ok(serde_json::json!({
        "SessionStart": [{"hooks": [{
            "type": "command",
            "command": format!("{} session-start {session_id} {port}", shell_quote(&exe.to_string_lossy())),
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
            "hooks": session_start_hook(port, session_id)?,
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

- Use the name in Bash commands, quoted, where you would use the value: `curl -H \"Authorization: Bearer $PIIF_SECRET_1\" …`. piifence sets the variables before each command runs, so the name expands to the real value.
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

/// `piifence session-start <session> <port>`, the `SessionStart` hook. Adds the line that runs `piifence env` to `CLAUDE_ENV_FILE` (once per file), and answers with VARIABLES_NOTE as context for the agent. A failure exits non-zero, so Claude Code shows it.
fn session_start(args: &[String]) -> Result<i32> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("read the hook input")?;
    let (session, port) = session_args(args)?;
    let line = format!(
        "eval \"$({} env {session} {port})\"\n",
        shell_quote(&real_exe()?.to_string_lossy())
    );
    let path = env::var("CLAUDE_ENV_FILE")
        .context("CLAUDE_ENV_FILE is not set, so Bash commands cannot get $PIIF_* values")?;
    let present = Path::new(&path).exists()
        && fs::read_to_string(&path)
            .with_context(|| format!("cannot read {path}"))?
            .contains(&line);
    if !present {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .with_context(|| format!("cannot write {path}"))?;
    }
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

/// `piifence env <session> <port>`: this session's values from the gateway as `export NAME='value'` lines, for the `eval` Claude Code runs before every Bash command. A gateway that does not answer is an error on stderr; the command then runs without the values.
fn print_env(args: &[String]) -> Result<i32> {
    let (session, port) = session_args(args)?;
    let response = http_get(
        port,
        "/control/env",
        &format!("x-piifence-session: {session}\r\n"),
        Duration::from_secs(2),
    )
    .with_context(|| format!("the gateway on port {port} did not answer"))?;
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
    let values = json["values"]
        .as_object()
        .context("the gateway's reply has no `values`")?;
    print!("{}", export_lines(values));
    Ok(0)
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
}
