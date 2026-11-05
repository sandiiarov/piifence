//! piifence CLI — launch Claude Code through the input-only redaction gateway.
//!
//! Usage:
//!   piifence claude [claude arguments...]
//!
//! It starts the gateway if it is not already healthy (upstream derived from the
//! user's current Claude Code settings), points this Claude Code session at it
//! with a temporary `--settings` override, runs Claude Code, then tears the
//! gateway down if this process started it. The user's settings file is never
//! modified.
//!
//! The override also adds a `SessionStart` hook, `piifence session-start`. It
//! tells the agent what `$PIIF_…` names are, and adds a line to Claude Code's
//! `CLAUDE_ENV_FILE`, which Claude Code sources before every Bash command. That
//! line runs `piifence env`, which exports this session's values from the
//! gateway, so a command that names `$PIIF_SECRET_1` gets the real value.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 7788;
const GATEWAY_START_TIMEOUT: Duration = Duration::from_secs(45);

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("claude") => run_claude(&args[1..]),
        // Run by Claude Code, not by people: the hook and the line it writes.
        Some("session-start") => session_start(&args[1..]),
        Some("env") => print_env(&args[1..]),
        Some("-h") | Some("--help") | Some("help") | None => {
            usage();
            std::process::exit(0);
        }
        Some(other) => {
            eprintln!("piifence: unknown command `{other}`\n");
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    println!(
        "piifence — run Claude Code with local input redaction\n\n\
         Usage:\n  piifence claude [claude arguments...]\n\n\
         Starts the redaction gateway if needed, points this Claude Code session at\n\
         it, and streams responses back untouched. The gateway forwards redacted requests\n\
         to PIIF_UPSTREAM, else the ANTHROPIC_BASE_URL set in your shell or Claude Code\n\
         settings. No default provider is assumed; one of these must be set."
    );
}

fn run_claude(args: &[String]) -> ! {
    if args
        .iter()
        .any(|a| a == "--settings" || a.starts_with("--settings="))
    {
        eprintln!(
            "piifence: do not pass --settings/--settings= to `piifence claude`; \
             piifence supplies the gateway override itself."
        );
        std::process::exit(2);
    }

    let port: u16 = env::var("PIIF_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let gateway_url = format!("http://127.0.0.1:{port}");

    let Some(upstream) = resolve_upstream(&gateway_url) else {
        eprintln!(
            "piifence: no upstream configured. Set PIIF_UPSTREAM to your provider's base URL, \
             or ANTHROPIC_BASE_URL in your shell or Claude settings."
        );
        std::process::exit(1);
    };
    let mut gateway_child: Option<Child> = None;
    match running_gateway_upstream(port) {
        // Reuse only a gateway that forwards to the same place this launch would.
        // Reusing another one would send this session's credentials elsewhere.
        Some(running) if running == upstream => {
            eprintln!("piifence: using existing gateway on {gateway_url} (upstream {upstream})");
        }
        Some(running) => {
            eprintln!(
                "piifence: a gateway on {gateway_url} forwards to {running:?}, but this launch wants {upstream}. \
                 Stop that gateway or set PIIF_PORT to a free port."
            );
            std::process::exit(1);
        }
        None => {
            let gateway_bin = gateway_binary();
            let model_dir = resolve_model_dir();
            let gateway_log = gateway_log_path();
            let config_path = resolve_config_path();
            let repo_root = repo_root();
            eprintln!("piifence: starting gateway on {gateway_url} (upstream {upstream})");
            let log = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&gateway_log)
                .ok();
            let mut gateway_cmd = Command::new(&gateway_bin);
            gateway_cmd
                .env("PIIF_UPSTREAM", &upstream)
                .env("PIIF_MODEL_DIR", &model_dir)
                .env("PIIF_PORT", port.to_string())
                .envs(config_path.iter().map(|path| ("PIIF_CONFIG", path)));
            // The gateway resolves gitleaks.toml relative to its cwd; the launcher
            // usually runs from $HOME, so pin the config absolutely.
            if let Some(root) = &repo_root {
                let gitleaks = root.join("gitleaks.toml");
                if gitleaks.exists() {
                    gateway_cmd.env("PIIF_GITLEAKS_CONFIG", &gitleaks);
                }
                gateway_cmd.current_dir(root);
            }
            let child = gateway_cmd
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(match log {
                    Some(file) => Stdio::from(file),
                    None => Stdio::inherit(),
                })
                .spawn()
                .unwrap_or_else(|e| {
                    eprintln!(
                        "piifence: could not start gateway `{}`: {e}",
                        gateway_bin.display()
                    );
                    std::process::exit(1);
                });
            gateway_child = Some(child);

            if !wait_healthy(port, gateway_child.as_mut().unwrap()) {
                eprintln!("piifence: gateway did not become healthy; refusing to launch Claude Code (fail closed)");
                eprintln!(
                    "piifence: last gateway log lines ({}):",
                    gateway_log.display()
                );
                for line in tail_lines(&gateway_log, 15) {
                    eprintln!("  {line}");
                }
                if let Some(mut child) = gateway_child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                std::process::exit(1);
            }
            eprintln!("piifence: gateway ready (log: {})", gateway_log.display());
        }
    }

    let session_id = match new_session_id() {
        Ok(id) => id,
        Err(err) => {
            eprintln!("piifence: cannot create a session id: {err}");
            cleanup_gateway(gateway_child);
            std::process::exit(1);
        }
    };
    let settings_path = match write_settings_override(&gateway_url, port, &session_id) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("piifence: cannot write session settings: {err}");
            cleanup_gateway(gateway_child);
            std::process::exit(1);
        }
    };

    let claude = env::var("CLAUDE_BIN").unwrap_or_else(|_| "claude".to_string());
    let mut cmd = Command::new(&claude);
    cmd.arg("--settings").arg(&settings_path);
    // Notices: if the plugin is not installed globally, load it for this session
    // only via --plugin-dir (never copies into the user's config automatically).
    if !plugin_installed("piifence-notice") {
        match notice_plugin_dir() {
            Some(dir) => {
                eprintln!(
                    "piifence: loading notice plugin for this session from {}",
                    dir.display()
                );
                cmd.arg("--plugin-dir").arg(dir);
            }
            None => eprintln!(
                "piifence: notice plugin not found; redaction still works, but no in-UI notice"
            ),
        }
    }
    cmd.args(args).env("PIIF_GATEWAY_URL", &gateway_url);
    let status = cmd.status();

    let _ = fs::remove_file(&settings_path);
    cleanup_gateway(gateway_child);

    match status {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("piifence: failed to run `{claude}`: {err}");
            std::process::exit(1);
        }
    }
}

fn cleanup_gateway(child: Option<Child>) {
    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Upstream = the provider Claude Code is already configured for, so the gateway is
/// a drop-in hop in front of the user's real endpoint. Order: PIIF_UPSTREAM, the
/// shell's ANTHROPIC_BASE_URL, then the Claude settings file. None when nothing is
/// set: no provider is assumed, so the launcher refuses to run. A value that already
/// points at a gateway (ours, from an earlier run) is ignored.
fn resolve_upstream(gateway_url: &str) -> Option<String> {
    if let Ok(upstream) = env::var("PIIF_UPSTREAM") {
        return (!upstream.is_empty()).then_some(upstream);
    }
    let shell_base = env::var("ANTHROPIC_BASE_URL").ok();
    let candidates = [shell_base, user_settings_base_url()];
    candidates
        .into_iter()
        .flatten()
        .find(|base| !base.is_empty() && !base.starts_with(gateway_url))
}

fn claude_settings_path() -> PathBuf {
    if let Ok(dir) = env::var("CLAUDE_CONFIG_DIR") {
        return Path::new(&dir).join("settings.json");
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".claude/settings.json")
}

fn user_settings_base_url() -> Option<String> {
    let data = fs::read_to_string(claude_settings_path()).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    json.get("env")?
        .get("ANTHROPIC_BASE_URL")?
        .as_str()
        .map(|s| s.to_string())
}

/// Find the weights checkout: PIIF_MODEL_DIR, else walk up from the real binary
/// looking for `<repo>/data/config.json`, else `data` relative to cwd.
fn resolve_model_dir() -> PathBuf {
    if let Ok(dir) = env::var("PIIF_MODEL_DIR") {
        return PathBuf::from(dir);
    }
    let exe = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok());
    let mut dir = exe.and_then(|path| path.parent().map(|p| p.to_path_buf()));
    while let Some(current) = dir {
        let candidate = current.join("data");
        if candidate.join("config.json").exists() {
            return candidate;
        }
        dir = current.parent().map(|p| p.to_path_buf());
        if dir
            .as_ref()
            .map(|p| p.as_os_str().is_empty())
            .unwrap_or(true)
        {
            break;
        }
    }
    PathBuf::from("data")
}

fn gateway_binary() -> PathBuf {
    if let Ok(bin) = env::var("PIIF_GATEWAY_BIN") {
        return PathBuf::from(bin);
    }
    // current_exe may be the symlink path (e.g. /opt/homebrew/bin/piifence), so
    // also try the canonical target directory next to the real binary.
    if let Ok(exe) = env::current_exe() {
        let candidates = [
            exe.parent().map(|dir| dir.join("piifence-gateway")),
            fs::canonicalize(&exe)
                .ok()
                .and_then(|real| real.parent().map(|dir| dir.join("piifence-gateway"))),
        ];
        for candidate in candidates.into_iter().flatten() {
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("piifence-gateway")
}

/// Raw HTTP response to `GET path` on the loopback port, with `headers` (`Name: value` lines), or None if nothing answers in time.
fn http_get(port: u16, path: &str, headers: &str, timeout: Duration) -> Option<String> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().expect("valid loopback addr"),
        Duration::from_millis(300),
    )
    .ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{headers}Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .ok()?;
    // The gateway closes the connection after the response (Connection: close),
    // so reading to the end gets the whole reply.
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn health_response(port: u16) -> Option<String> {
    http_get(port, "/health", "", Duration::from_millis(500))
}

/// A healthy gateway on `port`: None when nothing healthy answers. Otherwise the
/// upstream it reports (empty when it reports none).
fn running_gateway_upstream(port: u16) -> Option<String> {
    let response = health_response(port)?;
    if !response.starts_with("HTTP/1.1 200") {
        return None;
    }
    Some(
        response
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("x-piifence-upstream")
                    .then(|| value.trim().to_string())
            })
            .unwrap_or_default(),
    )
}

fn wait_healthy(port: u16, child: &mut Child) -> bool {
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while Instant::now() < deadline {
        if running_gateway_upstream(port).is_some() {
            return true;
        }
        if let Ok(Some(status)) = child.try_wait() {
            eprintln!("piifence: gateway exited during startup ({status})");
            return false;
        }
        thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Configuration file for the gateway: PIIF_CONFIG, else
/// ~/.config/piifence/config.toml, else piifence.toml next to the checkout.
fn resolve_config_path() -> Option<PathBuf> {
    if let Ok(path) = env::var("PIIF_CONFIG") {
        return Some(PathBuf::from(path));
    }
    if let Ok(home) = env::var("HOME") {
        let candidate = Path::new(&home).join(".config/piifence/config.toml");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let exe = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok())?;
    let mut dir = exe.parent()?.to_path_buf();
    loop {
        let candidate = dir.join("piifence.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// Repository root: nearest ancestor of the real binary containing gitleaks.toml
/// (or the plugin directory).
fn repo_root() -> Option<PathBuf> {
    let exe = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok())?;
    let mut dir = exe.parent()?.to_path_buf();
    loop {
        if dir.join("gitleaks.toml").exists() || dir.join("plugin/piifence-notice").exists() {
            return Some(dir);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

fn gateway_log_path() -> PathBuf {
    if let Ok(path) = env::var("PIIF_GATEWAY_LOG") {
        return PathBuf::from(path);
    }
    env::temp_dir().join("piifence-gateway.log")
}

fn tail_lines(path: &Path, count: usize) -> Vec<String> {
    let data = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = data.lines().collect();
    lines[lines.len().saturating_sub(count)..]
        .iter()
        .map(|line| line.to_string())
        .collect()
}

/// Write the per-session settings override. The name is unique and the file is
/// created with `create_new`, so a file or symlink planted at a guessable /tmp path
/// cannot make this write land somewhere else. Mode 0600 is set at creation.
/// A random 32-hex-digit id for this Claude Code session. The gateway keys the session's settings and `$PIIF_…` values on it, and hands values only to a caller that knows it, so it comes from the OS random source.
fn new_session_id() -> std::io::Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// `ANTHROPIC_CUSTOM_HEADERS` for the session: the user's own (shell, else Claude Code settings) plus the session id header. The override replaces the user's value, so theirs is carried over.
fn custom_headers(session_id: &str) -> String {
    let existing = env::var("ANTHROPIC_CUSTOM_HEADERS")
        .ok()
        .or_else(user_settings_custom_headers)
        .filter(|headers| !headers.trim().is_empty());
    let ours = format!("x-piifence-session: {session_id}");
    match existing {
        Some(existing) => format!("{}\n{ours}", existing.trim_end()),
        None => ours,
    }
}

fn user_settings() -> Option<serde_json::Value> {
    let data = fs::read_to_string(claude_settings_path()).ok()?;
    serde_json::from_str(&data).ok()
}

fn user_settings_custom_headers() -> Option<String> {
    user_settings()?
        .get("env")?
        .get("ANTHROPIC_CUSTOM_HEADERS")?
        .as_str()
        .map(str::to_string)
}

/// The `SessionStart` hook that sets the session up: `piifence session-start <session> <port>`, by this binary's real path.
fn session_start_hook(port: u16, session_id: &str) -> serde_json::Value {
    let exe = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok())
        .unwrap_or_else(|| PathBuf::from("piifence"));
    serde_json::json!({
        "SessionStart": [{"hooks": [{
            "type": "command",
            "command": format!("{} session-start {session_id} {port}", shell_quote(&exe.to_string_lossy())),
        }]}]
    })
}

fn write_settings_override(
    gateway_url: &str,
    port: u16,
    session_id: &str,
) -> std::io::Result<PathBuf> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = env::temp_dir().join(format!(
        "piifence-claude-settings-{}-{nonce}.json",
        std::process::id()
    ));
    let content = format!(
        "{}\n",
        serde_json::json!({
            "env": {
                "ANTHROPIC_BASE_URL": gateway_url,
                "ANTHROPIC_CUSTOM_HEADERS": custom_headers(session_id),
            },
            "hooks": session_start_hook(port, session_id),
        })
    );
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(content.as_bytes())?;
    Ok(path)
}

fn plugin_installed(name: &str) -> bool {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".claude/skills").join(name).exists()
}

/// Locate the notice plugin shipped with this checkout: PIIF_PLUGIN_DIR, else walk
/// up from the real binary looking for plugin/piifence-notice.
fn notice_plugin_dir() -> Option<PathBuf> {
    if let Ok(dir) = env::var("PIIF_PLUGIN_DIR") {
        let path = PathBuf::from(dir);
        return path.exists().then_some(path);
    }
    let exe = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok())?;
    let mut dir = exe.parent()?.to_path_buf();
    loop {
        let candidate = dir.join("plugin").join("piifence-notice");
        if candidate.join(".claude-plugin/plugin.json").exists() {
            return Some(candidate);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// What `$PIIF_…` names are, given to the agent when the session starts (and again after `/clear` or a compaction, which start it again). Without it the agent meets a name in tool output with no idea what it is: it warns that a secret leaked, or decides the variable holds its own name, and does not know it can use it.
const VARIABLES_NOTE: &str = "# piifence environment variables

This session runs through piifence, which keeps secrets and personal data from reaching you. Before anything is sent to you (the user's prompts, command output, file contents), piifence replaces each sensitive value with an environment variable name such as `$PIIF_SECRET_1` or `$PIIF_EMAIL_2`. The real value stays on the user's machine.

- Use the name in Bash commands, quoted, where you would use the value: `curl -H \"Authorization: Bearer $PIIF_SECRET_1\" …`. piifence sets the variables before each command runs, so the name expands to the real value.
- Files, environment variables and command output on the user's machine hold the real value; only what is sent to you shows the name. A value you see as a `$PIIF_…` name was not exposed to you or the provider: do not warn that it leaked or suggest rotating it on that account.
- When a command prints a value, you see its name again: `echo $PIIF_SECRET_1` shows you `$PIIF_SECRET_1` although the variable holds the real value. Do not conclude from that that the variable is wrong or holds its own name, and do not try to print, decode or otherwise reveal the values.
- A placeholder such as `<secret_3>` stands for a value piifence could not give a name; it cannot be used in commands.";

/// `<session> <port>` from a hook's or `env`'s arguments, if both are well-formed.
fn session_args(args: &[String]) -> Option<(&str, u16)> {
    let [session, port] = args else { return None };
    let well_formed = session.len() == 32 && session.bytes().all(|b| b.is_ascii_hexdigit());
    well_formed.then_some((session.as_str(), port.parse().ok()?))
}

/// `piifence session-start <session> <port>`, the `SessionStart` hook. Adds the line that runs `piifence env` to `CLAUDE_ENV_FILE` (once per file), and answers with VARIABLES_NOTE as context for the agent. It never fails the hook: without the line, commands just run without the values.
fn session_start(args: &[String]) -> ! {
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);
    let Some((session, port)) = session_args(args) else {
        eprintln!("piifence session-start: expected <session> <port>");
        std::process::exit(0);
    };
    let exe = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok())
        .unwrap_or_else(|| PathBuf::from("piifence"));
    let line = format!(
        "eval \"$({} env {session} {port})\"\n",
        shell_quote(&exe.to_string_lossy())
    );
    match env::var("CLAUDE_ENV_FILE") {
        Ok(path) if !path.is_empty() => {
            let present = fs::read_to_string(&path).is_ok_and(|text| text.contains(&line));
            let written = present
                || fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .and_then(|mut file| file.write_all(line.as_bytes()))
                    .is_ok();
            if !written {
                eprintln!(
                    "piifence: cannot write {path}; Bash commands will not get $PIIF_* values"
                );
            }
        }
        _ => eprintln!(
            "piifence: CLAUDE_ENV_FILE is not set; Bash commands will not get $PIIF_* values"
        ),
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
    std::process::exit(0);
}

/// `piifence env <session> <port>`: this session's values from the gateway as `export NAME='value'` lines, for the `eval` Claude Code runs before every Bash command. Prints nothing when the gateway does not answer, so the command still runs.
fn print_env(args: &[String]) -> ! {
    let Some((session, port)) = session_args(args) else {
        std::process::exit(0);
    };
    let response = http_get(
        port,
        "/control/env",
        &format!("x-piifence-session: {session}\r\n"),
        Duration::from_secs(2),
    );
    let values = response
        .filter(|response| response.starts_with("HTTP/1.1 200"))
        .and_then(|response| {
            let (_, body) = response.split_once("\r\n\r\n")?;
            serde_json::from_str::<serde_json::Value>(body).ok()
        });
    if let Some(values) = values.as_ref().and_then(|v| v.get("values")?.as_object()) {
        print!("{}", export_lines(values));
    }
    std::process::exit(0);
}

/// `export NAME='value'` for each `PIIF_<CATEGORY>_<N>` name; anything else is skipped, as is a value with a NUL byte, which a shell variable cannot hold.
fn export_lines(values: &serde_json::Map<String, serde_json::Value>) -> String {
    values
        .iter()
        .filter(|(name, _)| {
            name.strip_prefix("PIIF_")
                .and_then(|rest| rest.rsplit_once('_'))
                .is_some_and(|(category, number)| {
                    !category.is_empty()
                        && category.bytes().all(|b| b.is_ascii_uppercase())
                        && !number.is_empty()
                        && number.bytes().all(|b| b.is_ascii_digit())
                })
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
            "PIIF_EMAIL_12": "a@b.io",
            "PATH": "/tmp/evil",
            "PIIF_SECRET_2": "nul\u{0}byte",
            "PIIF_SECRET_X": "nope",
        });
        let out = export_lines(values.as_object().unwrap());
        assert_eq!(
            out,
            "export PIIF_EMAIL_12='a@b.io'\nexport PIIF_SECRET_1='it'\\''s $HOME `x`'\n"
        );
    }

    #[test]
    fn session_args_are_checked() {
        let ok = vec![
            "0123456789abcdef0123456789abcdef".to_string(),
            "7788".to_string(),
        ];
        assert_eq!(
            session_args(&ok),
            Some(("0123456789abcdef0123456789abcdef", 7788))
        );
        assert_eq!(
            session_args(&["x; rm -rf /".to_string(), "7788".to_string()]),
            None
        );
        assert_eq!(session_args(&ok[..1]), None);
    }
}
