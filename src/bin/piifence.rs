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
        Some(Some(running)) if running == upstream => {
            eprintln!("piifence: using existing gateway on {gateway_url} (upstream {upstream})");
        }
        Some(running) => {
            eprintln!(
                "piifence: a gateway on {gateway_url} forwards to {}, but this launch wants {upstream}. \
                 Stop that gateway or set PIIF_PORT to a free port.",
                running.as_deref().unwrap_or("an unknown upstream (older gateway build)")
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

    let settings_path = match write_settings_override(&gateway_url) {
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
    for (name, purpose) in [
        ("piifence-notice", "notice"),
        ("piifence-approval", "approval"),
    ] {
        if plugin_installed(name) {
            continue;
        }
        if let Some(dir) = plugin_dir(name) {
            eprintln!(
                "piifence: loading {purpose} plugin for this session from {}",
                dir.display()
            );
            cmd.arg("--plugin-dir").arg(dir);
        } else if name == "piifence-notice" {
            eprintln!(
                "piifence: notice plugin not found; redaction still works, but no in-UI notice"
            );
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

/// Raw HTTP response from `/health` on the loopback port, or None if nothing answers.
fn health_response(port: u16) -> Option<String> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().expect("valid loopback addr"),
        Duration::from_millis(300),
    )
    .ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    stream
        .write_all(
            format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    // The gateway closes the connection after the response (Connection: close),
    // so reading to the end gets the whole reply.
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// A healthy gateway on `port`: None when nothing healthy answers. Otherwise the
/// upstream it reports (None inside for a gateway too old to report one).
fn running_gateway_upstream(port: u16) -> Option<Option<String>> {
    let response = health_response(port)?;
    if !response.starts_with("HTTP/1.1 200") {
        return None;
    }
    Some(response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("x-piifence-upstream")
            .then(|| value.trim().to_string())
    }))
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
fn write_settings_override(gateway_url: &str) -> std::io::Result<PathBuf> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = env::temp_dir().join(format!(
        "piifence-claude-settings-{}-{nonce}.json",
        std::process::id()
    ));
    let content = format!(
        "{{\"env\":{{\"ANTHROPIC_BASE_URL\":\"{}\"}}}}\n",
        gateway_url
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

/// Locate a plugin shipped with this checkout: PIIF_PLUGIN_DIR applies to the
/// notice plugin, PIIF_APPROVAL_PLUGIN_DIR to the approval mod; otherwise walk
/// up from the real binary looking for plugin/<name>.
fn plugin_dir(name: &str) -> Option<PathBuf> {
    let override_var = match name {
        "piifence-approval" => "PIIF_APPROVAL_PLUGIN_DIR",
        _ => "PIIF_PLUGIN_DIR",
    };
    if let Ok(dir) = env::var(override_var) {
        let path = PathBuf::from(dir);
        return path.exists().then_some(path);
    }
    let exe = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok())?;
    let mut dir = exe.parent()?.to_path_buf();
    loop {
        let candidate = dir.join("plugin").join(name);
        if candidate.join(".claude-plugin/plugin.json").exists() {
            return Some(candidate);
        }
        dir = dir.parent()?.to_path_buf();
    }
}
