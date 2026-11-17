//! piifence CLI — route Claude Code through the secret-redaction gateway, and the commands piifence's hooks run.
//!
//! Usage:
//!   piifence install [--upstream URL]
//!   piifence uninstall
//!   piifence status
//!   piifence reveal --conversation UUID [--json]
//!
//! `install` does three things, in this order, so Claude Code is never pointed at a gateway that is not running: it runs the gateway as a launchd agent that launchd keeps alive and starts at login (`start_agent`), installs piifence's Claude Code plugins at user scope from a local marketplace it writes into the state dir (`write_marketplace`), and sets `env.ANTHROPIC_BASE_URL` to the gateway in the user's Claude Code settings. Every Claude Code that reads those settings (the CLI, `claude -p`, the IDE extensions, the desktop app) then sends its model requests through the gateway, which tells sessions apart by the session id Claude Code sends with each request. `uninstall` undoes the three in the opposite order and puts back the base URL the settings had before.
//!
//! The `piifence-session` plugin adds two hooks; they ship in a plugin, not in the settings file, because a managed policy can drop the hooks of settings files while it still loads plugins. `SessionStart` runs `piifence session-start <port>`: it tells the agent what `$PIIF_SECRET_<N>` names are, binds Claude Code's session id on the gateway so a resumed conversation gets its old names back, and adds a line to Claude Code's `CLAUDE_ENV_FILE`, which Claude Code sources before every Bash command. That line runs `piifence env`, which exports this session's values from the gateway, so a command that names a variable gets the real value. `PreToolUse` runs `piifence restore <port>` on every tool call: it puts the real values into the tool's input, so a file the agent writes or an MCP argument holds the value, not the name; a backslash before a name's `$` counts as part of the name. In Bash and Monitor commands it fills in only the names the shell would not expand (single quotes, quoted heredocs, an escaped `$`), escaped for where they stand; PowerShell is skipped.
//!
//! Files: `$PIIF_DATA_DIR` (default `~/.local/share/piifence`, which `scripts/install.sh` sets) holds `model/` (the secret model) and `plugin/`, the sources of piifence's Claude Code plugins (`piifence-session`, the hooks; `piifence-notice`, the notice; and `piifence-reveal`, which draws values in place of names on screen). The gateway binary sits next to this one. The hooks and the notice plugin reach the gateway on its control socket, `$PIIF_STATE_DIR/run/<port>.sock` (state dir `~/.local/state/piifence` by default), in a directory only the user can open; the gateway hands out no session data on TCP.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

const DEFAULT_PORT: u16 = 7788;
const GATEWAY_START_TIMEOUT: Duration = Duration::from_secs(45);
/// The marketplace piifence's plugins are installed from.
const MARKETPLACE: &str = "piifence";

/// piifence's Claude Code plugins, in `plugin/` of the data dir.
const PLUGINS: &[&str] = &["piifence-session", "piifence-notice", "piifence-reveal"];

/// Where the gateway forwards when nothing else names a provider: where Claude Code itself sends requests by default.
const DEFAULT_UPSTREAM: &str = "https://api.anthropic.com";

/// Variables `install` passes on to the gateway agent when they are set, so a gateway installed for a test keeps its state, cache, config and logs where the test put them.
const PASSED_TO_GATEWAY: &[&str] = &[
    "PIIF_STATE_DIR",
    "PIIF_CACHE_DIR",
    "PIIF_CONFIG",
    "PIIF_AUDIT_LOG",
    "PIIF_AUDIT_BODY",
];

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("install") => install(&args[1..]),
        Some("uninstall") => uninstall(&args[1..]),
        Some("status") => status(&args[1..]),
        Some("reveal") => reveal(&args[1..]),
        // Run by Claude Code, not by people: the hooks and the line the session-start hook writes.
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
         Usage:\n  \
         piifence install [--upstream URL]\n      \
         Run the gateway as a launchd agent, send every Claude Code through it\n      \
         (env.ANTHROPIC_BASE_URL in ~/.claude/settings.json) and enable piifence's\n      \
         plugins. The upstream is --upstream, else PIIF_UPSTREAM, else the one an\n      \
         earlier install used, else the base URL your settings name, else\n      \
         {DEFAULT_UPSTREAM}.\n  \
         piifence uninstall\n      \
         Undo install: the setting first, then the plugins, then the agent.\n  \
         piifence status\n      \
         Print {{\"installed\",\"routed\",\"running\",\"upstream\",\"url\",\"port\"}}.\n  \
         piifence reveal --conversation UUID [--json]\n      \
         Print stdin with the conversation's names replaced by their values."
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

/// The folder that holds the sources of piifence's Claude Code plugins, `plugin/` in `data`, after checking each is there.
fn plugins(data: &Path) -> Result<PathBuf> {
    for name in PLUGINS {
        existing(
            data.join("plugin").join(name),
            &format!("the {name} plugin"),
        )?;
    }
    Ok(data.join("plugin"))
}

fn gateway_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// Whether `base`, a base URL, is the gateway at `url`.
fn is_gateway(base: &str, url: &str) -> bool {
    base.trim_end_matches('/') == url
}

/// The launchd label of the gateway agent on `port`.
fn agent_label(port: u16) -> String {
    if port == DEFAULT_PORT {
        "com.piifence.gateway".to_string()
    } else {
        format!("com.piifence.gateway.{port}")
    }
}

/// The agent's plist: in `$PIIF_LAUNCH_AGENTS_DIR`, default `~/Library/LaunchAgents`, where launchd loads it again at every login.
fn agent_plist(port: u16) -> Result<PathBuf> {
    let dir = match env::var("PIIF_LAUNCH_AGENTS_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => home()?.join("Library/LaunchAgents"),
    };
    Ok(dir.join(format!("{}.plist", agent_label(port))))
}

/// What `install` did, kept in the state dir so `uninstall` can undo it: the upstream, and the base URL the settings had before.
fn install_record(port: u16) -> Result<PathBuf> {
    Ok(piifence::control::state_dir()?.join(format!("install-{port}.json")))
}

fn claude_settings_path() -> Result<PathBuf> {
    if let Ok(dir) = env::var("CLAUDE_CONFIG_DIR") {
        return Ok(Path::new(&dir).join("settings.json"));
    }
    Ok(home()?.join(".claude/settings.json"))
}

/// The JSON object in `path`; an empty object when the file is missing or empty. Anything but an object is an error.
fn read_json(path: &Path) -> Result<Value> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(json!({})),
        Err(err) => return Err(err).with_context(|| format!("cannot read {}", path.display())),
    };
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    let value: Value = serde_json::from_str(&text)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    if !value.is_object() {
        bail!("{} does not hold a JSON object", path.display());
    }
    Ok(value)
}

/// Write `value` to `path` as JSON, through a temporary file renamed over it, so Claude Code never reads half a settings file. An existing file keeps its permissions.
fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let temp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    fs::write(&temp, format!("{}\n", serde_json::to_string_pretty(value)?))
        .with_context(|| format!("cannot write {}", temp.display()))?;
    if let Ok(meta) = fs::metadata(path) {
        fs::set_permissions(&temp, meta.permissions())
            .with_context(|| format!("cannot set the permissions of {}", temp.display()))?;
    }
    fs::rename(&temp, path).with_context(|| format!("cannot replace {}", path.display()))
}

/// `env.ANTHROPIC_BASE_URL` in Claude Code settings.
fn settings_base_url(settings: &Value) -> Option<String> {
    settings["env"]["ANTHROPIC_BASE_URL"]
        .as_str()
        .map(str::to_string)
}

/// `settings` with `env.ANTHROPIC_BASE_URL` set to `base`, or removed when `base` is None. An `env` left empty is removed.
fn with_base_url(mut settings: Value, base: Option<&str>) -> Value {
    let Some(object) = settings.as_object_mut() else {
        return settings;
    };
    let env = object.entry("env").or_insert_with(|| json!({}));
    if !env.is_object() {
        *env = json!({});
    }
    let vars = env.as_object_mut().expect("an object");
    match base {
        Some(base) => {
            vars.insert("ANTHROPIC_BASE_URL".to_string(), base.into());
        }
        None => {
            vars.shift_remove("ANTHROPIC_BASE_URL");
        }
    }
    if vars.is_empty() {
        object.shift_remove("env");
    }
    settings
}

/// The settings keys `claude plugin` adds for piifence's plugins and leaves behind as `{}` when it removes them.
const PLUGIN_SETTINGS: &[&str] = &["enabledPlugins", "extraKnownMarketplaces"];

/// `settings` without those of `keys` that hold an empty object.
fn without_empty(mut settings: Value, keys: &[&str]) -> Value {
    if let Some(object) = settings.as_object_mut() {
        for key in keys {
            if object
                .get(*key)
                .is_some_and(|v| v.as_object().is_some_and(|o| o.is_empty()))
            {
                object.shift_remove(*key);
            }
        }
    }
    settings
}

/// The upstream for `install`: `flag` (`--upstream`), else `from_env` (`PIIF_UPSTREAM`), else `recorded` (what an earlier install used), else `settings_base` (the base URL the settings name now) unless that is this gateway, else `DEFAULT_UPSTREAM`.
fn choose_upstream(
    flag: Option<&str>,
    from_env: Option<&str>,
    recorded: Option<&str>,
    settings_base: Option<&str>,
    url: &str,
) -> String {
    [
        flag,
        from_env,
        recorded,
        settings_base.filter(|base| !is_gateway(base, url)),
    ]
    .into_iter()
    .flatten()
    .find(|upstream| !upstream.is_empty())
    .unwrap_or(DEFAULT_UPSTREAM)
    .to_string()
}

/// The user's numeric id, for launchd's `gui/<uid>` domain.
fn uid() -> Result<String> {
    let out = Command::new("id")
        .arg("-u")
        .output()
        .context("cannot run id -u")?;
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) {
        bail!("cannot read the user id from id -u");
    }
    Ok(uid)
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The launchd plist that runs `gateway` with the environment `vars` as `label`, started at login and again whenever it exits, logging to `log`.
fn launchd_plist(label: &str, gateway: &Path, vars: &[(String, String)], log: &Path) -> String {
    let vars: String = vars
        .iter()
        .map(|(name, value)| {
            format!(
                "    <key>{}</key><string>{}</string>\n",
                xml_escape(name),
                xml_escape(value)
            )
        })
        .collect();
    let label = xml_escape(label);
    let gateway = xml_escape(&gateway.to_string_lossy());
    let log = xml_escape(&log.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key><array><string>{gateway}</string></array>
  <key>EnvironmentVariables</key>
  <dict>
{vars}  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#
    )
}

fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    Command::new("launchctl")
        .args(args)
        .output()
        .context("cannot run launchctl")
}

/// launchd's name for the gateway agent on `port`.
fn agent_target(port: u16) -> Result<String> {
    Ok(format!("gui/{}/{}", uid()?, agent_label(port)))
}

/// Whether launchd has the gateway agent on `port` loaded.
fn agent_loaded(port: u16) -> Result<bool> {
    Ok(launchctl(&["print", &agent_target(port)?])?
        .status
        .success())
}

/// Stop the gateway agent on `port` and unload it, when it is loaded, and wait until the port is free.
fn stop_agent(port: u16) -> Result<()> {
    if !agent_loaded(port)? {
        return Ok(());
    }
    let out = launchctl(&["bootout", &agent_target(port)?])?;
    if !out.status.success() && agent_loaded(port)? {
        bail!(
            "launchctl bootout {} failed: {}",
            agent_target(port)?,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    wait_until_closed(port)
}

/// The last `n` lines of the file at `path`, joined for an error message.
fn tail(path: &Path, n: usize) -> String {
    match fs::read_to_string(path) {
        Ok(text) => {
            let lines: Vec<&str> = text.lines().collect();
            lines[lines.len().saturating_sub(n)..].join("\n  ")
        }
        Err(err) => format!("cannot read it: {err}"),
    }
}

/// Run `gateway` as the launchd agent for `port`, replacing an agent piifence loaded before, and wait until it forwards to `upstream`. Fails, and unloads the agent again, when the gateway does not come up; fails before loading anything when another program holds the port.
fn start_agent(
    port: u16,
    gateway: &Path,
    vars: &[(String, String)],
    log: &Path,
    upstream: &str,
) -> Result<()> {
    stop_agent(port)?;
    if tcp_answers(port) {
        bail!(
            "something else already answers on 127.0.0.1:{port}: a gateway that an older `piifence claude` started, or another program. Stop it, or set PIIF_PORT to a free port, and run `piifence install` again."
        );
    }
    let plist = agent_plist(port)?;
    if let Some(dir) = plist.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    if let Some(dir) = log.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    fs::write(
        &plist,
        launchd_plist(&agent_label(port), gateway, vars, log),
    )
    .with_context(|| format!("cannot write {}", plist.display()))?;
    let domain = format!("gui/{}", uid()?);
    let out = launchctl(&["bootstrap", &domain, &plist.to_string_lossy()])?;
    if !out.status.success() {
        bail!(
            "launchctl bootstrap {domain} {} failed: {}",
            plist.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if let Err(err) = wait_for_gateway(port, upstream) {
        let _ = launchctl(&["bootout", &agent_target(port)?]);
        bail!(
            "{err:#}; the agent was unloaded again. Last lines of its log ({}):\n  {}",
            log.display(),
            tail(log, 15)
        );
    }
    Ok(())
}

/// Wait until a gateway that forwards to `upstream` answers on `port`. Loading the secret model takes a few seconds.
fn wait_for_gateway(port: u16, upstream: &str) -> Result<()> {
    let socket = control_socket(port)?;
    let deadline = Instant::now() + GATEWAY_START_TIMEOUT;
    while Instant::now() < deadline {
        match running_gateway_upstream(port, &socket) {
            Ok(Some(running)) if running == upstream => return Ok(()),
            Ok(Some(running)) => {
                bail!("the gateway on port {port} forwards to {running:?}, not {upstream}")
            }
            // Not up yet, or up on TCP and not yet on its control socket.
            _ => thread::sleep(Duration::from_millis(250)),
        }
    }
    bail!(
        "no gateway answered on port {port} within {} s",
        GATEWAY_START_TIMEOUT.as_secs()
    )
}

/// Copy the directory `from` into `to`, files and subdirectories.
fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to).with_context(|| format!("cannot create {}", to.display()))?;
    for entry in fs::read_dir(from).with_context(|| format!("cannot list {}", from.display()))? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)
                .with_context(|| format!("cannot copy {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// A plugin's `hooks.json` with its placeholders filled in: `@PIIFENCE@` becomes this binary's path and `@SOCKET@` the gateway's control socket, both quoted for a shell, and `@PORT@` the gateway's port.
fn fill_hooks(text: &str, exe: &Path, socket: &Path, port: u16) -> Result<String> {
    let mut hooks: Value = serde_json::from_str(text).context("hooks.json is not JSON")?;
    let exe = shell_quote(&exe.to_string_lossy());
    let socket = shell_quote(&socket.to_string_lossy());
    let mut stack = vec![&mut hooks];
    while let Some(value) = stack.pop() {
        match value {
            Value::String(s) => {
                *s = s
                    .replace("@PIIFENCE@", &exe)
                    .replace("@SOCKET@", &socket)
                    .replace("@PORT@", &port.to_string());
            }
            Value::Array(items) => stack.extend(items.iter_mut()),
            Value::Object(map) => stack.extend(map.values_mut()),
            _ => {}
        }
    }
    Ok(format!("{}\n", serde_json::to_string_pretty(&hooks)?))
}

/// A mod's source with `@PIIFENCE_PATH@` (inside a single-quoted string) replaced by this binary's path and `@PORT@` by the gateway's port.
fn fill_module(text: &str, exe: &Path, port: u16) -> String {
    let path = exe
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('\'', "\\'");
    text.replace("@PIIFENCE_PATH@", &path)
        .replace("@PORT@", &port.to_string())
}

/// Write the marketplace piifence's plugins are installed from, `marketplace/` in `state`: the plugins copied from `source` with their placeholders filled in (`fill_hooks`, `fill_module`), and a catalog that lists them. Returns its path.
fn write_marketplace(state: &Path, source: &Path, exe: &Path, port: u16) -> Result<PathBuf> {
    let dir = state.join("marketplace");
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("cannot remove {}", dir.display()))?;
    }
    let socket = control_socket(port)?;
    let mut listed = Vec::new();
    for name in PLUGINS {
        let target = dir.join("plugins").join(name);
        copy_dir(&source.join(name), &target)?;
        let hooks = target.join("hooks/hooks.json");
        if hooks.exists() {
            let filled = fill_hooks(&fs::read_to_string(&hooks)?, exe, &socket, port)?;
            fs::write(&hooks, filled)?;
        }
        let module = target.join("hooks/register.ts");
        if module.exists() {
            let filled = fill_module(&fs::read_to_string(&module)?, exe, port);
            fs::write(&module, filled)?;
        }
        let manifest = read_json(&target.join(".claude-plugin/plugin.json"))?;
        listed.push(json!({
            "name": name,
            "source": format!("./plugins/{name}"),
            "description": manifest["description"],
            "version": manifest["version"],
        }));
    }
    write_json(
        &dir.join(".claude-plugin/marketplace.json"),
        &json!({"name": MARKETPLACE, "owner": {"name": "piifence"}, "plugins": listed}),
    )?;
    Ok(dir)
}

/// Run `claude plugin <args>` with the `claude` in `$CLAUDE_BIN`, else the one on PATH.
fn claude_plugin(args: &[&str]) -> Result<()> {
    let claude = env::var_os("CLAUDE_BIN").unwrap_or_else(|| "claude".into());
    let out = Command::new(&claude)
        .arg("plugin")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("cannot run `{} plugin`", claude.to_string_lossy()))?;
    if !out.status.success() {
        let said = format!(
            "{} {}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        bail!("`claude plugin {}` failed: {}", args.join(" "), said.trim());
    }
    Ok(())
}

/// Uninstall piifence's plugins and remove its marketplace. Returns what failed, which is expected for what was not installed.
fn remove_plugins() -> Vec<String> {
    let mut failed = Vec::new();
    for name in PLUGINS {
        let id = format!("{name}@{MARKETPLACE}");
        if let Err(err) = claude_plugin(&["uninstall", &id, "--scope", "user"]) {
            failed.push(format!("{err:#}"));
        }
    }
    if let Err(err) = claude_plugin(&["marketplace", "remove", MARKETPLACE]) {
        failed.push(format!("{err:#}"));
    }
    failed
}

/// Install piifence's plugins at user scope from the marketplace at `dir`, replacing any earlier install, so Claude Code picks up the files just written.
fn install_plugins(dir: &Path) -> Result<()> {
    remove_plugins();
    claude_plugin(&["marketplace", "add", &dir.to_string_lossy()])?;
    for name in PLUGINS {
        claude_plugin(&[
            "install",
            &format!("{name}@{MARKETPLACE}"),
            "--scope",
            "user",
        ])?;
    }
    Ok(())
}

/// Remove `bin/claude` from the state dir when it is the shim an older piifence installed, which runs a command this piifence no longer has.
fn remove_old_shim(state: &Path) -> Result<()> {
    let shim = state.join("bin/claude");
    if fs::read_to_string(&shim).is_ok_and(|text| text.contains(" nested-claude ")) {
        fs::remove_file(&shim).with_context(|| format!("cannot remove {}", shim.display()))?;
        eprintln!("piifence: removed the old claude shim {}", shim.display());
    }
    Ok(())
}

/// `piifence install [--upstream <url>]`: run the gateway as a launchd agent, install piifence's plugins, then point Claude Code's user settings at the gateway, in that order, so the settings never name a gateway that is not running. Running it again replaces all three.
fn install(args: &[String]) -> Result<i32> {
    let opts = options(args, &["--upstream"], &[])?;
    let port = port()?;
    let url = gateway_url(port);
    let data = data_dir()?;
    let exe = real_exe()?;
    let gateway = existing(exe.with_file_name("piifence-gateway"), "the gateway binary")?;
    let model = existing(data.join("model"), "the secret model")?;
    let source = plugins(&data)?;
    let state = piifence::control::state_dir()?;
    let settings_path = claude_settings_path()?;
    let record_path = install_record(port)?;
    let record = read_json(&record_path)?;
    let current = settings_base_url(&read_json(&settings_path)?);
    let previous = if record.get("port").is_some() {
        record["previous_base_url"].as_str().map(str::to_string)
    } else {
        current.clone().filter(|base| !is_gateway(base, &url))
    };
    let upstream = choose_upstream(
        opts.get("--upstream").map(String::as_str),
        env::var("PIIF_UPSTREAM").ok().as_deref(),
        record["upstream"].as_str(),
        current.as_deref(),
        &url,
    );
    if is_gateway(&upstream, &url) {
        bail!("the upstream cannot be the gateway itself ({url})");
    }
    write_json(
        &record_path,
        &json!({"port": port, "upstream": upstream, "previous_base_url": previous}),
    )?;

    let log = state.join(format!("gateway-{port}.log"));
    let mut vars = vec![
        ("PIIF_UPSTREAM".to_string(), upstream.clone()),
        (
            "PIIF_MODEL_DIR".to_string(),
            model.to_string_lossy().into_owned(),
        ),
        ("PIIF_PORT".to_string(), port.to_string()),
        // The gateway runs gitleaks, so it needs the PATH this install sees, not launchd's bare one.
        ("PATH".to_string(), env::var("PATH").unwrap_or_default()),
    ];
    for name in PASSED_TO_GATEWAY {
        if let Ok(value) = env::var(name) {
            vars.push((name.to_string(), value));
        }
    }
    start_agent(port, &gateway, &vars, &log, &upstream)?;
    eprintln!(
        "piifence: the launchd agent {} runs the gateway on {url} (upstream {upstream}, log {})",
        agent_label(port),
        log.display()
    );

    let market = write_marketplace(&state, &source, &exe, port)?;
    install_plugins(&market)?;
    eprintln!(
        "piifence: installed the plugins {} at user scope",
        PLUGINS.join(", ")
    );

    let settings = with_base_url(read_json(&settings_path)?, Some(&url));
    write_json(&settings_path, &settings)?;
    eprintln!(
        "piifence: {} now sends Claude Code to {url}",
        settings_path.display()
    );
    remove_old_shim(&state)?;
    status(&[])
}

/// `piifence uninstall`: undo `install` in the opposite order. The settings go first, so no Claude Code starts against a gateway that is about to stop; the base URL they had before install comes back. Settings that no longer name the gateway are left alone.
fn uninstall(args: &[String]) -> Result<i32> {
    options(args, &[], &[])?;
    let port = port()?;
    let url = gateway_url(port);
    let settings_path = claude_settings_path()?;
    let record_path = install_record(port)?;
    let record = read_json(&record_path)?;
    let settings = read_json(&settings_path)?;
    if settings_base_url(&settings).is_some_and(|base| is_gateway(&base, &url)) {
        let previous = record["previous_base_url"].as_str();
        write_json(&settings_path, &with_base_url(settings, previous))?;
        match previous {
            Some(base) => eprintln!(
                "piifence: {} sends Claude Code to {base} again",
                settings_path.display()
            ),
            None => eprintln!(
                "piifence: removed ANTHROPIC_BASE_URL from {}",
                settings_path.display()
            ),
        }
    } else {
        eprintln!(
            "piifence: {} does not send Claude Code to {url}; left it alone",
            settings_path.display()
        );
    }
    for failed in remove_plugins() {
        eprintln!("piifence: note: {failed}");
    }
    let settings = read_json(&settings_path)?;
    let tidied = without_empty(settings.clone(), PLUGIN_SETTINGS);
    if tidied != settings {
        write_json(&settings_path, &tidied)?;
    }
    stop_agent(port)?;
    let plist = agent_plist(port)?;
    if plist.exists() {
        fs::remove_file(&plist).with_context(|| format!("cannot remove {}", plist.display()))?;
    }
    let market = piifence::control::state_dir()?.join("marketplace");
    if market.exists() {
        fs::remove_dir_all(&market)
            .with_context(|| format!("cannot remove {}", market.display()))?;
    }
    if record_path.exists() {
        fs::remove_file(&record_path)
            .with_context(|| format!("cannot remove {}", record_path.display()))?;
    }
    eprintln!("piifence: uninstalled; the stored names in the state dir are kept");
    Ok(0)
}

/// `piifence status`: whether piifence is installed, whether Claude Code's settings send it to the gateway, and whether the gateway runs, as JSON.
fn status(args: &[String]) -> Result<i32> {
    options(args, &[], &[])?;
    let port = port()?;
    let url = gateway_url(port);
    let routed = settings_base_url(&read_json(&claude_settings_path()?)?)
        .is_some_and(|base| is_gateway(&base, &url));
    let upstream = running_gateway_upstream(port, &control_socket(port)?)
        .ok()
        .flatten();
    println!(
        "{}",
        json!({
            "installed": install_record(port)?.exists(),
            "routed": routed,
            "running": upstream.is_some(),
            "upstream": upstream,
            "url": url,
            "port": port,
        })
    );
    Ok(0)
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

/// What `$PIIF_SECRET_<N>` names are, given to the agent when the session starts (and again after `/clear` or a compaction, which start it again). Without it the agent meets a name in tool output with no idea what it is: it warns that a secret leaked, or decides the variable holds its own name, and does not know it can use it.
const VARIABLES_NOTE: &str = "# piifence environment variables

This session runs through piifence, which keeps secrets (API keys, tokens, passwords, private keys) from reaching you. Before anything is sent to you (the user's prompts, command output, file contents), piifence replaces each secret with an environment variable name such as `$PIIF_SECRET_1`. The real value stays on the user's machine.

- Use the name in Bash commands, inside double quotes, where you would use the value: `curl -H \"Authorization: Bearer $PIIF_SECRET_1\" …`. piifence exports the variables before each command runs, so the shell expands the name, and scripts the command starts can read the variable too. Where the shell would not expand a name (single quotes, quoted heredocs such as `<<'EOF'`), piifence puts the value in before the command runs, so a commit message or a file written from a command gets the value too. Never put a backslash before a name to keep it as text: the name stands for the value, and piifence fills in the value there as well.
- Everywhere else, write the name where the value belongs: in file contents (Write, Edit), in an edit's old text, and in arguments to other tools (MCP tools, for example). piifence puts the real value in before the tool runs, so a file you write holds the value and an edit matches the file.
- A name can stand for text that is not a secret, such as a ticket key, a hostname or a version string. Treat it as that text: write the name wherever the text belongs, in a commit message, a branch name or a file, and piifence puts the text in.
- When a letter, digit or `_` comes right after a name, piifence writes the name in braces, as in `${PIIF_SECRET_…}_old`. Keep the braces when you use the name, in commands and in files: without them, the shell reads a longer variable name that does not exist.
- Files, environment variables and command output on the user's machine hold the real value; only what is sent to you shows the name. A value you see as a `$PIIF_…` name was not exposed to you or the provider: do not warn that it leaked or suggest rotating it on that account.
- When a command prints a value, you see its name again: `echo $PIIF_SECRET_1` shows you `$PIIF_SECRET_1` although the variable holds the real value. Do not conclude from that that the variable is wrong or holds its own name, and do not try to print, decode or otherwise reveal the values.";

/// A Claude Code session id, the UUID Claude Code sends with each request and gives each hook, in lower case.
fn session_uuid(id: &str) -> Result<String> {
    if !piifence::names::is_conversation_id(id) {
        bail!("{id:?} is not a Claude Code session id");
    }
    Ok(id.to_ascii_lowercase())
}

fn port_arg(port: &str) -> Result<u16> {
    port.parse()
        .with_context(|| format!("{port:?} is not a port"))
}

/// `<session> <port>` from `env`'s arguments.
fn session_args(args: &[String]) -> Result<(String, u16)> {
    let [session, port] = args else {
        bail!("expected <session> <port>");
    };
    Ok((session_uuid(session)?, port_arg(port)?))
}

/// A hook's `<port>` argument and its JSON input on stdin.
fn hook_input(args: &[String]) -> Result<(u16, Value)> {
    let [port] = args else {
        bail!("expected <port>");
    };
    let port = port_arg(port)?;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("read the hook input")?;
    let hook: Value = serde_json::from_str(&input).context("the hook input is not JSON")?;
    Ok((port, hook))
}

/// The session id in a hook's input.
fn hook_session(hook: &Value) -> Result<String> {
    session_uuid(
        hook["session_id"]
            .as_str()
            .context("the hook input has no session_id")?,
    )
}

/// Whether this Claude Code asks the gateway to qualify names from other conversations, which an embedding app does by adding `x-piifence-qualify-foreign` to `ANTHROPIC_CUSTOM_HEADERS`.
fn qualifies_foreign() -> bool {
    env::var("ANTHROPIC_CUSTOM_HEADERS").is_ok_and(|headers| {
        headers
            .to_ascii_lowercase()
            .contains("x-piifence-qualify-foreign")
    })
}

/// `piifence session-start <port>`, the `SessionStart` hook. Binds the session on the gateway (see `bind_session`), adds the line that runs `piifence env` to `CLAUDE_ENV_FILE`, and answers with VARIABLES_NOTE as context for the agent. A failure exits non-zero, so Claude Code shows it.
fn session_start(args: &[String]) -> Result<i32> {
    let (port, hook) = hook_input(args)?;
    let session = hook_session(&hook)?;
    bind_session(&session, port)?;
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
    let note = if qualifies_foreign() {
        format!("{VARIABLES_NOTE}\n{QUALIFIED_NOTE}")
    } else {
        VARIABLES_NOTE.to_string()
    };
    println!(
        "{}",
        json!({
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": note,
            }
        })
    );
    Ok(0)
}

/// Added to VARIABLES_NOTE for a session whose Claude Code sends `x-piifence-qualify-foreign`.
const QUALIFIED_NOTE: &str = "- Text from another conversation's transcript shows its names as `[[piif:<8 hex>:<n>]]`. Each stands for a value from that other conversation, kept on this machine. Write it exactly as it appears when you mention it, and never put it in a command or a tool argument: nothing fills it in there.";

/// `existing` env file content with every earlier `piifence env` line dropped and `line` added. A resumed conversation keeps its env file, so without this it would also run the lines of its earlier sessions, some through a binary an upgrade has removed.
fn env_file_with(existing: &str, line: &str) -> String {
    let ours = regex::Regex::new(r#"^eval "\$\('[^']*' env [0-9a-f-]{32,36} [0-9]+\)"$"#)
        .expect("valid pattern");
    let mut kept: String = existing
        .lines()
        .filter(|l| !ours.is_match(l))
        .map(|l| format!("{l}\n"))
        .collect();
    kept.push_str(line);
    kept
}

/// Tell the gateway that `session` has started, so it loads the names a resumed conversation already uses and stores new ones (encrypted, with a key kept in the Keychain).
fn bind_session(session: &str, port: u16) -> Result<()> {
    let socket = control_socket(port)?;
    let response = control_get(
        &socket,
        "/control/bind",
        &format!("x-piifence-session: {session}\r\n"),
        Duration::from_secs(30),
    )
    .with_context(|| {
        format!(
            "the gateway's control socket {} did not answer; is piifence installed (`piifence status`)?",
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
    print!("{}", export_lines(&session_values(&session, port)?));
    Ok(0)
}

/// Options from `args`: `--name value` or `--name=value` for the names in `with_value`, and bare `--name` for those in `flags`. Anything else is an error.
fn options(
    args: &[String],
    with_value: &[&str],
    flags: &[&str],
) -> Result<std::collections::HashMap<String, String>> {
    let mut found = std::collections::HashMap::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (arg.as_str(), None),
        };
        if with_value.contains(&name) {
            let value = match inline {
                Some(value) => value,
                None => rest
                    .next()
                    .with_context(|| format!("{name} needs a value"))?
                    .clone(),
            };
            found.insert(name.to_string(), value);
        } else if flags.contains(&name) && inline.is_none() {
            found.insert(name.to_string(), String::new());
        } else {
            bail!("unknown option `{arg}`");
        }
    }
    Ok(found)
}

/// The stored table of `conversation` as `{name: value}`, read without changing it. None when there is no Keychain key yet; an empty map when the conversation has no table.
fn stored_values(
    names_dir: &Path,
    conversation: &str,
) -> Result<Option<std::collections::HashMap<String, String>>> {
    let Some(key) = piifence::names::read_key()? else {
        return Ok(None);
    };
    let entries = piifence::names::open(&names_dir.join(conversation), conversation, &key)?;
    Ok(Some(
        entries
            .into_iter()
            .map(|(name, value, _)| (name, value))
            .collect(),
    ))
}

/// `piifence reveal --conversation <uuid> [--json]`: the text on stdin with real values in place of names, on stdout. Own names (`$PIIF_SECRET_<n>`, `${PIIF_SECRET_<n>}`) come from the conversation `--conversation`, a Claude Code session id: from the running gateway when it answers, else from the conversation's stored table. A qualified name, `[[piif:<8 hex>:<n>]]`, comes from the stored table of the one conversation whose id starts with those 8 hex digits. Stored tables are only read, never saved again. A name that does not resolve stays as it is; `--json` prints `{"text", "unresolved"}` with those names. Values are never logged.
fn reveal(args: &[String]) -> Result<i32> {
    let opts = options(args, &["--conversation"], &["--json"])?;
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .context("read stdin")?;
    let names_dir = piifence::control::state_dir()?.join("names");
    let own = match opts.get("--conversation") {
        Some(id) => conversation_values(&names_dir, &session_uuid(id)?, port()?)?,
        None => Default::default(),
    };
    let mut unresolved: Vec<String> = Vec::new();
    let mut miss = |name: &str| {
        if !unresolved.iter().any(|n| n == name) {
            unresolved.push(name.to_string());
        }
    };
    let mut tables: std::collections::HashMap<
        String,
        Option<std::collections::HashMap<String, String>>,
    > = Default::default();
    let qualified =
        piifence::qualify::qualified_pattern().replace_all(&text, |caps: &regex::Captures| {
            let prefix = &caps[1];
            let table = tables.entry(prefix.to_string()).or_insert_with(|| {
                match piifence::names::conversations_with_prefix(&names_dir, prefix) {
                    Ok(ids) if ids.len() == 1 => match stored_values(&names_dir, &ids[0]) {
                        Ok(table) => table,
                        Err(err) => {
                            eprintln!("piifence: cannot read the names of {}: {err:#}", ids[0]);
                            None
                        }
                    },
                    _ => None,
                }
            });
            match table
                .as_ref()
                .and_then(|t| t.get(&format!("PIIF_SECRET_{}", &caps[2])))
            {
                Some(value) => value.clone(),
                None => {
                    miss(&caps[0]);
                    caps[0].to_string()
                }
            }
        });
    let revealed = name_pattern().replace_all(&qualified, |caps: &regex::Captures| {
        let number = caps.get(2).or(caps.get(3)).map_or("", |m| m.as_str());
        match own.get(&format!("PIIF_SECRET_{number}")) {
            Some(value) => format!("{}{value}", &caps[1]),
            None => {
                let name = caps[0].trim_start_matches('\\');
                miss(name);
                caps[0].to_string()
            }
        }
    });
    if opts.contains_key("--json") {
        println!(
            "{}",
            serde_json::json!({"text": revealed, "unresolved": unresolved})
        );
    } else {
        print!("{revealed}");
    }
    Ok(0)
}

/// The `{name: value}` table of `conversation`: the running gateway's, which also holds names not stored yet, when a gateway answers on `port`; else the stored one.
fn conversation_values(
    names_dir: &Path,
    conversation: &str,
    port: u16,
) -> Result<std::collections::HashMap<String, String>> {
    if tcp_answers(port) {
        return Ok(session_values(conversation, port)?
            .into_iter()
            .filter_map(|(name, value)| Some((name, value.as_str()?.to_string())))
            .collect());
    }
    Ok(stored_values(names_dir, conversation)?.unwrap_or_default())
}

/// Tools whose input a shell reads, which expands `$PIIF_SECRET_<N>` itself from the exported variables, so the hook fills in only the names the shell would not expand (`piifence::shellfill`). The hook leaves `PowerShell` commands alone.
const SHELL_TOOLS: &[&str] = &["Bash", "Monitor"];

/// `piifence restore <port>`, the `PreToolUse` hook. The agent only ever sees names, so it writes `$PIIF_SECRET_<N>` into file contents, edits, and MCP tool arguments, where no shell expands it. This puts each known name's real value back into the tool's input before the tool runs. A backslash that escapes a name's `$` goes with the name. In `Bash` and `Monitor` commands only the names the shell would not expand are filled in, escaped for where they stand (`SHELL_TOOLS`). `PowerShell` and inputs without a name are left alone. A failure exits 2, which blocks the call, so a tool never runs with a name where a value belongs.
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
    let (port, hook) = hook_input(args)?;
    let session = hook_session(&hook)?;
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
        let values = session_values(&session, port)?;
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
    let values = session_values(&session, port)?;
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

/// Replace every name in every string of `value` with its value. A name this session does not have is an error. A bare name that runs into a letter or `_` is filled too: its number is read whole, and no shell reads this input, so the name cannot be taken for a longer variable.
fn fill_values(
    value: &mut serde_json::Value,
    values: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let pattern = name_pattern();
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::String(s) => {
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
    fn fill_values_fills_a_bare_name_that_runs_into_a_letter_or_underscore() {
        let values = serde_json::json!({"PIIF_SECRET_1": "one", "PIIF_SECRET_12": "twelve"});
        let values = values.as_object().unwrap();
        let mut input = serde_json::json!({"content": format!(
            "{}x {}_old {}-x {}x {}s",
            bare(1), bare(1), bare(1), braced(1), bare(12)
        )});
        fill_values(&mut input, values).unwrap();
        assert_eq!(input["content"], "onex one_old one-x onex twelves");
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
        let older = format!("eval \"$('/gone/piifence' env {} 7788)\"\n", "a".repeat(32));
        let old = "eval \"$('/gone/piifence' env 0f0f0f0f-1111-2222-3333-444444444444 7788)\"\n";
        let line = "eval \"$('/opt/piifence' env 0f0f0f0f-5555-6666-7777-888888888888 7788)\"\n";
        let existing = format!("export OTHER=1\n{older}{old}{old}");
        assert_eq!(
            env_file_with(&existing, line),
            format!("export OTHER=1\n{line}")
        );
        assert_eq!(
            env_file_with(&format!("export OTHER=1\n{line}"), line),
            format!("export OTHER=1\n{line}")
        );
        assert_eq!(env_file_with("", line), line);
    }

    #[test]
    fn options_take_values_and_flags() {
        let args: Vec<String> = ["--session", "abc", "--json", "--upstream=http://x"]
            .map(String::from)
            .to_vec();
        let found = options(&args, &["--session", "--upstream"], &["--json"]).unwrap();
        assert_eq!(found["--session"], "abc");
        assert_eq!(found["--upstream"], "http://x");
        assert!(found.contains_key("--json"));
        let bad = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            options(&args, &["--session"], &["--json"]).is_err()
        };
        assert!(bad(&["--session"]));
        assert!(bad(&["--json=1"]));
        assert!(bad(&["--other"]));
    }

    /// A fresh directory in the temp dir for the test `name`, removed first if it exists.
    fn test_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("piif-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write `content` to `path` (creating its directory) with `mode`.
    fn write_file(path: &Path, content: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
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

    #[test]
    fn session_args_are_checked() {
        let id = "0F0F0F0F-1111-2222-3333-444444444444";
        let ok = vec![id.to_string(), "7788".to_string()];
        assert_eq!(session_args(&ok).unwrap(), (id.to_ascii_lowercase(), 7788));
        assert!(session_args(&["x; rm -rf /".to_string(), "7788".to_string()]).is_err());
        assert!(session_args(&["a".repeat(32), "7788".to_string()]).is_err());
        assert!(session_args(&[id.to_string(), "port".to_string()]).is_err());
        assert!(session_args(&ok[..1]).is_err());
    }

    #[test]
    fn session_plugin_hooks_are_filled_for_this_install() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugin");
        let exe = Path::new("/opt/pf dir/piifence");
        let socket = Path::new("/tmp/run/7797.sock");
        let filled = |plugin: &str| -> serde_json::Value {
            let text = fs::read_to_string(source.join(plugin).join("hooks/hooks.json")).unwrap();
            serde_json::from_str(&fill_hooks(&text, exe, socket, 7797).unwrap()).unwrap()
        };
        let hooks = filled("piifence-session");
        let command = |event: &str| {
            hooks["hooks"][event][0]["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            command("SessionStart"),
            "'/opt/pf dir/piifence' session-start 7797"
        );
        assert_eq!(command("PreToolUse"), "'/opt/pf dir/piifence' restore 7797");
        assert_eq!(hooks["hooks"]["PreToolUse"][0]["matcher"], "*");
        let notice = filled("piifence-notice").to_string();
        assert!(
            notice.contains("PIIF_GATEWAY_SOCKET='/tmp/run/7797.sock'"),
            "{notice}"
        );
        for plugin in PLUGINS {
            let hooks = source.join(plugin).join("hooks/hooks.json");
            if hooks.exists() {
                let text = filled(plugin).to_string();
                assert!(
                    !text.contains("@PIIFENCE@")
                        && !text.contains("@PORT@")
                        && !text.contains("@SOCKET@"),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn fill_module_writes_the_path_into_a_quoted_string() {
        assert_eq!(
            fill_module(
                "const PIIFENCE = '@PIIFENCE_PATH@'\nconst PORT = @PORT@\n",
                Path::new("/a/it's\\x"),
                7788
            ),
            "const PIIFENCE = '/a/it\\'s\\\\x'\nconst PORT = 7788\n"
        );
    }

    #[test]
    fn the_marketplace_holds_every_plugin_filled_in() {
        let state = test_dir("marketplace");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugin");
        let dir = write_marketplace(&state, &source, Path::new("/opt/piifence"), 7797).unwrap();
        let catalog = read_json(&dir.join(".claude-plugin/marketplace.json")).unwrap();
        assert_eq!(catalog["name"], MARKETPLACE);
        let listed: Vec<&str> = catalog["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(listed, PLUGINS);
        let mut stack = vec![dir.clone()];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                stack.extend(fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
            } else if path.extension().is_some_and(|ext| ext != "md") {
                let text = fs::read_to_string(&path).unwrap();
                for mark in ["@PIIFENCE@", "@PORT@", "@SOCKET@", "@PIIFENCE_PATH@"] {
                    assert!(!text.contains(mark), "{} still has {mark}", path.display());
                }
            }
        }
        let module =
            fs::read_to_string(dir.join("plugins/piifence-reveal/hooks/register.ts")).unwrap();
        assert!(module.contains("'/opt/piifence'"), "{module}");
        fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn the_base_url_is_set_and_removed_without_touching_other_settings() {
        let settings = serde_json::json!({"model": "opus", "env": {"A": "1"}, "hooks": {}});
        let set = with_base_url(settings.clone(), Some("http://127.0.0.1:7788"));
        assert_eq!(
            serde_json::to_string(&set).unwrap(),
            r#"{"model":"opus","env":{"A":"1","ANTHROPIC_BASE_URL":"http://127.0.0.1:7788"},"hooks":{}}"#
        );
        assert_eq!(
            settings_base_url(&set).as_deref(),
            Some("http://127.0.0.1:7788")
        );
        assert_eq!(with_base_url(set, None), settings);
        let only = serde_json::json!({"env": {"ANTHROPIC_BASE_URL": "http://x"}});
        assert_eq!(with_base_url(only, None), serde_json::json!({}));
        let restored = with_base_url(serde_json::json!({}), Some("http://proxy.test"));
        assert_eq!(
            settings_base_url(&restored).as_deref(),
            Some("http://proxy.test")
        );
        let left = serde_json::json!({"model": "opus", "enabledPlugins": {}, "extraKnownMarketplaces": {"other": {}}});
        assert_eq!(
            without_empty(left, PLUGIN_SETTINGS),
            serde_json::json!({"model": "opus", "extraKnownMarketplaces": {"other": {}}})
        );
    }

    #[test]
    fn the_upstream_falls_back_in_order() {
        let url = "http://127.0.0.1:7788";
        let pick = |flag, from_env, recorded, settings| {
            choose_upstream(flag, from_env, recorded, settings, url)
        };
        assert_eq!(pick(Some("f"), Some("e"), Some("r"), Some("s")), "f");
        assert_eq!(pick(None, Some("e"), Some("r"), Some("s")), "e");
        assert_eq!(pick(None, None, Some("r"), Some("s")), "r");
        assert_eq!(pick(None, None, None, Some("s")), "s");
        assert_eq!(
            pick(None, None, None, Some("http://127.0.0.1:7788/")),
            DEFAULT_UPSTREAM
        );
        assert_eq!(pick(None, Some(""), None, None), DEFAULT_UPSTREAM);
    }

    #[test]
    fn the_agent_plist_escapes_its_values() {
        let plist = launchd_plist(
            "com.piifence.gateway",
            Path::new("/opt/a&b/piifence-gateway"),
            &[(
                "PIIF_UPSTREAM".to_string(),
                "http://x/?a=1&b=<2>".to_string(),
            )],
            Path::new("/tmp/gw.log"),
        );
        assert!(plist.contains("<string>/opt/a&amp;b/piifence-gateway</string>"));
        assert!(plist
            .contains("<key>PIIF_UPSTREAM</key><string>http://x/?a=1&amp;b=&lt;2&gt;</string>"));
        assert!(plist.contains("<key>KeepAlive</key><true/>"));
        assert_eq!(agent_label(DEFAULT_PORT), "com.piifence.gateway");
        assert_eq!(agent_label(7797), "com.piifence.gateway.7797");
    }

    #[test]
    fn json_files_are_replaced_whole_and_keep_their_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("write-json");
        let path = dir.join("settings.json");
        assert_eq!(read_json(&path).unwrap(), serde_json::json!({}));
        write_file(&path, "{\"a\": 1}", 0o600);
        write_json(&path, &serde_json::json!({"a": 2})).unwrap();
        assert_eq!(read_json(&path).unwrap(), serde_json::json!({"a": 2}));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        write_file(&path, "[1]", 0o600);
        assert!(read_json(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
