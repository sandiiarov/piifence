<div align="center">

# 🔒 piifence

**Keep your secrets out of your coding agent's prompts.**

A small local proxy between Claude Code and the model provider. It finds API keys, tokens, passwords and private keys in every outgoing request and swaps each one for an environment variable name before the request leaves your machine.

![macOS](https://img.shields.io/badge/platform-macOS%20(Apple%20Silicon)-lightgrey)
![Claude Code](https://img.shields.io/badge/agent-Claude%20Code-d97757)
![Runs locally](https://img.shields.io/badge/detection-100%25%20local-2ea44f)
![Status](https://img.shields.io/badge/status-experimental-orange)

[Install](#-install) · [Use](#-use) · [What it catches](#-what-it-catches) · [How it works](#-how-it-works) · [Configure](#-configure) · [Troubleshooting](#-troubleshooting) · [Limitations](#-limitations)

</div>

---

## ✨ What it does

Coding agents send a lot to the model provider: your prompts, file contents, `.env` files, command output and logs. piifence replaces every secret in that traffic with a name. The provider only ever sees the name, and the real value stays on your machine. Commands the agent runs locally still get the real value, so the agent can still do its job.

```text
you type:       deploy with DATABASE_URL=postgres://admin:hunter2@db.internal/prod

provider sees:  deploy with DATABASE_URL=$PIIF_SECRET_1

agent runs:     psql "$PIIF_SECRET_1" -c 'select 1'      # gets the real URL locally
```

After each turn, Claude Code shows what was replaced. The notice has a masked preview and never the value itself:

```text
piifence: replaced 1 secret(s) — DATABASE_CREDENTIAL×1 ($PIIF_SECRET_1 post…prod)
```

> [!NOTE]
> piifence looks for **secrets only**. Names, emails and other personal data are sent as they are.

## 📦 Install

You need macOS on Apple Silicon and [Homebrew](https://brew.sh). Either way below, piifence is built from source, which takes about 4 minutes, and the secret model (about 70 MB) is downloaded and checked against pinned SHA-256 hashes.

**With Homebrew:**

```bash
brew tap sandiiarov/piifence https://github.com/sandiiarov/piifence
brew install piifence
```

Homebrew installs Rust and gitleaks as dependencies and puts the `piifence` command in `$(brew --prefix)/bin`. `brew upgrade piifence` updates it, and `brew install --HEAD piifence` builds the latest `main` instead of the pinned release.

**With the install script:**

```bash
curl -fsSL https://raw.githubusercontent.com/sandiiarov/piifence/main/scripts/install.sh | bash
```

The script adds Rust, git and gitleaks if they are missing, puts the `piifence` command in `~/.local/bin`, and the model in `~/.local/share/piifence/model`. To install from a checkout instead, run `scripts/install.sh`.

Use one of the two. If both are installed, the one that comes first in your `PATH` runs (`which piifence` tells you which).

## 🚀 Use

Start Claude Code through piifence and tell it where your provider is:

```bash
PIIF_UPSTREAM=https://api.anthropic.com piifence claude
```

If `ANTHROPIC_BASE_URL` is already set in your shell or in your Claude Code settings, run `piifence claude` without `PIIF_UPSTREAM`. Every argument after `claude` goes to Claude Code as usual, so `piifence claude -c` continues your last conversation.

There is nothing to switch on. Every secret found is replaced.

### How the agent works with a secret it can't see

| Where | What happens |
|---|---|
| **Your prompt, files, command output, `CLAUDE.md`** | They reach the provider with each secret replaced by a name such as `$PIIF_SECRET_1`. What you see in Claude Code doesn't change: only what goes to the provider does. |
| **Bash commands** | Before every command, Claude Code exports the session's `$PIIF_SECRET_*` variables with their real values, so `curl -H "Authorization: Bearer $PIIF_SECRET_1" …` works, and so does any script the command starts. |
| **Files the agent writes, edits and other tool calls** | No shell expands a name in a file's contents or in an MCP tool's arguments. So before any tool other than Bash runs, piifence puts the real value in place of each name in the tool's input. A file the agent writes holds the value, an edit matches a file that holds one, and a Slack or GitHub tool gets the real id or token. The value stays on your machine: Claude Code keeps the tool call in the conversation as the agent wrote it, with the name, and if the value comes back in a later tool result, the gateway replaces it with its name again. Your permission prompts still apply, and they show the real value. |
| **Output that prints a value** | If a command prints a value, as `echo $PIIF_SECRET_1` would, piifence puts the name back before the output reaches the provider. |
| **The agent's instructions** | When the session starts, the agent gets a short note: `$PIIF_*` names stand for real values kept on your machine, and a value it sees only as a name was not exposed. Without the note, an agent that sees `$PIIF_SECRET_1` in output tends to warn you that a secret leaked. |

> [!IMPORTANT]
> The gateway serves only `piifence claude` sessions. Plain `claude` pointed at the gateway is refused, because its requests lack the session id that `piifence claude` adds.
>
> The gateway hands a session's values only to your own account. `piifence env`, the `PreToolUse` hook and the notice reach it on a Unix socket in `~/.local/state/piifence/run/`, a directory only you can open. Its TCP port, which every account on the Mac can reach, serves only the proxy and a health check.

## 🔍 What it catches

Three detectors read every piece of text. A value that any of them finds is replaced.

| Detector | What it finds |
|---|---|
| 🧩 **[gitleaks](https://github.com/gitleaks/gitleaks) rules** | Known formats: AWS, GitHub, OpenAI, Anthropic, Stripe, Slack and many more, private keys, JWTs, passwords in config files, credentials in URLs, and base64-encoded copies of these. |
| 🧠 **[SporeLabs Scrub](https://huggingface.co/SporeLabs/scrub)** | Secrets with no known format, recognised from context: API keys, access tokens, passwords, one-time codes, credentials in prose. It is a 17M-parameter model that runs on your CPU in about 0.2 GB of memory; piifence uses only its secret head. |
| 🔑 **Key rules** | A quoted random-looking value whose key, or the key of the block around it, names a secret (`"api_key": "…"`, the `default` of an HCL `variable "API_KEY"`); a value named in prose or under a label in any common language (`the wifi password for the office is …`, `мой пароль …`, `## Webhook secret`); a `<prefix>_<random>` key of any provider (`tvly-dev-…`, `pa-…`); and a bare hex key that no hash word (`commit`, `sha256`) explains. Full-width look-alike letters (`ｇｈｐ_…`) are folded to ASCII, and invisible characters such as zero-width spaces and soft hyphens are dropped, before every detector reads the text again. |

The model reads tool output the way a terminal shows it: `$ <command>` before Bash output, `$ cat <path>` before a file, and `VAR=` before the output of `echo $VAR`. So a bare value that a command prints is read together with its name.

<details>
<summary><b>Values piifence leaves alone</b></summary>

The model sometimes calls a random-looking string a secret. piifence drops a model finding when the whole value is one of these:

- **Identifiers:** UUIDs (including Claude Code's session ids in `~/.claude/projects/…`), `toolu_…` ids, AWS resource ids, upper-case ids such as chat and channel ids (`U0ABCD12E`), host names and Kubernetes pod names.
- **Hashes:** git SHAs, image digests.
- **Paths, numbers and versions:** file paths, `sed -n '885,1150p'` ranges, versions, timestamps, SVG path data.
- **Durations and timestamps:** `2m34s`, `150ms`, `2026-10-30T12:34:56Z`, even right after a word like `pass` or `secret`.
- **Plain words.**
- **Lists and phrases** where every piece is one of these shapes, such as several ids in a shell loop.
- **Values whose name says what they are:** a URL query value under a name that doesn't sound secret (`?atlOrigin=eyJ…`), or a JSON value under a key such as `slug`, `id`, `sha` or `name`.
- **Stand-ins:** `sk-...`, `YOUR_API_KEY`, `***`.
- **Fragments:** anything under 4 characters, and anything with no letter or digit, such as a lone `{`.

piifence judges the whole token around a finding, so a model finding on part of an id is dropped when the full id is one of these shapes. A value of one of these shapes is still replaced when a secret keyword comes right before it, as in `API_KEY=886dcfc3-…`, or on one of the two lines above in key position, as in `"credentials": {`. Durations and timestamps are dropped even then.

Known formats that gitleaks finds are replaced, and so is a URL query value whose name says it is secret (`?token=`, `&userJwt=`, `?apiKey=`), unless the value is only an environment reference (`$SONAR_TOKEN`, `${JIRA_API_TOKEN:-$ATL_API_TOKEN}`) a placeholder word that names itself (`deploy-token`, `invalid-token`), or starts with `…`.

</details>

## 🔬 How it works

```mermaid
flowchart LR
    you([You]) --> cc
    subgraph cc [Claude Code]
        bash["Bash commands<br/>get $PIIF_SECRET_* exported first"]
    end
    cc -- request --> gw["piifence gateway (localhost)<br/>finds secrets in every part of the request<br/>names them $PIIF_SECRET_*"]
    gw -- redacted request --> provider([Provider])
    provider -- response, streamed back untouched --> cc
    bash <-. "values for this session only" .-> gw
```

`piifence claude` starts the gateway, gives the session a random id, and launches Claude Code with a temporary settings file and the notice plugin:

- **The gateway** is a proxy on `127.0.0.1:7788`. It scans every outgoing request (prompt, tool output, files, system prompt) and replaces each secret with its `$PIIF_SECRET_*` name. It keeps the values in memory and hands them only to the session they belong to, and only on its control socket, `~/.local/state/piifence/run/7788.sock`, never on its TCP port. It also saves each conversation's names, encrypted, so a resumed conversation gets them back (see [Guarantees](#guarantees)).
- **A `SessionStart` hook** gives the agent the note about `$PIIF_*` names, and tells the gateway which Claude Code conversation the session is. It also adds one line to the file that Claude Code loads before every Bash command (`CLAUDE_ENV_FILE`). That line runs `piifence env`, which fetches the session's values from the gateway and exports them.
- **A `PreToolUse` hook** runs `piifence restore` before every tool call. When the tool's input holds a `$PIIF_SECRET_*` name, it fetches the session's values and puts each value in place of its name; a backslash right before the name's `$` counts as part of the name. In Bash and Monitor commands it fills in a value only where the shell would not expand the name itself (single quotes, quoted heredocs, an escaped `$`), and PowerShell commands are left alone. If the gateway doesn't answer or a name is unknown, the hook blocks the call instead of letting the tool run with a name where a value belongs.

Here is what happens when the agent finds a secret in a file and then uses it:

```mermaid
sequenceDiagram
    participant A as Agent (Claude Code)
    participant G as piifence gateway
    participant P as Provider
    A->>G: tool output with GITHUB_TOKEN=ghp_…
    G->>P: GITHUB_TOKEN=$PIIF_SECRET_1
    P-->>A: run curl -H "Authorization: Bearer $PIIF_SECRET_1" …
    A->>G: before the command: piifence env (this session)
    G-->>A: export PIIF_SECRET_1='ghp_…'
    A->>A: run the command with the real value
```

### Guarantees

- 🏠 **Everything stays local.** Detection runs on your machine. Nothing is sent anywhere except the redacted request.
- 🔁 **Names are stable.** The same value gets the same name on every turn, so the conversation stays consistent and prompt caching keeps working.
- ⏯️ **Names survive a restart.** The agent's own messages, and scripts it wrote, hold names like `$PIIF_SECRET_39`. So the gateway saves each conversation's name→value table, and `piifence claude -c` or `--resume` loads it back, even after the gateway restarted. The table is a file in `~/.local/state/piifence/names/`, named after the conversation id, readable only by you, and encrypted (XChaCha20-Poly1305) with a random key kept in your macOS login Keychain (service `piifence`, account `names-key`). A table nobody has resumed for 30 days is deleted.
- 🙈 **No raw values are written in the clear.** Apart from that encrypted table, values live only in the gateway's memory, in the environment of the commands the agent runs, and in the tool inputs the `PreToolUse` hook fills in on your machine. Logs and the notice hold only kinds, counts and masked previews.
- 👤 **Other accounts on your Mac can't read the values.** Any account can connect to the gateway's TCP port, so the gateway serves only the proxy there. It hands out values, saved names and the notice's previews only on a Unix socket in `~/.local/state/piifence/run/`, a directory only you can open.
- 🛡️ **A value put back never goes out.** Before detection, the gateway replaces every value it has named in the session with its name, everywhere in the request. After detection it sweeps the whole request again, so a value first found late in a request is also replaced where it appeared earlier, and in fields that are not scanned. So a value that comes back in a file the agent reads, or in command output, leaves your machine as its name. Only thinking blocks (signed by the provider, so they can't be changed), base64 attachments and the request's `metadata` are left as they are.
- 🚫 **It fails closed.** If a request can't be fully scanned, it is blocked, not sent. If the gateway can't start, Claude Code isn't launched.

<details>
<summary><b>Inside the gateway: the steps for each piece of text</b></summary>

```mermaid
flowchart TD
    text[text block] --> known["replace values already named<br/>in this session"]
    known --> ctx["put the shell context in front<br/>($ command, $ cat path, VAR=)"]
    ctx --> model["model, in 3 KB windows"]
    ctx --> iso["model again on a copy where values<br/>glued to non-ASCII text are set apart"]
    ctx --> rules["gitleaks and the key rules<br/>(quoted keys, prose and labels, prefixed keys, hex)"]
    ctx --> fold["the same steps on a copy with full-width<br/>letters folded and invisible characters dropped"]
    model --> guards["guards: drop ids, hashes, paths, numbers,<br/>words, stand-ins, values named as things"]
    iso --> guards
    rules --> allow["guards: env references, file:line,<br/>your allow list"]
    guards --> union[union of overlapping spans]
    allow --> union
    fold --> union
    union --> name["replace each with $PIIF_SECRET_N"]
    name --> sweep["sweep the whole request for every named value"]
```

- **Each text is scanned once.** Claude Code sends the whole conversation on every turn. The gateway records what it found in each piece of text in `~/.cache/piifence/detections.jsonl`, so a resumed session doesn't scan its history again. The file holds a hash of each text with the positions and kinds found in it, never the text or the values. A new piifence build, model, allow list or gitleaks version starts an empty cache.
- **Long text is scanned in pieces.** The model reads text in windows of 3,000 bytes, each with 500 more bytes of lookahead, so a value on a window edge is still seen whole. On an M4 CPU it reads about 16 to 19 KB of new text per second, in about 0.2 GB of memory.
- **If the gateway doesn't answer before a command,** `piifence env` prints an error and the command runs without the values.

</details>

## 🔧 Configure

piifence works with no configuration. There is one optional setting: if piifence keeps replacing a value of yours that isn't a secret, list a regex for it in `~/.config/piifence/config.toml`:

```toml
# Values matching any of these are never replaced.
allow = ['^PROJ-\d+$', '^build-[0-9a-f]{12}$']
```

`allow` is the only key. An unknown key or an invalid regex stops the gateway from starting, so a typo can't quietly change what gets replaced. See [`piifence.toml.example`](piifence.toml.example).

Inline `gitleaks:allow` comments and `.gitleaksignore` files have no effect on the gateway. A line is scanned whatever it says about itself, and only your `allow` list makes exceptions.

<details>
<summary><b>Environment variables</b></summary>

| Variable | Default | What it does |
|---|---|---|
| `PIIF_UPSTREAM` | `ANTHROPIC_BASE_URL` from your shell, then from Claude Code settings | The provider the gateway forwards to. |
| `PIIF_PORT` | `7788` | The gateway's port on `127.0.0.1`. |
| `PIIF_CONFIG` | `~/.config/piifence/config.toml` | The config file. |
| `PIIF_DATA_DIR` | `~/.local/share/piifence` (Homebrew: `$(brew --prefix)/opt/piifence/share/piifence`) | Where the model and the notice plugin are installed. |
| `PIIF_CACHE_DIR` | `~/.cache/piifence` | Where the detection cache is kept. |
| `PIIF_STATE_DIR` | `~/.local/state/piifence` | Where each conversation's encrypted names are kept, in `names/`, and the gateway's control socket, in `run/`. |
| `PIIF_GATEWAY_LOG` | `$TMPDIR/piifence-gateway.log` | The gateway's own log. |
| `PIIF_EXIT_WHEN_UNUSED` | `10` | Seconds a gateway started by `piifence claude` keeps running after the last `piifence claude` that used it exits. `0` keeps it running until you stop it. |
| `PIIF_AUDIT_LOG` | `/tmp/piifence-audit.log` | One line per replacement: kind, position, name and masked preview. |
| `PIIF_AUDIT_BODY` | unset | Set to `1` to also log each rewritten request body. |
| `PIIF_PREFIX` | `~/.local` | Install prefix, read by `install.sh`. |

A value that is set but can't be parsed, such as `PIIF_PORT=abc`, is an error.

</details>

## 🩺 Troubleshooting

<details>
<summary><b>Upgrading</b></summary>

1. Quit every `piifence claude` session. A gateway that `piifence claude` started exits by itself about 10 seconds after its last session ends; until then, a new `piifence claude` reuses it.
2. Run `brew upgrade piifence`, or the install script again.
3. Check that no old gateway is left with `pgrep -fl piifence-gateway`, and stop any you find with `pkill -f piifence-gateway`.

</details>

<details>
<summary><b>The gateway doesn't start</b></summary>

`piifence claude` prints the error and the path of the gateway log. Common causes:

- **A config error**, such as `unknown field` or `invalid allow pattern`. Older versions had settings like `categories` and `auto_approve`, and those are now errors. Keep only `allow` in `~/.config/piifence/config.toml`, or delete the file.
- **`no upstream configured`**: set `PIIF_UPSTREAM`, or `ANTHROPIC_BASE_URL` in your shell or Claude Code settings.
- **`a gateway on … forwards to …`**: another session's gateway is using the port with a different provider. Quit that session, or set `PIIF_PORT` to a free port.
- **`no piifence gateway answers on …`**: something answers on the port, but it is not a gateway this piifence can reach: another program, another account's gateway, a gateway from a piifence older than the control socket, or one started with a different `PIIF_STATE_DIR`. Stop it, or set `PIIF_PORT` to a free port.
- **`cannot hold a lease`**: a gateway from an older piifence is still running on the port. Quit the sessions that use it, or stop it with `pkill -f piifence-gateway`.

</details>

<details>
<summary><b>A command fails with <code>PIIF_SECRET_N: unbound variable</code></b></summary>

The name has no value in this session. This happens to a conversation that was last run with a piifence older than the saved names, or that was unused for 30 days, or whose names file can't be read. Ask the agent to read the value again from where it came from (the file, the URL, the command), which gives it a name that works. If the session-start hook printed an error about the conversation's names, it says which file or Keychain item failed.

</details>

<details>
<summary><b>Uninstalling</b></summary>

```bash
pkill -f piifence-gateway
brew uninstall piifence && brew untap sandiiarov/piifence    # if installed with Homebrew
rm -rf ~/.local/bin/piifence ~/.local/libexec/piifence ~/.local/share/piifence    # if installed with the script
rm -rf ~/.local/state/piifence ~/.cache/piifence ~/.config/piifence
security delete-generic-password -s piifence -a names-key
```

piifence never edits `~/.claude/settings.json`, so there's nothing to undo in Claude Code.

</details>

## 🚧 Limitations

- **It's experimental.** Use it as a safety net, not as your only protection.
- **It covers secrets only.** Personal data such as names, emails and phone numbers is sent as it is.
- **It rewrites input only.** The agent works with variable names, and responses aren't scanned or rewritten.
- **Names last 30 days.** A conversation resumed after 30 days unused has lost its saved names, so a `$PIIF_SECRET_N` the agent wrote before then has no value.
- **The agent can use every secret it comes across** in commands, including sending it somewhere.
- **Secrets that look like ids get through.** For example, a hex key right after a word like `commit` or `sha256` is read as a hash and sent as it is, and so is a secret in a URL query parameter whose name doesn't say it is secret.
- **It runs on macOS only, with Claude Code only.**

## 🧑‍💻 Development

```bash
cargo build --release
scripts/fetch-weights.sh /tmp/piifence-model
PIIF_MODEL_DIR=/tmp/piifence-model scripts/check.sh    # every check, including the secret suite
```

| Doc | What's in it |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Architecture, module ownership and contracts. |
| [`tests/secrets/README.md`](tests/secrets/README.md) | The end-to-end secret suite: 943 cases through the real gateway. |
| [`docs/model-options.md`](docs/model-options.md) | Why piifence uses SporeLabs Scrub, with the benchmarks. |
| [`docs/research/`](docs/research/README.md) | What other secret detectors, redaction proxies and papers do, and what piifence can take from them. |
| [`plugin/piifence-notice/README.md`](plugin/piifence-notice/README.md) | The plugin that shows what was replaced. |

## 📄 License

There is no license yet. The code is all rights reserved until one is added.
