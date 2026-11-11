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

You need macOS on Apple Silicon and [Homebrew](https://brew.sh). The installer adds Rust, git and gitleaks if they are missing.

```bash
curl -fsSL https://raw.githubusercontent.com/sandiiarov/piifence/main/scripts/install.sh | bash
```

The installer builds piifence, puts the `piifence` command in `~/.local/bin`, and downloads the secret model (about 128 MB, checked against pinned SHA-256 hashes) to `~/.local/share/piifence/model`. To install from a checkout instead, run `scripts/install.sh`.

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
| **Files the agent writes, edits and other tool calls** | No shell expands a name in a file's contents or in an MCP tool's arguments. So before any tool other than Bash runs, piifence puts the real value in place of each name in the tool's input. A file the agent writes holds the value, an edit matches a file that holds one, and a Slack or GitHub tool gets the real id or token. Your permission prompts still apply, and they show the real value. |
| **Output that prints a value** | If a command prints a value, as `echo $PIIF_SECRET_1` would, piifence puts the name back before the output reaches the provider. |
| **The agent's instructions** | When the session starts, the agent gets a short note: `$PIIF_*` names stand for real values kept on your machine, and a value it sees only as a name was not exposed. Without the note, an agent that sees `$PIIF_SECRET_1` in output tends to warn you that a secret leaked. |

> [!IMPORTANT]
> The gateway serves only `piifence claude` sessions. Plain `claude` pointed at the gateway is refused, because its requests lack the session id that `piifence claude` adds.

## 🔍 What it catches

Three detectors read every piece of text. A value that any of them finds is replaced.

| Detector | What it finds |
|---|---|
| 🧩 **[gitleaks](https://github.com/gitleaks/gitleaks) rules** | Known formats: AWS, GitHub, OpenAI, Anthropic, Stripe, Slack and many more, private keys, JWTs, passwords in config files, credentials in URLs, and base64-encoded copies of these. |
| 🧠 **[cbx-secrets-detector-32M](https://huggingface.co/CobuildX-AI/cbx-secrets-detector-32M)** | Secrets with no known format, recognised from context: API keys, access tokens, passwords, database and cloud credentials, private and encryption keys. It is a 32M-parameter model that runs on your CPU. |
| 🔑 **Key rule** | A quoted random-looking value whose key, or the key of the block around it, names a secret: `"api_key": "…"`, `password: '…'`, or the `default` of an HCL `variable "API_KEY"`. |

The model reads tool output the way a terminal shows it: `$ <command>` before Bash output, `$ cat <path>` before a file, and `VAR=` before the output of `echo $VAR`. So a bare value that a command prints is read together with its name.

<details>
<summary><b>Values piifence leaves alone</b></summary>

The model sometimes calls a random-looking string a secret. piifence drops a model finding when the whole value is one of these:

- **Identifiers:** UUIDs (including Claude Code's session ids in `~/.claude/projects/…`), `toolu_…` ids, AWS resource ids.
- **Hashes:** git SHAs, image digests.
- **Paths, numbers and versions:** file paths, `sed -n '885,1150p'` ranges, versions, timestamps.
- **Plain words.**
- **Stand-ins:** `sk-...`, `YOUR_API_KEY`, `***`.
- **Fragments:** anything under 4 characters, and anything with no letter or digit, such as a lone `{`.

A value of one of these shapes is still replaced when a secret keyword comes right before it, as in `API_KEY=886dcfc3-…`. Known formats that gitleaks finds are always replaced.

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

- **The gateway** is a proxy on `127.0.0.1:7788`. It scans every outgoing request (prompt, tool output, files, system prompt) and replaces each secret with its `$PIIF_SECRET_*` name. It keeps the values in memory and hands them only to the session they belong to.
- **A `SessionStart` hook** gives the agent the note about `$PIIF_*` names. It also adds one line to the file that Claude Code loads before every Bash command (`CLAUDE_ENV_FILE`). That line runs `piifence env`, which fetches the session's values from the gateway and exports them.
- **A `PreToolUse` hook** runs `piifence restore` before every other tool call. When the tool's input holds a `$PIIF_SECRET_*` name, it fetches the session's values and puts each value in place of its name. If the gateway doesn't answer or a name is unknown, the hook blocks the call instead of letting the tool run with a name where a value belongs.

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
- 🙈 **No raw values are stored.** Values live only in the gateway's memory and in the environment of the commands the agent runs. Logs and the notice hold only kinds, counts and masked previews.
- 🚫 **It fails closed.** If a request can't be fully scanned, it is blocked, not sent. If the gateway can't start, Claude Code isn't launched.

<details>
<summary><b>Inside the gateway: the steps for each piece of text</b></summary>

```mermaid
flowchart TD
    text[text block] --> known["replace values already named<br/>in this session"]
    known --> ctx["put the shell context in front<br/>($ command, $ cat path, VAR=)"]
    ctx --> model["model, in 3 KB windows"]
    ctx --> iso["model again on a copy where values<br/>glued to non-ASCII text are set apart"]
    ctx --> rules[gitleaks and the key rule]
    model --> guards["guards: drop ids, hashes, paths,<br/>numbers, words, stand-ins"]
    iso --> guards
    rules --> allow["guards: env references, file:line,<br/>your allow list"]
    guards --> union[union of overlapping spans]
    allow --> union
    union --> name["replace each with $PIIF_SECRET_N"]
```

- **Each text is scanned once.** Claude Code sends the whole conversation on every turn. The gateway records what it found in each piece of text in `~/.cache/piifence/detections.jsonl`, so a resumed session doesn't scan its history again. The file holds a hash of each text with the positions and kinds found in it, never the text or the values. A new piifence build, model, allow list or gitleaks version starts an empty cache.
- **Long text is scanned in pieces.** The model reads text in windows of 3,000 bytes, each with 500 more bytes of lookahead, so a value on a window edge is still seen whole. On an M4 CPU it reads about 19 KB of new text per second.
- **If the gateway doesn't answer before a command,** `piifence env` prints an error and the command runs without the values.

</details>

## 🔧 Configure

piifence works with no configuration. There is one optional setting: if piifence keeps replacing a value of yours that isn't a secret, list a regex for it in `~/.config/piifence/config.toml`:

```toml
# Values matching any of these are never replaced.
allow = ['^PROJ-\d+$', '^build-[0-9a-f]{12}$']
```

`allow` is the only key. An unknown key or an invalid regex stops the gateway from starting, so a typo can't quietly change what gets replaced. See [`piifence.toml.example`](piifence.toml.example).

<details>
<summary><b>Environment variables</b></summary>

| Variable | Default | What it does |
|---|---|---|
| `PIIF_UPSTREAM` | `ANTHROPIC_BASE_URL` from your shell, then from Claude Code settings | The provider the gateway forwards to. |
| `PIIF_PORT` | `7788` | The gateway's port on `127.0.0.1`. |
| `PIIF_CONFIG` | `~/.config/piifence/config.toml` | The config file. |
| `PIIF_DATA_DIR` | `~/.local/share/piifence` | Where the model and the notice plugin are installed. |
| `PIIF_CACHE_DIR` | `~/.cache/piifence` | Where the detection cache is kept. |
| `PIIF_GATEWAY_LOG` | `$TMPDIR/piifence-gateway.log` | The gateway's own log. |
| `PIIF_AUDIT_LOG` | `/tmp/piifence-audit.log` | One line per replacement: kind, position, name and masked preview. |
| `PIIF_AUDIT_BODY` | unset | Set to `1` to also log each rewritten request body. |
| `PIIF_PREFIX` | `~/.local` | Install prefix, read by `install.sh`. |

A value that is set but can't be parsed, such as `PIIF_PORT=abc`, is an error.

</details>

## 🩺 Troubleshooting

<details>
<summary><b>Upgrading</b></summary>

1. Quit every `piifence claude` session. `piifence claude` reuses a gateway that is already running, so an old gateway keeps serving until it stops.
2. Run the install command again.
3. Check that no old gateway is left with `pgrep -fl piifence-gateway`, and stop any you find with `pkill -f piifence-gateway`.

</details>

<details>
<summary><b>The gateway doesn't start</b></summary>

`piifence claude` prints the error and the path of the gateway log. Common causes:

- **A config error**, such as `unknown field` or `invalid allow pattern`. Older versions had settings like `categories` and `auto_approve`, and those are now errors. Keep only `allow` in `~/.config/piifence/config.toml`, or delete the file.
- **`no upstream configured`**: set `PIIF_UPSTREAM`, or `ANTHROPIC_BASE_URL` in your shell or Claude Code settings.
- **`a gateway on … forwards to …`**: another session's gateway is using the port with a different provider. Quit that session, or set `PIIF_PORT` to a free port.

</details>

<details>
<summary><b>Uninstalling</b></summary>

```bash
pkill -f piifence-gateway
rm -rf ~/.local/bin/piifence ~/.local/libexec/piifence ~/.local/share/piifence ~/.cache/piifence ~/.config/piifence
```

piifence never edits `~/.claude/settings.json`, so there's nothing to undo in Claude Code.

</details>

## 🚧 Limitations

- **It's experimental.** Use it as a safety net, not as your only protection.
- **It covers secrets only.** Personal data such as names, emails and phone numbers is sent as it is.
- **It rewrites input only.** The agent works with variable names, and responses aren't scanned or rewritten.
- **Values live in memory only.** If the gateway restarts during a session, values get names again as they are found, possibly with different numbers.
- **The agent can use every secret it comes across** in commands, including sending it somewhere.
- **Secrets that look like ids get through.** For example, 32 hex characters with no keyword such as `key` or `token` before them are sent as they are.
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
| [`docs/model-options.md`](docs/model-options.md) | Why piifence uses cbx-secrets-detector-32M, with the benchmarks. |
| [`plugin/piifence-notice/README.md`](plugin/piifence-notice/README.md) | The plugin that shows what was replaced. |

## 📄 License

There is no license yet. The code is all rights reserved until one is added.
