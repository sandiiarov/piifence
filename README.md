# piifence

**Keep your secrets out of your coding agent's prompts.**

Coding agents send a lot to the model provider: your prompts, file contents, `.env` files, command output, logs. piifence is a small local proxy that sits between Claude Code and the provider. It finds secrets (API keys, tokens, passwords, private keys, credentials in connection strings) in every outgoing request and swaps each one for an environment variable name before the request leaves your machine. The real value stays on your machine, and commands the agent runs locally still get it.

```text
you type:       deploy with DATABASE_URL=postgres://admin:hunter2@db.internal/prod

provider sees:  deploy with DATABASE_URL=$PIIF_SECRET_1

agent runs:     psql "$PIIF_SECRET_1" -c 'select 1'      # gets the real URL locally
```

piifence looks for secrets only. Names, emails and other personal data are sent as they are.

## Install

macOS only (the detector uses Apple's Accelerate framework). Needs [Homebrew](https://brew.sh); the installer adds Rust, git and gitleaks if they are missing.

```bash
curl -fsSL https://raw.githubusercontent.com/sandiiarov/piifence/main/scripts/install.sh | bash
```

This builds piifence, installs it to `~/.local/bin`, and downloads the secret model (about 128 MB) to `~/.local/share/piifence/model`.

## Use

Start Claude Code through piifence and tell it where your provider is:

```bash
PIIF_UPSTREAM=https://api.anthropic.com piifence claude
```

If you already set `ANTHROPIC_BASE_URL` in your shell or Claude Code settings, just run `piifence claude`. Every argument after `claude` goes to Claude Code as usual.

There is nothing to configure: every secret found is replaced. After each turn Claude Code lists the secrets found anywhere in the request, including your prompt, tool output and files, with a masked preview and never the value itself:

```text
piifence: replaced 1 secret(s) — DATABASE_CREDENTIAL×1 ($PIIF_SECRET_1 post…prod)
```

### How the agent uses a secret it can't see

- **Anywhere in the request.** Your prompt, files, command output and `CLAUDE.md` reach the provider with each secret replaced by a name such as `$PIIF_SECRET_1`. What you see in Claude Code stays as it was: only what goes to the provider is changed.
- **In commands.** Before every Bash command, Claude Code exports the session's `$PIIF_SECRET_*` variables with their real values, so `curl -H "Authorization: Bearer $PIIF_SECRET_1" …` works. The provider never gets the value.
- **Printed back.** If a command prints a value, as `echo $PIIF_SECRET_1` would, piifence puts the variable's name back in its place before the output reaches the provider.
- **What the agent is told.** When the session starts, the agent gets a short note: `$PIIF_*` names stand for real values kept on your machine, it can use them in Bash commands, and a value it sees as a name was not exposed. Without the note, an agent that sees `$PIIF_SECRET_1` in command output tends to warn you that a secret leaked.

The gateway only serves `piifence claude` sessions: a messages request without the session id that `piifence claude` adds is refused.

### Values it leaves alone

The model sometimes calls a random-looking string a secret. piifence drops what the model finds when the whole value is an identifier, a hash, a path, a number or a plain word: UUIDs (including Claude Code's session ids in `~/.claude/projects/…`), git SHAs, image digests, `toolu_…` ids, AWS resource ids, `sed -n '885,1150p'` ranges, versions and timestamps. It also drops stand-in secrets such as `sk-...`, `YOUR_API_KEY` and `***`, anything under 4 characters, and any span with no letter or digit, such as a lone `{`. A value of one of those shapes is still replaced when a secret keyword comes right before it, as in `API_KEY=886dcfc3-…`. Known secret formats found by gitleaks are always replaced.

If piifence still replaces a value of yours that is not a secret, list a regex for it in `~/.config/piifence/config.toml` (see `piifence.toml.example`):

```toml
allow = ['^PROJ-\d+$', '^build-[0-9a-f]{12}$']
```

## What it catches

Three detectors run on every piece of text, and a value any of them finds is replaced:

| Detector | Finds |
|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) rules | known formats: AWS, GitHub, OpenAI, Anthropic, Stripe, Slack and many more, private keys, JWTs, passwords assigned in config files, credentials in URLs; also base64-encoded copies of these |
| [cbx-secrets-detector-32M](https://huggingface.co/CobuildX-AI/cbx-secrets-detector-32M) | secrets with no known format, from context: an API key, access token, password, database or cloud credential, private or encryption key, or another secret. A 32M-parameter model that runs locally on the CPU |
| key rule | a quoted random-looking value whose key, or the key of the block around it, names a secret: `"api_key": "…"`, `password: '…'`, the `default` of an HCL `variable "API_KEY"` |

The model reads tool output the way a shell transcript shows it: `$ <command>` before Bash output, `$ cat <path>` before a file, and `VAR=` before the output of `echo $VAR`, so a bare value printed by a command is read with its name.

## How it works

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

- **The gateway**, a proxy on `127.0.0.1:7788`. It runs detection on every outgoing request (prompt, tool output, files, system prompt) and replaces each secret with its `$PIIF_SECRET_*` name. It keeps the values in memory and hands them only to the session they belong to.
- **A `SessionStart` hook.** It gives the agent the note about `$PIIF_*` names, and adds one line to the file Claude Code sources before every Bash command (`CLAUDE_ENV_FILE`). That line runs `piifence env`, which fetches the session's values from the gateway and exports them.

Inside the gateway, each piece of text goes through these steps:

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

A secret the agent finds in a file goes through these steps:

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

Properties:

- **Everything stays local.** Detection runs on your machine; nothing is sent anywhere except the redacted request.
- **Stable names.** The same value gets the same name on every turn, so the conversation stays consistent and prompt caching keeps working.
- **No raw values stored.** Values live only in the gateway's memory and in the environment of the commands the agent runs. Logs and the notice hold only kinds, counts and masked previews.
- **Each text is scanned once.** Claude Code sends the whole conversation on every turn. The gateway remembers what it found in each piece of text in `~/.cache/piifence/detections.jsonl` (set `PIIF_CACHE_DIR` to move it), so a resumed session does not scan its history again. The file holds a hash of each text with the positions and kinds found in it, never the text or the values. A new piifence build, model, allow list or gitleaks version starts from an empty cache.
- **Long text is scanned in pieces.** The model reads text in windows of 3,000 bytes, each with 500 more bytes of lookahead, so a value on a window edge is still seen whole. On an M4 CPU it reads about 19 KB of new text per second.
- **Fails closed.** If a request cannot be scanned, it is blocked, not sent. If the gateway cannot start, Claude Code is not launched. If the gateway does not answer before a command, `piifence env` prints an error and the command runs without the values.

## Limitations

- Experimental. Use it as a safety net, not as your only protection.
- Secrets only: personal data such as names, emails and phone numbers is sent as it is.
- Input only: the agent works with variable names, and responses are not scanned or rewritten.
- The gateway keeps the values behind the variables in memory only. If it restarts during a session, values get names again as they are found in the next requests, possibly with different numbers.
- The agent can use every secret it comes across in commands, including sending it somewhere.
- A secret that looks like an id, such as 32 hex characters with no keyword like `key` or `token` before it, is sent as is.
- macOS only, and Claude Code is the only supported agent today.

## Development

```bash
cargo build --release
scripts/fetch-weights.sh /tmp/piifence-model
PIIF_MODEL_DIR=/tmp/piifence-model scripts/check.sh    # every check, including the secret suite
```

`CLAUDE.md` describes the architecture and contracts. `tests/secrets/README.md` covers the end-to-end suite, and `docs/model-options.md` the model benchmarks behind the choice of model.

## License

No license yet: the code is all rights reserved until one is added.
