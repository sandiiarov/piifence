# piifence

**Keep your secrets and personal data out of your coding agent's prompts.**

Coding agents send a lot to the model provider: your prompts, file contents, `.env` files, command output, logs. piifence is a small local proxy that sits between Claude Code and the provider. It finds secrets and personal data in every outgoing request and swaps each one for an environment variable name before the request leaves your machine. The real value stays on your machine, and commands the agent runs locally still get it.

```text
you type:       deploy with DATABASE_URL=postgres://admin:hunter2@db.internal/prod
                and send the report to jane.doe@acme.io

provider sees:  deploy with DATABASE_URL=$PIIF_SECRET_1
                and send the report to $PIIF_EMAIL_1

agent runs:     psql "$PIIF_SECRET_1" -c 'select 1'      # gets the real URL locally
```

## Install

macOS only (the detector uses Apple's Accelerate framework). Needs [Homebrew](https://brew.sh); the installer adds Rust, git and gitleaks if they are missing.

```bash
curl -fsSL https://raw.githubusercontent.com/sandiiarov/piifence/main/scripts/install.sh | bash
```

This builds piifence and installs it to `~/.local/bin`. Without the model it can only run in [secrets-only mode](#secrets-only-no-model-download). To also download the detection model (about 2.8 GB, needed for personal data and for secrets with no known format):

```bash
curl -fsSL https://raw.githubusercontent.com/sandiiarov/piifence/main/scripts/install.sh | bash -s -- --with-weights
```

## Use

Start Claude Code through piifence and tell it where your provider is:

```bash
PIIF_UPSTREAM=https://api.anthropic.com piifence claude
```

If you already set `ANTHROPIC_BASE_URL` in your shell or Claude Code settings, just run `piifence claude`. Every argument after `claude` goes to Claude Code as usual.

Nothing is asked and there is nothing to configure: every value is replaced. After each turn Claude Code lists the values found anywhere in the request, including your prompt, tool output and files, with a masked preview and never the value itself:

```text
piifence: redacted 1 value(s) — secret×1 ($PIIF_SECRET_1 post…prod)
```

### How the agent uses a secret it can't see

- **Anywhere in the request.** Your prompt, files, command output and `CLAUDE.md` reach the provider with each value replaced by a name such as `$PIIF_SECRET_1`. What you see in Claude Code stays as it was: only what goes to the provider is changed.
- **In commands.** Before every Bash command, Claude Code exports the session's `$PIIF_*` variables with their real values, so `curl -H "Authorization: Bearer $PIIF_SECRET_1" …` works. The provider never gets the value.
- **Printed back.** If a command prints a value, as `echo $PIIF_SECRET_1` would, piifence puts the variable's name back in its place before the output reaches the provider.
- **What the agent is told.** When the session starts, the agent gets a short note: `$PIIF_*` names stand for real values kept on your machine, it can use them in Bash commands, and a value it sees as a name was not exposed. Without the note, an agent that sees `$PIIF_SECRET_1` in command output tends to warn you that a secret leaked.

A value gets a placeholder like `<secret_3>` instead of a variable for any request that does not come from `piifence claude` (for example a plain `claude` pointed at the proxy), since nothing could hand that session the values.

### Secrets only, no model download

To redact only credentials, using pattern rules and no model, create `~/.config/piifence/config.toml`:

```toml
categories = ["secret"]
llm_filter = false
```

### Values it leaves alone

The detection model tends to call any random-looking string a secret. piifence drops what the model finds when the whole value is an identifier, a hash, a path or a number: UUIDs (including Claude Code's session ids in `~/.claude/projects/…`), git SHAs, image digests, `toolu_…` ids, AWS resource ids, `sed -n '885,1150p'` ranges, versions and timestamps. It also drops stand-in secrets such as `sk-...`, `YOUR_API_KEY` and `***`. A value of one of those shapes is still replaced when a secret keyword comes right before it, as in `API_KEY=886dcfc3-…`. Known secret formats found by gitleaks are always replaced.

If piifence still replaces a value of yours that is not sensitive, list a regex for it in `~/.config/piifence/config.toml`:

```toml
allow = ['^PROJ-\d+$', '^build-[0-9a-f]{12}$']
```

## What it catches

| Category | Examples |
|---|---|
| `secret` | API keys and tokens (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack and many more), private keys, JWTs, passwords in config files and connection strings |
| `private_email`, `private_phone`, `private_person`, `private_address` | contact details and names |
| `account_number`, `private_url`, `private_date` | account and card numbers, private links, dates |

Secrets are found by [gitleaks](https://github.com/gitleaks/gitleaks) rules plus [OpenAI Privacy Filter](https://github.com/eugenehp/privacy-filter-rs), a small model that runs locally on the CPU. Personal data needs the model. `piifence.toml.example` shows how to pick categories.

## How it works

```mermaid
flowchart LR
    you([You]) --> cc
    subgraph cc [Claude Code]
        bash["Bash commands<br/>get $PIIF_* exported first"]
    end
    cc -- request --> gw["piifence gateway (localhost)<br/>detects values in every part of the request<br/>names them $PIIF_*"]
    gw -- redacted request --> provider([Provider])
    provider -- response, streamed back untouched --> cc
    bash <-. "values for this session only" .-> gw
```

`piifence claude` starts the gateway, gives the session a random id, and launches Claude Code with a temporary settings file:

- **The gateway**, a proxy on `127.0.0.1:7788`. It runs detection on every outgoing request (prompt, tool output, files, system prompt) and replaces each value with its `$PIIF_*` name. It keeps the values in memory and hands them only to the session they belong to.
- **A `SessionStart` hook.** It gives the agent the note about `$PIIF_*` names, and adds one line to the file Claude Code sources before every Bash command (`CLAUDE_ENV_FILE`). That line runs `piifence env`, which fetches the session's values from the gateway and exports them.

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
- **No raw values stored.** Values live only in the gateway's memory and in the environment of the commands the agent runs. Logs and the notice hold only labels, counts and masked previews.
- **Fails closed.** If a request cannot be redacted, it is blocked, not sent. If the gateway does not answer before a command, the command runs without the values.

## Limitations

- Experimental. Use it as a safety net, not as your only protection.
- Input only: the agent works with placeholders or variable names, and responses are not scanned or rewritten.
- The gateway keeps the values behind the variables in memory only. If it restarts during a session, values get names again as they are found in the next requests, possibly with different numbers.
- The agent can use every secret it comes across in commands, including sending it somewhere.
- A secret that looks like an id, such as 32 hex characters with no keyword like `key` or `token` before it, is sent as is.
- macOS only, and Claude Code is the only supported agent today.

## Development

```bash
cargo build --release
scripts/check.sh          # every check; runs the model suites too when weights are present
```

`AGENTS.md` describes the architecture and contracts; `docs/gateway-spike.md` covers the gateway in depth.

## License

No license yet: the code is all rights reserved until one is added.
