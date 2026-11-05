# piifence

**Keep your secrets and personal data out of your coding agent's prompts.**

Coding agents send a lot to the model provider: your prompts, file contents, `.env` files, command output, logs. piifence is a small local proxy that sits between Claude Code and the provider. It finds secrets and personal data in every outgoing request and swaps each one for an environment variable name before the request leaves your machine. The real value stays in Claude Code's environment, so commands the agent runs locally still work with it.

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

When your prompt holds a sensitive value, a toast lists what was replaced, with a masked preview and never the value itself:

```text
piifence replaced 1 sensitive value(s) in your prompt:
  secret if-a…12j1 → $PIIF_SECRET_1
```

Nothing is asked and there is nothing to configure: every value is replaced. After each turn Claude Code also lists the values found anywhere in the request, including tool output and files:

```text
piifence: redacted 1 value(s) — secret×1 ($PIIF_SECRET_2 post…prod)
```

### How the agent uses a secret it can't see

- **In your prompt.** piifence puts the value in an environment variable inside Claude Code, rewrites your prompt to use the variable's name, and tells the agent the variable is there. Commands the agent runs locally get the real value; the provider never does.
- **In files, command output and `CLAUDE.md`.** The value reaches the provider as `$PIIF_SECRET_2`. When the agent runs a Bash command that names that variable, piifence sets it just before the command runs.
- **Printed back.** If a command prints a value, as `echo $PIIF_SECRET_1` would, piifence puts the variable's name back in its place before the output reaches the provider.

What you see in Claude Code stays as it was: only what goes to the provider is changed.

A value gets a placeholder like `<secret_3>` instead of a variable in two cases: when its category has used all 9 variables of the session, and for any request that does not come from `piifence claude` (for example a plain `claude` pointed at the proxy), since nothing could hand that session the values.

### Secrets only, no model download

To redact only credentials, using pattern rules and no model, create `~/.config/piifence/config.toml`:

```toml
categories = ["secret"]
llm_filter = false
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
        mod["piifence-env mod<br/>prompt values → $PIIF_*<br/>sets $PIIF_* before Bash runs"]
    end
    cc -- request --> gw["piifence gateway (localhost)<br/>detects values in every part of the request<br/>names them $PIIF_* (or a placeholder)"]
    gw -- redacted request --> provider([Provider])
    provider -- response, streamed back untouched --> cc
    mod <-. "values for this session only" .-> gw
```

`piifence claude` starts two pieces and connects them with a random per-session id:

- **The gateway**, a proxy on `127.0.0.1:7788`. It runs detection on every outgoing request (prompt, tool output, files, system prompt) and replaces each value with its `$PIIF_*` name. It keeps the values in memory and hands them only to the session they belong to.
- **The `piifence-env` mod**, loaded into Claude Code for that session. It rewrites your prompt, shows the toast, and fetches values from the gateway when a Bash command needs them.

A secret the agent finds in a file goes through these steps:

```mermaid
sequenceDiagram
    participant A as Agent (Claude Code)
    participant M as piifence-env mod
    participant G as piifence gateway
    participant P as Provider
    A->>G: tool output with GITHUB_TOKEN=ghp_…
    G->>P: GITHUB_TOKEN=$PIIF_SECRET_1
    P-->>A: run curl -H "Authorization: Bearer $PIIF_SECRET_1" …
    A->>M: Bash command names $PIIF_SECRET_1
    M->>G: look up PIIF_SECRET_1 (this session)
    G-->>M: the real value
    M->>A: set $PIIF_SECRET_1, then run the command
```

Properties:

- **Everything stays local.** Detection runs on your machine; nothing is sent anywhere except the redacted request.
- **Stable names.** The same value gets the same name on every turn, so the conversation stays consistent and prompt caching keeps working.
- **No raw values stored.** Values live only in the gateway's memory and Claude Code's environment. Logs, toasts and the notice hold only labels, counts and masked previews.
- **Fails closed.** If a request cannot be redacted, it is blocked, not sent. If the gateway cannot take a value from your prompt, the prompt is blocked rather than put an unprotected value in the environment.

## Limitations

- Experimental. Use it as a safety net, not as your only protection.
- Input only: the agent works with placeholders or variable names, and responses are not scanned or rewritten.
- Environment variables are limited to 9 per category (`$PIIF_SECRET_1` to `$PIIF_SECRET_9`) per session; after that, values become placeholders.
- The gateway keeps the values behind those variables in memory only. If it restarts during a session, the variables made from your prompts are registered again with your next prompt, but variables made from tool output are lost until the agent reads that output again.
- The agent can use every secret it comes across in commands, including sending it somewhere.
- macOS only, and Claude Code is the only supported agent today.

## Development

```bash
cargo build --release
scripts/check.sh          # every check; runs the model suites too when weights are present
```

`AGENTS.md` describes the architecture and contracts; `docs/gateway-spike.md` covers the gateway in depth.

## License

No license yet: the code is all rights reserved until one is added.
