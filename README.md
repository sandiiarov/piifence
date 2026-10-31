# piifence

**Keep your secrets and personal data out of your coding agent's prompts.**

Coding agents send a lot to the model provider: your prompts, file contents, `.env` files, command output, logs. piifence is a small local proxy that sits between Claude Code and the provider. It finds secrets and personal data in every outgoing request and replaces them with placeholders before the request leaves your machine.

```text
you type:       deploy with DATABASE_URL=postgres://admin:hunter2@db.internal/prod
                and send the report to jane.doe@acme.io

provider sees:  deploy with DATABASE_URL=<secret_1>
                and send the report to <private_email_1>
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

After each turn Claude Code shows what was redacted, without the value itself:

```text
piifence: redacted 1 value(s) — secret×1 (<secret_1> post…prod)
```

### Let the agent use a secret without seeing it

A placeholder hides the value, but the agent can't use it either. piifence can instead put the value in an environment variable inside Claude Code and send only the variable's name. Commands the agent runs locally get the real value; the provider never does.

```text
you type:       use this API key if-ajsdlk231lj12kl12j1 to call the staging API

piifence asks:  piifence detected 1 sensitive value(s) in this prompt:
                  secret if-a…12j1 → $PIIF_SECRET_1
                [Use $PIIF_SECRET_1]  [Redact]  [Send raw]  [Block]

provider sees:  use this API key $PIIF_SECRET_1 to call the staging API

agent runs:     curl -H "Authorization: Bearer $PIIF_SECRET_1" https://staging.example.com/...
```

Secrets in command output, tool results and `CLAUDE.md` become variables automatically, with no question asked. If you close the dialog, the value is replaced with a placeholder. This is on by default with `piifence claude`.

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

```text
Claude Code ──request──▶ piifence (localhost) ──redacted request──▶ provider
     ▲                                                                   │
     └────────────────── response, streamed back untouched ◀─────────────┘
```

- **Everything stays local.** Detection runs on your machine; nothing is sent anywhere except the redacted request.
- **Stable placeholders.** The same value gets the same placeholder on every turn, so the conversation stays consistent and prompt caching keeps working.
- **No raw values stored.** Logs and the notice hold only labels, counts and masked previews.
- **Fails closed.** If a request cannot be redacted, it is blocked, not sent.
- **You stay in control.** For each prompt with a secret you choose: turn it into an environment variable, redact it, send it raw, or block the prompt.

## Limitations

- Experimental. Use it as a safety net, not as your only protection.
- Input only: the agent works with placeholders or variable names, and responses are not scanned or rewritten.
- Environment variables are limited to 4 per category (`$PIIF_SECRET_1` to `$PIIF_SECRET_4`) per session; after that, values become placeholders.
- macOS only, and Claude Code is the only supported agent today.

## Development

```bash
cargo build --release
scripts/check.sh          # every check; runs the model suites too when weights are present
```

`AGENTS.md` describes the architecture and contracts; `docs/gateway-spike.md` covers the gateway in depth.

## License

No license yet: the code is all rights reserved until one is added.
