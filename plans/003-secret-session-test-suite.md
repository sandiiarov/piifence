# Plan 003: Add an end-to-end secret test suite built from Claude Code request shapes

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving to the next step. If anything in the "STOP conditions" section occurs, stop and report — do not improvise. When done, update the status row for this plan in `plans/README.md` — unless a reviewer dispatched you and told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 39dd159..HEAD -- src/bin/gateway.rs src/config.rs gitleaks.toml AGENTS.md`
> This plan adds new files and only reads the gateway's behaviour. If `src/bin/gateway.rs` changed, re-read "How the gateway behaves" below against the live code. Plans 001 and 002 are expected to change it; that is fine. If request handling (`/health`, `/v1/messages`, header forwarding) changed, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: L (1–2 days: about half for the format catalogue, half for contexts, the harness and triage)
- **Risk**: LOW (adds test files only; no product code changes)
- **Depends on**: none. Run it before plans 001 and 002, so it can catch regressions they introduce.
- **Category**: tests
- **Planned at**: commit `39dd159`, 2026-10-30

## Why this matters

piifence is a local proxy that redacts secrets and personal data from Claude Code's API requests before they reach the model provider. The project's main promise is that no credential leaves the machine. Today that promise is tested by about 30 single-sentence cases (`tests/corpus.json`, and the untracked `tests/corpus-secrets.json`), scored only by which labels the detector returned.

Leaks in practice come from where a secret sits inside a real Claude Code request, not only from its format. Examples:
- a `.env` file shown by the Read tool with line-number prefixes
- a key at the very start of a Bash tool result
- a value repeated on line 3 of a block
- a secret straddling the 6,000-byte detection window
- a secret inside a block type the gateway never walks

This plan builds a black-box suite. It sends realistic `/v1/messages` bodies through the real gateway into a local fake upstream, then checks what actually went over the wire. It covers many secret formats across many request locations, plus hard negatives (UUIDs, hashes, env references) that must not be redacted. The result is a coverage report by format and by location, with every current gap recorded explicitly, so improvements and regressions are both visible.

## Current state

### How the gateway behaves (read from `src/bin/gateway.rs` at 39dd159)

- Binary: `target/release/piifence-gateway`, built by `cargo build --release`.
- Env: `PIIF_UPSTREAM` (required, base URL it forwards to), `PIIF_PORT` (default 7788), `PIIF_MODEL_DIR` (model weights dir), `PIIF_AUDIT_LOG` (default `/tmp/piifence-audit.log`; set it to a temp file), `PIIF_CATEGORIES` (comma-separated categories; overrides the config file), `PIIF_CONFIG` (path to a TOML config with `categories = [...]` and `llm_filter = true|false`; format in `piifence.toml.example`), `PIIF_GITLEAKS_CONFIG` (path to `gitleaks.toml`).
- On start it prints `piifence gateway listening on http://127.0.0.1:<port>` to stderr. `GET /health` returns 200 `ok`.
- Requests from a browser (any `Origin` header) or with a `Host` other than `127.0.0.1:<port>` / `localhost:<port>` get 403. Python's `urllib` sends `Host: 127.0.0.1:<port>`, which is accepted.
- `POST /v1/messages` and `POST /v1/messages/count_tokens`: the JSON body is redacted, then forwarded to `PIIF_UPSTREAM` + the same path. All request headers are forwarded except `host`, `content-length`, `accept-encoding` and `connection`, so a custom header such as `x-piif-case` reaches the upstream. If redaction fails, the gateway answers 502 and forwards nothing.
- Other `POST /v1/messages/*` paths are refused with 403.
- What is redacted today (`redact_payload`, `redact_content`, lines 362-524): `system` (a string or text blocks); in `messages[].content` (a string or an array), `text` blocks, `tool_result.content` (a string or an array of text blocks, scanned with the originating tool call as context), and every string leaf of `tool_use.input`. Any other block type is forwarded untouched. User text is also searched for `<bash-input>…</bash-input>` with `<bash-stdout>…</bash-stdout>` or `<local-command-stdout>…</local-command-stdout>`.
- Placeholders look like `<secret_1>`, `<private_email_2>`, `<account_number_3>`, and so on.
- The model scans long text in 6,000-byte windows with 1,000 bytes of overlap (`src/detect.rs:177-179`).

### gitleaks

`gitleaks.toml` at the repo root extends the gitleaks default rules (`[extend] useDefault = true`, gitleaks 8.30.1) and adds four rules: `piifence-aws-access-token`, `piifence-openai-project-key`, `piifence-url-credentials`, `piifence-opencode-key`. The default rule set, with each rule's regex, is `config/gitleaks.toml` in the gitleaks repo at tag `v8.30.1`: https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml. That file is the authority for what a format must look like for its gitleaks rule to fire.

`.gitleaksignore` lists fingerprints of documented test fixtures, so the repo stays clean under a gitleaks scan. This suite must not add any secret-shaped literal to the repo. See the rule in step 1.

### Existing test conventions

- `tests/corpus.json`: an array of `{id, tier, text, expect: [labels]}` cases, run by `cargo run --release` (`src/main.rs`).
- Python already exists in the repo (`plugin/piifence-notice/scripts/notice.py`) and uses the standard library only. Match that: no third-party Python packages.

## Commands you will need

| Purpose | Command (run from repo root) | Expected on success |
|---|---|---|
| Build | `cargo build --release` | exit 0 |
| gitleaks present | `gitleaks version` | prints `8.30.1` or later |
| Generator self-check | `python3 -I tests/secrets/run.py --check-generators` | prints one line per format; exit 0 |
| Full suite | `python3 -I tests/secrets/run.py --model-dir <weights dir>` | exit 0; prints the coverage report |
| One mode | `... --mode secret` (modes: `all`, `secret`, `secret-rules`) | exit 0 |
| Subset | `... --filter github` (substring of case id) | exit 0 |
| Repo stays clean | `gitleaks dir tests/secrets --no-banner` | `no leaks found` |

Model weights: if `data/config.json` does not exist, ask the operator for the weights directory (on the planning machine it is `/Users/alexs/piifence-trial/src/data`).

## Scope

**In scope** (create):
- `tests/secrets/run.py` — harness: fake upstream, gateway lifecycle, case runner, checks, report
- `tests/secrets/formats.py` — secret format catalogue and value generators
- `tests/secrets/contexts.py` — builders that place a value into a Claude Code request body
- `tests/secrets/negatives.py` — hard negatives that must not be redacted
- `tests/secrets/expectations.json` — recorded known gaps
- `tests/secrets/README.md` — how to run the suite and how to triage a failure

**In scope** (edit): `AGENTS.md` — add one bullet pointing to the suite.

**Out of scope** (do NOT touch):
- Any file under `src/`, `plugin/`, `scripts/`, and `gitleaks.toml`. This plan measures; it does not fix. A failing case becomes a recorded gap, not a code change.
- `tests/corpus.json`, `tests/corpus-secrets.json`, `src/main.rs` — the model-level corpus stays as is.
- `.gitleaksignore` — if the repo scan finds something in `tests/secrets`, fix the fixture (step 1 rule), never add an ignore.

## Git workflow

- Branch: `feature/secret-session-tests` from `main`.
- Commit messages: imperative summary of 60 characters or less, blank line, one bullet per change, trailer `Co-authored-by: Claude <noreply@anthropic.com>`. Example from `git log`: "Window long model input and keep secret spans whole".
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Format catalogue with runtime generators (`tests/secrets/formats.py`)

**Rule for the whole suite: no secret-shaped literal is ever written to a file.** Every secret value is generated at runtime from a template by a seeded `random.Random`. The same format id always produces the same value, which keeps runs reproducible. This keeps `gitleaks dir` clean and avoids GitHub push protection.

Define a small template language and a generator:
- `{A:n}`: n characters from upper-case letters and digits
- `{a:n}`: n characters from lower-case letters and digits
- `{L:n}`: n letters, either case
- `{h:n}`: n lower-case hex digits
- `{H:n}`: n upper-case hex digits
- `{d:n}`: n decimal digits
- `{b62:n}`: n base62 characters
- `{b64:n}`: n base64 characters (letters, digits, `+`, `/`)
- `{b64url:n}`: n base64url characters (letters, digits, `-`, `_`)
- `{pw:n}`: a human-style password of length n, mixing letters, digits and at least one of `!#%&*-_.`
- `{at}`: a literal `@`. Use it in URL templates so the template text itself (in `formats.py`) does not look like a URL with embedded credentials to gitleaks. Likewise, write PEM header lines as `"-----BEGIN " + kind + " PRIVATE KEY-----"`, never as one literal.
- Everything else is literal.

Each format is a dict:

```python
{
    "id": "github_pat_classic",   # unique, snake_case
    "family": "vcs",              # cloud | vcs | ai | payments | comms | registry | saas | structural | generic
    "template": "ghp_{b62:36}",
    "var": "GITHUB_TOKEN",        # variable name used when a context writes an assignment
    "gitleaks_rule": "github-pat",  # expected rule id, or None if no rule should match
    "multiline": False,
}
```

Some formats are composite and need a function instead of a template; allow `"build": callable(rng) -> str`. Use this for: PEM blocks (header line, 64-char base64 body lines, footer), Basic auth (`base64("user:" + password)`), docker `config.json` `auth`, and JSON-embedded PEM (`\n` escaped).

Required catalogue (at least these, about 85 formats). Templates are starting points. For every row with a gitleaks rule, open the v8.30.1 default config linked above, find the rule, and make the template satisfy its regex. If a rule id below does not exist in v8.30.1, set `gitleaks_rule` to the closest real id or `None`, and note it in a comment.

| family | id | template / build | var |
|---|---|---|---|
| cloud | aws_access_key_id | `AKIA{A:16}` | AWS_ACCESS_KEY_ID |
| cloud | aws_secret_access_key | `{b64:40}` | AWS_SECRET_ACCESS_KEY |
| cloud | gcp_api_key | `AIza{b64url:35}` | GOOGLE_API_KEY |
| cloud | gcp_service_account_json | build: JSON object with `"type": "service_account"` and `"private_key"` holding an escaped PEM | GOOGLE_APPLICATION_CREDENTIALS_JSON |
| cloud | azure_storage_account_key | `{b64:86}==` | AZURE_STORAGE_KEY |
| cloud | azure_ad_client_secret | `{L:3}{d:1}Q~{b64url:34}` | AZURE_CLIENT_SECRET |
| cloud | azure_sas_signature | `sv=2022-11-02&ss=b&srt=sco&sp=rwdlac&se=2027-01-01T00:00:00Z&sig={b64url:43}%3D` | AZURE_SAS |
| cloud | digitalocean_pat | `dop_v1_{h:64}` | DIGITALOCEAN_TOKEN |
| cloud | heroku_api_key_v2 | `HRKU-AA{b64url:58}` | HEROKU_API_KEY |
| cloud | alibaba_access_key_id | `LTAI{a:20}` | ALIBABA_ACCESS_KEY_ID |
| cloud | cloudflare_api_token | `{b64url:40}` | CLOUDFLARE_API_TOKEN |
| vcs | github_pat_classic | `ghp_{b62:36}` | GITHUB_TOKEN |
| vcs | github_oauth | `gho_{b62:36}` | GH_OAUTH_TOKEN |
| vcs | github_user_to_server | `ghu_{b62:36}` | GH_USER_TOKEN |
| vcs | github_server_to_server | `ghs_{b62:36}` | GH_APP_TOKEN |
| vcs | github_refresh | `ghr_{b62:36}` | GH_REFRESH_TOKEN |
| vcs | github_fine_grained_pat | `github_pat_11{A:20}_{b62:59}` | GITHUB_PAT |
| vcs | gitlab_pat | `glpat-{b64url:20}` | GITLAB_TOKEN |
| vcs | gitlab_pipeline_trigger | `glptt-{h:40}` | GITLAB_TRIGGER_TOKEN |
| vcs | atlassian_api_token | `ATATT3{b64url:186}` | ATLASSIAN_API_TOKEN |
| ai | anthropic_api_key | `sk-ant-api03-{b64url:93}AA` | ANTHROPIC_API_KEY |
| ai | anthropic_admin_key | `sk-ant-admin01-{b64url:93}AA` | ANTHROPIC_ADMIN_KEY |
| ai | openai_project_key | `sk-proj-{b64url:156}` | OPENAI_API_KEY |
| ai | openai_legacy_key | `sk-{b62:20}T3BlbkFJ{b62:20}` | OPENAI_API_KEY |
| ai | huggingface_token | `hf_{L:34}` | HF_TOKEN |
| ai | openrouter_key | `sk-or-v1-{h:64}` | OPENROUTER_API_KEY |
| ai | groq_key | `gsk_{b62:52}` | GROQ_API_KEY |
| ai | replicate_token | `r8_{b62:37}` | REPLICATE_API_TOKEN |
| ai | perplexity_key | `pplx-{b62:48}` | PERPLEXITY_API_KEY |
| ai | xai_key | `xai-{b62:80}` | XAI_API_KEY |
| ai | opencode_key | `oc_sk_{h:32}` | OPENCODE_API_KEY |
| payments | stripe_live_secret | `sk_live_{b62:24}` | STRIPE_SECRET_KEY |
| payments | stripe_restricted | `rk_live_{b62:24}` | STRIPE_RESTRICTED_KEY |
| payments | stripe_test_secret | `sk_test_{b62:24}` | STRIPE_TEST_KEY |
| payments | stripe_webhook_secret | `whsec_{b62:32}` | STRIPE_WEBHOOK_SECRET |
| payments | square_access_token | `EAAA{b64url:60}` | SQUARE_ACCESS_TOKEN |
| payments | braintree_access_token | `access_token$production${a:16}${h:32}` | BRAINTREE_TOKEN |
| comms | slack_bot_token | `xoxb-{d:11}-{d:13}-{b62:24}` | SLACK_BOT_TOKEN |
| comms | slack_user_token | `xoxp-{d:11}-{d:11}-{d:13}-{h:32}` | SLACK_USER_TOKEN |
| comms | slack_app_token | `xapp-1-A{A:10}-{d:13}-{h:64}` | SLACK_APP_TOKEN |
| comms | slack_webhook_url | `https://hooks.slack.com/services/T{A:8}/B{A:10}/{b62:24}` | SLACK_WEBHOOK_URL |
| comms | discord_webhook_url | `https://discord.com/api/webhooks/{d:18}/{b64url:68}` | DISCORD_WEBHOOK |
| comms | twilio_api_key | `SK{h:32}` | TWILIO_API_KEY |
| comms | sendgrid_key | `SG.{b64url:22}.{b64url:43}` | SENDGRID_API_KEY |
| comms | mailgun_key | `key-{h:32}` | MAILGUN_API_KEY |
| comms | mailchimp_key | `{h:32}-us{d:2}` | MAILCHIMP_API_KEY |
| comms | telegram_bot_token | `{d:10}:AA{b64url:33}` | TELEGRAM_BOT_TOKEN |
| registry | npm_token | `npm_{b62:36}` | NPM_TOKEN |
| registry | pypi_token | `pypi-AgEIcHlwaS5vcmc{b64url:70}` | PYPI_TOKEN |
| registry | rubygems_key | `rubygems_{h:48}` | GEM_HOST_API_KEY |
| registry | nuget_key | `oy2{a:43}` | NUGET_API_KEY |
| registry | dockerhub_pat | `dckr_pat_{b64url:27}` | DOCKERHUB_TOKEN |
| saas | vault_service_token | `hvs.{b64url:90}` | VAULT_TOKEN |
| saas | terraform_cloud_token | `{b62:14}.atlasv1.{b64url:67}` | TFE_TOKEN |
| saas | doppler_token | `dp.pt.{b62:43}` | DOPPLER_TOKEN |
| saas | pulumi_token | `pul-{h:40}` | PULUMI_ACCESS_TOKEN |
| saas | grafana_service_account | `glsa_{b62:32}_{h:8}` | GRAFANA_TOKEN |
| saas | newrelic_user_key | `NRAK-{A:27}` | NEW_RELIC_API_KEY |
| saas | datadog_api_key | `{h:32}` | DD_API_KEY |
| saas | shopify_access_token | `shpat_{h:32}` | SHOPIFY_ACCESS_TOKEN |
| saas | linear_api_key | `lin_api_{b62:40}` | LINEAR_API_KEY |
| saas | postman_api_key | `PMAK-{h:24}-{h:34}` | POSTMAN_API_KEY |
| saas | sentry_user_token | `sntryu_{h:64}` | SENTRY_AUTH_TOKEN |
| saas | supabase_pat | `sbp_{h:40}` | SUPABASE_ACCESS_TOKEN |
| saas | planetscale_password | `pscale_pw_{b64url:43}` | PLANETSCALE_PASSWORD |
| saas | age_secret_key | `AGE-SECRET-KEY-1{A:58}` | AGE_KEY |
| structural | pem_rsa_private_key | build: `-----BEGIN RSA PRIVATE KEY-----`, 10 lines of 64 base64 chars, footer | (multiline) |
| structural | pem_ec_private_key | build, `EC PRIVATE KEY` | (multiline) |
| structural | pem_openssh_private_key | build, `OPENSSH PRIVATE KEY` | (multiline) |
| structural | pem_pkcs8_private_key | build, `PRIVATE KEY` | (multiline) |
| structural | pem_encrypted_private_key | build, `ENCRYPTED PRIVATE KEY` | (multiline) |
| structural | pgp_private_key_block | build, `PGP PRIVATE KEY BLOCK` | (multiline) |
| structural | jwt | `eyJ{b64url:30}.eyJ{b64url:60}.{b64url:43}` | ACCESS_TOKEN |
| structural | basic_auth_header | build: `Basic ` + base64(`deploy:` + `{pw:16}`); the secret to check is the base64 part | (header) |
| structural | bearer_opaque | `{b62:40}` placed as `Authorization: Bearer <v>` | (header) |
| structural | url_postgres | `postgres://app:{pw:18}{at}db.internal:5432/app`; the secret is the password | DATABASE_URL |
| structural | url_mysql | `mysql://root:{pw:14}{at}10.0.0.5:3306/shop` | MYSQL_URL |
| structural | url_mongodb_srv | `mongodb+srv://svc:{pw:20}{at}cluster0.abcde.mongodb.net/db` | MONGO_URI |
| structural | url_redis | `redis://:{pw:24}{at}cache.internal:6379/0` | REDIS_URL |
| structural | url_amqp | `amqp://worker:{pw:16}{at}mq.internal:5672/` | AMQP_URL |
| structural | url_git_https_token | `https://x-access-token:` + github_pat_classic + `@github.com/acme/app.git` | GIT_REMOTE |
| structural | sqlserver_conn_string | `Server=tcp:sql.internal,1433;Database=app;User Id=sa;Password={pw:18};` | SQL_CONN |
| structural | jdbc_password | `jdbc:postgresql://db.internal/app?user=app&password={pw:16}` | JDBC_URL |
| structural | kubeconfig_token | `{b64url:120}` placed as `token: <v>` under a kubeconfig user | (yaml) |
| structural | docker_config_auth | build: base64(`user:` + `{pw:20}`) placed as `"auth": "<v>"` | (json) |
| structural | netrc_password | `{b62:40}` placed as `machine github.com login bot password <v>` | (netrc) |
| generic | password_human | `{pw:14}` | DB_PASSWORD |
| generic | password_with_quote_and_backslash | build: a password containing `"`, `'` and `\` | DB_PASSWORD |
| generic | password_with_dollar_and_space | build: a password containing `$` and a space | ADMIN_PASSWORD |
| generic | hex32_with_keyword | `{h:32}` | API_KEY |
| generic | hex64_with_keyword | `{h:64}` | SIGNING_SECRET |
| generic | base64_40_with_keyword | `{b64:40}` | CLIENT_SECRET |
| generic | hex32_bare_no_keyword | `{h:32}` placed with no keyword at all (expected gap) | (none) |

For composite formats, the catalogue entry must also say which substring is the secret to check: the password, not the whole URL.

Add `--check-generators` to `run.py` (step 4). It generates every format, pipes `<var>=<value>` (or the composite as-is) into `gitleaks stdin --report-format json --report-path - --exit-code 0 --no-banner -c gitleaks.toml`, and prints `format_id  expected_rule  actual_rules`. Exit non-zero if any format with a non-None `gitleaks_rule` is not matched by that rule. This separates generator mistakes from pipeline gaps.

**Verify**: `python3 -I tests/secrets/run.py --check-generators` → exit 0. `gitleaks dir tests/secrets --no-banner` → `no leaks found`.

### Step 2: Claude Code request contexts (`tests/secrets/contexts.py`)

A context is a function `build(value, fmt, rng) -> (path, body, keep)`:
- `path` is `/v1/messages`, or `/v1/messages/count_tokens` for one context.
- `body` is a complete request dict.
- `keep` is a list of non-secret strings from the same body that must reach the upstream unchanged; it measures over-redaction around the secret.

Every body must look like what Claude Code sends:
- `model`, `max_tokens`, `stream: true`
- `system` as an array of text blocks, the first with `cache_control: {"type": "ephemeral"}`
- `messages` alternating user/assistant
- `tool_use` blocks with ids like `toolu_01` + 22 base62 chars
- `tool_result` blocks that reference those ids

Use a shared helper that wraps a payload into this skeleton, so each context only builds its own part.

Implement at least these contexts (id → what it builds):

1. `prompt_text` — user text block: `use {VAR} {v} for the deploy`
2. `prompt_string` — user `content` as a plain string
3. `prompt_with_system_reminder` — user content: a text block `<system-reminder>\nContents of /repo/CLAUDE.md:\n…{VAR}={v}…\n</system-reminder>`, then the prompt block
4. `system_array` — the value inside a `system` text block (as CLAUDE.md content)
5. `system_string` — `system` as one string
6. `bash_mode` — user text `<bash-input>cat .env</bash-input><bash-stdout>{dotenv}</bash-stdout>`, where `{dotenv}` is 8 lines with the secret on line 5
7. `local_command_stdout` — `<local-command-stdout>…{v}…</local-command-stdout>`
8. `tool_use_bash_command` — assistant `tool_use` name `Bash`, `input.command` = `curl -s -H "Authorization: Bearer {v}" https://api.internal/v1/me`, plus its `tool_result`
9. `tool_use_write_env` — `Write` with `file_path: "/repo/.env"`, `content`: a dotenv containing the value
10. `tool_use_edit` — `Edit` with the value in `new_string` and a different generated value of the same format in `old_string` (both must be redacted)
11. `tool_use_subagent_prompt` — `Task` (also try `Agent`) with `input.prompt` containing the value
12. `read_result_tab` — `Read` tool_result string in Claude Code's numbered format: lines `     1\tKEY=value`, the secret on line 4
13. `read_result_arrow` — same, but with the `     1→` prefix style
14. `tool_result_text_array` — `tool_result.content` = `[{type: text, text: …}]`
15. `tool_result_with_image` — `[{type: image, source: {type: base64, media_type: image/png, data: <a small valid PNG base64>}}, {type: text, text: …{v}…}]`
16. `bash_echo_bare` — Bash `echo ${VAR}`, tool_result is the bare value plus `\n`, so the secret is at offset 0
17. `grep_result` — `src/config.py:12:    api_key = "{v}"`
18. `git_diff_result` — a unified diff adding `+{VAR}={v}`
19. `json_log_line` — `{"level":"debug","msg":"auth ok","token":"{v}"}` inside tool output
20. `env_dump` — `env` output, 40 lines (PATH, HOME, SHELL, LANG…), the secret in the middle; `keep` includes PATH and HOME lines
21. `ansi_colored` — the value wrapped in `\x1b[32m…\x1b[0m`
22. `crlf_lines` — dotenv with `\r\n` line endings
23. `window_cut` — about 14,000 bytes of realistic log filler; the value placed so it starts 10 bytes before byte 6,000 (it crosses the first window edge), and a second value (another generated value of the same format) at about byte 5,500 (inside the overlap)
24. `repeated_lines` — the same value on lines 2, 9 and 30 of one tool result
25. `many_in_one_block` — one dotenv with 12 different formats from the catalogue (all must be redacted); used once, not per format
26. `tool_result_is_error` — `is_error: true` and an error message containing the value
27. `mcp_tool_result` — tool name `mcp__github__get_file_contents`, array content
28. `assistant_echo` — an earlier assistant text block repeating the value (models do echo secrets)
29. `assistant_with_thinking` — an earlier assistant message: `[{type: thinking, thinking: "", signature: "<300 base64 chars>"}, {type: tool_use, …value in input…}]`. Extra check: the `signature` and `thinking` fields must arrive byte-identical.
30. `document_text_source` — user content block `{type: document, source: {type: text, media_type: text/plain, data: …{v}…}, title: "notes.txt"}`
31. `search_result_in_tool_result` — tool_result content `[{type: search_result, source: …, title: …, content: [{type: text, text: …{v}…}]}]`
32. `count_tokens` — the `prompt_text` body sent to `/v1/messages/count_tokens`
33. `unicode_neighbours` — the value directly between CJK characters and an emoji with no spaces
34. `config_syntaxes` — one case per syntax, each holding the value: YAML `key: v`, TOML `key = "v"`, INI, XML `<password>v</password>`, Java properties, HCL, shell `export VAR='v'`, CLI flags `--token=v` and `-p'v'`
35. `url_query_param` — `https://api.example.com/v1/items?api_key={v}&page=2`
36. `compaction_summary` — user text beginning `This session is being continued from a previous conversation…` with the value inside the summary
37. `json_in_write_content` — `Write` of `config.json`, whose content is JSON holding the value (so the value is double-escaped in the request)
38. `base64_wrapped` — a Kubernetes Secret manifest with `data: { TOKEN: base64(value) }`. The leak check uses the raw value (it should not appear). Also record whether the base64 form was redacted (report only; expected gap).

Contexts 30, 31 and 38 are expected to fail today. The gateway does not walk `document` or `search_result` blocks, and nothing decodes base64. They must still be built and run, so the gap is visible.

**Verify**: a small self-test at the bottom of `contexts.py` (`python3 -I tests/secrets/contexts.py`) builds every context with a dummy value. It asserts that each body is valid JSON, that the dummy value appears in it, and that every `keep` string appears in it. Expected output: `contexts ok: 38` (or the count you built).

### Step 3: Hard negatives (`tests/secrets/negatives.py`)

Each negative is a string that must reach the upstream unchanged. Place each one in two contexts: `prompt_text` and `read_result_tab`. Generate random parts at runtime as in step 1.
- UUID v4; Anthropic-style request id `req_011C{b62:20}`; full and short git SHAs; a 5-line `git log --oneline` output
- `sha256:{h:64}` docker image digest; npm lockfile `"integrity": "sha512-{b64:86}=="`; `go.sum` line `h1:{b64:43}=`; an `md5sum` output line; `.min.js` chunk names with an 8-hex hash
- env references: `$API_KEY`, `${API_KEY}`, `process.env.API_KEY`, `os.environ["API_KEY"]`, `os.getenv("API_KEY")`, `ENV['API_KEY']`, `${{ secrets.API_KEY }}`, `{{ .Values.apiKey }}`
- placeholders: `YOUR_API_KEY_HERE`, `<your-token>`, `changeme`, `xxxxxxxxxxxxxxxx`, `sk-...`, `***`, piifence's own `<secret_1>` and `$PIIF_SECRET_1`
- other: hex colours, semver strings, ISO timestamps, a 12-hex docker container id, Kubernetes pod names like `api-7d9f8b6c5-x2klm`, an AWS ARN, `127.0.0.1:8080`

Scoring for negatives:
- **Fail**: the string was replaced by a `<secret_N>` placeholder.
- **Other-category false positive** (reported, not failed): it was replaced by any other placeholder, such as `<account_number_N>`.

### Step 4: The harness (`tests/secrets/run.py`)

Standard library only. Behaviour:

1. **Fake upstream.** Start a `http.server.ThreadingHTTPServer` on a free port in a thread. For every POST it stores `(path, headers["x-piif-case"], raw body bytes)` and answers `200` with a minimal JSON body.
2. **Gateway.** For each mode, start `target/release/piifence-gateway` as a subprocess. Use `cwd` = repo root, a free `PIIF_PORT`, `PIIF_UPSTREAM=http://127.0.0.1:<sink port>`, `PIIF_AUDIT_LOG=<tempdir>/audit.log`, `PIIF_MODEL_DIR=<--model-dir>`, and `PIIF_GITLEAKS_CONFIG=<repo>/gitleaks.toml`. Poll `GET /health` until 200, with a 180-second timeout; on timeout, print the gateway's stderr and exit 2. Stop the gateway when the mode finishes.
   - `all`: no category override (production default).
   - `secret`: `PIIF_CATEGORIES=secret`.
   - `secret-rules`: `PIIF_CONFIG=<tempdir>/piifence.toml` containing `categories = ["secret"]` and `llm_filter = false`.
   - `--mode` picks one mode; the default runs all three.
3. **Cases.** Build the case list:
   - every format × {`prompt_text`, `read_result_tab`, `tool_use_bash_command`}
   - a core set of 12 formats × every context. The core set: `github_pat_classic`, `aws_access_key_id`, `aws_secret_access_key`, `anthropic_api_key`, `openai_project_key`, `stripe_live_secret`, `slack_bot_token`, `pem_rsa_private_key`, `jwt`, `url_postgres`, `password_human`, `hex32_with_keyword`
   - `many_in_one_block` once
   - all negatives

   The case id is `<context>/<format or negative id>`. `--filter` keeps the ids containing the given substring.
4. **Send.** POST each body to the gateway at its path, with headers `content-type: application/json`, `x-api-key: test`, `anthropic-version: 2023-06-01` and `x-piif-case: <case id>`. Run cases sequentially; the gateway has one detector worker anyway.
5. **Checks per case**, on the body the sink received:
   - **blocked**: no body arrived (the gateway returned 4xx/5xx). Record the status.
   - **leak**: walk every string in the received JSON. For each secret value in the case, set `k = max(8, ceil(len(secret) / 2))`. If any string contains any substring of length `k` of the secret, the case is a leak. This also catches partial redaction. For multiline secrets, use the base64 body lines, not the header.
   - **over-redaction**: each `keep` string must appear unchanged in some string of the received JSON.
   - **structure**: the received JSON must equal the sent JSON once every string is replaced by a marker. Same keys, same arrays, same non-string values. For `assistant_with_thinking`, `signature` and `thinking` must be byte-identical.
   - **determinism** (`--repeat 2`): send the case twice; both received bodies must be byte-identical. Report-only by default; `--require-deterministic` makes it a failure. Turn that on once plan 001 is done.
6. **Expectations.** `tests/secrets/expectations.json` maps `"<mode>|<case id>"` to `{"status": "known_gap", "reason": "<one line>"}`.
   - A failing case that is not listed is a **regression**, and the run exits 1.
   - A listed case that now passes prints `FIXED (remove from expectations): <key>`.
   - `--record-gaps` writes all current failures into the file with reason `"recorded <date>: <first failed check>"`.
7. **Report.** Print:
   - per mode, a table of family → (cases, passed, leaks, blocked, over-redactions)
   - per mode, a table of context → (cases, passed, leaks)
   - negatives: secret false positives and other-category false positives
   - the failure list: case id, failed check, and for leaks the matching window masked to its first 4 characters plus `…`
   - totals

   Never print a full generated value.
8. **Exit codes**: 0 when there are no regressions, 1 when there are regressions, 2 on a harness or setup error.

**Verify**:
- `python3 -I tests/secrets/run.py --model-dir <weights dir> --mode secret --filter github_pat_classic` → runs, prints the report, exits 0 or 1. It must not exit 2.
- Then `--filter negative`-style ids (for example `--filter uuid`) → runs.

### Step 5: First full run, triage, record gaps

1. `python3 -I tests/secrets/run.py --model-dir <weights dir> --repeat 2` (all three modes; expect 15–40 minutes). Save the output: `... | tee /tmp/piif-secrets-first-run.txt`.
2. Triage every failure into exactly one of:
   - **(a) harness or generator bug.** The fixture is wrong: the value doesn't match its gitleaks rule, a `keep` string really is a secret, or the context is malformed. Fix the fixture and re-run.
   - **(b) real product gap.** Leave it failing.
3. When only (b) remains, run with `--record-gaps`. Then edit each reason in `expectations.json` to a one-line human description, for example `"document blocks are not walked by redact_content"` or `"model labels AccountKey as account_number; secret-only mode drops it"`.
4. Re-run without `--record-gaps`.

**Verify**: the re-run exits 0. It prints no `FIXED` lines; if it does, the model output is non-deterministic, which is a STOP condition.

### Step 6: Docs

1. `tests/secrets/README.md`: what the suite checks, how to run each mode, how to read the report, the triage rule from step 5, and the "never write a secret-shaped literal" rule.
2. `AGENTS.md`: under the validation bullets (near line 129, where `cargo run --release` and `cargo test --release` are described), add: "`python3 -I tests/secrets/run.py --model-dir <weights>` runs the end-to-end secret suite (formats × Claude Code request locations) through the real gateway. It must exit 0. Known gaps are listed in `tests/secrets/expectations.json`; a change that fixes one must remove its entry."

**Verify**: `grep -n "tests/secrets/run.py" AGENTS.md` → one match.

## Test plan

This plan is itself the test suite. Its own checks:
- `--check-generators` proves each format matches its intended gitleaks rule.
- The `contexts.py` self-test proves every context embeds the value and its `keep` strings.
- `gitleaks dir tests/secrets` proves no secret-shaped literal was committed.
- Sanity check of the checks themselves: add `--self-test` to `run.py`. It starts only the fake upstream, POSTs three cases straight to it (bypassing the gateway), and runs the checks. Expect `leak` for `prompt_text/github_pat_classic`, `leak` for `window_cut/jwt`, and a pass for the `prompt_text` UUID negative. It exits 0 only if all three results match. Verify: `python3 -I tests/secrets/run.py --self-test` → exit 0.

## Done criteria

- [ ] `python3 -I tests/secrets/run.py --check-generators` exits 0
- [ ] `python3 -I tests/secrets/run.py --self-test` exits 0
- [ ] `python3 -I tests/secrets/contexts.py` prints `contexts ok: N` with N ≥ 38
- [ ] The catalogue has ≥ 85 formats: `python3 -I -c "import sys; sys.path.insert(0,'tests/secrets'); import formats; print(len(formats.FORMATS))"` prints ≥ 85
- [ ] `python3 -I tests/secrets/run.py --model-dir <weights dir>` exits 0, with every failure listed in `expectations.json` with a human-written reason
- [ ] `gitleaks dir tests/secrets --no-banner` reports `no leaks found`
- [ ] `git status` shows only new files under `tests/secrets/`, plus `AGENTS.md` and `plans/README.md`
- [ ] The first-run report (`/tmp/piif-secrets-first-run.txt`) is summarised in the PR description or handed to the operator: per-family and per-context pass rates for each mode, and the gap list
- [ ] `plans/README.md` status row for 003 updated

## STOP conditions

Stop and report back if:
- More than half of all positive cases leak in mode `all`. That points to a harness bug (wrong port, sink not receiving, wrong leak check), not the product.
- The gateway returns 403 for the harness's requests (the Host or Origin check). Report the request headers.
- A run shows `FIXED` lines without any code change: detection is not deterministic, which affects plan 001.
- Making a case pass seems to require editing anything under `src/`, `plugin/` or `gitleaks.toml`. Record it as a gap instead.
- `gitleaks dir tests/secrets` finds a leak you cannot remove by moving it to runtime generation.

## Maintenance notes

- The expectations file is the gap backlog for secret detection. Every detection fix (unwalked block types, gitleaks multi-line offsets, Azure keys, bare keys) should remove entries, and the PR should show the `FIXED` lines.
- When Claude Code changes its request shapes (new block types, new tool names), add a context. Capturing a real request with `PIIF_AUDIT_BODY=1` is a good way to see the current shape. Copy only the structure into a context builder, never the content.
- When gitleaks is upgraded, re-run `--check-generators`; rule ids and regexes change between versions.
- `secret-rules` mode is the fast rules-only configuration. Its gaps show what users lose by setting `llm_filter = false`, which is worth surfacing in the docs.
- Not covered here: response-side leaks (out of scope by design) and endpoints other than `/v1/messages*`.
