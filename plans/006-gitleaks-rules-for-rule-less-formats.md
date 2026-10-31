# Plan 006: Catch the rule-less secret formats with piifence gitleaks rules

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat efdd25e..HEAD -- gitleaks.toml tests/secrets/formats.py tests/secrets/expectations.json AGENTS.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition. (Plans 004 and 005 change
> `expectations.json`; that is expected. `gitleaks.toml` and `formats.py`
> must still match the excerpts.)

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (new regexes can over-match; the suite's 66 negative cases and a repo-wide gitleaks baseline are the gates)
- **Depends on**: plans/004-walk-every-content-block.md (for the weights-free `--mode secret-rules` run used throughout; the rule changes themselves are independent)
- **Category**: security
- **Planned at**: commit `efdd25e`, 2026-10-30

## Why this matters

In rules-only mode (`llm_filter = false`, the fast path that never loads the model) gitleaks is the whole detector. 147 of the suite's 249 known gaps are in that mode, and 74 of them read "no gitleaks rule or guard matches this format; only the model catches it". The formats are everyday ones: a password assigned in `.env`, YAML or JSON, a JDBC or SQL Server connection string, a `.netrc` line, an `Authorization: Basic` or `Bearer` header, an Azure storage account key or SAS signature, a Discord webhook, a Docker Hub or Braintree token, and a Redis URL with no user name. A second class of gap comes from the default gitleaks rules requiring a quote, space, `;` or line end after the value: an Anthropic key, Stripe key or JWT followed by `&`, `<`, an ANSI escape or CJK text is missed, and in model modes the model misses some of those too (13 gaps say "no gitleaks rule matches and the model misses it here"). Rules are deterministic, so every format caught here is caught in all three modes and in every context, not just where the model happens to work.

## Current state

Files:

- `gitleaks.toml` — the project config: extends the gitleaks default rules and adds four rules. The gateway and the suite both point gitleaks at it (`PIIF_GITLEAKS_CONFIG`).
- `tests/secrets/formats.py` — the format catalogue. Each `Format` lists in `rules` the gitleaks rule ids that must match its generated line; `run.py --check-generators` verifies that.
- `tests/secrets/negatives.py` — 33 strings that must never gain a `<secret_N>` placeholder (UUIDs, git SHAs, digests, env references like `$API_KEY` and `process.env.API_KEY`, placeholders like `changeme`, `YOUR_API_KEY_HERE`, `<your-token>`, `***`). The suite runs each in two contexts.
- `tests/secrets/expectations.json` — known gaps keyed `"<mode>|<context>/<format>"`.
- `AGENTS.md:58-67` — lists the custom rules by name; update it.
- `scripts/install.sh:66` copies `gitleaks.toml` to `$PREFIX/share/piifence/gitleaks.toml`; an installed launcher keeps using the old copy until `scripts/install.sh` is re-run. `src/bin/piifence.rs:109-115` points a checkout's launcher at the repo file directly.

`gitleaks.toml` today, complete:

```toml
# piifence gitleaks config: default rules + AWS key rule variant that also
# matches documentation-style EXAMPLE key IDs. The stock aws-access-token rule
# allowlists values ending in EXAMPLE (gitleaks/gitleaks config line ~217), so
# the canonical example key never reaches a redaction pipeline. A redaction
# gateway should treat it as a secret anyway.
title = "piifence"
[extend]
useDefault = true

[[rules]]
id = "piifence-aws-access-token"
description = "AWS access key ID, including documentation-style EXAMPLE values that the default rule allowlists"
regex = '''\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b'''
entropy = 3
keywords = ["a3t", "akia", "asia", "abia", "acca"]

[[rules]]
id = "piifence-openai-project-key"
description = "OpenAI project/service-account API key (gitleaks default rule length is too strict)"
regex = '''\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b'''
keywords = ["sk-proj", "sk-svcacct", "sk-admin"]

[[rules]]
id = "piifence-url-credentials"
description = "Credentials embedded in a URL (postgres, mysql, mongo, redis, amqp, ftp, http)"
regex = '''\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|ftp|ftps|https?)://[^\s:/@]{1,64}:[^\s@/]{1,128}@[^\s]+'''
keywords = ["://"]

[[rules]]
id = "piifence-opencode-key"
description = "OpenCode API key (bare value in tool output, no assignment keyword)"
regex = '''\boc_sk_[A-Za-z0-9_-]{20,}\b'''
keywords = ["oc_sk_"]
```

How gitleaks 8.30.1 reads a rule (verified against its default config and its stdin behaviour):

- `regex` is Go RE2 syntax: no lookahead or lookbehind; `\b`, `(?i)`, `(?-i:…)`, `\x60` (backtick) work. Write it in a TOML literal string `'''…'''` so backslashes are not escaped.
- The reported `Secret` is the first non-empty capture group, or the whole match when the regex has no group. The gateway redacts the `Secret`.
- `keywords` are lowercase substrings; the rule runs on a text only if at least one keyword occurs in it (case-insensitive). Every rule should have at least one.
- `entropy` is the minimum Shannon entropy of the `Secret` (bits per character). `changeme` is about 2.75; `xxxxxxxxxxxxxxxx` is 0; a random 14-character password is about 3.5.
- `[[rules.allowlists]]` under a rule drops matches: `regexes` are tested against the `Secret` by default, or against the whole match with `regexTarget = "match"`, or the line with `"line"`; `stopwords` are case-insensitive substrings of the secret.

Why the default `generic-api-key` rule misses the password-style formats (`/tmp` copy of the default config, `id = "generic-api-key"`): its value class is `([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})` and it requires `(?:[\x60'"\s;]|\\[nr]|$)` after the value. A password containing `! # % & *`, a base64 value with `+` or `/` after an upper-case letter, or any value followed by `&`, `<` or an escape code does not match.

The `Format` fields that matter, `tests/secrets/formats.py:85-104`:

```python
@dataclasses.dataclass
class Format:
    id: str
    family: str
    template: str = None
    build: object = None  # callable(rng) -> (full, secrets, line or None)
    var: str = None
    rules: tuple = None
    multiline: bool = False
```

`run.py --check-generators` (`tests/secrets/run.py:376-391`) scans each format's `line` with `gitleaks stdin -c gitleaks.toml` and passes when `rules is None` or one listed id is found.

Format lines the new rules must match (the value parts are generated at run time; these are the literal parts, from `tests/secrets/formats.py:137-217` and `220-350`):

| Format id | Line shape (value in `{}`) | Today |
|---|---|---|
| `password_human` | `DB_PASSWORD={14-char password with a symbol}` | no rule; 43 rules-only gaps (it runs in every context) |
| `password_with_quote_and_backslash` | `DB_PASSWORD={value containing " ' and \}` | no rule |
| `password_with_dollar_and_space` | `ADMIN_PASSWORD={value containing $ and a space}` | no rule; a space inside an unquoted value is not matchable, leave it |
| `base64_40_with_keyword` | `CLIENT_SECRET={40 base64 chars}` | `rules=None` with a comment about `+` and `/` |
| `jdbc_password` | `JDBC_URL=jdbc:postgresql://db.internal/app?user=app&password={pw}` | no rule |
| `sqlserver_conn_string` | `SQL_CONN=Server=tcp:sql.internal,1433;Database=app;User Id=sa;Password={pw};` | no rule |
| `netrc_password` | `machine github.com login bot password {40 chars}` | no rule |
| `basic_auth_header` | `Authorization: Basic {base64}` | no rule |
| `bearer_opaque` | `Authorization: Bearer {40 chars}` | no rule |
| `azure_storage_conn_string` | `AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=…;AccountKey={86 base64}==;EndpointSuffix=core.windows.net` | no rule |
| `azure_sas_signature` | `AZURE_SAS=sv=2022-11-02&ss=b&srt=sco&sp=rwdlac&se=…&sig={43 base64url}%3D` | no rule |
| `discord_webhook_url` | `DISCORD_WEBHOOK=https://discord.com/api/webhooks/{18 digits}/{68 base64url}` | no rule |
| `dockerhub_pat` | `DOCKERHUB_TOKEN=dckr_pat_{27 base64url}` | generic rule only when the var is present |
| `braintree_access_token` | `BRAINTREE_TOKEN=access_token$production${16}${32 hex}` | no rule |
| `url_redis_no_user` | `REDIS_URL=redis://:{pw}@cache.internal:6379/0` | url rule needs at least one user character |
| `anthropic_api_key`, `anthropic_admin_key`, `stripe_live_secret`, `stripe_restricted`, `stripe_test_secret`, `jwt` | prefixed tokens | default rules need a delimiter after the value |
| `openrouter_key` `sk-or-v1-{64 hex}`, `groq_key` `gsk_{52}`, `replicate_token` `r8_{37}`, `xai_key` `xai-{80}`, `stripe_webhook_secret` `whsec_{32}`, `supabase_pat` `sbp_{40 hex}`, `atlassian_api_token` `ATATT3{186 base64url}`, `nuget_key` `oy2{43}` | prefixed tokens | generic rule only when the var is present |

Default rule regexes being relaxed (gitleaks 8.30.1 default config):

- `anthropic-api-key`: `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`
- `stripe-access-token`: `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)` with `entropy = 2`
- `jwt`: `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)` with `entropy = 3`

Repository baseline: `gitleaks dir . -c gitleaks.toml` on the checkout reports findings in `docs/gateway-spike.md`, `docs/m1-notes.md`, `src/detect.rs`, `src/guards.rs`, `tests/corpus.json`, `tests/m1-report.txt` (documentation-style example values used on purpose), plus noise under `target/`, `__pycache__` and the untracked `tests/corpus-secrets.json`. The new rules must not add any finding to that list.

Convention: `gitleaks.toml` rule ids are `piifence-<thing>`; each rule has `id`, `description`, `regex`, `keywords`, and `entropy` where the value is free-form. `tests/secrets/README.md:52-54`: never write a secret-shaped literal into the repo; the suite generates every value.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Config parses and rules match their formats | `python3 -I tests/secrets/run.py --check-generators` | `99 formats, 0 mismatches`, exit 0 |
| Rules-only suite (no weights) | `python3 -I tests/secrets/run.py --mode secret-rules` | exit 0, no `FAIL` |
| Full suite | `python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data` | exit 0; about 25 minutes |
| Repo baseline | `gitleaks dir . -c gitleaks.toml --no-banner --no-color --exit-code 0 --report-format json --report-path - \| jq -r '[.[] \| select(.File \| test("^target/\|__pycache__\|corpus-secrets") \| not) \| .File + ":" + (.StartLine\|tostring) + ":" + .RuleID] \| sort \| .[]'` | the same list before and after |
| Suite fixtures stay secret-free | `gitleaks dir tests/secrets --no-banner` | no leaks |
| Build (unchanged code, but the suite needs the binary) | `cargo build --release` | exit 0 |

Weights on this machine: `/Users/alexs/piifence-trial/src/data`. Elsewhere, `scripts/fetch-weights.sh`.

## Scope

**In scope** (the only files you should modify):
- `gitleaks.toml`
- `tests/secrets/formats.py` (`rules=` tuples and the one comment at line 347 only)
- `tests/secrets/expectations.json` (via `--record-gaps`)
- `AGENTS.md` (the rule list at lines 58–67)
- `plans/README.md` (status row)

**Out of scope** (do NOT touch, even though they look related):
- `src/` — no Rust change is needed; if a format only passes with a code change, record it as a gap instead.
- `tests/secrets/negatives.py` and `tests/secrets/contexts.py` — a negative that trips a new rule is a rule bug, never a fixture to delete.
- A bare high-entropy hex rule (`hex32_bare_no_keyword`): it would flag md5sums, git SHAs and digests; leave that format a gap.
- The `generic-api-key` default rule and its delimiter: relaxing a keyword-based rule is a false-positive risk; only prefix-identified tokens get relaxed variants here.
- `scripts/install.sh`.

## Git workflow

- Branch: `fix/gitleaks-rules-for-rule-less-formats` from `main`.
- One commit per step. Message style: summary of at most 60 characters, blank line, bullets, trailer `Co-authored-by: Claude <noreply@anthropic.com>` (see `git log --oneline -8`).
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Record the repository baseline

Run the "Repo baseline" command from the table and save its output to `/tmp/piif-006-baseline.txt`. Expected: about 16 lines, all in the six files named under "Current state".

**Verify**: `wc -l /tmp/piif-006-baseline.txt` → a non-zero count; `grep -c "target/" /tmp/piif-006-baseline.txt` → `0`.

### Step 2: Relax the URL rule and add the assignment rule

In `gitleaks.toml`:

1. In `piifence-url-credentials`, change the user part `[^\s:/@]{1,64}` to `[^\s:/@]{0,64}` so `redis://:password@host` matches.
2. Append this rule:

```toml
[[rules]]
id = "piifence-password-assignment"
description = "Password, secret, key or token assigned with = or : in env, config, shell or JSON; allows the symbols and base64 characters the default generic rule rejects"
regex = '''(?i)(?:^|[\s"'\x60,;{(&?])[a-z0-9_.-]{0,40}?(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)["']?\s*(?:[:=]|=>|:=)\s*(?:"([^"\r\n]{8,128})"|'([^'\r\n]{8,128})'|([^\s"'\x60][^\s\x60;,&]{7,127}))'''
entropy = 3.0
keywords = ["password", "passwd", "pwd", "passphrase", "secret", "key", "token"]

[[rules.allowlists]]
description = "references, templates and placeholders are not values"
regexes = [
    '''^(?:\$|\{\{|<|%\(|os\.|process\.|ENV\[|env\(|getenv|System\.getenv)''',
    '''(?i)^(?:your|change[_-]?me|example|placeholder|sample|dummy|redacted|none|null|true|false|undefined)''',
    '''(?i)_here$''',
    '''^[x*#.-]{8,}$''',
]

[[rules.allowlists]]
description = "identifiers that end in key or token but are not credentials"
regexTarget = "match"
regexes = [
    '''(?i)(?:hot|mon|turn|pub(?:lic)?|primary|foreign|sort|hash|partition|index|idx|shard|cache|ssh[_-]?public|host|session[_-]?id|csrf|xsrf|anti[_-]?forgery|cancellation|continuation|page|next|prev|cursor)[_-]?(?:key|token)''',
    '''(?i)(?:key|token)[_-]?(?:board|code|frame|word|up|down|left|right|press|ring|size|name|id|path|file|type|store|alias|length|count|expiry|expires|ttl|url|uri|endpoint)''',
]
```

How the three value alternatives work: a double-quoted value, a single-quoted value, or an unquoted value that starts with a non-quote and may contain quotes afterwards (so `DB_PASSWORD=ab"cd'ef\12` is captured whole) but stops at whitespace, backtick, `;`, `,` or `&` (so `Password=…;` and `password=…&next=` capture only the value). The first allowlist drops env references (`$API_KEY`, `${{ secrets.X }}`, `process.env.X`, `os.environ[...]`), placeholders and runs of `x`/`*`; the second drops identifiers such as `hotkey`, `csrf_token` or `keyboard` that end in or start with the keyword.

**Verify**: `python3 -I tests/secrets/run.py --check-generators` → exit 0 (the new rule is not yet listed for any format, so this only proves the config parses and nothing regressed). Then `python3 -I tests/secrets/run.py --mode secret-rules` → exit 0 and `negatives: 66 cases, 0 secret false positives`; new `FIXED (remove from expectations)` lines are expected and fine at this point. If any negative shows `secret false positive` or any case shows `over-redaction`, tighten the allowlist or the value class and rerun; do not continue with a false positive.

### Step 3: Add the shape-specific rules

Append to `gitleaks.toml`:

```toml
[[rules]]
id = "piifence-netrc-password"
description = ".netrc credential line (machine … login … password …), also when split over lines"
regex = '''(?i)\bmachine\s+\S+\s+login\s+\S+\s+password\s+(\S{8,})'''
entropy = 3.0
keywords = ["machine"]

[[rules]]
id = "piifence-authorization-header"
description = "Authorization: Basic | Bearer | Token header with a literal credential (env references like $API_KEY do not match)"
regex = '''(?i)\bauthorization["']?\s*[:=]\s*["']?(?:basic|bearer|token)\s+([A-Za-z0-9._~+/=-]{16,})'''
entropy = 3.0
keywords = ["authorization"]

[[rules]]
id = "piifence-azure-storage-account-key"
description = "Azure storage connection string AccountKey"
regex = '''(?i)accountkey=([A-Za-z0-9+/]{86}==)'''
keywords = ["accountkey="]

[[rules]]
id = "piifence-azure-sas-signature"
description = "Azure SAS token signature (sig= query parameter)"
regex = '''(?i)(?:^|[?&;])sig=([A-Za-z0-9%+/_-]{40,120})'''
entropy = 3.0
keywords = ["sig="]

[[rules]]
id = "piifence-discord-webhook"
description = "Discord webhook URL (the token after the channel id grants posting rights)"
regex = '''https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/([A-Za-z0-9_-]{60,80})'''
keywords = ["discord"]

[[rules]]
id = "piifence-dockerhub-pat"
description = "Docker Hub personal access token"
regex = '''\b(dckr_pat_[A-Za-z0-9_-]{27,})\b'''
keywords = ["dckr_pat_"]

[[rules]]
id = "piifence-braintree-access-token"
description = "Braintree access token"
regex = '''\b(access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[0-9a-f]{32})\b'''
keywords = ["access_token$"]
```

**Verify**: `python3 -I tests/secrets/run.py --check-generators` → exit 0; `gitleaks dir tests/secrets --no-banner` → no leaks.

### Step 4: Add delimiter-free variants for prefixed tokens

Append to `gitleaks.toml`. These duplicate default rules minus the trailing-delimiter requirement; the prefix makes them safe without one.

```toml
[[rules]]
id = "piifence-anthropic-key"
description = "Anthropic API/admin key, no delimiter required after the value (default rule misses keys followed by &, <, CJK text or an escape code)"
regex = '''\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{93}AA)'''
keywords = ["sk-ant-"]

[[rules]]
id = "piifence-stripe-secret-key"
description = "Stripe secret/restricted key, no delimiter required after the value"
regex = '''\b((?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{24,99})'''
entropy = 2
keywords = ["sk_test_", "sk_live_", "sk_prod_", "rk_test_", "rk_live_", "rk_prod_"]

[[rules]]
id = "piifence-jwt"
description = "JSON Web Token, no delimiter required after the value"
regex = '''\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.[a-zA-Z0-9\/\\_-]{10,}={0,2})'''
entropy = 3
keywords = ["ey"]

[[rules]]
id = "piifence-openrouter-key"
regex = '''\b(sk-or-v1-[0-9a-f]{64})\b'''
keywords = ["sk-or-v1-"]

[[rules]]
id = "piifence-groq-key"
regex = '''\b(gsk_[A-Za-z0-9]{40,})\b'''
keywords = ["gsk_"]

[[rules]]
id = "piifence-replicate-token"
regex = '''\b(r8_[A-Za-z0-9]{30,})\b'''
keywords = ["r8_"]

[[rules]]
id = "piifence-xai-key"
regex = '''\b(xai-[A-Za-z0-9]{60,})\b'''
keywords = ["xai-"]

[[rules]]
id = "piifence-stripe-webhook-secret"
regex = '''\b(whsec_[A-Za-z0-9]{24,})\b'''
keywords = ["whsec_"]

[[rules]]
id = "piifence-supabase-pat"
regex = '''\b(sbp_[0-9a-f]{40})\b'''
keywords = ["sbp_"]

[[rules]]
id = "piifence-atlassian-api-token"
regex = '''\b(ATATT3[A-Za-z0-9_-]{100,})'''
keywords = ["atatt3"]

[[rules]]
id = "piifence-nuget-key"
regex = '''\b(oy2[a-z0-9]{43})\b'''
keywords = ["oy2"]
```

Give each of the last eight a one-line `description` in the same style as the others.

**Verify**: `python3 -I tests/secrets/run.py --check-generators` → exit 0.

### Step 5: Point the formats at their rules

In `tests/secrets/formats.py` set `rules=` as follows (add to an existing tuple where one exists):

| Format id | `rules` |
|---|---|
| `password_human`, `password_with_quote_and_backslash`, `base64_40_with_keyword`, `jdbc_password`, `sqlserver_conn_string` | `("piifence-password-assignment",)` and replace the comment at line 347 with one saying the piifence assignment rule allows `+` and `/` |
| `netrc_password` | `("piifence-netrc-password",)` |
| `basic_auth_header`, `bearer_opaque` | `("piifence-authorization-header",)` |
| `azure_storage_conn_string` | `("piifence-azure-storage-account-key",)` |
| `azure_sas_signature` | `("piifence-azure-sas-signature",)` |
| `discord_webhook_url` | `("piifence-discord-webhook",)` |
| `dockerhub_pat` | `("piifence-dockerhub-pat",)` |
| `braintree_access_token` | `("piifence-braintree-access-token",)` |
| `url_redis_no_user` | `("piifence-url-credentials",)` |
| `anthropic_api_key`, `anthropic_admin_key` | add `"piifence-anthropic-key"` |
| `stripe_live_secret`, `stripe_restricted`, `stripe_test_secret` | add `"piifence-stripe-secret-key"` |
| `jwt` | add `"piifence-jwt"` |
| `openrouter_key`, `groq_key`, `replicate_token`, `xai_key`, `stripe_webhook_secret`, `supabase_pat`, `atlassian_api_token`, `nuget_key` | the matching new id |

Leave `password_with_dollar_and_space`, `hex32_bare_no_keyword`, `kubeconfig_token`, `docker_config_auth`, `gcp_service_account_json` unchanged.

**Verify**: `python3 -I tests/secrets/run.py --check-generators` → `99 formats, 0 mismatches`, exit 0. If `password_with_quote_and_backslash` prints `BAD`, set its `rules` back to `None` and note it in the maintenance section of your report; everything else must be `ok`.

### Step 6: Run the suite and refresh the known gaps

```sh
cargo build --release
python3 -I tests/secrets/run.py --mode secret-rules
python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data --record-gaps
```

Expected: no `FAIL`, `0 secret false positives` in every mode, and these known-gap removals in `secret-rules` mode: most `*/password_human` entries (the ones whose context has no keyword, such as `bash_echo_bare`, stay), all `*/jdbc_password`, `*/url_redis_no_user`, `*/braintree_access_token`, `*/netrc_password`, `*/dockerhub_pat`, `*/discord_webhook_url`, `*/bearer_opaque`, `*/basic_auth_header`, `*/base64_40_with_keyword`, `*/azure_storage_conn_string`, `*/azure_sas_signature`, and the `ansi_colored`, `config_xml`, `unicode_neighbours`, `url_query_param` entries for `anthropic_api_key`, `stripe_live_secret`, `jwt`. In the model modes, the entries whose reason mentions "followed by '&'" for those three formats should also go. Report the actual before/after counts per mode. For any new entry, replace the auto-generated reason with a one-line cause.

**Verify**: a second run without `--record-gaps` exits 0 with `0 regressions` and `0 fixed` in all three modes; `gitleaks dir tests/secrets --no-banner` → no leaks.

### Step 7: Confirm the repository baseline is unchanged

Rerun the "Repo baseline" command into `/tmp/piif-006-after.txt`.

**Verify**: `diff /tmp/piif-006-baseline.txt /tmp/piif-006-after.txt` → no output. Any new line is a false positive on the repo's own prose, code or fixtures: tighten the responsible rule (allowlist or value class) and go back to Step 6.

### Step 8: Update the rule list in AGENTS.md

Replace the parenthetical list at `AGENTS.md:59-62` (currently naming four custom rules) with a sentence that says the config adds about twenty `piifence-*` rules for formats the default set misses (passwords and secrets assigned with `=` or `:`, URL and header credentials, Azure, Discord, Docker Hub, Braintree, delimiter-free Anthropic/Stripe/JWT variants and eight vendor prefixes) and that `tests/secrets/run.py --check-generators` is the list's test.

**Verify**: `grep -c "check-generators" AGENTS.md` → at least `2`.

## Test plan

- `--check-generators` is the unit test for every rule: each format's line must match at least one listed rule id.
- The suite's 66 negative cases (33 negatives × 2 contexts) in `secret-rules` mode are the false-positive test; they must report `0 secret false positives`.
- `over-redaction` failures in any context are the harmless-line test (the `keep` strings).
- The repo baseline diff (Step 7) is the prose/code false-positive test.
- Full suite: no `FAIL`, gap entries removed as listed in Step 6.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `python3 -I tests/secrets/run.py --check-generators` → `99 formats, 0 mismatches`, exit 0
- [ ] `python3 -I tests/secrets/run.py --mode secret-rules` exits 0 with `0 secret false positives` and no `FAIL`
- [ ] `python3 -I tests/secrets/run.py --model-dir /Users/alexs/piifence-trial/src/data` exits 0 with `0 regressions` and `0 fixed` in all modes
- [ ] `jq -r 'keys[] | select(startswith("secret-rules|"))' tests/secrets/expectations.json | wc -l` is lower than 147 by at least 60
- [ ] `diff /tmp/piif-006-baseline.txt /tmp/piif-006-after.txt` → empty
- [ ] `gitleaks dir tests/secrets --no-banner` → no leaks
- [ ] `git status` shows no modified files outside the in-scope list
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- `gitleaks.toml` or the `Format` dataclass no longer matches the excerpts.
- A negative case reports `secret false positive` and two attempts at tightening the rule have not cleared it (report the negative id and the rule).
- The repo baseline gains a line that you cannot remove without weakening a rule below what its format needs.
- `--check-generators` reports a mismatch for a format whose rule is listed in Step 5 other than `password_with_quote_and_backslash`.
- gitleaks rejects the config (it prints a config error and the suite reports every case `blocked`): report the error text; do not switch to `useDefault = false`.

## Maintenance notes

- Every rule is tied to a format in `tests/secrets/formats.py`; adding a rule without a format (or the reverse) is the thing a reviewer should refuse.
- The assignment rule is the broadest one. Its allowlists are the place to add a word when a false positive appears; prefer adding a negative to `tests/secrets/negatives.py` in the same change so it stays fixed.
- After this lands, installed copies need `scripts/install.sh` again to pick up the new config (it copies `gitleaks.toml`).
- Deferred: a `gitleaks:allow` comment or a `.gitleaksignore` in the gateway's working directory can still suppress findings (`--ignore-gitleaks-allow` restores the former); that is a gateway flag change, tracked in `plans/README.md`.
- Deferred: `password_with_dollar_and_space` (a space inside an unquoted value) and `hex32_bare_no_keyword` stay model-only by design.
