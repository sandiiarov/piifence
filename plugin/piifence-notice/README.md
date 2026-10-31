# piifence-notice — Claude Code plugin

Shows a Claude Code notice (a `systemMessage`) whenever the piifence gateway
redacted input on its way to the provider. It displays **metadata only** — label
counts and placeholder tokens from the gateway `/stats` endpoint; never the raw
values, never the surrounding text.

## Requirements

- piifence gateway running on `http://127.0.0.1:7788` (override with
  `PIIF_GATEWAY_URL`).
- `python3` (stdlib only; `curl` not required).

## Install

```bash
cp -R plugin/piifence-notice ~/.claude/skills/piifence-notice
```

The plugin auto-loads on the next Claude Code session as
`piifence-notice@skills-dir`. To test without installing:

```bash
claude --plugin-dir /path/to/plugin/piifence-notice ...
```

Disable/remove:

```bash
claude plugin disable piifence-notice@skills-dir
rm -rf ~/.claude/skills/piifence-notice
```

## What you see

- `SessionStart`: `piifence: active — input redaction on (nothing redacted yet)`
  or `… — N value(s) redacted so far` (N distinct values since the gateway started).
- `Stop` (after a turn in which a value was redacted for the first time; a value
  re-sent in the history is not reported again):
  `piifence: redacted 2 value(s) — private_email×2 (<private_email_1>, <private_email_2>)`

If the gateway is not running, the plugin stays silent (no piifence in the path,
no noise).

## State

`/tmp/piifence-notice-state.json` stores the number of distinct values seen (the
gateway's `/stats` `values` counter) so notices are only shown for values redacted
for the first time. Delete it to re-show the current total.
