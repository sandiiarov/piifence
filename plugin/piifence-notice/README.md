# piifence-notice — Claude Code plugin

Shows a Claude Code notice (a `systemMessage`) whenever the piifence gateway replaced a secret on its way to the provider. It shows **metadata only**, from the gateway's `/stats` endpoint: the kind of secret, its `$PIIF_SECRET_<N>` name and a masked preview (first and last 4 characters). Never the value, never the surrounding text.

## Loading

`piifence claude` loads the plugin for its session with `--plugin-dir` and sets `PIIF_GATEWAY_URL`. `scripts/install.sh` installs it to `~/.local/share/piifence/plugin/piifence-notice`. Nothing is copied into your Claude Code config.

Requires `python3` (standard library only).

## What you see

- `SessionStart`: `piifence: active — secret redaction on (nothing replaced yet)`, or `… — N secret(s) replaced so far` (N distinct values since the gateway started).
- `Stop`, after a turn in which a secret was replaced for the first time (a value re-sent in the history is not reported again): `piifence: replaced 1 secret(s) — API_KEY×1 ($PIIF_SECRET_1 sk-a…9xQz)`

If the gateway does not answer, the hook fails and Claude Code shows the error.

## State

`/tmp/piifence-notice-state.json` (or `$PIIF_NOTICE_STATE`) stores the number of distinct values seen, the gateway's `/stats` `values` counter, so a notice covers only values replaced for the first time. Delete it to see the current total again.
