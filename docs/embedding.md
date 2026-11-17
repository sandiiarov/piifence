# Embedding piifence

A program that runs Claude Code itself (the Agent SDK, a desktop app, a sidecar) can put its sessions behind piifence with three commands. Each prints one JSON object on stdout, writes progress to stderr, and exits non-zero on failure. The examples below are real output from a test run on port 7799, with session ids shown as `<32 hex>` and values left out.

```text
App                       piifence                    Gateway (127.0.0.1:7788)
 │                           │                              │
 ├─ piifence gateway ───────▶├─ reuse, or start detached ──▶│
 │◀─ {url, port, upstream} ──┤                              │
 ├─ piifence session ───────▶│                              │
 │◀─ {session, port, settings}                              │
 ├─ start Claude Code with settings.env and settings.hooks ─▶│  (requests carry x-piifence-session)
 ├─ text with names | piifence reveal ─▶ text with values   │
```

## `piifence gateway [--upstream URL] [--pid PID]`

Reuses the gateway already listening on the port, or starts one detached, and leases it for `PID` (default: the caller, the parent of this process). The gateway keeps running while any leased process lives, and exits 10 seconds (`PIIF_EXIT_WHEN_UNUSED`) after the last one dies. So pass the pid of the long-lived app process when a short-lived shell runs the command.

`--upstream` defaults to `PIIF_UPSTREAM`, else the `ANTHROPIC_BASE_URL` in the shell or Claude Code settings. The port is `PIIF_PORT`, default 7788.

```console
$ piifence gateway --upstream http://127.0.0.1:7800 --pid 4242
{"port":7799,"upstream":"http://127.0.0.1:7800","url":"http://127.0.0.1:7799"}
```

stderr shows `piifence: starting gateway on …` and `piifence: gateway ready (log: …)` the first time, and `piifence: using existing gateway on …` after that. A gateway that forwards somewhere else is not taken over:

```console
$ piifence gateway --upstream http://127.0.0.1:7801
piifence: a gateway on http://127.0.0.1:7799 forwards to "http://127.0.0.1:7800", but this launch wants http://127.0.0.1:7801 …
$ echo $?
1
```

## `piifence session [--session ID] [--qualify-foreign]`

Prints what one Claude Code session needs: a session id (new, or `ID`, 32 hex digits, to keep using one) and the settings to start Claude Code with. It does not start the gateway; run `piifence gateway` first.

```console
$ piifence session --qualify-foreign
{
  "session": "<32 hex>",
  "port": 7799,
  "settings": {
    "env": {
      "ANTHROPIC_BASE_URL": "http://127.0.0.1:7799",
      "ANTHROPIC_CUSTOM_HEADERS": "x-piifence-session: <32 hex>\nx-piifence-qualify-foreign: 1"
    },
    "hooks": {
      "SessionStart": [{"hooks": [{"type": "command", "command": "'/opt/homebrew/opt/piifence/bin/piifence' session-start <32 hex> 7799 qualify"}]}],
      "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "'/opt/homebrew/opt/piifence/bin/piifence' restore <32 hex> 7799"}]}]
    }
  }
}
```

- `ANTHROPIC_CUSTOM_HEADERS` keeps the user's own headers (from the shell, else Claude Code settings) and adds the session header. Any `x-piifence-…` header inherited from an outer piifence session is dropped, so the gateway sees exactly one session id.
- The hooks are required. `SessionStart` binds the session to its conversation and gives the agent the note about names. `PreToolUse` puts real values into tool input. The gateway refuses a request that offers tools from a session whose hooks never ran (HTTP 400, `HOOKS_MISSING`), so a session without them fails closed rather than running tools on names.
- With the Agent SDK, pass `settings.env` as the environment and `settings.hooks` as the hooks setting, or write `settings` to a file and pass it with `--settings`.

### `--qualify-foreign`

A name only means something in the conversation that made it. When a tool shows another conversation's transcript (`cc-search`, or a `.jsonl` under `~/.claude/projects`), its names would read as this conversation's. With `--qualify-foreign`, the gateway rewrites such names in `tool_result` text as `[[piif:<first 8 hex of that conversation's id>:<n>]]`:

- The conversation id comes from the name's own line: the last id before the name, else the first id after it. A line without an id takes the last id of the nearest line above that has one.
- A name whose id is this session's own conversation, or that has no id above it, stays as it is.
- The rewrite is deterministic, so the prompt cache keeps working.
- The session-start note tells the agent what the form means and that nothing fills it in inside a tool argument.

A tool result as Claude Code sent it, and as the provider received it:

```text
2026-11-16	proj	3	abcdef01-2222-4333-8444-555555555555	the token is $PIIF_SECRET_4, id $PIIF_SECRET_4 here
2026-11-16	proj	3	abcdef01-2222-4333-8444-555555555555	the token is [[piif:abcdef01:4]], id [[piif:abcdef01:4]] here
```

Detection does not change: values are still found and named the same way, and qualifying only renames names that already exist.

## `piifence reveal [--session ID | --conversation UUID] [--json]`

Reads text on stdin and prints it with values in place of names.

- `$PIIF_SECRET_<n>` and `${PIIF_SECRET_<n>}` resolve from the live session through the gateway (`--session`), or from that conversation's stored table (`--conversation`). With neither, they stay.
- `[[piif:<8 hex>:<n>]]` resolves from the stored table of the one conversation whose id starts with those 8 hex digits. When none or several match, it stays.
- Stored tables are only read: never saved again, and their 30-day clock is not reset.
- A name that does not resolve stays as it is. Values are never logged.
- Exit 0 also when names stay unresolved; check `unresolved` with `--json`.

```console
$ printf 'own %s, foreign [[piif:%s:1]], unknown [[piif:00000000:3]]' '$PIIF_SECRET_4' 6f0c1a2b \
    | piifence reveal --conversation 6f0c1a2b-… --json
{"text":"own <value>, foreign <value>, unknown [[piif:00000000:3]]","unresolved":["[[piif:00000000:3]]"]}
```

Without `--json`, only the text is printed.

## Rules for the embedding program

- Show revealed text to the user only. Never send it back to the model, or the values reach the provider.
- Keep one `piifence session` per Claude Code session. Reuse its id with `--session` when resuming, so names stay the same.
- Run the gateway as the same user that runs Claude Code: the control socket (`~/.local/state/piifence/run/<port>.sock`) and the Keychain key belong to that user.
