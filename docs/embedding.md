# Embedding piifence

After `piifence install`, a program that runs Claude Code itself (a desktop app, a sidecar, a script) needs nothing from piifence to put its sessions behind it. Every Claude Code that reads the user settings, `claude -p` included, sends its requests through the gateway and runs piifence's hooks. The gateway tells sessions apart by Claude Code's own session id, so the id the program already has for a session (from `--output-format json`, `--session-id`, or the Agent SDK) is the id piifence uses.

```text
App                         Claude Code                  Gateway (127.0.0.1:7788)
 │                              │                               │
 ├─ claude -p … ───────────────▶│                               │
 │                              ├─ SessionStart hook: bind ────▶│
 │                              ├─ requests (x-claude-code-session-id) ─▶│
 │◀─ result, session_id ────────┤                               │
 ├─ text with names | piifence reveal --conversation <session_id> ─▶ text with values
```

- **Check first.** `piifence status` prints `{"installed", "routed", "running", "upstream", "url", "port"}`. `routed` is true when the user settings send Claude Code to the gateway, and `running` when the gateway answers.
- **Keep the user settings.** A Claude Code started with `--setting-sources` that leaves out `user`, with its own `ANTHROPIC_BASE_URL`, or with plugins turned off is not covered: it either skips the gateway or is refused by it (HTTP 400, `HOOKS_MISSING`, for a request that offers tools from a session whose `SessionStart` hook never ran).
- **Resume to keep names.** `--resume <id>` and `--continue` keep the session id, so the conversation gets its names back, even after the gateway restarted. `--fork-session` and `/clear` start a new id with no names.
- **Subagents share their parent's names.** Claude Code sends the parent's session id with a subagent's requests.

## Names from other conversations

Add `x-piifence-qualify-foreign: 1` to `ANTHROPIC_CUSTOM_HEADERS` in the environment of the Claude Code that reads other conversations' transcripts. The gateway reads the header and never forwards it, and the session-start hook then adds a note about the form below.

A name only means something in the conversation that made it. When a tool shows another conversation's transcript (`cc-search`, or a `.jsonl` under `~/.claude/projects`), its names would read as this conversation's. With the header, the gateway rewrites such names in `tool_result` text as `[[piif:<first 8 hex of that conversation's id>:<n>]]`:

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

## `piifence reveal --conversation UUID [--json]`

Reads text on stdin and prints it with values in place of names.

- `$PIIF_SECRET_<n>` and `${PIIF_SECRET_<n>}` resolve from the conversation `--conversation`, a Claude Code session id: from the running gateway when it answers, which also knows names not saved yet, else from the conversation's stored table. Without `--conversation`, they stay.
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
- Run Claude Code and `piifence reveal` as the user who ran `piifence install`: the control socket (`~/.local/state/piifence/run/<port>.sock`) and the Keychain key belong to that user.
