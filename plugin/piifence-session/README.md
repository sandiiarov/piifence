# piifence-session

The hooks that make `$PIIF_SECRET_<N>` names work in a `piifence claude` session.

- `SessionStart` runs `piifence session-start`. It gives the agent the note on what the names are, binds the session to Claude Code's conversation id, and adds the line that exports the session's values before every Bash command to `CLAUDE_ENV_FILE`.
- `PreToolUse` runs `piifence restore` on every tool call. It puts the real values into the tool's input, so a file the agent writes or an MCP argument holds the value, not the name.

`piifence claude` loads this plugin with `--plugin-dir` and sets the environment the hooks read: `PIIF_BIN` (the piifence binary), `PIIF_SESSION`, `PIIF_SESSION_PORT` and `PIIF_SESSION_NESTED`. The hooks live in a plugin, not in the `--settings` file the launcher writes, because a managed policy can drop the hooks of settings files while it still loads plugins.

If a policy blocks these hooks too, the gateway notices: the `SessionStart` hook never reaches it, so it refuses the session's agent requests with an error that says so, instead of letting the agent write names into files.
