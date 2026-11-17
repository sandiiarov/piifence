# piifence-session

The hooks that make `$PIIF_SECRET_<N>` names work in every Claude Code that `piifence install` sends through the gateway.

- `SessionStart` runs `piifence session-start <port>`. It gives the agent the note on what the names are, binds Claude Code's session id on the gateway so a resumed conversation gets its names back, and adds the line that exports the session's values before every Bash command to `CLAUDE_ENV_FILE`.
- `PreToolUse` runs `piifence restore <port>` on every tool call. It puts the real values into the tool's input, so a file the agent writes or an MCP argument holds the value, not the name.

`piifence install` installs this plugin at user scope from a local marketplace in `~/.local/state/piifence/marketplace`, with the piifence binary's path and the gateway's port written into `hooks/hooks.json` in place of `@PIIFENCE@` and `@PORT@`. The hooks live in a plugin, not in the settings file, because a managed policy can drop the hooks of settings files and still load plugins.

If a policy blocks these hooks too, the gateway notices: the `SessionStart` hook never reaches it, so it refuses the session's agent requests with an error that says so, instead of letting the agent write names into files.
