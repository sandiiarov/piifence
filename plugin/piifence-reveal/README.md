# piifence-reveal — Claude Code plugin

Draws the real value in place of each `$PIIF_SECRET_<N>` name in the agent's replies and in tool rows (such as `Bash(…)`), on your screen only. The piifence gateway replaces secrets with names before anything reaches the provider, so the agent writes names, and without this plugin you read names too, even where the name stands for something harmless such as a port number.

## Loading

`piifence claude` passes piifence's `plugin/` folder to `--plugin-dir`, which loads this plugin next to the notice plugin. Nothing is copied into your Claude Code config.

## How it works

It is a hooks module (`hooks/register.ts`) with two `ui.render` hooks, on `AssistantMessage` and `ToolUse`. When a drawn text holds a name it does not know yet, it runs `piifence env <session> <port>` (the session id from `ANTHROPIC_CUSTOM_HEADERS`, the port from `ANTHROPIC_BASE_URL`, both set by `piifence claude`) and keeps the values in memory, loading them again at most every 2 seconds.

Only the drawing changes. The transcript file, the ctrl+o view and what the model reads keep the names. A name it cannot resolve is drawn as it is.

## Turning it off

Set `PIIF_REVEAL=off` before `piifence claude` to see the names instead, for example while you share your screen.
