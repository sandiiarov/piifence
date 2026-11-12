# piifence-reveal — Claude Code plugin

Draws the real value in place of each `$PIIF_SECRET_<N>` name everywhere Claude Code draws one: the agent's replies, your prompts (a compaction summary too), tool rows such as `Bash(…)` and their output, slash-command output and question dialogs. It changes your screen only. The piifence gateway replaces secrets with names before anything reaches the provider, so the agent writes names, and without this plugin you read names too, even where the name stands for something harmless such as a port number.

## Loading

`piifence claude` passes piifence's `plugin/` folder to `--plugin-dir`, which loads this plugin next to the notice plugin. Nothing is copied into your Claude Code config.

## How it works

It is a hooks module (`hooks/register.ts`) with `ui.render` hooks on `AssistantMessage`, `UserMessage`, `ToolUse` (input and output), `ToolResult`, `CommandOutput` and `AskUserQuestion`. When a drawn text holds a name it does not know yet, it runs `piifence env <session> <port>` (the session id from `ANTHROPIC_CUSTOM_HEADERS`, the port from `ANTHROPIC_BASE_URL`, both set by `piifence claude`) and keeps the values in memory, loading them again at most every 2 seconds.

Only the drawing changes. The transcript file and what the model reads keep the names. A name it cannot resolve is drawn as it is. Thinking blocks and hook messages have no render hook in Claude Code, so a name there stays a name.

## Turning it off

Set `PIIF_REVEAL=off` before `piifence claude` to see the names instead, for example while you share your screen.
