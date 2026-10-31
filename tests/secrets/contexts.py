"""Builders that place a generated value into a Claude Code-shaped /v1/messages request.

A context is `build(make) -> (path, body, keep)`:
  make(salt) returns a formats.Generated (salt "0" is the primary value; other salts
  give more values of the same format), path is the gateway path, body the request
  dict, and keep the non-secret strings that must reach the upstream unchanged.

Run directly for a self-test: `python3 -I tests/secrets/contexts.py`.
"""
import base64
import json
import random
import string

MODEL = "claude-sonnet-5-5"
SYSTEM_PREAMBLE = "You are Claude Code, Anthropic's official CLI for Claude."
SMALL_PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


def tool_id(salt):
    rng = random.Random("toolu|" + salt)
    return "toolu_01" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(22))


def text(t):
    return {"type": "text", "text": t}


def user(*blocks):
    return {"role": "user", "content": list(blocks)}


def assistant(*blocks):
    return {"role": "assistant", "content": list(blocks)}


def request(messages, system=None):
    if system is None:
        system = [{"type": "text", "text": SYSTEM_PREAMBLE, "cache_control": {"type": "ephemeral"}}]
    return {"model": MODEL, "max_tokens": 32000, "stream": True, "system": system, "messages": messages}


def tool_turn(name, tool_input, result, salt="t", is_error=False):
    """An assistant tool_use and the user tool_result answering it."""
    tid = tool_id(name + salt)
    result_block = {"type": "tool_result", "tool_use_id": tid, "content": result}
    if is_error:
        result_block["is_error"] = True
    return [
        assistant(text("Let me check."), {"type": "tool_use", "id": tid, "name": name, "input": tool_input}),
        user(result_block),
    ]


def conversation(*turns, prompt="Help me fix the deploy script.", system=None):
    """A first user prompt, then the given turns, then a short follow-up prompt."""
    messages = [user(text(prompt))]
    for turn in turns:
        messages.extend(turn if isinstance(turn, list) else [turn])
    if messages[-1]["role"] == "assistant":
        messages.append(user(text("ok, continue")))
    return request(messages, system)


def dotenv(g, position=5, crlf=False):
    lines = ["NODE_ENV=production", "PORT=8080", "LOG_LEVEL=debug", "APP_NAME=billing-api",
             "REGION=eu-west-1", "FEATURE_FLAGS=checkout,search", "TIMEOUT_MS=3000"]
    lines.insert(position - 1, g.line)
    return ("\r\n" if crlf else "\n").join(lines) + "\n"


DOTENV_KEEP = ["NODE_ENV=production", "PORT=8080", "APP_NAME=billing-api"]


def numbered(content, arrow=False):
    sep = "\u2192" if arrow else "\t"
    return "\n".join(f"{i:>6}{sep}{line}" for i, line in enumerate(content.split("\n"), 1))


# --- contexts -----------------------------------------------------------------


def prompt_text(make):
    g = make("0")
    return "/v1/messages", request([user(text(f"for the deploy use {g.line} please"))]), ["for the deploy use"]


def prompt_string(make):
    g = make("0")
    body = request([{"role": "user", "content": f"for the deploy use {g.line} please"}])
    return "/v1/messages", body, ["for the deploy use"]


def prompt_with_system_reminder(make):
    g = make("0")
    reminder = ("<system-reminder>\nContents of /repo/CLAUDE.md (project instructions):\n\n"
                f"# Deploy\nRun `make deploy`.\n{g.line}\n</system-reminder>")
    body = request([user(text(reminder), text("deploy the app"))])
    return "/v1/messages", body, ["Run `make deploy`.", "deploy the app"]


def system_array(make):
    g = make("0")
    system = [
        {"type": "text", "text": SYSTEM_PREAMBLE, "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": f"# claudeMd\nUse the staging cluster.\n{g.line}\n"},
    ]
    return "/v1/messages", request([user(text("hi"))], system), ["Use the staging cluster."]


def system_string(make):
    g = make("0")
    return "/v1/messages", request([user(text("hi"))], f"{SYSTEM_PREAMBLE}\n{g.line}"), [SYSTEM_PREAMBLE]


def bash_mode(make):
    g = make("0")
    t = f"<bash-input>cat .env</bash-input><bash-stdout>{dotenv(g)}</bash-stdout><bash-stderr></bash-stderr>"
    return "/v1/messages", request([user(text(t)), assistant(text("I see the env.")), user(text("ok"))]), DOTENV_KEEP


def local_command_stdout(make):
    g = make("0")
    t = f"<local-command-stdout>Loaded config:\n{g.line}\nDone.</local-command-stdout>"
    return "/v1/messages", request([user(text(t))]), ["Loaded config:"]


def tool_use_bash_command(make):
    g = make("0")
    secret = g.secrets[0] if not g.multiline else g.full
    cmd = f'curl -s -H "Authorization: Bearer {secret}" https://api.internal/v1/me'
    body = conversation(tool_turn("Bash", {"command": cmd, "description": "Call the API"}, '{"id": 42}'))
    return "/v1/messages", body, ["curl -s -H", "Call the API"]


def tool_use_write_env(make):
    g = make("0")
    body = conversation(tool_turn("Write", {"file_path": "/repo/.env", "content": dotenv(g)},
                                  "File created successfully at: /repo/.env"))
    return "/v1/messages", body, DOTENV_KEEP + ["File created successfully"]


def tool_use_edit(make):
    g, old = make("0"), make("edit-old")
    tool_input = {"file_path": "/repo/.env", "old_string": old.line, "new_string": g.line, "replace_all": False}
    body = conversation(tool_turn("Edit", tool_input, "The file /repo/.env has been updated."))
    return "/v1/messages", body, ["has been updated"], [old]


def tool_use_subagent_prompt(make):
    g = make("0")
    prompt = f"Investigate why login fails. The service uses {g.line}. Report the root cause."
    body = conversation(tool_turn("Task", {"description": "Debug login", "prompt": prompt,
                                            "subagent_type": "general-purpose"}, "Root cause: expired cert."))
    return "/v1/messages", body, ["Investigate why login fails.", "Root cause: expired cert."]


def read_result_tab(make):
    g = make("0")
    content = numbered(dotenv(g, position=4))
    body = conversation(tool_turn("Read", {"file_path": "/repo/.env"}, content))
    return "/v1/messages", body, ["NODE_ENV=production", "PORT=8080"]


def read_result_arrow(make):
    g = make("0")
    content = numbered(dotenv(g, position=4), arrow=True)
    body = conversation(tool_turn("Read", {"file_path": "/repo/.env"}, content))
    return "/v1/messages", body, ["NODE_ENV=production", "PORT=8080"]


def tool_result_text_array(make):
    g = make("0")
    body = conversation(tool_turn("Bash", {"command": "cat config/prod.env"}, [text(dotenv(g))]))
    return "/v1/messages", body, DOTENV_KEEP


def tool_result_with_image(make):
    g = make("0")
    content = [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": SMALL_PNG}},
               text(f"Screenshot OCR:\nSettings > API\n{g.line}\n")]
    body = conversation(tool_turn("mcp__browser__screenshot", {"url": "https://admin.internal"}, content))
    return "/v1/messages", body, ["Settings > API"]


def bash_echo_bare(make):
    g = make("0")
    var = g.var or "TOKEN"
    body = conversation(tool_turn("Bash", {"command": f"echo ${var}", "description": "Print the value"}, g.full + "\n"))
    return "/v1/messages", body, ["Print the value"]


def grep_result(make):
    g = make("0")
    out = f"src/config.py:12:    {g.line}\nsrc/config.py:13:    timeout = 30\n"
    body = conversation(tool_turn("Grep", {"pattern": "KEY|TOKEN|SECRET", "output_mode": "content"}, out))
    return "/v1/messages", body, ["timeout = 30"]


def git_diff_result(make):
    g = make("0")
    lines = "\n".join("+" + line for line in g.line.split("\n"))
    diff = ("diff --git a/.env.example b/.env.example\nindex 3b18e51..a9c4f2d 100644\n"
            "--- a/.env.example\n+++ b/.env.example\n@@ -1,2 +1,3 @@\n NODE_ENV=production\n"
            f"{lines}\n PORT=8080\n")
    body = conversation(tool_turn("Bash", {"command": "git diff"}, diff))
    return "/v1/messages", body, ["diff --git a/.env.example b/.env.example"]


def json_log_line(make):
    g = make("0")
    log = json.dumps({"level": "debug", "msg": "auth ok", "user_id": 42, "token": g.full})
    body = conversation(tool_turn("Bash", {"command": "tail -1 logs/app.jsonl"}, log + "\n"))
    return "/v1/messages", body, ["auth ok"]


def env_dump(make):
    g = make("0")
    lines = ["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/Users/dev", "SHELL=/bin/zsh", "LANG=en_US.UTF-8",
             "TERM=xterm-256color", "USER=dev", "EDITOR=vim", "PWD=/repo"]
    lines += [f"APP_SETTING_{i}=value{i}" for i in range(30)]
    lines.insert(20, g.line)
    body = conversation(tool_turn("Bash", {"command": "env"}, "\n".join(lines) + "\n"))
    return "/v1/messages", body, ["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/Users/dev"]


def ansi_colored(make):
    g = make("0")
    out = f"\x1b[1mConfig\x1b[0m\n\x1b[32m{g.line}\x1b[0m\n\x1b[33mwarning: debug on\x1b[0m\n"
    body = conversation(tool_turn("Bash", {"command": "./bin/show-config --color"}, out))
    return "/v1/messages", body, ["warning: debug on"]


def crlf_lines(make):
    g = make("0")
    body = conversation(tool_turn("Read", {"file_path": "C:\\repo\\.env"}, dotenv(g, crlf=True)))
    return "/v1/messages", body, ["NODE_ENV=production", "PORT=8080"]


def _log_filler(n_bytes, seed):
    rng = random.Random(seed)
    lines, size = [], 0
    while size < n_bytes:
        line = (f"2026-10-30T12:{rng.randrange(60):02d}:{rng.randrange(60):02d}Z INFO worker[{rng.randrange(9)}] "
                f"processed job {rng.randrange(10**6)} in {rng.randrange(900)}ms queue=default\n")
        lines.append(line)
        size += len(line)
    return "".join(lines)[:n_bytes]


def window_cut(make):
    """A ~14 KB tool result: one value straddles the 6,000-byte window edge, a second
    value of the same format sits in the 5,000-6,000 overlap."""
    g, second = make("0"), make("window-2")
    tool_input = {"command": "kubectl logs deploy/api"}
    # The gateway scans tool output behind this context prefix, so model-window offsets
    # are shifted by its length (see redact_content in src/bin/gateway.rs).
    prefix = len("Tool call: Bash " + json.dumps(tool_input, separators=(",", ":")) + "\nTool output:\n")
    first_at = 6000 - 10 - prefix
    # In the overlap when it fits; long values (PEM blocks) start earlier and run into it.
    second_at = min(5500 - prefix, first_at - len(second.line) - 2)
    filler = _log_filler(16000, "window")
    out = filler[:second_at] + "\n" + second.line + "\n"
    out += filler[len(out):first_at]
    out = out[:first_at] + g.line + "\n" + filler[first_at:14000]
    body = conversation(tool_turn("Bash", tool_input, out))
    return "/v1/messages", body, ["queue=default"], [second]


def repeated_lines(make):
    g = make("0")
    lines = [f"line {i}: ok" for i in range(1, 35)]
    for pos in (2, 9, 30):
        lines[pos - 1] = f"retry {pos}: using {g.line}"
    body = conversation(tool_turn("Bash", {"command": "grep -n using deploy.log"}, "\n".join(lines)))
    return "/v1/messages", body, ["line 1: ok", "line 33: ok"]


def tool_result_is_error(make):
    g = make("0")
    err = f"Error: authentication failed for credential {g.line}\n  at login (auth.js:12)"
    body = conversation(tool_turn("Bash", {"command": "npm run deploy"}, err, is_error=True))
    return "/v1/messages", body, ["at login (auth.js:12)"]


def mcp_tool_result(make):
    g = make("0")
    content = [text("File: config/prod.yml"), text(f"service:\n  name: billing\n  {g.line}\n")]
    body = conversation(tool_turn("mcp__github__get_file_contents", {"owner": "acme", "repo": "app",
                                                                      "path": "config/prod.yml"}, content))
    return "/v1/messages", body, ["File: config/prod.yml"]


def assistant_echo(make):
    g = make("0")
    messages = [user(text("what is in the env file?")),
                assistant(text(f"The file sets {g.line} and a few other values.")),
                user(text("thanks, now rotate it"))]
    return "/v1/messages", request(messages), ["thanks, now rotate it"]


THINKING_SIGNATURE = base64.b64encode(random.Random("signature").randbytes(225)).decode()


def assistant_with_thinking(make):
    g = make("0")
    tid = tool_id("thinking")
    messages = [
        user(text("deploy with the right key")),
        assistant({"type": "thinking", "thinking": "", "signature": THINKING_SIGNATURE},
                  {"type": "tool_use", "id": tid, "name": "Bash",
                   "input": {"command": f"export {g.var or 'TOKEN'}='{g.full}' && make deploy"}}),
        user({"type": "tool_result", "tool_use_id": tid, "content": "deployed"}),
    ]
    return "/v1/messages", request(messages), ["deploy with the right key", "deployed"]


def document_text_source(make):
    g = make("0")
    doc = {"type": "document", "title": "notes.txt",
           "source": {"type": "text", "media_type": "text/plain", "data": f"Ops notes\n{g.line}\nRotate monthly.\n"}}
    return "/v1/messages", request([user(doc, text("summarise these notes"))]), ["summarise these notes"]


def search_result_in_tool_result(make):
    g = make("0")
    result = [{"type": "search_result", "source": "https://wiki.internal/ops", "title": "Ops runbook",
               "content": [text(f"To deploy, export {g.line} first.")]}]
    body = conversation(tool_turn("search_wiki", {"query": "deploy"}, result))
    return "/v1/messages", body, ["Ops runbook"]


def document_with_title_and_context(make):
    g = make("0")
    doc = {"type": "document", "title": "creds for " + g.line, "context": "pasted from " + g.line,
           "source": {"type": "text", "media_type": "text/plain", "data": "Ops notes\nRotate monthly.\n"}}
    return "/v1/messages", request([user(doc, text("summarise these notes"))]), ["summarise these notes"]


def search_result_top_level(make):
    g = make("0")
    result = {"type": "search_result", "source": "https://wiki.internal/ops", "title": "Ops runbook",
              "content": [text(g.line)]}
    return "/v1/messages", request([user(result, text("what does the runbook say?"))]), ["Ops runbook"]


def tool_result_document_block(make):
    g = make("0")
    doc = {"type": "document", "title": "ops.txt",
           "source": {"type": "text", "media_type": "text/plain", "data": f"Ops notes\n{g.line}\n"}}
    body = conversation(tool_turn("fetch_doc", {"id": 7}, [doc]))
    return "/v1/messages", body, ["Let me check."]


def repeated_on_one_line(make):
    g = make("0")
    body = conversation(tool_turn("Bash", {"command": "grep -r TOKEN ."}, f"a.env:{g.line}  b.env:{g.line}\n"))
    return "/v1/messages", body, ["Let me check."]


def count_tokens(make):
    _, body, keep = prompt_text(make)[:3]
    body = dict(body)
    body.pop("stream", None)
    body.pop("max_tokens", None)
    return "/v1/messages/count_tokens", body, keep


def unicode_neighbours(make):
    g = make("0")
    secret = g.secrets[0] if not g.multiline else g.full
    t = f"密钥是{secret}请保管🔑 thanks"
    return "/v1/messages", request([user(text(t))]), ["thanks"]


def _syntax_variants(g):
    v = g.full if not g.multiline else g.full
    name = (g.var or "token").lower()
    return {
        "yaml": f"{name}: {v}\n",
        "toml": f'{name} = "{v}"\n',
        "ini": f"[auth]\n{name} = {v}\n",
        "xml": f"<config><{name}>{v}</{name}></config>",
        "properties": f"app.{name}={v}\n",
        "hcl": f'variable "{name}" {{\n  default = "{v}"\n}}\n',
        "shell_export": f"export {g.var or 'TOKEN'}='{v}'\n",
        "cli_flag": f"./deploy --token={v} --region eu-west-1\n",
    }


def _config_syntax(kind):
    def build(make):
        g = make("0")
        content = _syntax_variants(g)[kind]
        body = conversation(tool_turn("Read", {"file_path": f"/repo/config.{kind}"}, content))
        return "/v1/messages", body, ["Let me check."]

    build.__name__ = f"config_{kind}"
    return build


def url_query_param(make):
    g = make("0")
    secret = g.secrets[0] if not g.multiline else g.full
    out = f"GET https://api.example.com/v1/items?api_key={secret}&page=2 -> 200 OK\n"
    body = conversation(tool_turn("Bash", {"command": "tail -1 access.log"}, out))
    return "/v1/messages", body, ["-> 200 OK"]


def compaction_summary(make):
    g = make("0")
    summary = ("This session is being continued from a previous conversation that ran out of context. "
               f"Summary:\n1. The user configured the deploy with {g.line}.\n2. Tests pass.")
    return "/v1/messages", request([user(text(summary))]), ["2. Tests pass."]


def json_in_write_content(make):
    g = make("0")
    content = json.dumps({"service": "billing", "credentials": {"value": g.full}}, indent=2)
    body = conversation(tool_turn("Write", {"file_path": "/repo/config.json", "content": content},
                                  "File created successfully at: /repo/config.json"))
    return "/v1/messages", body, ['"service": "billing"']


def base64_wrapped(make):
    g = make("0")
    encoded = base64.b64encode(g.full.encode()).decode()
    manifest = ("apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-secrets\ntype: Opaque\n"
                f"data:\n  TOKEN: {encoded}\n")
    body = conversation(tool_turn("Read", {"file_path": "/repo/k8s/secret.yaml"}, manifest))
    return "/v1/messages", body, ["name: app-secrets"]


CONTEXTS = {
    f.__name__: f
    for f in [
        prompt_text, prompt_string, prompt_with_system_reminder, system_array, system_string, bash_mode,
        local_command_stdout, tool_use_bash_command, tool_use_write_env, tool_use_edit,
        tool_use_subagent_prompt, read_result_tab, read_result_arrow, tool_result_text_array,
        tool_result_with_image, bash_echo_bare, grep_result, git_diff_result, json_log_line, env_dump,
        ansi_colored, crlf_lines, window_cut, repeated_lines, tool_result_is_error, mcp_tool_result,
        assistant_echo, assistant_with_thinking, document_text_source, search_result_in_tool_result,
        count_tokens, unicode_neighbours, url_query_param, compaction_summary, json_in_write_content,
        base64_wrapped, document_with_title_and_context, search_result_top_level, tool_result_document_block,
        repeated_on_one_line,
    ]
    + [_config_syntax(k) for k in ["yaml", "toml", "ini", "xml", "properties", "hcl", "shell_export", "cli_flag"]]
}

# Every format runs through these; formats.CORE runs through all of CONTEXTS.
BASE_CONTEXTS = ["prompt_text", "read_result_tab", "tool_use_bash_command"]


def build_case(context_id, make):
    """Run a context. Returns (path, body, keep, extra) where extra lists additional
    Generated values (of the same format) that the body also contains."""
    out = CONTEXTS[context_id](make)
    if len(out) == 3:
        return (*out, [])
    return out


def many_in_one_block(formats_module):
    """One .env holding a value of each formats.MANY format."""
    gens = [formats_module.BY_ID[fid].generate("many") for fid in formats_module.MANY]
    content = "\n".join(["NODE_ENV=production"] + [g.line for g in gens] + ["PORT=8080"]) + "\n"
    body = conversation(tool_turn("Read", {"file_path": "/repo/.env"}, numbered(content)))
    return "/v1/messages", body, ["NODE_ENV=production", "PORT=8080"], gens


def _self_test():
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import formats

    def all_strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, list):
            for item in value:
                yield from all_strings(item)
        elif isinstance(value, dict):
            for k, item in value.items():
                yield k
                yield from all_strings(item)

    fmt_ids = ["github_pat_classic", "pem_rsa_private_key", "url_postgres", "password_with_quote_and_backslash"]
    for cid in CONTEXTS:
        for fid in fmt_ids:
            fmt = formats.BY_ID[fid]
            path, body, keep, extra = build_case(cid, fmt.generate)
            raw = json.dumps(body)
            json.loads(raw)
            strings = list(all_strings(body))
            g = fmt.generate("0")
            if cid != "base64_wrapped":
                for s in g.secrets + [s for e in extra for s in e.secrets]:
                    assert any(v in x for x in strings for v in formats.leak_variants(s)), \
                        f"{cid}/{fid}: value not embedded"
            for k in keep:
                assert any(k in x for x in strings), f"{cid}/{fid}: keep {k!r} not embedded"
                assert not any(k in s or s in k for s in g.secrets), f"{cid}/{fid}: keep overlaps a secret"
            assert path.startswith("/v1/messages")
    path, body, keep, gens = many_in_one_block(formats)
    assert len(gens) == len(formats.MANY)
    print(f"contexts ok: {len(CONTEXTS)}")


if __name__ == "__main__":
    _self_test()
