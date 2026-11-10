"""Score candidate secret detectors on the piifence secret suite, without the gateway.

Each suite case's request body has its system and message strings scanned by an engine; every span found becomes
$PIIF_SECRET_N, as in the gateway, and the suite's own evaluate() scores what is left. Engines: gitleaks, cbx (cbx-secrets-detector-32M),
egemma (egemma-pii-secrets, secret labels only, with its own rules). `+gitleaks` unions a model with gitleaks;
`+guards` passes the model's spans through the gateway's guards (src/guards.rs, via examples/guard_filter.rs).
`+shell` frames tool results as a shell transcript (see shell_framing), which is what the gateway does now.
`+isolate` runs the model a second time on a copy where long random-looking tokens glued to non-ASCII text are set
apart with spaces and quotes, and keeps the union (see isolate_view). `+keyrule` adds a rule-based pass: a quoted
random-looking value whose own key or parent block key is secret-named (see key_rule_spans). Both were tuned on this
suite's own failures, so their scores here overstate what they would do on new text.

Without `+shell`, a model sees a tool_result's text after the tool call that produced it
(`Tool call: <name> <input JSON>\nTool output:`), the gateway's framing before 2026-11-09. Only spans inside the
output count. The harness skips env-value replacement. Scored with gitleaks alone it matched the gateway's former
rules-only mode exactly (915/945 on 2026-11-09).

Usage: $PIIF_BENCH_DIR/venv/bin/python -I bench/models/shootout.py [engine ...]   (after bench/models/setup.sh)
       e.g. engines: gitleaks cbx+gitleaks cbx+gitleaks+guards egemma+gitleaks egemma+gitleaks+guards
"""
import collections
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import time

repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
bench = os.environ.get("PIIF_BENCH_DIR", os.path.expanduser("~/.cache/piifence/bench"))
engines_wanted = sys.argv[1:] or ["gitleaks", "cbx", "cbx+gitleaks", "cbx+gitleaks+guards", "egemma", "egemma+gitleaks", "egemma+gitleaks+guards"]
sys.path.insert(0, os.path.join(repo, "tests/secrets"))
import run as suite  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GITLEAKS_CONFIG = os.path.join(repo, "gitleaks.toml")


def gitleaks_spans(text):
    out = subprocess.run(
        ["gitleaks", "stdin", "-c", GITLEAKS_CONFIG, "--report-format", "json", "--report-path", "-",
         "--exit-code", "0", "--no-banner", "--no-color"],
        input=text, capture_output=True, text=True,
    ).stdout
    spans = []
    for finding in json.loads(out or "[]"):
        if any(tag.startswith("decoded:") for tag in finding.get("Tags") or []):
            continue
        value = finding["Secret"]
        start = text.find(value)
        while value and start != -1:
            spans.append((start, start + len(value)))
            start = text.find(value, start + 1)
    return spans


class Cbx:
    def __init__(self):
        module = load_module("cbx_secrets", os.path.join(bench, "dl/cbx32/cbx_secrets.py"))
        self.det = module.SecretDetector(path=os.path.join(bench, "dl/cbx32"), device="cpu")

    def spans(self, text):
        return [(s["start"], s["end"]) for s in self.det.extract(text)]


class Egemma:
    def __init__(self):
        sys.path.insert(0, os.path.join(bench, "dl/egemma"))  # redact.py imports trace_rules from its folder
        module = load_module("redact", os.path.join(bench, "dl/egemma/redact.py"))
        self.red = module.Redactor(backend="onnx")

    def spans(self, text):
        return [(s["start"], s["end"]) for s in self.red.spans(text) if s["label"].startswith("SECRET_")]


SKIP_KEYS = {"type", "role", "id", "tool_use_id", "name", "media_type", "signature", "cache_control", "model"}


def tool_calls(body):
    """tool_use id -> (tool name, input) for every tool call in the request."""
    calls = {}
    for message in body.get("messages", []):
        content = message.get("content")
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_use" and "id" in block:
                calls[block["id"]] = (block.get("name", ""), block.get("input", {}))
    return calls


def gateway_framing(name, tool_input):
    """The gateway's context (gateway.rs `tool_result_context`): input JSON cut at 800 bytes."""
    raw = json.dumps(tool_input, separators=(",", ":"), ensure_ascii=False).encode()[:800]
    return f"Tool call: {name} {raw.decode(errors='ignore')}\nTool output:\n"


ECHO_VAR = re.compile(r'^\s*echo\s+"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?\s*$')


def shell_framing(name, tool_input):
    """A shell transcript, the kind of text code models are trained on. `echo $VAR` output reads as `VAR=<output>`,
    so the name sits right before the value; other Bash commands read as `$ <command>`, Read as `$ cat <path>`."""
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    if name == "Bash" and ECHO_VAR.match(command):
        return f"{ECHO_VAR.match(command).group(1)}="
    if name == "Bash" and command:
        return f"$ {command[:800]}\n"
    if name == "Read" and isinstance(tool_input, dict) and tool_input.get("file_path"):
        return f"$ cat {tool_input['file_path']}\n"
    return gateway_framing(name, tool_input)


def scan_strings(body, visit, framing=gateway_framing):
    """Call visit(str, context) -> str on every string the gateway would redact: system and messages, not thinking
    blocks. `context` is the text a model reads before a tool_result's string (`framing` of its tool call), else
    None."""
    calls = {tool_id: framing(*call) for tool_id, call in tool_calls(body).items()}

    def walk(value, key=None, context=None):
        if isinstance(value, str):
            return value if key in SKIP_KEYS else visit(value, context)
        if isinstance(value, list):
            return [walk(v, key, context) for v in value]
        if isinstance(value, dict):
            if value.get("type") in ("thinking", "redacted_thinking", "image"):
                return value
            if value.get("type") == "tool_result":
                context = calls.get(value.get("tool_use_id"))
            return {k: walk(v, k, context) for k, v in value.items()}
        return value
    out = copy.deepcopy(body)
    for field in ("system", "messages"):
        if field in out:
            out[field] = walk(out[field])
    return out


TOKEN = re.compile(r"[\x21-\x7e]{12,}")


def random_looking(value):
    """Long, no spaces, and mixes letters with digits or symbols; UUIDs and plain words do not count."""
    if re.fullmatch(r"[0-9a-fA-F]{32,}", value):
        return True
    if len(value) < 12 or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value, re.I):
        return False
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    return bool(re.search(r"[A-Za-z]", value)) and bool(re.search(r"[0-9]", value)) and classes >= 3


def isolate_view(text):
    """Copy of `text` where every long random-looking ASCII token that touches a non-ASCII character is set apart
    as ` "token" `, plus a map from each index of the copy to an index of `text` (inserted characters map to the
    next original one). None when nothing changes."""
    cuts = []
    for m in TOKEN.finditer(text):
        before = text[m.start() - 1] if m.start() else " "
        after = text[m.end()] if m.end() < len(text) else " "
        if (ord(before) > 127 or ord(after) > 127) and random_looking(m.group()):
            cuts.append((m.start(), m.end()))
    if not cuts:
        return None
    out, index, last = [], [], 0
    for a, b in cuts:
        out += [text[last:a], ' "', text[a:b], '" ']
        index += list(range(last, a)) + [a, a] + list(range(a, b)) + [b, b]
        last = b
    out.append(text[last:])
    index += list(range(last, len(text) + 1))
    return "".join(out), index


SECRET_NAME = re.compile(r"(?i)api[_-]?key|secret|passw(?:or)?d|\bpwd\b|token|credential|private[_-]?key|access[_-]?key")
BLOCK_OPEN = re.compile(r"[{\[:]\s*$")
KEY_VALUE = re.compile(r"""^\s*["']?([\w.-]+)["']?\s*[:=]\s*(["'])([^"'\s]+)\2\s*,?\s*$""")
WORD = re.compile(r"[A-Za-z_][\w.-]*")


def key_rule_spans(text):
    """Quoted random-looking values whose own key, or the key of the block around them (a JSON/YAML parent object,
    an HCL `variable "name" {`), is secret-named. Blocks are tracked by indentation, so this reads pretty-printed
    JSON, YAML, TOML and HCL, not one-line JSON."""
    spans, stack, offset = [], [], 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped and stripped[0] not in "}]":
            while stack and stack[-1][0] >= indent:
                stack.pop()
            m = KEY_VALUE.match(line)
            if m and random_looking(m.group(3)):
                names = m.group(1) + " " + (stack[-1][1] if stack else "")
                if SECRET_NAME.search(names):
                    spans.append((offset + m.start(3), offset + m.end(3)))
            elif BLOCK_OPEN.search(stripped):
                stack.append((indent, " ".join(WORD.findall(stripped))))
        offset += len(line)
    return spans


def merge(spans):
    merged = []
    for a, b in sorted(spans):
        if merged and a < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


class Guards:
    """The gateway's model-span guards (src/guards.rs), through examples/guard_filter.rs. Offsets in and out are
    Python string indices; the filter works in UTF-8 bytes."""

    def __init__(self):
        target = os.environ.get("CARGO_TARGET_DIR", os.path.join(repo, "target"))
        subprocess.run(["cargo", "build", "--release", "--example", "guard_filter"], cwd=repo, check=True,
                       env=dict(os.environ, CARGO_TARGET_DIR=target), capture_output=True)
        self.proc = subprocess.Popen([os.path.join(target, "release/examples/guard_filter")],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def keep(self, text, spans):
        if not spans:
            return spans
        to_byte = lambda i: len(text[:i].encode())  # noqa: E731
        by_bytes = {(to_byte(a), to_byte(b)): (a, b) for a, b in spans}
        self.proc.stdin.write(json.dumps({"text": text, "spans": list(by_bytes)}) + "\n")
        self.proc.stdin.flush()
        return [by_bytes[tuple(span)] for span in json.loads(self.proc.stdout.readline())]


def run_engine(name, model, cases, guards=None):
    parts = name.split("+")
    use_gitleaks = "gitleaks" in parts
    use_isolate = "isolate" in parts
    use_keyrule = "keyrule" in parts
    stats = {"model_s": 0.0, "bytes": 0}
    counter = [0]

    def visit(text, context):
        spans = []
        if model is not None:
            prefix = context or ""
            t = time.perf_counter()
            found = model.spans(prefix + text)
            stats["model_s"] += time.perf_counter() - t
            stats["bytes"] += len((prefix + text).encode())
            if guards is not None:
                found = guards.keep(prefix + text, found)
            spans += [(max(a, len(prefix)) - len(prefix), b - len(prefix)) for a, b in found if b > len(prefix)]
            view = isolate_view(text) if use_isolate else None
            if view is not None:
                isolated, index = view
                t = time.perf_counter()
                found = model.spans(prefix + isolated)
                stats["model_s"] += time.perf_counter() - t
                stats["bytes"] += len((prefix + isolated).encode())
                if guards is not None:
                    found = guards.keep(prefix + isolated, found)
                found = [(max(a, len(prefix)) - len(prefix), b - len(prefix)) for a, b in found if b > len(prefix)]
                spans += [(index[a], index[b]) for a, b in found if index[a] < index[b]]
        if use_keyrule:
            spans += key_rule_spans(text)
        if use_gitleaks:
            spans += gitleaks_spans(text)
        out, last = [], 0
        for a, b in merge(spans):
            counter[0] += 1
            out += [text[last:a], f"$PIIF_SECRET_{counter[0]}"]
            last = b
        return "".join(out + [text[last:]])

    results = []
    for case in cases:
        redacted = scan_strings(case.body, visit, shell_framing if "shell" in parts else gateway_framing)
        failures, _ = suite.evaluate(case, [json.dumps(redacted)], 200)
        results.append((case, failures))
    return results, stats


def summarize(name, results, stats):
    pos = [(c, f) for c, f in results if not c.negative]
    neg = [(c, f) for c, f in results if c.negative]
    kinds = collections.Counter(f[0].split(" (")[0] for _, f in pos if f)
    neg_fp = sum(1 for _, f in neg if f)
    speed = f"{stats['bytes'] / 1024 / stats['model_s']:.1f} KB/s" if stats["model_s"] else "-"
    print(f"{name:16s} positives {sum(1 for _, f in pos if not f)}/{len(pos)}  "
          f"({', '.join(f'{k} {v}' for k, v in kinds.most_common()) or 'no failures'})  "
          f"negatives with a false positive {neg_fp}/{len(neg)}  model speed {speed}", flush=True)
    return {c.id: f for c, f in results if f}


cases = suite.build_cases()
print(f"{len(cases)} cases ({sum(c.negative for c in cases)} negatives)", flush=True)
models = {}
guards = None
failures_by_engine = {}
for name in engines_wanted:
    base = name.split("+")[0]
    if base != "gitleaks" and base not in models:
        t = time.perf_counter()
        models[base] = {"cbx": Cbx, "egemma": Egemma}[base]()
        print(f"loaded {base} in {time.perf_counter() - t:.1f} s", flush=True)
    if "guards" in name.split("+") and guards is None:
        guards = Guards()
    results, stats = run_engine(name, models.get(base), cases, guards if "guards" in name.split("+") else None)
    failures_by_engine[name] = summarize(name, results, stats)

out = os.path.join(bench, "shootout-failures.json")
with open(out, "w") as f:
    json.dump(failures_by_engine, f, indent=1)
print(f"failures per engine: {out}")
