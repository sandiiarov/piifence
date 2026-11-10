"""Check the Rust port of cbx-secrets-detector-32M (src/model.rs) against the model's Python reference (cbx_secrets.py).

Both read the same texts: every string the gateway scans in the secret suite's requests, with the tool-call context the gateway puts before a tool result. The script reports how many texts get the same spans from both, lists the ones that differ, and times both.

Usage: $PIIF_BENCH_DIR/venv/bin/python -I bench/models/parity.py   (after bench/models/setup.sh)
"""
import importlib.util
import json
import os
import subprocess
import sys
import time

repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
bench = os.environ.get("PIIF_BENCH_DIR", os.path.expanduser("~/.cache/piifence/bench"))
model_dir = os.path.join(bench, "dl/cbx32")
sys.path.insert(0, os.path.join(repo, "tests/secrets"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run as suite  # noqa: E402

spec = importlib.util.spec_from_file_location("cbx_secrets", os.path.join(model_dir, "cbx_secrets.py"))
cbx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cbx)

texts = []
for case in suite.build_cases():
    calls = {}
    for message in case.body.get("messages", []):
        content = message.get("content")
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls[block.get("id")] = (block.get("name", ""), json.dumps(block.get("input", {}), separators=(",", ":")))

    def walk(value, context=None):
        if isinstance(value, str):
            texts.append((context or "") + value)
        elif isinstance(value, list):
            for v in value:
                walk(v, context)
        elif isinstance(value, dict):
            if value.get("type") in ("thinking", "redacted_thinking", "image"):
                return
            if value.get("type") == "tool_result" and value.get("tool_use_id") in calls:
                name, raw = calls[value["tool_use_id"]]
                context = f"Tool call: {name} {raw[:800]}\nTool output:\n"
            for k, v in value.items():
                if k not in ("type", "role", "id", "tool_use_id", "name", "media_type", "signature", "cache_control", "model"):
                    walk(v, context)
    for field in ("system", "messages"):
        walk(case.body.get(field))
texts = sorted({t for t in texts if t and len(t.encode()) <= 3000})
print(f"{len(texts)} distinct texts up to 3 KB", flush=True)

det = cbx.SecretDetector(path=model_dir, device="cpu")
t = time.perf_counter()
expected = [[(s["start"], s["end"], s["label"]) for s in det.extract(text)] for text in texts]
python_s = time.perf_counter() - t

target = os.environ.get("CARGO_TARGET_DIR", os.path.join(repo, "target"))
subprocess.run(["cargo", "build", "--release", "--example", "model_spans"], cwd=repo, check=True,
               env=dict(os.environ, CARGO_TARGET_DIR=target), capture_output=True)
t = time.perf_counter()
out = subprocess.run([os.path.join(target, "release/examples/model_spans"), model_dir], check=True, capture_output=True,
                     text=True, input="".join(json.dumps({"text": text}) + "\n" for text in texts)).stdout
rust_s = time.perf_counter() - t


def to_chars(text, start, end):
    raw = text.encode()
    return len(raw[:start].decode()), len(raw[:end].decode())


same, diffs = 0, []
for text, want, line in zip(texts, expected, out.splitlines()):
    got = [(*to_chars(text, a, b), kind) for a, b, kind in json.loads(line)]
    if got == want:
        same += 1
    else:
        diffs.append((text, want, got))
total_kb = sum(len(t.encode()) for t in texts) / 1024
print(f"same spans: {same}/{len(texts)}")
print(f"python: {python_s:.1f} s ({total_kb / python_s:.1f} KB/s)   rust: {rust_s:.1f} s incl. load ({total_kb / rust_s:.1f} KB/s)")
for text, want, got in diffs[:20]:
    print("---")
    print("python:", [(text[a:b][:40], k) for a, b, k in want])
    print("rust:  ", [(text[a:b][:40], k) for a, b, k in got])
