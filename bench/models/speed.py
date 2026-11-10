"""Throughput of the Python references of cbx-32M and egemma on long session-like text (made-up code, logs and prose), at two lengths. `parity.py` times our Rust port of cbx against its Python reference.

Usage: $PIIF_BENCH_DIR/venv/bin/python -I bench/models/speed.py   (after bench/models/setup.sh)"""
import importlib.util
import os
import sys
import time

bench = os.environ.get("PIIF_BENCH_DIR", os.path.expanduser("~/.cache/piifence/bench"))
chunk = (
    "fn main() { let cfg = load_config(\"app.toml\")?; println!(\"{}\", cfg.name); }\n"
    "2026-11-09T10:42:13Z INFO request id=4f1c2b served in 12ms path=/api/v1/users\n"
    "The build passed after I moved the parser into src/parse.rs and fixed the borrow.\n"
    "$ cargo test --release\nrunning 45 tests ... ok\n"
)
text = (chunk * 400)[:24_000]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def timed(fn, sample, runs=3):
    fn(sample[:500])  # warm-up
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        fn(sample)
        times.append(time.perf_counter() - t)
    return min(times)


cbx = load_module("cbx_secrets", os.path.join(bench, "dl/cbx32/cbx_secrets.py")).SecretDetector(path=os.path.join(bench, "dl/cbx32"), device="cpu")
sys.path.insert(0, os.path.join(bench, "dl/egemma"))
egemma = load_module("redact", os.path.join(bench, "dl/egemma/redact.py")).Redactor(backend="onnx")

for size in (3_000, 24_000):
    sample = text[:size]
    for name, fn in (("cbx-32M", cbx.extract), ("egemma (int8 ONNX, with rules)", egemma.spans)):
        secs = timed(fn, sample)
        print(f"{size:6d} bytes  {name:32s} {secs * 1000:7.0f} ms  {size / 1024 / secs:6.1f} KB/s", flush=True)
