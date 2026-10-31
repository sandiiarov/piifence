"""End-to-end secret suite: real gateway, fake upstream, Claude Code-shaped requests.

  python3 -I tests/secrets/run.py --model-dir <weights>            all three modes
  python3 -I tests/secrets/run.py --model-dir <weights> --mode secret --filter github
  python3 -I tests/secrets/run.py --mode secret-rules               rules only, no weights needed
  python3 -I tests/secrets/run.py --check-generators                formats vs gitleaks rules
  python3 -I tests/secrets/run.py --self-test                       checks vs a gateway-less sink

Each case is sent to `target/release/piifence-gateway`, which forwards the redacted body
to a local fake upstream; the checks run on what the upstream received. Exit codes:
0 no regressions, 1 regressions (failures not listed in expectations.json), 2 setup error.
See tests/secrets/README.md.
"""
import argparse
import collections
import datetime
import http.server
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import contexts  # noqa: E402
import formats  # noqa: E402
import negatives  # noqa: E402

EXPECTATIONS = os.path.join(HERE, "expectations.json")
ALL_CATEGORIES = ["account_number", "private_address", "private_email", "private_person",
                  "private_phone", "private_url", "private_date", "secret"]
MODES = {
    "all": {"categories": ALL_CATEGORIES, "llm_filter": True},
    "secret": {"categories": ["secret"], "llm_filter": True},
    "secret-rules": {"categories": ["secret"], "llm_filter": False},
}
SECRET_PLACEHOLDER = re.compile(r"<secret_\d+>")
ANY_PLACEHOLDER = re.compile(r"<(?:secret|private_[a-z]+|account_number)_\d+>")


# --- data walking ---------------------------------------------------------------


def strings_of(value):
    """Every string in a JSON value, object keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings_of(item)
    elif isinstance(value, dict):
        for k, item in value.items():
            yield k
            yield from strings_of(item)


def shape_of(value):
    """The value with every string replaced by a marker: same keys, arrays and scalars."""
    if isinstance(value, str):
        return "<s>"
    if isinstance(value, list):
        return [shape_of(v) for v in value]
    if isinstance(value, dict):
        return {k: shape_of(v) for k, v in value.items()}
    return value


def leak_window(secret, strings):
    """The first window of `secret` (half its length, at least 8 chars) found in any
    string, or None. Catches partial redaction as well as a full leak."""
    for variant in formats.leak_variants(secret):
        k = min(len(variant), max(8, math.ceil(len(variant) / 2)))
        windows = {variant[i:i + k] for i in range(len(variant) - k + 1)}
        for s in strings:
            for w in windows:
                if w in s:
                    return w
    return None


def mask(s):
    return s[:4] + "…" if len(s) > 4 else "…"


# --- cases ----------------------------------------------------------------------


class Case:
    def __init__(self, cid, family, context, path, body, secrets, keep, negative=False):
        self.id = cid
        self.family = family
        self.context = context
        self.path = path
        self.body = body
        self.secrets = secrets
        self.keep = keep
        self.negative = negative


def build_cases():
    cases = []
    for fmt in formats.FORMATS:
        ctx_ids = list(contexts.CONTEXTS) if fmt.id in formats.CORE else contexts.BASE_CONTEXTS
        for cid in ctx_ids:
            path, body, keep, extra = contexts.build_case(cid, fmt.generate)
            g = fmt.generate("0")
            secrets = list(g.secrets) + [s for e in extra for s in e.secrets]
            cases.append(Case(f"{cid}/{fmt.id}", fmt.family, cid, path, body, secrets, keep))
    path, body, keep, gens = contexts.many_in_one_block(formats)
    cases.append(Case("many_in_one_block/mixed", "mixed", "many_in_one_block", path, body,
                      [s for g in gens for s in g.secrets], keep))
    for neg in negatives.ALL:
        for cid in negatives.NEGATIVE_CONTEXTS:
            path, body, keep, _ = contexts.build_case(cid, neg.generate)
            value = neg.generate("0").full
            cases.append(Case(f"{cid}/{neg.id}", "negative", cid, path, body, [],
                              keep + [line for line in value.split("\n") if line], negative=True))
    return cases


def evaluate(case, received_list, status):
    """Return (failures, warnings) for one case. received_list holds the raw bodies
    the upstream got (one per repeat)."""
    failures, warnings = [], []
    if not received_list:
        failures.append(f"blocked (gateway status {status})")
        return failures, warnings
    try:
        received = json.loads(received_list[0])
    except ValueError:
        return ["upstream got invalid JSON"], warnings
    strings = list(strings_of(received))
    for secret in case.secrets:
        window = leak_window(secret, strings)
        if window:
            failures.append(f"leak ({mask(window)})")
            break
    if case.negative:
        sent = sum(len(SECRET_PLACEHOLDER.findall(s)) for s in strings_of(case.body))
        got = sum(len(SECRET_PLACEHOLDER.findall(s)) for s in strings)
        if got > sent:
            failures.append("secret false positive")
        elif any(not any(k in s for s in strings) for k in case.keep):
            warnings.append("other-category false positive")
    else:
        missing = [k for k in case.keep if not any(k in s for s in strings)]
        if missing:
            failures.append(f"over-redaction ({mask(missing[0])})")
    if shape_of(received) != shape_of(case.body):
        failures.append("structure changed")
    if case.context == "assistant_with_thinking":
        sent_block = case.body["messages"][1]["content"][0]
        got_block = received["messages"][1]["content"][0]
        if sent_block != got_block:
            failures.append("thinking block modified")
    if len(received_list) > 1 and len(set(received_list)) > 1:
        warnings.append("nondeterministic")
    return failures, warnings


# --- fake upstream and gateway ------------------------------------------------------


class Sink:
    def __init__(self):
        self.received = collections.defaultdict(list)
        sink = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                sink.received[self.headers.get("x-piif-case", "")].append(body)
                payload = b'{"type":"message","content":[]}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def post(port, path, body, case_id):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", "x-api-key": "test",
                 "anthropic-version": "2023-06-01", "x-piif-case": case_id})
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code


class Gateway:
    def __init__(self, mode, model_dir, sink_port, tmp):
        self.port = free_port()
        config = os.path.join(tmp, f"piifence-{mode}.toml")
        with open(config, "w") as f:
            f.write(f"categories = {json.dumps(MODES[mode]['categories'])}\n")
            f.write(f"llm_filter = {'true' if MODES[mode]['llm_filter'] else 'false'}\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("PIIF_")}
        env.update({
            "PIIF_UPSTREAM": f"http://127.0.0.1:{sink_port}",
            "PIIF_PORT": str(self.port),
            "PIIF_AUDIT_LOG": os.path.join(tmp, f"audit-{mode}.log"),
            "PIIF_MODEL_DIR": model_dir,
            "PIIF_CONFIG": config,
            "PIIF_GITLEAKS_CONFIG": os.path.join(REPO, "gitleaks.toml"),
        })
        self.log_path = os.path.join(tmp, f"gateway-{mode}.log")
        self.log = open(self.log_path, "w")
        binary = os.path.join(REPO, "target", "release", "piifence-gateway")
        if not os.path.exists(binary):
            raise SystemExit(f"setup error: {binary} not found (run cargo build --release)")
        self.proc = subprocess.Popen([binary], cwd=REPO, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 180
        while time.time() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=2) as r:
                    if r.status == 200:
                        return
            except OSError:
                time.sleep(0.5)
        self.stop()
        with open(self.log_path) as f:
            sys.stderr.write(f.read())
        raise SystemExit(2)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()


# --- modes of operation ---------------------------------------------------------------


def run_mode(mode, cases, args, sink, tmp):
    gw = Gateway(mode, args.model_dir, sink.port, tmp)
    results = []
    try:
        for i, case in enumerate(cases, 1):
            key = f"{mode}|{case.id}"
            sink.received.pop(key, None)
            status = None
            for _ in range(args.repeat):
                status = post(gw.port, case.path, case.body, key)
            failures, warnings = evaluate(case, sink.received.get(key, []), status)
            if args.require_deterministic and "nondeterministic" in warnings:
                failures.append("nondeterministic")
            results.append((case, failures, warnings))
            if args.dump and failures and sink.received.get(key):
                os.makedirs(args.dump, exist_ok=True)
                with open(os.path.join(args.dump, key.replace("/", "__").replace("|", "--") + ".json"), "wb") as f:
                    f.write(sink.received[key][0])
            if i % 50 == 0:
                sys.stderr.write(f"  [{mode}] {i}/{len(cases)}\n")
    finally:
        gw.stop()
    return results


def table(title, rows, headers):
    print(f"\n{title}")
    widths = [max(len(str(r[i])) for r in rows + [headers]) for i in range(len(headers))]
    print("  " + "  ".join(str(h).ljust(w) for h, w in zip(headers, widths)))
    for r in rows:
        print("  " + "  ".join(str(c).ljust(w) for c, w in zip(r, widths)))


def report(mode, results, expectations):
    print(f"\n==================== mode: {mode} ====================")
    by_family = collections.defaultdict(lambda: [0, 0, 0, 0, 0])
    by_context = collections.defaultdict(lambda: [0, 0, 0])
    for case, failures, _ in results:
        if case.negative:
            continue
        fam, ctx = by_family[case.family], by_context[case.context]
        fam[0] += 1
        ctx[0] += 1
        if not failures:
            fam[1] += 1
            ctx[1] += 1
        if any(f.startswith("leak") for f in failures):
            fam[2] += 1
            ctx[2] += 1
        fam[3] += any(f.startswith("blocked") for f in failures)
        fam[4] += any(f.startswith("over-redaction") for f in failures)
    table("by family", [[k, *v] for k, v in sorted(by_family.items())],
          ["family", "cases", "passed", "leaks", "blocked", "over-redacted"])
    table("by context", [[k, *v] for k, v in sorted(by_context.items())], ["context", "cases", "passed", "leaks"])
    negs = [(c, f, w) for c, f, w in results if c.negative]
    print(f"\nnegatives: {len(negs)} cases, "
          f"{sum(1 for _, f, _ in negs if f)} secret false positives, "
          f"{sum(1 for _, _, w in negs if 'other-category false positive' in w)} other-category false positives")
    nondet = sum(1 for _, _, w in results if "nondeterministic" in w)
    if nondet:
        print(f"nondeterministic cases: {nondet}")

    regressions, gaps, fixed = [], [], []
    for case, failures, _ in results:
        key = f"{mode}|{case.id}"
        if failures and key in expectations:
            gaps.append((key, failures))
        elif failures:
            regressions.append((key, failures))
        elif key in expectations:
            fixed.append(key)
    print(f"\nknown gaps: {len(gaps)}")
    for key, failures in gaps:
        print(f"  GAP  {key}: {', '.join(failures)}")
    for key in fixed:
        print(f"  FIXED (remove from expectations): {key}")
    for key, failures in regressions:
        print(f"  FAIL {key}: {', '.join(failures)}")
    total = len(results)
    passed = sum(1 for _, f, _ in results if not f)
    print(f"\n{mode}: {passed}/{total} passed, {len(gaps)} known gaps, {len(regressions)} regressions, "
          f"{len(fixed)} fixed")
    return regressions, fixed


def load_expectations():
    if not os.path.exists(EXPECTATIONS):
        return {}
    with open(EXPECTATIONS) as f:
        return json.load(f)


def record_gaps(all_results, expectations):
    today = datetime.date.today().isoformat()
    for mode, results in all_results.items():
        for case, failures, _ in results:
            key = f"{mode}|{case.id}"
            if failures and key not in expectations:
                expectations[key] = {"status": "known_gap", "reason": f"recorded {today}: {failures[0]}"}
            elif not failures and key in expectations:
                del expectations[key]
    with open(EXPECTATIONS, "w") as f:
        json.dump(dict(sorted(expectations.items())), f, indent=2)
        f.write("\n")
    print(f"\nwrote {len(expectations)} known gaps to {EXPECTATIONS}")


def check_generators():
    config = os.path.join(REPO, "gitleaks.toml")
    bad = 0
    for fmt in formats.FORMATS:
        g = fmt.generate()
        out = subprocess.run(
            ["gitleaks", "stdin", "--report-format", "json", "--report-path", "-", "--exit-code", "0",
             "--no-banner", "--no-color", "-c", config],
            input=g.line.encode(), capture_output=True, check=True)
        found = sorted({f["RuleID"] for f in json.loads(out.stdout or b"[]") or []})
        ok = fmt.rules is None or bool(set(fmt.rules) & set(found))
        bad += not ok
        expected = ",".join(fmt.rules) if fmt.rules else "-"
        print(f"{'ok ' if ok else 'BAD'} {fmt.id:36} expected={expected:45} found={','.join(found) or '-'}")
    print(f"\n{len(formats.FORMATS)} formats, {bad} mismatches")
    return 1 if bad else 0


def self_test():
    """Run the checks against bodies posted straight to the sink (no redaction), so a
    leak must be reported; a negative must pass."""
    sink = Sink()
    try:
        cases = {c.id: c for c in build_cases()}
        expected = {"prompt_text/github_pat_classic": "leak", "window_cut/jwt": "leak",
                    "prompt_text/uuid_v4": "pass"}
        ok = True
        for cid, want in expected.items():
            case = cases[cid]
            status = post(sink.port, case.path, case.body, cid)
            failures, _ = evaluate(case, sink.received.get(cid, []), status)
            got = "leak" if any(f.startswith("leak") for f in failures) else ("pass" if not failures else failures[0])
            print(f"{'ok ' if got == want else 'BAD'} {cid}: want {want}, got {got}")
            ok &= got == want
        return 0 if ok else 1
    finally:
        sink.close()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model-dir", default=os.environ.get("PIIF_MODEL_DIR", os.path.join(REPO, "data")))
    p.add_argument("--mode", choices=list(MODES), action="append")
    p.add_argument("--filter", help="only cases whose id contains this substring")
    p.add_argument("--repeat", type=int, default=1, help="send each case N times and compare")
    p.add_argument("--require-deterministic", action="store_true")
    p.add_argument("--record-gaps", action="store_true", help="write current failures to expectations.json")
    p.add_argument("--check-generators", action="store_true")
    p.add_argument("--dump", metavar="DIR", help="write what the upstream received for each failing case")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()

    if args.check_generators:
        return check_generators()
    if args.self_test:
        return self_test()
    modes = args.mode or list(MODES)
    if any(MODES[m]["llm_filter"] for m in modes) and not os.path.exists(os.path.join(args.model_dir, "config.json")):
        print(f"setup error: no model weights in {args.model_dir} (pass --model-dir, or use --mode secret-rules)",
              file=sys.stderr)
        return 2

    cases = build_cases()
    if args.filter:
        cases = [c for c in cases if args.filter in c.id]
    if not cases:
        print("setup error: no cases match the filter", file=sys.stderr)
        return 2
    print(f"{len(cases)} cases x {len(modes)} modes ({', '.join(modes)}), repeat {args.repeat}")
    expectations = load_expectations()
    sink = Sink()
    all_results = {}
    with tempfile.TemporaryDirectory(prefix="piif-secrets-") as tmp:
        try:
            for mode in modes:
                started = time.time()
                all_results[mode] = run_mode(mode, cases, args, sink, tmp)
                sys.stderr.write(f"  [{mode}] done in {time.time() - started:.0f}s\n")
        finally:
            sink.close()
    regressions = []
    for mode, results in all_results.items():
        reg, _ = report(mode, results, expectations)
        regressions += reg
    if args.record_gaps:
        record_gaps(all_results, expectations)
        return 0
    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
