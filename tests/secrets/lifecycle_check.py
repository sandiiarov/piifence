"""Check that a gateway shared by two `piifence claude` launchers outlives the one that started it, and exits once neither uses it.

Starts two real launchers with a substitute for Claude Code, against the suite's fake upstream, on a free port (never 7788).

  PIIF_MODEL_DIR=<model> python3 -I tests/secrets/lifecycle_check.py      -> prints "lifecycle ok", exit 0
"""

import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import run  # noqa: E402

# Stands in for Claude Code: waits for its go file, then exits 0 only if the gateway still answers.
FAKE_CLAUDE = """import os, sys, time, urllib.request
while not os.path.exists(os.environ["LIFECYCLE_GO"]):
    time.sleep(0.1)
try:
    urllib.request.urlopen(os.environ["PIIF_GATEWAY_URL"] + "/health", timeout=5).read()
except OSError:
    sys.exit(3)
"""


def healthy(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


def control(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"x-piifence-session": "0" * 32})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as err:
        return err.code


def read(path):
    with open(path) as f:
        return f.read()


def wait_for(condition, seconds, what):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return
        time.sleep(0.2)
    raise AssertionError(f"timed out after {seconds} s waiting for {what}")


def stop_listener(port):
    """Stop whatever still listens on this check's own port, if the gateway failed to exit by itself."""
    pids = subprocess.run(["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True).stdout
    for pid in pids.split():
        os.kill(int(pid), signal.SIGTERM)


def main():
    model_dir = os.path.abspath(os.environ["PIIF_MODEL_DIR"].split(":")[0])
    target = os.environ.get("CARGO_TARGET_DIR", os.path.join(REPO, "target"))
    launcher = os.path.join(target, "release", "piifence")
    port = run.free_port()
    assert port != 7788, "the check must never touch the default port"
    sink = run.Sink()
    started = []
    with tempfile.TemporaryDirectory(prefix="piif-life-") as tmp:
        data = os.path.join(tmp, "data")
        os.makedirs(os.path.join(data, "plugin"))
        os.symlink(model_dir, os.path.join(data, "model"))
        os.symlink(os.path.join(REPO, "plugin", "piifence-notice"), os.path.join(data, "plugin", "piifence-notice"))
        script = os.path.join(tmp, "fake_claude.py")
        with open(script, "w") as f:
            f.write(FAKE_CLAUDE)
        fake = os.path.join(tmp, "claude")
        with open(fake, "w") as f:
            f.write(f'#!/bin/sh\nexec "{sys.executable}" -I "{script}"\n')
        os.chmod(fake, stat.S_IRWXU)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PIIF_", "ANTHROPIC_"))}
        env.update({
            "PIIF_DATA_DIR": data,
            "PIIF_UPSTREAM": f"http://127.0.0.1:{sink.port}",
            "PIIF_PORT": str(port),
            "PIIF_EXIT_WHEN_UNUSED": "1",
            "PIIF_GATEWAY_LOG": os.path.join(tmp, "gateway.log"),
            "PIIF_AUDIT_LOG": os.path.join(tmp, "audit.log"),
            "PIIF_CACHE_DIR": os.path.join(tmp, "cache"),
            "PIIF_STATE_DIR": os.path.join(tmp, "state"),
            "PIIF_CONFIG": os.path.join(tmp, "config.toml"),
            "CLAUDE_BIN": fake,
            "CLAUDE_CONFIG_DIR": os.path.join(tmp, "claude-config"),
        })

        def start(name):
            go = os.path.join(tmp, name + ".go")
            log = open(os.path.join(tmp, name + ".log"), "w")
            proc = subprocess.Popen([launcher, "claude"], env=dict(env, LIFECYCLE_GO=go),
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            started.append((proc, go, log))
            return proc, go

        try:
            first, first_go = start("first")
            wait_for(lambda: healthy(port), 180, "the gateway the first launcher starts")
            second, second_go = start("second")
            wait_for(lambda: "using existing gateway" in read(os.path.join(tmp, "second.log")), 30,
                     "the second launcher to reuse that gateway")
            open(first_go, "w").close()
            assert first.wait(timeout=30) == 0, read(os.path.join(tmp, "first.log"))
            time.sleep(3)
            assert healthy(port), "the gateway stopped while the second launcher still used it"
            assert control(port, "/control/lease") == 400, "a lease without a launcher pid must be refused"
            assert control(port, "/control/no-such-endpoint") == 404, "an unknown control path must not be forwarded"
            open(second_go, "w").close()
            assert second.wait(timeout=30) == 0, "the second session lost its gateway"
            wait_for(lambda: not healthy(port), 15, "the gateway to exit after the last launcher")
        finally:
            for proc, go, log in started:
                open(go, "w").close()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                log.close()
            if healthy(port):
                stop_listener(port)
            sink.close()
    print("lifecycle ok")


if __name__ == "__main__":
    main()
