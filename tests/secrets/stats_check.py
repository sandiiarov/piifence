"""Check that /stats counts a value once and the notice fires only for new values.

Starts the real gateway in secret-rules mode (no weights) against the suite's fake
upstream, sends the same prompt twice, then runs notice.py against it.

  python3 -I tests/secrets/stats_check.py      -> prints "stats ok", exit 0
"""

import json
import os
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import contexts  # noqa: E402
import formats  # noqa: E402
import run  # noqa: E402

NOTICE = os.path.join(REPO, "plugin", "piifence-notice", "scripts", "notice.py")


def stats(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=5) as r:
        return json.loads(r.read())


def notice(port, state_file, hook="Stop"):
    env = dict(os.environ, PIIF_GATEWAY_URL=f"http://127.0.0.1:{port}", PIIF_NOTICE_STATE=state_file)
    out = subprocess.run([sys.executable, "-I", NOTICE], input=json.dumps({"hook_event_name": hook}).encode(),
                         capture_output=True, env=env, check=True)
    return json.loads(out.stdout or b"{}")


def main():
    sink = run.Sink()
    with tempfile.TemporaryDirectory(prefix="piif-stats-") as tmp:
        gw = run.Gateway("secret-rules", "/nonexistent", sink.port, tmp)
        try:
            path, body, _ = contexts.prompt_text(formats.BY_ID["aws_access_key_id"].generate)
            state = os.path.join(tmp, "state.json")
            assert notice(gw.port, state, "SessionStart")["systemMessage"].startswith("piifence: active")
            assert run.post(gw.port, path, body, "one") == 200
            s = stats(gw.port)
            assert s["values"] == 1 and s["redactions"] == 1 and len(s["recent"]) == 1, s
            msg = notice(gw.port, state)["systemMessage"]
            assert "redacted 1 value(s)" in msg and "secret×1" in msg, msg
            # Claude Code re-sends the history: the same value must not be reported again.
            assert run.post(gw.port, path, body, "two") == 200
            s = stats(gw.port)
            assert s["values"] == 1 and s["redactions"] == 2 and len(s["recent"]) == 1, s
            assert notice(gw.port, state) == {}, "second turn must be silent"
        finally:
            gw.stop()
            sink.close()
    print("stats ok")


if __name__ == "__main__":
    main()
