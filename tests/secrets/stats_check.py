"""Check that /stats counts a value once, the notice fires only for new values, and only the control socket serves /stats and /control/.

Starts the real gateway against the suite's fake upstream, sends the same prompt twice, then runs notice.py against it.

  PIIF_MODEL_DIR=<model> python3 -I tests/secrets/stats_check.py      -> prints "stats ok", exit 0
"""

import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import contexts  # noqa: E402
import formats  # noqa: E402
import run  # noqa: E402

NOTICE = os.path.join(REPO, "plugin", "piifence-notice", "scripts", "notice.py")


def stats(gw):
    status, _, body = run.socket_get(gw.socket, "/stats")
    assert status == 200, (status, body)
    return json.loads(body)


def notice(gw, state_file, hook="Stop", switch="on"):
    env = dict(os.environ, PIIF_GATEWAY_SOCKET=gw.socket, PIIF_NOTICE_STATE=state_file, PIIF_NOTICE=switch)
    out = subprocess.run([sys.executable, "-I", NOTICE], input=json.dumps({"hook_event_name": hook}).encode(),
                         capture_output=True, env=env, check=True)
    return json.loads(out.stdout or b"{}")


def tcp_get(port, path, headers=None):
    """Status and headers of `GET path` on the gateway's TCP port; an error status is returned, not raised."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.headers
    except urllib.error.HTTPError as err:
        return err.code, err.headers


def main():
    sink = run.Sink()
    with tempfile.TemporaryDirectory(prefix="piif-stats-") as tmp:
        gw = run.Gateway(os.environ["PIIF_MODEL_DIR"], sink.port, tmp)
        try:
            path, body, _ = contexts.prompt_text(formats.BY_ID["aws_access_key_id"].generate)
            state = os.path.join(tmp, "state.json")
            assert notice(gw, state, "SessionStart", switch="") == {}, "the notice must be silent unless PIIF_NOTICE=on"
            assert notice(gw, state, "SessionStart")["systemMessage"].startswith("piifence: active")
            assert run.post(gw.port, path, body, "turn") == 200
            # Any account on this machine can connect to the TCP port, so nothing there may hand out a session's values or previews, or name the upstream.
            session = {"x-piifence-session": run.session_for("turn")}
            assert tcp_get(gw.port, "/control/env", session)[0] == 404, "TCP must not hand out a session's values"
            assert tcp_get(gw.port, "/stats")[0] == 404, "TCP must not serve /stats"
            status, headers = tcp_get(gw.port, "/health")
            assert status == 200 and headers.get("x-piifence-upstream") is None, "TCP /health must not name the upstream"
            status, _, reply = run.socket_get(gw.socket, "/control/env", session)
            assert status == 200 and "PIIF_SECRET_1" in json.loads(reply)["values"], "the control socket must hand the session its values"
            status, headers, _ = run.socket_get(gw.socket, "/health")
            assert status == 200 and headers.get("x-piifence-upstream"), "/health on the control socket must name the upstream"
            assert run.socket_get(gw.socket, "/v1/messages")[0] == 404, "the control socket must not forward to the provider"
            s = stats(gw)
            assert s["values"] == 1 and s["redactions"] == 1 and len(s["recent"]) == 1, s
            msg = notice(gw, state)["systemMessage"]
            assert "replaced 1 secret(s)" in msg and "×1" in msg and "$PIIF_SECRET_1" in msg, msg
            # Claude Code re-sends the history: the same value must not be reported again.
            assert run.post(gw.port, path, body, "turn") == 200
            s = stats(gw)
            assert s["values"] == 1 and s["redactions"] == 2 and len(s["recent"]) == 1, s
            assert notice(gw, state) == {}, "second turn must be silent"
        finally:
            gw.stop()
            sink.close()
    print("stats ok")


if __name__ == "__main__":
    main()
