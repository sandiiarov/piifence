#!/usr/bin/env python3
"""Claude Code hook: show piifence redaction notices via systemMessage.

Asks the local gateway's /stats endpoint how many distinct secrets were replaced, and emits a user-visible message when a secret was replaced for the first time since the last turn. Only metadata is shown (kinds, counts, `$PIIF_SECRET_<N>` names, masked previews), never a value or the text around it. It prints nothing unless PIIF_NOTICE=on.

`piifence claude` loads this plugin and sets PIIF_GATEWAY_SOCKET, the gateway's control socket: a Unix socket in a directory only the user can open, and the only place the gateway serves /stats. A gateway that does not answer is an error: the hook exits non-zero, so Claude Code shows it.

Env:
  PIIF_GATEWAY_SOCKET  required, e.g. ~/.local/state/piifence/run/7788.sock
  PIIF_NOTICE_STATE  default /tmp/piifence-notice-state.json
"""

import http.client
import json
import os
import pathlib
import socket
import sys

SOCKET = os.environ["PIIF_GATEWAY_SOCKET"]
STATE = pathlib.Path(os.environ.get("PIIF_NOTICE_STATE", "/tmp/piifence-notice-state.json"))


class SocketConnection(http.client.HTTPConnection):
    """HTTP over the gateway's control socket, a Unix socket, instead of TCP."""

    def __init__(self, path, timeout):
        super().__init__("127.0.0.1", timeout=timeout)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def fetch_stats():
    """The gateway's /stats, read on its control socket. An answer other than 200 is an error."""
    conn = SocketConnection(SOCKET, 1.5)
    try:
        conn.request("GET", "/stats")
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    if resp.status != 200:
        raise RuntimeError(f"the gateway answered /stats with {resp.status}")
    return json.loads(body)


def emit(payload):
    print(json.dumps(payload))
    sys.exit(0)


def previous_total():
    """Distinct values counted at the last notice; 0 before the first one."""
    if not STATE.exists():
        return 0
    return int(json.loads(STATE.read_text())["values"])


def main():
    if os.environ.get("PIIF_NOTICE") != "on":
        emit({})
    raw = sys.stdin.read()
    hook = json.loads(raw)["hook_event_name"] if raw.strip() else ""
    stats = fetch_stats()

    # `values` counts each distinct value once; the per-span counter grows every turn because the history is re-sent.
    total = int(stats["values"])
    previous = previous_total()
    STATE.write_text(json.dumps({"values": total}))

    if hook == "SessionStart":
        if total:
            emit({"systemMessage": f"piifence: active — {total} secret(s) replaced so far"})
        emit({"systemMessage": "piifence: active — secret redaction on (nothing replaced yet)"})

    # A smaller total means the gateway restarted and its counter started over; the state above is already resynced.
    new = total - previous
    if new <= 0:
        emit({})

    recent = stats["recent"][-new:]
    counts = {}
    for item in recent:
        counts[item["kind"]] = counts.get(item["kind"], 0) + 1
    breakdown = ", ".join(f"{kind}×{n}" for kind, n in sorted(counts.items()))
    samples = [f"{item['name']} {item['preview']}" for item in recent[:4]]
    emit({"systemMessage": f"piifence: replaced {new} secret(s) — {breakdown} ({', '.join(samples)})"})


if __name__ == "__main__":
    main()
