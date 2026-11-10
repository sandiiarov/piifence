#!/usr/bin/env python3
"""Claude Code hook: show piifence redaction notices via systemMessage.

Asks the local gateway's /stats endpoint how many distinct secrets were replaced, and emits a user-visible message when a secret was replaced for the first time since the last turn. Only metadata is shown (kinds, counts, `$PIIF_SECRET_<N>` names, masked previews), never a value or the text around it.

`piifence claude` loads this plugin and sets PIIF_GATEWAY_URL. A gateway that does not answer is an error: the hook exits non-zero, so Claude Code shows it.

Env:
  PIIF_GATEWAY_URL   required, e.g. http://127.0.0.1:7788
  PIIF_NOTICE_STATE  default /tmp/piifence-notice-state.json
"""

import json
import os
import pathlib
import sys
import urllib.request

GATEWAY = os.environ["PIIF_GATEWAY_URL"].rstrip("/")
STATE = pathlib.Path(os.environ.get("PIIF_NOTICE_STATE", "/tmp/piifence-notice-state.json"))


def emit(payload):
    print(json.dumps(payload))
    sys.exit(0)


def previous_total():
    """Distinct values counted at the last notice; 0 before the first one."""
    if not STATE.exists():
        return 0
    return int(json.loads(STATE.read_text())["values"])


def main():
    raw = sys.stdin.read()
    hook = json.loads(raw)["hook_event_name"] if raw.strip() else ""
    with urllib.request.urlopen(GATEWAY + "/stats", timeout=1.5) as resp:
        stats = json.loads(resp.read())

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
