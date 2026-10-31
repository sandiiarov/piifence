#!/usr/bin/env python3
"""Claude Code hook: show piifence redaction notices via systemMessage.

Reads the hook event JSON on stdin, asks the local gateway /stats endpoint how
many distinct values were redacted, and emits a user-visible message when a value
was redacted for the first time since the last turn. Only metadata is
displayed (labels, counts, placeholders) — never raw values, never the text.

Env:
  PIIF_GATEWAY_URL   default http://127.0.0.1:7788
  PIIF_NOTICE_STATE  default /tmp/piifence-notice-state.json
"""

import json
import os
import pathlib
import sys
import urllib.request

GATEWAY = os.environ.get("PIIF_GATEWAY_URL", "http://127.0.0.1:7788").rstrip("/")
STATE = pathlib.Path(os.environ.get("PIIF_NOTICE_STATE", "/tmp/piifence-notice-state.json"))


def emit(payload):
    print(json.dumps(payload))
    sys.exit(0)


def read_event():
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def load_state():
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {}


def save_state(total):
    try:
        STATE.write_text(json.dumps({"values": total}))
    except Exception:
        pass


def main():
    event = read_event()
    hook = event.get("hook_event_name", "")
    try:
        with urllib.request.urlopen(GATEWAY + "/stats", timeout=1.5) as resp:
            stats = json.loads(resp.read())
    except Exception:
        # Gateway not running: piifence is not in the path, so stay silent
        # instead of nagging every Claude Code session.
        emit({})

    # `values` counts each distinct value once; the per-span counter grows every turn
    # because the history is re-sent. The fallback keeps an older gateway working.
    total = int(stats.get("values", stats.get("redactions", 0)))
    previous = int(load_state().get("values", 0))

    if hook == "SessionStart":
        save_state(total)
        if total:
            emit({"systemMessage": f"piifence: active — {total} value(s) redacted so far"})
        emit({"systemMessage": "piifence: active — input redaction on (nothing redacted yet)"})

    new = total - previous
    if new <= 0:
        if new < 0:
            # The gateway restarted, so its counter started over. Resync, or the
            # notices stay silent until the new count passes the old one.
            save_state(total)
        emit({})

    recent = stats.get("recent", [])[-new:]
    counts = {}
    samples = []
    for item in recent:
        label = item.get("label", "unknown")
        counts[label] = counts.get(label, 0) + 1
        placeholder = item.get("placeholder", "")
        preview = item.get("preview", "")
        if placeholder and preview:
            samples.append(f"{placeholder} {preview}")
        elif placeholder:
            samples.append(placeholder)
    breakdown = ", ".join(f"{label}×{n}" for label, n in sorted(counts.items()))
    sample = f" ({', '.join(samples[:4])})" if samples else ""
    save_state(total)
    emit({"systemMessage": f"piifence: redacted {new} value(s) — {breakdown}{sample}"})


if __name__ == "__main__":
    main()
