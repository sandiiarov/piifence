"""Replay a growing conversation through a piifence gateway, the way Claude Code does.

Each turn re-sends the full history plus one new user message, then appends a short
assistant reply. The gateway must run with PIIF_AUDIT_BODY=1 so it logs every redacted
body to /tmp/piifence-redacted-bodies.jsonl. Point PIIF_UPSTREAM at a dead port
(http://127.0.0.1:9): the gateway redacts, logs the body, then answers 502, which is fine.

Usage: python3 -I plans/tools/measure_turns.py <port> <turns>

Prints one line per turn, then three summary lines used by the plans' done criteria:
  distinct renderings of message 1: N   (1 means history is rewritten identically every turn)
  max turn ms: X
  last turn ms: Y
All values are synthetic: example.org emails and a GitHub-format token generated from a fixed seed.
"""
import json
import random
import string
import sys
import time
import urllib.request

PORT = int(sys.argv[1])
TURNS = int(sys.argv[2])
BODY_LOG = "/tmp/piifence-redacted-bodies.jsonl"

# Built at runtime from a fixed seed, so the file holds no token-shaped literal.
_rng = random.Random(1)
TOKEN = "ghp" + "_" + "".join(_rng.choice(string.ascii_letters + string.digits) for _ in range(36))
FIRST = (
    "Please email the report to jordan.miller@example.org and use token "
    f"{TOKEN} for the push."
)


def user_text(i):
    if i == 0:
        return FIRST
    return f"Step {i}: run the tests in module_{i} and summarise failures. Contact dana{i}@example.net if blocked."


def send(messages):
    body = json.dumps({"model": "m", "max_tokens": 10, "messages": messages}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/v1/messages",
        data=body,
        headers={"content-type": "application/json", "x-api-key": "fake"},
        method="POST",
    )
    started = time.time()
    try:
        urllib.request.urlopen(req, timeout=600).read()
    except Exception:
        pass  # the upstream is a dead port; the gateway answers 502 after redacting
    return (time.time() - started) * 1000


def main():
    try:
        with open(BODY_LOG) as f:
            start_lines = sum(1 for _ in f)
    except FileNotFoundError:
        start_lines = 0
    messages = []
    times = []
    for i in range(TURNS):
        messages.append({"role": "user", "content": [{"type": "text", "text": user_text(i)}]})
        times.append(send(messages))
        messages.append({"role": "assistant", "content": [{"type": "text", "text": f"Done with step {i}."}]})
    with open(BODY_LOG) as f:
        lines = f.read().splitlines()[start_lines:]
    firsts = [json.loads(line)["messages"][0]["content"][0]["text"] for line in lines]
    for k, ms in enumerate(times, 1):
        first = firsts[k - 1] if k - 1 < len(firsts) else "(no body logged)"
        print(f"turn {k:3d}  {ms:8.0f} ms  message 1 -> {first}")
    print(f"distinct renderings of message 1: {len(set(firsts))}")
    print(f"max turn ms: {max(times):.0f}")
    print(f"last turn ms: {times[-1]:.0f}")


main()
