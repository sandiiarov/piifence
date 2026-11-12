"""Cases mined from real Claude Code sessions, with every secret, id, host and name replaced.

mined.jsonl holds one case per line: the latest user prompt, the tool call and its result (or the user text alone), a label ("secret" or "not_secret"), a category saying what the value is, and the value itself. Each excerpt is a synthetic twin of a real block the gateway flagged: values were swapped for random characters of the same shape, internal words and person names for stand-ins, and the twin was kept only when the gateway still flagged it at the same place. Any span that a secret rule could match is stored as a marker «N:prefix|shape» and filled here with seeded random characters (A upper, a lower, 9 digit, H and h hex letters, anything else literal), so the file holds no secret-shaped literal. The same N is the same value throughout a case.

A secret case fails on a leak of its value. A not_secret case fails when its value does not reach the upstream unchanged, which is how a false positive shows up.

Run directly to print the cases with markers filled: `python3 -I tests/secrets/mined.py`.
"""
import json
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import contexts  # noqa: E402

PATH = os.path.join(HERE, "mined.jsonl")
MARKER = re.compile(r"«(\d+):([^|»]*)\|([^»]*)»")
CLASSES = {"A": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "a": "abcdefghijklmnopqrstuvwxyz", "9": "0123456789", "H": "ABCDEF", "h": "abcdef"}


def filler(case_id):
    values = {}

    def fill(m):
        n, prefix, shape = m.groups()
        if n not in values:
            rng = random.Random(f"mined|{case_id}|{n}")
            values[n] = prefix + "".join(rng.choice(CLASSES[c]) if c in CLASSES else c for c in shape)
        return values[n]

    def walk(value):
        if isinstance(value, str):
            return MARKER.sub(fill, value)
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value

    return walk


def body(record):
    prompt = record.get("prompt") or "Continue."
    if record["kind"] == "user_text":
        return contexts.request([contexts.user(contexts.text(record["text"]))])
    if record["kind"] == "tool_use_input":
        turn = contexts.tool_turn(record["tool"], record["input"], "Done.", salt=record["id"])
    else:
        turn = contexts.tool_turn(record["tool"], record["input"], record["text"], salt=record["id"])
    return contexts.request([contexts.user(contexts.text(prompt))] + turn)


def load():
    """Yield (case id, category, kind, body, value, is_secret) with markers filled."""
    for line in open(PATH, encoding="utf-8"):
        record = filler(json.loads(line)["id"])(json.loads(line))
        value = record["value"]
        if record["label"] == "secret":
            value = value.strip(" \t\r\n'\"`(),;:")
        yield f"{record['category']}/{record['id']}", record["category"], record["kind"], body(record), value, record["label"] == "secret"


if __name__ == "__main__":
    for cid, _, kind, b, value, secret in load():
        print(f"{'SECRET' if secret else 'not   '} {kind:15} {cid}")
