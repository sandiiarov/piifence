# Secret suite

An end-to-end test of secret redaction. `run.py` starts the real gateway (`target/release/piifence-gateway`) in front of a local fake upstream, sends Claude Code-shaped `/v1/messages` bodies through it, and checks what the upstream actually received.

## What it covers

- `formats.py`: about 100 secret formats (cloud, AI, VCS, payments, SaaS, comms, registries, PEM keys, connection strings, passwords, generic high-entropy values). Each format lists the gitleaks rule it is meant to trigger, or none.
- `contexts.py`: 44 places a secret shows up in a Claude Code request: the prompt, system prompt, `!` bash mode, tool calls (`Bash`, `Write`, `Edit`, `Task`), `Read` and `Grep` results, diffs, logs, ANSI and CRLF output, a value cut by the model's 6,000-byte window, thinking blocks, documents, search results, `count_tokens`, eight config syntaxes, and more.
- `negatives.py`: strings that look secret but must pass through unchanged (UUIDs, git SHAs, digests, env references, placeholders, ARNs).

Every format runs in three base contexts; the formats in `formats.CORE` run in all contexts. One extra case puts many formats in one `.env` file. Negatives run in two contexts.

Each case is checked for:

| check | fails when |
|---|---|
| blocked | the gateway did not forward the request |
| leak | any string the upstream received contains half of a secret (at least 8 characters), raw or JSON-escaped |
| over-redaction | a harmless line in the case (`keep`) was changed |
| structure | keys, arrays or non-string values changed |
| thinking | a thinking block or its signature changed |
| secret false positive | a negative gained a `<secret_N>` placeholder |
| nondeterministic | with `--repeat 2`, two sends of the same body differed (failure only with `--require-deterministic`) |

## Running it

```sh
cargo build --release
python3 -I tests/secrets/run.py --model-dir <weights dir>                 # all three modes
python3 -I tests/secrets/run.py --model-dir <weights dir> --mode secret --filter github
python3 -I tests/secrets/run.py --mode secret-rules   # no weights needed (the model is not loaded)
python3 -I tests/secrets/run.py --check-generators   # each format matches its gitleaks rule
python3 -I tests/secrets/run.py --self-test          # the checks themselves, no gateway
python3 -I tests/secrets/stats_check.py              # /stats counters and the notice, no weights
```

Modes: `all` (every category), `secret` (secret only), `secret-rules` (secret only, `llm_filter = false`). The harness writes its own config for each mode and ignores any `PIIF_*` variables in your shell.

Exit codes: 0 when every failure is a known gap, 1 on a regression, 2 on a setup error.

## Known gaps

`expectations.json` maps `"<mode>|<case id>"` to a one-line reason. A listed failure prints as `GAP`, an unlisted one as `FAIL`, and a listed case that now passes as `FIXED (remove from expectations)`. A change that fixes a gap must remove its entry.

## Triage

For each `FAIL`, decide which of these it is:

1. **Harness or generator bug.** The value does not match its gitleaks rule, a `keep` string is really a secret, or the context is malformed. Fix the fixture.
2. **Real detection gap.** Record it with `--record-gaps`, then edit the reason to say why, for example "document blocks are not walked by redact_content".

Never fix a failure by editing `src/` from this suite's branch; record it, and fix it in its own change.

## Never write a secret-shaped literal

Every secret is generated at run time from a template with a seeded `random.Random`, so runs are reproducible and the repo stays clean under `gitleaks dir`. Write `{at}` instead of `@` in URL templates, and build PEM headers from pieces. Check with `gitleaks dir tests/secrets --no-banner`.
