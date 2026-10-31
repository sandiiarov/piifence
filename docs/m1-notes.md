# M1 notes — model validation and guarded pipeline

Run: 2026-10-25 on Apple M4 (32 GiB), macOS 27, `privacy-filter-rs` 0.1.0,
weights `eugenehp/privacy-filter-rs` (2.8 GB, 140 tensors), backend
**NdArray + Apple Accelerate (CPU)** (see "Deviations"), gitleaks pre-pass
(`gitleaks 8.30.1`, `gitleaks.toml`), wrapper guards (`src/guards.rs`).
Raw harness output: `tests/m1-report.txt`.

## Results — three pipelines, same corpus

| pipeline | tally | gate |
| --- | --- | --- |
| raw model | 12/15 | FAIL (`sec-01`, `sec-05`, `neg-01`) |
| + gitleaks pre-pass | 13/15 | FAIL (`sec-05`, `neg-01`) |
| + guards, no pre-pass | 14/15 | FAIL (`sec-01`) |
| **+ gitleaks + guards (current)** | **15/15, exit 0** | **PASS** |

The committed report is the guarded run. Toggles reproduce the rows above:
`PIIF_GUARDS=0` → 13/15; `PIIF_GITLEAKS=0` → 14/15; both off → 12/15. The guards do not
change the model — they veto its output and record every veto in the report:

```
✅ sec-05: got=[] want=[]
    [suppressed:placeholder]      0.970  SECRET  "PII_SECRET_a1b2c3d4"  [model]
✅ neg-01: got=[] want=[]
    [suppressed:env-ref-allowlist] 0.542  SECRET  " os.environ.get('DB_PASS"  [model]
```

## What each blocker needed

### `sec-05` — placeholder round-trip

The model still emits `SECRET` at 0.970 over `PII_SECRET_a1b2c3d4`. The
placeholder guard suppresses any span that lies entirely inside a
pipeline-owned placeholder token: the legacy `PII_<LABEL>_<8hex>` /
`PF_<LABEL>_<8hex>` shape used by this corpus, and the M2 scheme
`<(private_)?[a-z_]+_\d+>` (`<private_email_1>`, `<secret_1>`, ...).

Why this shape matters (probe results, full table in `docs/prior-art.md`):
the model re-redacts hash-style placeholders — `<PF_*_8hex>`, `SECRETGATE_hmac`,
`__RDX_KEY_*`, `<private_email_a1b2c3d4>` — but ignores model-native angle
tokens with numeric ids: `<private_email_1>`, `<private_person_1>`,
`<secret_1>`, `<account_number_1>`, `[EMAIL_1]`, `[REDACTED]`.

M2 follow-up: generate placeholders in the numbered form, keep the legacy shape
in the guard during migration, and add a corpus case for the final format.

### `neg-01` — false positive on an env-var reference

The model still emits `SECRET` at 0.542 over ` os.environ.get('DB_PASS`. The
env-ref allowlist suppresses `SECRET` spans that overlap environment-reference
syntax: `os.environ.get(...)`, `os.environ[...]`, `os.getenv(...)`,
`process.env.*`.

The rule is deliberately narrow because the false positive is narrow: only the
single-quoted `password = os.environ.get('DB_PASS')` form fires; double quotes,
`os.environ[...]`, `os.getenv(...)`, `process.env.*`, other keys and
`x = os.environ.get(...)` are already clean. A confidence floor was considered
and rejected: `neg-01` is 0.542 versus 0.677 for the weakest true positive
(`sec-04`) — too thin to be safe.

### `sec-01` — AWS key (closed by the gitleaks pre-pass)

The model misses it. gitleaks' stock `aws-access-token` rule also ignores it
because of its `.+EXAMPLE$` allowlist; the project config adds
`piifence-aws-access-token` without that allowlist, so
`AKIAIOSFODNN7EXAMPLE` is reported at [20,40). The config also adds
`piifence-openai-project-key` (the stock rule length misses the corpus token)
and `piifence-url-credentials` (URL-embedded credentials). See the gitleaks
section below.

## What this proves — and what it does not

Proves: the shipped pipeline (model + gitleaks + guards) passes the 15-case
acceptance gate, and every suppression is printed with its reason and span.

Does not prove:

- The raw model is safe — it still produces both false positives and both
  misses; the gate passes because the wrapper vetoes them.
- The guards are robust against adversarial input. The placeholder guard skips
  anything shaped like our token namespace, so the namespace must stay unique
  and pipeline-owned; the env-ref rule is a narrow allowlist, not general
  false-positive suppression. These need adversarial cases in M2.
- Anything about span boundaries for replacement: `sec-04` still leaves
  `postgres://admin` uncovered (see below), and the guards only decide
  keep/drop, they do not repair boundaries.

## Observation — `sec-04`: postgres URI produced 2 spans, with a boundary leak

Input `postgres://admin:hunter2@db.internal:5432/prod`. The model alone produces
two spans (`SECRET` over `:hunter2`, `PRIVATE_URL` over the host/path), leaving
`postgres://admin` unredacted — a username leak.

The deterministic layer now has a `piifence-url-credentials` gitleaks rule that
covers the whole URI (`postgres://admin:hunter2@db.internal:5432`), and the merge
policy lets that secret supersede the model's partial spans. The corpus
expectation was therefore corrected to `["SECRET"]`: the shipped pipeline
redacts one span covering the full credential-bearing URL, which is the safer
behavior. The model-only observation remains above as the reason the rule exists.

## gitleaks pre-pass — implementation notes

- `gitleaks stdin --report-format json --report-path - --exit-code 0 --no-banner
  --no-color`, once per text block, with `gitleaks.toml`
  (`[extend] useDefault = true` + the AWS rule variant).
- Config override `PIIF_GITLEAKS_CONFIG`; disable with `PIIF_GITLEAKS=0`.
- Merge: gitleaks findings are labelled `secret` (score 1.0) and dropped when
  they overlap a model span, so the JWT case yields one span even though both
  engines detect it. Exceptions: a deterministic secret covering >=80% of an
  overlapping model PII span replaces that label (AWS key in prose is model
  `private_person`), and the URL-credential rule supersedes the model's partial
  URL/password spans. Exception: a deterministic secret covering >=80% of an
  overlapping model PII span replaces that label — the model labels an AWS key
  in prose as `private_person`, and the shipped redaction must say `secret`.
- Byte offsets: 1-based `StartColumn`, exclusive `EndColumn`, validated against
  the reported secret with a literal-search fallback.
- Cost: ~19 ms per invocation; fine for M1, batch per payload in M2.

## Verified non-issues

- `pii` 5/5 including two same-category spans (2× `PRIVATE_EMAIL`, gate's
  mandatory `pii-05`), person+address, date+account, standalone URL.
- `neg-02` … `neg-05` clean; gitleaks adds no findings on them.
- `sec-02` (sk-proj token) and `sec-03` (JWT) detect at ~1.000.
- Guard unit tests (`cargo test --release`) cover legacy and numbered
  placeholders, env-ref variants, and that real secrets/PII are not suppressed.

## Deviations from the original spec

1. **MLX backend not used.** `mlx` builds burn-mlx → mlx-sys-burn 0.2.2 →
   MLX 0.25.1 from source; with Xcode 27.1 / Metal toolchain 27 the Metal
   kernels fail to compile (20 constructor-initialization errors in
   `mlx/backend/metal/kernels/steel/gemm/mma.h`). The first attempt also failed
   with `xcrun: unable to find utility "metal"` until
   `xcodebuild -downloadComponent MetalToolchain` installed the toolchain; the
   compile errors persisted. M1 runs on the default NdArray + Accelerate CPU
   backend (README: 91 tok/s, correct predictions); label results are
   backend-independent. Revisit MLX or the Python/Swift MLX path before M3
   performance work; do not quote MLX speeds from this run.
2. **gitleaks pre-pass added** beyond the spec (follow-up request):
   `src/gitleaks.rs`, `gitleaks.toml`, `brew install gitleaks`.
3. **Wrapper guards added** beyond the spec (follow-up request): `src/guards.rs`
   with placeholder skip and env-ref allowlist, printed suppressions, unit
   tests, `PIIF_GUARDS` toggle.
4. `Cargo.toml`: `privacy-filter-rs` uses default features + `blas-accelerate`,
   not `default-features = false, features = ["mlx"]`; `regex` added for guards.
5. Device selection uses `backend::device()` rather than
   `<Device as Default>::default()` (same effect, no reliance on `Default`).
6. `scripts/fetch-weights.sh` was mode 600; it is now executable.

## Runtime notes

- Model load: 2.8–6.3 s depending on page cache (2.8 GB bf16 → f32, 140
  tensors).
- Per-case model forward pass: 0.13–2.17 s CPU for 9–57 tokens (first case
  slowest); gitleaks ~19 ms/case; guards are regex-only (< 1 ms).
- Harness exits non-zero on any mismatch; guarded run exits 0 with 15/15.

## Gate decision

**PASSED for the guarded pipeline** (15/15, exit 0): `sec-05` and `neg-01` are
resolved by wrapper guards, `sec-01` by the gitleaks pre-pass. M2 is unblocked
on the condition that the guarded pipeline — not the raw model — is the
baseline, with placeholder/boundary/adversarial cases added to the M2 corpus
(new placeholder format, `sec-04` span merge, forged-pragma-style inputs). The
false-positive allowlist and placeholder namespace are now part of the product
contract, not a test workaround.
