# Label taxonomy and placeholder mapping

Label taxonomy for the piifence redaction gateway: the model's privacy span categories and how each one maps to a stable placeholder token.

## Source model

- **Model:** OpenAI Privacy Filter — 1.5B parameters total, ~50M active parameters, Apache-2.0.
- **Inference crate:** `privacy-filter-rs` v0.1.0 (NdArray + Apple Accelerate CPU backend for M1; MLX is blocked by the Xcode 27 Metal toolchain). It exposes the same labels per span via `entity_group` (lowercase snake_case): https://github.com/eugenehp/privacy-filter-rs
- **Card:** https://huggingface.co/openai/privacy-filter — section "Output Shape" (raw Markdown: https://huggingface.co/openai/privacy-filter/raw/main/README.md).

## Model card taxonomy (verbatim)

Quoted verbatim from the model card's "Output Shape" section:

> Privacy Filter can detect 8 privacy span categories:
>
> 1. `account_number`
> 2. `private_address`
> 3. `private_email`
> 4. `private_person`
> 5. `private_phone`
> 6. `private_url`
> 7. `private_date`
> 8. `secret`
>
> To perform token-classification, each non-background span category is expanded into boundary-tagged token classes: `B-<label>`, `I-<label>`, `E-<label>`, `S-<label>`, plus the background class, `O`. So the total number of token-level output classes is 33: 1 background class \+ 8 span labels \* 4 boundary tags \= 33 classes. This means the output head emits 33 logits for each token. For a sequence of length T, the output has shape `[T, 33]`; for a batch of size B, it has shape `[B, T, 33]`.
>
> The token-label vocabulary consists of the background label `O` plus BIOES-tagged variants of each privacy category: `account_number`, `private_address`, `private_email`, `private_person`, `private_phone`, `private_url`, `private_date`, and `secret`. In other words, for each category, the model predicts `B-`, `I-`, `E-`, and `S-` forms corresponding to begin, inside, end, and single-token spans. At inference time, these per-token logits are decoded into coherent BIOES span labels using constrained sequence decoding.

## Placeholder mapping (M2 proposal)

Not implemented as written. The gateway uses `<secret_N>` / `<{category}_N>`, numbered once per value through a per-process keyed hash (`Placeholders` in `src/bin/gateway.rs`). An unkeyed short hash of a low-entropy value such as an email can be reversed by guessing candidates, so it would leak the value.

Placeholder format: `<PF_{CATEGORY}_{8-hex}>`, where `CATEGORY` is the uppercase token below and `8-hex` is the first 8 hex characters of `sha256(category + real value)` — deterministic and stable per session for the same category/value pair. Examples are illustrative only.

| model label | placeholder category token | placeholder example |
| --- | --- | --- |
| `secret` | `SECRET` | `<PF_SECRET_7f3e9d1c>` |
| `private_email` | `EMAIL` | `<PF_EMAIL_a1b2c3d4>` |
| `private_person` | `PERSON` | `<PF_PERSON_9c4f2e1a>` |
| `private_phone` | `PHONE` | `<PF_PHONE_4e2b7a91>` |
| `private_address` | `ADDRESS` | `<PF_ADDRESS_c8d1f5e3>` |
| `private_url` | `URL` | `<PF_URL_b3d8f0e2>` |
| `private_date` | `DATE` | `<PF_DATE_6a9e0b44>` |
| `account_number` | `ACCOUNT` | `<PF_ACCOUNT_d7c3a812>` |

## Unknown labels: fail closed

Any `entity_group` outside the 8 labels above is a harness or crate fault, not a placeholder category. Do not invent a category, do not pass the value through unredacted, and do not substitute a generic placeholder: abort the redaction and surface an error (fail closed). Never emit the raw value on this path.

## Sources

- Model card: https://huggingface.co/openai/privacy-filter
- Model card raw README ("Output Shape"): https://huggingface.co/openai/privacy-filter/raw/main/README.md
- Rust inference crate `privacy-filter-rs` v0.1.0: https://github.com/eugenehp/privacy-filter-rs
