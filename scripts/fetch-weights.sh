#!/usr/bin/env bash
# Fetch the OpenAI Privacy Filter weights used by the Rust inference crate.
# ~2.8 GB; destination is data/ by default, override with PIIF_MODEL_DIR.
set -euo pipefail

DEST="${PIIF_MODEL_DIR:-data}"

if [ ! -d "$DEST" ]; then
  git lfs install
  git clone https://huggingface.co/eugenehp/privacy-filter-rs "$DEST"
else
  echo "already present: $DEST"
fi

du -sh "$DEST"

for f in config.json model.safetensors tokenizer.json viterbi_calibration.json; do
  if [ ! -f "$DEST/$f" ]; then
    echo "missing required file: $DEST/$f" >&2
    exit 1
  fi
done

echo "weights ok: $DEST"
