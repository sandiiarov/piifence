#!/usr/bin/env bash
# Set up the model bench: a Python venv and the candidate models, pinned to the revisions in docs/model-options.md.
# Everything goes in $PIIF_BENCH_DIR (default ~/.cache/piifence/bench), outside the repo.
# Usage: bench/models/setup.sh
set -euo pipefail
dir="${PIIF_BENCH_DIR:-$HOME/.cache/piifence/bench}"
mkdir -p "$dir/dl/cbx32" "$dir/dl/egemma"
uv venv -q -p 3.12 "$dir/venv"
uv pip install -q -p "$dir/venv/bin/python" torch==2.15.0 transformers==5.22.1 onnxruntime==1.31.1 huggingface_hub safetensors tokenizers
"$dir/venv/bin/hf" download CobuildX-AI/cbx-secrets-detector-32M --revision d6af1fabe7e6404edd4545ad1d3f62b1e7eda475 --local-dir "$dir/dl/cbx32"
"$dir/venv/bin/hf" download nekomimi-llc/egemma-pii-secrets --revision 98eba7d519b1e639d6fb4ebbe83355d6f01a6502 --local-dir "$dir/dl/egemma"
echo "bench ready in $dir"
