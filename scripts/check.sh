#!/usr/bin/env bash
# One command for every check. Fast checks first; the model-backed suite modes and
# the M1 corpus gate only when weights are present (PIIF_MODEL_DIR, default data/).
# Usage: scripts/check.sh [--no-suite]   (--no-suite skips the gateway-backed suites)
set -euo pipefail
cd "$(dirname "$0")/.."

run() { echo "==> $*"; "$@"; }

run cargo fmt --check
run cargo clippy --release --all-targets -- -D warnings
run cargo build --release
run cargo test --release
run python3 -I tests/secrets/run.py --self-test
run python3 -I tests/secrets/run.py --check-generators
run python3 -I tests/secrets/contexts.py
run gitleaks dir tests/secrets --no-banner

if [ "${1:-}" != "--no-suite" ]; then
  run python3 -I tests/secrets/stats_check.py
  run python3 -I tests/secrets/run.py --mode secret-rules
  model_dir="${PIIF_MODEL_DIR:-data}"
  if [ -f "$model_dir/config.json" ]; then
    run python3 -I tests/secrets/run.py --model-dir "$model_dir" --mode all --mode secret
    PIIF_MODEL_DIR="$model_dir" run cargo run --release
  else
    echo "==> skipping model-backed checks (no weights at $model_dir; set PIIF_MODEL_DIR)"
  fi
fi
echo "check: all passed"
