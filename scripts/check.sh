#!/usr/bin/env bash
# One command for every check. Fast checks first, then the secret suite against a real gateway.
# Usage: scripts/check.sh [--no-suite]   (--no-suite skips the suite; otherwise PIIF_MODEL_DIR must point at the model files)
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
  : "${PIIF_MODEL_DIR:?set PIIF_MODEL_DIR to the model directory, or pass --no-suite}"
  run python3 -I tests/secrets/stats_check.py
  run python3 -I tests/secrets/run.py --model-dir "$PIIF_MODEL_DIR"
fi
echo "check: all passed"
