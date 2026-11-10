#!/usr/bin/env bash
# Download the secret model, cbx-secrets-detector-32M (about 128 MB), at a pinned revision, and check every file's SHA-256.
# Usage: scripts/fetch-weights.sh <model dir>
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: fetch-weights.sh <model dir>" >&2
  exit 2
fi
DEST="$1"
REPO="CobuildX-AI/cbx-secrets-detector-32M"
REVISION="d6af1fabe7e6404edd4545ad1d3f62b1e7eda475"

FILES=(
  "config.json 8ace5bcc84d2d036f45b08588001c3edaf092a15daf980b26a4e2bb94d48cab7"
  "model.safetensors d67e3291d7c84eb6d2051edb3287c8f9e12efeaa03f87b68201503d139113a83"
  "tokenizer.json 6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30"
  "secrets_config.json 03d42d78d5b5f69989d5f0718e65606c55fd7bcb3186ae78e8bdb387dbee9828"
)

mkdir -p "$DEST"
for entry in "${FILES[@]}"; do
  read -r name sha <<<"$entry"
  path="$DEST/$name"
  if [ -f "$path" ] && echo "$sha  $path" | shasum -a 256 -c --status; then
    echo "ok: $path"
    continue
  fi
  echo "==> downloading $name"
  curl -fsSL --retry 3 -o "$path.part" "https://huggingface.co/$REPO/resolve/$REVISION/$name"
  echo "$sha  $path.part" | shasum -a 256 -c --status || {
    rm -f "$path.part"
    echo "fetch-weights.sh: $name does not match its pinned SHA-256" >&2
    exit 1
  }
  mv "$path.part" "$path"
done
echo "model ok: $DEST"
