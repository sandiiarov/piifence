#!/usr/bin/env bash
# Download the secret model, SporeLabs Scrub (a 17M-parameter ModernBERT, about 70 MB), at a pinned revision, and check every file's SHA-256.
# Usage: scripts/fetch-weights.sh <model dir>
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: fetch-weights.sh <model dir>" >&2
  exit 2
fi
DEST="$1"
REPO="SporeLabs/scrub"
REVISION="62fb8bfd026382b243cee14fc24aebd30f834645"

# local name, path in the repo, SHA-256
FILES=(
  "config.json encoder/config.json 5759220cc6549f0134ca7ecdcd3429fb4fc79a33bd1790d9362bfac96a728fc1"
  "model.safetensors encoder/model.safetensors bf712987417903cb2e169e6ad7f91f11deaf29ba3b985701ed69e8ef4da6f98e"
  "heads.safetensors heads.safetensors 429c3f396fb31d48dcfcb67d8f37ac26b819820ee3341d35c4583ec88a6443d3"
  "tokenizer.json tokenizer.json 6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30"
  "scrub_config.json scrub_config.json cd204e12caa5a7dbceb1c4a5e3d418da0705dc89d825f221fb768cab52999d52"
)

mkdir -p "$DEST"
for entry in "${FILES[@]}"; do
  read -r name remote sha <<<"$entry"
  path="$DEST/$name"
  if [ -f "$path" ] && echo "$sha  $path" | shasum -a 256 -c --status; then
    echo "ok: $path"
    continue
  fi
  echo "==> downloading $remote"
  curl -fsSL --retry 3 -o "$path.part" "https://huggingface.co/$REPO/resolve/$REVISION/$remote"
  echo "$sha  $path.part" | shasum -a 256 -c --status || {
    rm -f "$path.part"
    echo "fetch-weights.sh: $remote does not match its pinned SHA-256" >&2
    exit 1
  }
  mv "$path.part" "$path"
done
rm -f "$DEST/secrets_config.json"
echo "model ok: $DEST"
