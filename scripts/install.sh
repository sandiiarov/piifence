#!/usr/bin/env bash
# Install piifence, from this checkout or straight from GitHub.
#
#   scripts/install.sh                 # build and install to ~/.local
#   scripts/install.sh --with-weights  # also download the ~2.8 GB model weights
#   PIIF_PREFIX=/opt/piifence scripts/install.sh
#   curl -fsSL https://raw.githubusercontent.com/sandiiarov/piifence/main/scripts/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --with-weights
#
# Run outside a checkout (e.g. piped from curl), it clones the repo into
# $PREFIX/share/piifence/src (or updates that clone) and builds from there.
#
# Layout under $PREFIX:
#   bin/piifence                  wrapper that sets the env vars below, then runs the launcher
#   libexec/piifence/             real piifence and piifence-gateway binaries
#   share/piifence/gitleaks.toml  gitleaks rules
#   share/piifence/plugin/        Claude Code notice and approval plugins
#
# The wrapper honours PIIF_MODEL_DIR if you set it; otherwise it uses
# $PREFIX/share/piifence/data, or ~/.local/share/piifence/data by default.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "install.sh: macOS only (the detector uses Apple Accelerate)." >&2
  exit 1
fi

WITH_WEIGHTS=0
for arg in "$@"; do
  case "$arg" in
    --with-weights) WITH_WEIGHTS=1 ;;
    -h|--help)
      if [ -f "${BASH_SOURCE[0]:-}" ]; then
        sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      else
        echo "usage: install.sh [--with-weights]   (PIIF_PREFIX sets the install prefix, default ~/.local)"
      fi
      exit 0
      ;;
    *) echo "install.sh: unknown option: $arg" >&2; exit 2 ;;
  esac
done

PREFIX="${PIIF_PREFIX:-$HOME/.local}"
DEFAULT_MODEL_DIR="$PREFIX/share/piifence/data"
REPO_URL="https://github.com/sandiiarov/piifence"

need_brew_pkg() {
  local cmd="$1" pkg="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    return
  fi
  if ! command -v brew >/dev/null 2>&1; then
    echo "install.sh: '$cmd' is missing and Homebrew is not installed. Install $pkg yourself, then rerun." >&2
    exit 1
  fi
  echo "==> installing $pkg with Homebrew"
  brew install "$pkg"
}

# The checkout this script lives in, if any. Piped from curl there is no script
# file, so fetch the source instead.
REPO=""
if [ -f "${BASH_SOURCE[0]:-}" ]; then
  REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
WEIGHTS_CMD="$REPO/scripts/install.sh --with-weights"
if [ -z "$REPO" ] || ! grep -q '^name = "piifence-m1"' "$REPO/Cargo.toml" 2>/dev/null; then
  need_brew_pkg git git
  REPO="$PREFIX/share/piifence/src"
  WEIGHTS_CMD="curl -fsSL https://raw.githubusercontent.com/sandiiarov/piifence/main/scripts/install.sh | bash -s -- --with-weights"
  if [ -d "$REPO/.git" ]; then
    echo "==> updating $REPO"
    git -C "$REPO" pull --ff-only --quiet
  else
    echo "==> cloning $REPO_URL into $REPO"
    mkdir -p "$(dirname "$REPO")"
    git clone --depth 1 --quiet "$REPO_URL" "$REPO"
  fi
fi

need_brew_pkg cargo rust
need_brew_pkg gitleaks gitleaks
if [ "$WITH_WEIGHTS" = 1 ]; then
  need_brew_pkg git-lfs git-lfs
fi

echo "==> building release binaries in $REPO"
(cd "$REPO" && cargo build --release)

echo "==> installing into $PREFIX"
LIBEXEC="$PREFIX/libexec/piifence"
SHARE="$PREFIX/share/piifence"
mkdir -p "$PREFIX/bin" "$LIBEXEC" "$SHARE/plugin"
cp "$REPO/target/release/piifence" "$REPO/target/release/piifence-gateway" "$LIBEXEC/"
cp "$REPO/gitleaks.toml" "$SHARE/gitleaks.toml"
rm -rf "$SHARE/plugin/piifence-notice" "$SHARE/plugin/piifence-approval"
cp -R "$REPO/plugin/piifence-notice" "$REPO/plugin/piifence-approval" "$SHARE/plugin/"

# Wrapper: point the launcher at the installed files. Existing PIIF_* values win.
cat > "$PREFIX/bin/piifence" <<EOF
#!/usr/bin/env bash
export PIIF_GITLEAKS_CONFIG="\${PIIF_GITLEAKS_CONFIG:-$SHARE/gitleaks.toml}"
export PIIF_PLUGIN_DIR="\${PIIF_PLUGIN_DIR:-$SHARE/plugin/piifence-notice}"
export PIIF_APPROVAL_PLUGIN_DIR="\${PIIF_APPROVAL_PLUGIN_DIR:-$SHARE/plugin/piifence-approval}"
export PIIF_MODEL_DIR="\${PIIF_MODEL_DIR:-$DEFAULT_MODEL_DIR}"
exec "$LIBEXEC/piifence" "\$@"
EOF
chmod +x "$PREFIX/bin/piifence"

if [ "$WITH_WEIGHTS" = 1 ]; then
  if [ -f "$DEFAULT_MODEL_DIR/config.json" ]; then
    echo "==> weights already present in $DEFAULT_MODEL_DIR"
  else
    echo "==> downloading model weights (about 2.8 GB) into $DEFAULT_MODEL_DIR"
    (cd "$REPO" && PIIF_MODEL_DIR="$DEFAULT_MODEL_DIR" bash scripts/fetch-weights.sh)
  fi
fi

echo
echo "Installed: $PREFIX/bin/piifence"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
if [ "$WITH_WEIGHTS" = 0 ] && [ ! -f "$DEFAULT_MODEL_DIR/config.json" ]; then
  echo "Model weights are not installed yet. Run: $WEIGHTS_CMD"
fi
echo "Then set the upstream (PIIF_UPSTREAM, or ANTHROPIC_BASE_URL) and run: piifence claude"
