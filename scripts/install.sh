#!/usr/bin/env bash
# Install piifence, from this checkout or straight from GitHub.
#
#   scripts/install.sh                 # build and install to ~/.local
#   PIIF_PREFIX=/opt/piifence scripts/install.sh
#   curl -fsSL https://raw.githubusercontent.com/sandiiarov/piifence/main/scripts/install.sh | bash
#
# Run outside a checkout (e.g. piped from curl), it clones the repo into $PREFIX/share/piifence/src (or updates that clone) and builds from there.
#
# Layout under $PREFIX:
#   bin/piifence                          wrapper that sets PIIF_DATA_DIR, then runs the launcher
#   libexec/piifence/                     the piifence and piifence-gateway binaries
#   share/piifence/model/                 the secret model (SporeLabs Scrub, about 70 MB)
#   share/piifence/plugin/piifence-notice the Claude Code notice plugin
#   share/piifence/plugin/piifence-reveal the plugin that draws values in place of names
#   share/piifence/plugin/piifence-session the session hooks: values for Bash, values back into tool input
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "install.sh: macOS only (the detector uses Apple Accelerate)." >&2
  exit 1
fi

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      echo "usage: install.sh   (PIIF_PREFIX sets the install prefix, default ~/.local)"
      exit 0
      ;;
    *) echo "install.sh: unknown option: $arg" >&2; exit 2 ;;
  esac
done

PREFIX="${PIIF_PREFIX:-$HOME/.local}"
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

# The checkout this script lives in. Piped from curl there is no script file, so fetch the source instead.
REPO=""
if [ -f "${BASH_SOURCE[0]:-}" ]; then
  REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
if [ -z "$REPO" ]; then
  need_brew_pkg git git
  REPO="$PREFIX/share/piifence/src"
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

echo "==> building release binaries in $REPO"
# An explicit target dir, so a CARGO_TARGET_DIR in the environment cannot leave stale binaries where we copy from.
(cd "$REPO" && cargo build --release --bins --target-dir "$REPO/target")

echo "==> installing into $PREFIX"
LIBEXEC="$PREFIX/libexec/piifence"
SHARE="$PREFIX/share/piifence"
mkdir -p "$PREFIX/bin" "$LIBEXEC" "$SHARE/plugin"
# Remove before copying: overwriting a binary in place (for example while an old launcher still runs) makes macOS kill the new one at launch.
for bin in piifence piifence-gateway; do
  rm -f "$LIBEXEC/$bin"
  cp "$REPO/target/release/$bin" "$LIBEXEC/$bin"
done
for plugin in piifence-notice piifence-reveal piifence-session; do
  rm -rf "$SHARE/plugin/$plugin"
  cp -R "$REPO/plugin/$plugin" "$SHARE/plugin/"
done
bash "$REPO/scripts/fetch-weights.sh" "$SHARE/model"

cat > "$PREFIX/bin/piifence" <<EOF
#!/usr/bin/env bash
export PIIF_DATA_DIR="$SHARE"
exec "$LIBEXEC/piifence" "\$@"
EOF
chmod +x "$PREFIX/bin/piifence"

echo
echo "Installed: $PREFIX/bin/piifence"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
echo "Then set the upstream (PIIF_UPSTREAM, or ANTHROPIC_BASE_URL) and run: piifence claude"
