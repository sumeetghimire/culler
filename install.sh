#!/bin/sh
# culler installer — detects OS/arch, downloads the latest release binary,
# verifies the checksum, and installs to /usr/local/bin or ~/.local/bin.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/sumeetghimire/culler/main/install.sh | sh

set -e

REPO="sumeetghimire/culler"
BINARY="culler"

# ── helpers ──────────────────────────────────────────────────────────────────

say() { printf '\033[1m%s\033[0m\n' "$*" >&2; }
err() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || err "Required tool not found: $1. Install it and retry."
}

# ── detect OS and arch ───────────────────────────────────────────────────────

detect_os() {
  case "$(uname -s)" in
    Linux)  echo "linux" ;;
    Darwin) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) err "Unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) err "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ── install location ─────────────────────────────────────────────────────────

install_dir() {
  if [ -w /usr/local/bin ]; then
    echo "/usr/local/bin"
  else
    mkdir -p "$HOME/.local/bin"
    echo "$HOME/.local/bin"
  fi
}

# ── fetch latest version tag ─────────────────────────────────────────────────

latest_version() {
  need curl
  curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed 's/.*"tag_name": *"\(.*\)".*/\1/'
}

# ── main ─────────────────────────────────────────────────────────────────────

main() {
  need curl

  OS=$(detect_os)
  ARCH=$(detect_arch)
  VERSION=$(latest_version)

  if [ -z "$VERSION" ]; then
    err "Could not determine latest release. Check https://github.com/${REPO}/releases"
  fi

  EXT="tar.gz"
  if [ "$OS" = "windows" ]; then
    EXT="zip"
    BINARY="culler.exe"
  fi

  ARCHIVE="${BINARY%.*}_${OS}_${ARCH}.${EXT}"
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  ARCHIVE_URL="${BASE_URL}/${ARCHIVE}"
  CHECKSUM_URL="${BASE_URL}/checksums.txt"

  TMPDIR=$(mktemp -d)
  trap 'rm -rf "$TMPDIR"' EXIT

  say "Downloading culler ${VERSION} for ${OS}/${ARCH}..."
  curl -sSfL "$ARCHIVE_URL" -o "$TMPDIR/$ARCHIVE"
  curl -sSfL "$CHECKSUM_URL" -o "$TMPDIR/checksums.txt"

  # Verify checksum
  say "Verifying checksum..."
  cd "$TMPDIR"
  if command -v sha256sum >/dev/null 2>&1; then
    grep "$ARCHIVE" checksums.txt | sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    grep "$ARCHIVE" checksums.txt | shasum -a 256 -c -
  else
    say "Warning: cannot verify checksum (sha256sum/shasum not found)"
  fi

  # Extract
  if [ "$EXT" = "tar.gz" ]; then
    tar -xzf "$ARCHIVE" -C "$TMPDIR"
  else
    unzip -q "$ARCHIVE" -d "$TMPDIR"
  fi

  DEST=$(install_dir)
  say "Installing to ${DEST}/culler..."
  BINARY_PATH=$(find "$TMPDIR" -type f -name "$BINARY" | head -1)
  [ -z "$BINARY_PATH" ] && err "Could not find binary '$BINARY' in extracted archive"
  mv "$BINARY_PATH" "$DEST/$BINARY"
  chmod +x "$DEST/$BINARY" 2>/dev/null || true

  say "culler ${VERSION} installed successfully!"

  if ! echo "$PATH" | grep -q "$DEST"; then
    say ""
    say "Add ${DEST} to your PATH:"
    say "  export PATH=\"\$PATH:${DEST}\""
  fi

  say ""
  say "Get started:"
  say "  grype dir:. -o json | culler"
}

main "$@"
