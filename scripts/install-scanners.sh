#!/usr/bin/env bash
# Installs the scanner tools used by the audit engine (PRD §11), without Docker
# and without touching system directories:
#   - Semgrep  → its own virtualenv (.tools/semgrep-venv), linked as .tools/bin/semgrep.
#                Kept apart from the app's .venv: Semgrep pins its own dependency versions
#                (e.g. PyJWT ~=2.13) and must never hold back the app's security libraries.
#   - Gitleaks → downloaded to .tools/bin, SHA-256 verified against the release checksums
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
SEMGREP_VENV="$ROOT/.tools/semgrep-venv"
BIN_DIR="$ROOT/.tools/bin"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.178.0}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch=arm64 ;;
  x86_64|amd64) arch=x64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

echo "==> Semgrep $SEMGREP_VERSION → $SEMGREP_VENV"
mkdir -p "$BIN_DIR"
[ -x "$SEMGREP_VENV/bin/python" ] || "$PYTHON" -m venv "$SEMGREP_VENV"
"$SEMGREP_VENV/bin/pip" install --quiet --upgrade pip
"$SEMGREP_VENV/bin/pip" install --quiet "semgrep==$SEMGREP_VERSION"
ln -sf "$SEMGREP_VENV/bin/semgrep" "$BIN_DIR/semgrep"
"$BIN_DIR/semgrep" --version

echo "==> Gitleaks $GITLEAKS_VERSION → $BIN_DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
asset="gitleaks_${GITLEAKS_VERSION}_${os}_${arch}.tar.gz"
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/checksums.txt" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
expected="$(grep " $asset\$" "$tmp/checksums.txt" | awk '{print $1}')"
actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "Checksum mismatch for $asset (expected '$expected', got '$actual')" >&2
  exit 1
fi
tar -xzf "$tmp/$asset" -C "$tmp" gitleaks
install -m 0755 "$tmp/gitleaks" "$BIN_DIR/gitleaks"
"$BIN_DIR/gitleaks" version

echo "Done."
