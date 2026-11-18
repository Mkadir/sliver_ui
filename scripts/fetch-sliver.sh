#!/usr/bin/env bash
# Clone BishopFox/sliver v1.7.3 into third_party/sliver (not committed).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${SLIVER_SRC:-$ROOT/third_party/sliver}"
TAG="${SLIVER_TAG:-v1.7.3}"
REPO="${SLIVER_REPO:-https://github.com/BishopFox/sliver.git}"

if [[ -f "$DEST/go.mod" ]] && grep -q 'module github.com/bishopfox/sliver' "$DEST/go.mod"; then
  echo "[*] sliver checkout already at $DEST"
  exit 0
fi

mkdir -p "$(dirname "$DEST")"
if [[ -d "$DEST/.git" ]]; then
  git -C "$DEST" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null || git -C "$DEST" fetch --depth 1 origin "$TAG"
  git -C "$DEST" checkout -q "$TAG"
  echo "[+] updated $DEST to $TAG"
  exit 0
fi

echo "[*] cloning $REPO $TAG → $DEST"
git clone --depth 1 --branch "$TAG" "$REPO" "$DEST"
echo "[+] cloned $TAG"
