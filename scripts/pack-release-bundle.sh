#!/usr/bin/env bash
# Build sliver-ui + patched sliver-server and pack an offline distributable.
# Output does not require cloning this GitHub repo on the target machine.
#
# Usage (from repo root):
#   bash scripts/pack-release-bundle.sh
#   bash scripts/pack-release-bundle.sh --skip-build   # use existing ./sliver-* binaries
#
# Produces: dist/sliver-ui-bundle-<os>-<arch>-<date>.tar.gz

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKIP_BUILD=0
OUT_DIR="${ROOT}/dist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1; shift ;;
    --out) OUT_DIR="${2:?}"; shift 2 ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
esac
stamp="$(date +%Y%m%d_%H%M%S)"
name="sliver-ui-bundle-${os}-${arch}-${stamp}"
stage="${OUT_DIR}/${name}"
tarball="${OUT_DIR}/${name}.tar.gz"

cd "$ROOT"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "[*] building UI (make build)…"
  make build
  echo "[*] building patched sliver-server…"
  export GOCACHE="${GOCACHE:-/tmp/go-cache-sliver}"
  export GOEXPERIMENT="${GOEXPERIMENT:-nojsonv2}"
  bash scripts/build-sliver-server.sh
fi

[[ -x "${ROOT}/sliver-ui" ]] || { echo "missing ./sliver-ui — run without --skip-build" >&2; exit 1; }
[[ -x "${ROOT}/sliver-server" ]] || { echo "missing ./sliver-server" >&2; exit 1; }
[[ -x "${ROOT}/sliver-client" ]] || { echo "missing ./sliver-client" >&2; exit 1; }

rm -rf "$stage" "$tarball"
mkdir -p "${stage}/bin" "${stage}/share" "$OUT_DIR"
cp -f "${ROOT}/sliver-ui" "${ROOT}/sliver-server" "${ROOT}/sliver-client" "${stage}/bin/"
chmod 755 "${stage}/bin/"*
cp -f "${ROOT}/scripts/bundle/setup.sh" "${stage}/setup.sh"
cp -f "${ROOT}/scripts/bundle/setup.ps1" "${stage}/setup.ps1"
cp -f "${ROOT}/scripts/bundle/README.md" "${stage}/README.md"
cp -f "${ROOT}/scripts/bundle/share/ms-update-http-c2.json" "${stage}/share/"
chmod 755 "${stage}/setup.sh"

if grep -qE 'github.com/.*/releases/.*/sliver-ui-' "${stage}/setup.sh"; then
  echo "refusing to pack: setup.sh still downloads UI from GitHub" >&2
  exit 1
fi

tar -C "$OUT_DIR" -czf "$tarball" "$name"
rm -rf "$stage"

echo "[+] wrote ${tarball}"
ls -lh "$tarball"
echo
echo "Distribute that archive. Recipients run:"
echo "  tar xzf $(basename "$tarball") && cd ${name} && bash setup.sh"
