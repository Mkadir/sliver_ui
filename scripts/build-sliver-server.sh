#!/usr/bin/env bash
# Fetch Sliver v1.7.3, apply generator patches, build sliver-server + sliver-client.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${SLIVER_SRC:-$ROOT/third_party/sliver}"
OUT="${SLIVER_SERVER_OUT:-$ROOT/sliver-server}"
CLIENT_OUT="${SLIVER_CLIENT_OUT:-$ROOT/sliver-client}"

bash "$ROOT/scripts/fetch-sliver.sh"

SEED_FILE="$SRC/.sliverui-seed"
if [[ ! -f "$SEED_FILE" ]]; then
  openssl rand -hex 16 > "$SEED_FILE"
  echo "[*] new proto seed → $SEED_FILE"
fi
SEED="$(tr -d ' \n' < "$SEED_FILE")"
echo "[*] applying generator + proto patches (seed $SEED)"
mkdir -p "$ROOT/patches/sliver-v1.7.3"
echo "$SEED" > "$ROOT/patches/sliver-v1.7.3/seed.hex"
# Always morph from the stock identifier list. Walking an already-patched
# tree as -proto-src re-collects morphed names and double-applies.
NEEDLES="$ROOT/patches/sliver-v1.7.3/proto-idents.json"
[[ -f "$NEEDLES" ]] || { echo "missing $NEEDLES" >&2; exit 1; }
(cd "$ROOT/backend" && go run ./cmd/sliverpatch -root "$SRC" -generator -proto -proto-pkg -seed "$SEED" -needles "$NEEDLES") | tee "$ROOT/patches/sliver-v1.7.3/last-apply.json"
echo "[*] applying the same proto name map to sliver-ui backend"
(cd "$ROOT/backend" && go run ./cmd/sliverpatch -root "$ROOT/backend" -generator=false -proto -proto-pkg -seed "$SEED" -needles "$NEEDLES")
if [[ -f "$ROOT/backend/go.mod" ]] && ! grep -q "=> ../third_party/sliver" "$ROOT/backend/go.mod"; then
  echo "[*] go.mod replace github.com/bishopfox/sliver => ../third_party/sliver"
  (cd "$ROOT/backend" && go mod edit -replace github.com/bishopfox/sliver=../third_party/sliver && go mod tidy)
fi

echo "[*] building sliver-server (first run downloads Go/garble/zig assets — slow)"
# Skip `make clean` so a second run does not wipe .downloaded_assets.
(
  cd "$SRC"
  if [[ ! -f .downloaded_assets ]]; then
    make .downloaded_assets
  fi
  GOOS="$(go env GOOS)"
  GOARCH="$(go env GOARCH)"
  # Go 1.27+ may enable jsonv2 by default; Sliver's vendored
  # go-json-experiment alias expects APIs not present there.
  export GOEXPERIMENT="${GOEXPERIMENT:-nojsonv2}"
  CGO_ENABLED=0 go build -mod=vendor -trimpath -tags go_sqlite,server \
    -ldflags "-s -w" \
    -o "$OUT" ./server
  CGO_ENABLED=0 go build -mod=vendor -trimpath -tags go_sqlite,client \
    -ldflags "-s -w" \
    -o "$CLIENT_OUT" ./client
)
chmod 755 "$OUT" "$CLIENT_OUT"
echo "[+] $OUT"
echo "[+] $CLIENT_OUT"
echo "[+] protobuf family names were rewritten with seed $SEED (same map in sliver-ui)."
echo "[!] rebuild sliver-ui after this: cd backend && go build"
