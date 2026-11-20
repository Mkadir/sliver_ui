#!/usr/bin/env bash
# Spin the offline bundle in Docker and smoke-test UI + generate.
# Usage (repo root):
#   bash scripts/docker-test-bundle.sh
#   bash scripts/docker-test-bundle.sh /path/to/sliver-ui-bundle-*.tar.gz

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE="${1:-}"
if [[ -z "$BUNDLE" ]]; then
  BUNDLE="$(ls -t "$ROOT"/dist/sliver-ui-bundle-linux-amd64-*.tar.gz 2>/dev/null | head -1 || true)"
fi
[[ -n "$BUNDLE" && -f "$BUNDLE" ]] || { echo "no bundle tarball found" >&2; exit 1; }

NAME="sliv-bundle-test"
IMG="debian:bookworm-slim"
PORT_UI=18080
PORT_MTLS=18888

echo "[*] bundle: $BUNDLE"
docker rm -f "$NAME" >/dev/null 2>&1 || true

# Host ports may still be in use; pick free UI port check
if ss -ltn 2>/dev/null | grep -q ":${PORT_UI} "; then
  echo "port ${PORT_UI} busy" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
tar xzf "$BUNDLE" -C "$STAGE"
BUNDLE_DIR="$(find "$STAGE" -maxdepth 1 -type d -name 'sliver-ui-bundle-*' | head -1)"
[[ -d "$BUNDLE_DIR" ]] || { echo "bad archive layout" >&2; exit 1; }

# Ensure setup has sliver symlink (in case older tarball)
if ! grep -q 'ln -sfn "$CLIENT_BIN" "${HOME}/bin/sliver"' "$BUNDLE_DIR/setup.sh"; then
  echo "[!] tarball setup.sh lacks sliver symlink — using repo setup.sh"
  cp -f "$ROOT/scripts/bundle/setup.sh" "$BUNDLE_DIR/setup.sh"
  chmod 755 "$BUNDLE_DIR/setup.sh"
fi

echo "[*] starting container…"
docker run -d --name "$NAME" \
  --network bridge \
  -p "${PORT_UI}:8080" \
  -p "${PORT_MTLS}:8888" \
  -v "$BUNDLE_DIR:/bundle:ro" \
  "$IMG" \
  bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates procps iproute2 git >/tmp/apt.log 2>&1 && \
    cp -a /bundle /opt/sliver-ui-bundle && cd /opt/sliver-ui-bundle && \
    bash setup.sh --skip-systemd --addr 0.0.0.0:8080 --user admin --pass testpass123 --no-start && \
    export PATH="/root/bin:$PATH" && \
    nohup /root/.local/share/sliver-ui/bin/sliver-server daemon >/tmp/sliver-server.log 2>&1 & \
    for i in $(seq 1 60); do ss -ltn | grep -q ":31337 " && break; sleep 1; done && \
    set -a && . /root/.config/sliver-ui/env && set +a && \
    nohup /root/.local/share/sliver-ui/bin/sliver-ui --no-window --no-browser --addr 0.0.0.0:8080 --profile sliverui >/tmp/sliver-ui.log 2>&1 & \
    for i in $(seq 1 60); do curl -fsS -o /dev/null http://127.0.0.1:8080/ && break; sleep 1; done && \
    echo READY && sleep infinity'

echo "[*] waiting for READY…"
for i in $(seq 1 180); do
  if docker logs "$NAME" 2>&1 | grep -q '^READY$'; then
    echo "[+] container ready (${i}s)"
    break
  fi
  if [[ $i -eq 180 ]]; then
    echo "[x] timeout waiting for READY" >&2
    docker logs "$NAME" 2>&1 | tail -80
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    exit 1
  fi
  sleep 1
done

BASE="http://127.0.0.1:${PORT_UI}"
CJ="$(mktemp)"

echo "[*] login…"
code=$(curl -sS -c "$CJ" -o /tmp/sliv-login.json -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"testpass123"}' \
  "${BASE}/api/auth/login")
echo "  login HTTP $code $(head -c 120 /tmp/sliv-login.json)"
[[ "$code" == "200" ]] || { docker logs "$NAME" 2>&1 | tail -40; exit 1; }

echo "[*] /api/jobs…"
curl -sS -b "$CJ" "${BASE}/api/jobs" | head -c 300; echo

echo "[*] CLI: sliver vs sliver-client…"
docker exec "$NAME" bash -lc 'export PATH="/root/bin:$PATH"; command -v sliver; command -v sliver-client; sliver version 2>&1 | head -5 || sliver-client version 2>&1 | head -5'

echo "[*] seed ms-update (if share present)…"
docker exec "$NAME" bash -lc '
  if [[ -f /opt/sliver-ui-bundle/share/ms-update-http-c2.json ]]; then
    curl -fsS -c /tmp/cj -H "Content-Type: application/json" \
      -d "{\"username\":\"admin\",\"password\":\"testpass123\"}" http://127.0.0.1:8080/api/auth/login >/dev/null
    curl -sS -b /tmp/cj -H "Content-Type: application/json" \
      -d "{\"overwrite\":true,\"config\":$(cat /opt/sliver-ui-bundle/share/ms-update-http-c2.json)}" \
      http://127.0.0.1:8080/api/http-c2-profiles | head -c 200
    echo
  fi
'

echo "[*] start mTLS listener on 8888…"
# Prefer UI API if available
curl -sS -b "$CJ" -H 'Content-Type: application/json' \
  -d '{"type":"mtls","addr":"0.0.0.0","port":8888,"tls":false}' \
  "${BASE}/api/listeners" | tee /tmp/sliv-listener.json | head -c 400
echo

echo "[*] generate linux/amd64 exe (mtls) — may take several minutes (assets)…"
# Use mtls so default HTTP C2 block does not apply
gen_code=$(curl -sS -b "$CJ" -o /tmp/sliv-gen.json -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  --max-time 600 \
  -d '{"name":"docker_smoke","os":"linux","arch":"amd64","format":"exe","c2":[{"address":"127.0.0.1:8888","protocol":"mtls"}],"obfuscate":false}' \
  "${BASE}/api/generate")
echo "  generate HTTP $gen_code"
python3 - <<'PY'
import json
p="/tmp/sliv-gen.json"
try:
    d=json.load(open(p))
except Exception as e:
    print("  body parse fail", e, open(p).read()[:500])
    raise SystemExit(1)
print("  keys", list(d.keys())[:12])
print("  success", d.get("success"), "message", str(d.get("message") or d.get("error") or "")[:200])
if d.get("data"):
    print("  data_b64_len", len(d["data"]))
PY

if [[ "$gen_code" != "200" ]]; then
  echo "[!] generate failed — server/ui logs:"
  docker exec "$NAME" bash -lc 'tail -80 /tmp/sliver-server.log; echo ----; tail -80 /tmp/sliver-ui.log'
fi

echo "[*] container left running as ${NAME} (UI http://127.0.0.1:${PORT_UI}/). Stop with: docker rm -f ${NAME}"
rm -f "$CJ"
