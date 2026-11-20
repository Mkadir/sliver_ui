#!/usr/bin/env bash
# Offline setup for a packed Sliver UI + patched sliver-server bundle.
# Does NOT download this project's GitHub releases. Binaries must be in ./bin/.
#
# Usage (from the extracted bundle directory):
#   bash setup.sh
#   bash setup.sh --addr 127.0.0.1:8080 --user admin --pass '…'
#
# Flags:
#   --addr HOST:PORT   UI listen (default 0.0.0.0:8080 — all interfaces, no reverse proxy)
#   --user / --pass    UI login (random pass if omitted)
#   --no-auth          Disable UI login
#   --prefix DIR       Install prefix (default ~/.local/share/sliver-ui)
#   --skip-systemd     Files only
#   --no-start         Enable units but do not start
#   --replace-server   Overwrite an existing sliver.service
#   -h, --help

set -euo pipefail

ADDR="0.0.0.0:8080"
UI_USER="admin"
UI_PASS=""
NO_AUTH=0
SKIP_SYSTEMD=0
NO_START=0
REPLACE_SERVER=0
PREFIX="${HOME}/.local/share/sliver-ui"
PROFILE="sliverui"

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${BUNDLE_DIR}/bin"
SHARE="${BUNDLE_DIR}/share"

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
log()  { printf '%s[*]%s %s\n' "$CYN" "$RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YLW" "$RST" "$*"; }
die()  { printf '%s[x]%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,20p' "$0" | sed 's/^# \?//'; exit 0; }

random_pass() {
  if have openssl; then openssl rand -base64 18 | tr -d '/+=' | head -c 20; return; fi
  if have python3; then
    python3 - <<'PY'
import secrets, string
print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)))
PY
    return
  fi
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --addr) ADDR="${2:?}"; shift 2 ;;
    --user) UI_USER="${2:?}"; shift 2 ;;
    --pass) UI_PASS="${2:?}"; shift 2 ;;
    --no-auth) NO_AUTH=1; shift ;;
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --skip-systemd) SKIP_SYSTEMD=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --replace-server) REPLACE_SERVER=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$(uname -s)" == "Linux" || "$(uname -s)" == "Darwin" ]] || die "Linux or macOS required (on Windows use setup.ps1 → WSL)"
[[ -n "${HOME:-}" ]] || die "HOME is not set"

# Implant generate (garble) shells out to `git apply`. Without git, UI generate returns exit status 1.
ensure_git() {
  if have git; then
    ok "git: $(command -v git)"
    return
  fi
  warn "git not found — implant generate will fail until git is installed"
  if [[ "$(id -u)" -eq 0 ]] && have apt-get; then
    log "installing git via apt-get…"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git >/dev/null 2>&1 || true
  elif [[ "$(id -u)" -eq 0 ]] && have dnf; then
    dnf install -y -q git >/dev/null 2>&1 || true
  elif [[ "$(id -u)" -eq 0 ]] && have yum; then
    yum install -y -q git >/dev/null 2>&1 || true
  elif have brew; then
    brew install git >/dev/null 2>&1 || true
  fi
  if have git; then
    ok "git installed: $(command -v git)"
  else
    warn "install git manually (apt/dnf/yum/brew), then retry generate"
  fi
}
ensure_git

for b in sliver-ui sliver-server sliver-client; do
  [[ -x "${BIN_SRC}/${b}" || -f "${BIN_SRC}/${b}" ]] || die "missing ${BIN_SRC}/${b} — unpack the full bundle"
done

INSTALL_BIN="${PREFIX}/bin"
UNIT_DIR="${HOME}/.local/lib/systemd/system"
CONFIG_DIR="${HOME}/.config/sliver-ui"
ENV_FILE="${CONFIG_DIR}/env"
CLIENT_CONFIGS="${HOME}/.sliver-client/configs"
UI_BIN="${INSTALL_BIN}/sliver-ui"
SERVER_BIN="${INSTALL_BIN}/sliver-server"
CLIENT_BIN="${INSTALL_BIN}/sliver-client"

mkdir -p "$INSTALL_BIN" "$CONFIG_DIR" "$CLIENT_CONFIGS" "${HOME}/bin" "$UNIT_DIR"

log "offline bundle setup (no GitHub download)"
log "prefix=${PREFIX} addr=${ADDR}"

cp -f "${BIN_SRC}/sliver-ui" "$UI_BIN"
cp -f "${BIN_SRC}/sliver-server" "$SERVER_BIN"
cp -f "${BIN_SRC}/sliver-client" "$CLIENT_BIN"
chmod 755 "$UI_BIN" "$SERVER_BIN" "$CLIENT_BIN"
ln -sfn "$UI_BIN" "${HOME}/bin/sliver-ui"
ln -sfn "$SERVER_BIN" "${HOME}/bin/sliver-server"
ln -sfn "$CLIENT_BIN" "${HOME}/bin/sliver-client"
# Operators often type `sliver` (upstream CLI name) — point it at our client.
ln -sfn "$CLIENT_BIN" "${HOME}/bin/sliver"
ok "installed binaries → ${INSTALL_BIN}"
# Ensure ~/bin is on PATH for this shell and future logins (best-effort).
case ":${PATH}:" in
  *":${HOME}/bin:"*) ;;
  *) export PATH="${HOME}/bin:${PATH}" ;;
esac
if [[ -f "${HOME}/.profile" ]] && ! grep -q 'HOME/bin' "${HOME}/.profile" 2>/dev/null; then
  printf '\n# sliver-ui bundle\nexport PATH="$HOME/bin:$PATH"\n' >> "${HOME}/.profile"
fi
ok "PATH includes ${HOME}/bin (symlink: sliver → sliver-client)"

# Operator profile (wires UI ↔ server)
if [[ -f "${CLIENT_CONFIGS}/${PROFILE}.cfg" || -f "${CLIENT_CONFIGS}/${PROFILE}.json" ]]; then
  ok "keeping existing profile ${PROFILE}"
else
  log "issuing operator ${PROFILE}"
  if [[ ! -d "${HOME}/.sliver" ]]; then
    "$SERVER_BIN" unpack >/dev/null 2>&1 || true
  fi
  op_file="${CLIENT_CONFIGS}/${PROFILE}.cfg"
  if "$SERVER_BIN" operator --name "$PROFILE" --lhost 127.0.0.1 --lport 31337 --permissions all --save "$op_file" >/dev/null 2>&1; then
    ln -sfn "${PROFILE}.cfg" "${CLIENT_CONFIGS}/${PROFILE}.json"
    ok "wrote ${op_file}"
  else
    die "could not issue operator config (check ${SERVER_BIN} operator --help)"
  fi
fi

# UI auth
if [[ "$NO_AUTH" -eq 1 ]]; then
  rm -f "$ENV_FILE"
  warn "UI auth disabled"
else
  if [[ -z "$UI_PASS" && -f "$ENV_FILE" ]] && grep -q '^SLIVER_UI_PASS=' "$ENV_FILE"; then
    UI_PASS="$(grep '^SLIVER_UI_PASS=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
    UI_USER="$(grep '^SLIVER_UI_USER=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
    UI_USER="${UI_USER:-admin}"
    ok "keeping existing UI credentials"
  else
    [[ -n "$UI_PASS" ]] || UI_PASS="$(random_pass)"
  fi
  umask 077
  cat > "$ENV_FILE" <<EOF
SLIVER_UI_USER=${UI_USER}
SLIVER_UI_PASS=${UI_PASS}
EOF
  chmod 600 "$ENV_FILE"
  ok "wrote ${ENV_FILE}"
fi

run_user="$(id -un)"
run_group="$(id -gn)"

cat > "${UNIT_DIR}/sliver.service" <<EOF
[Unit]
Description=Sliver C2 teamserver (offline bundle)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${run_user}
Group=${run_group}
WorkingDirectory=${PREFIX}
ExecStart=${SERVER_BIN} daemon
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

cat > "${UNIT_DIR}/sliver-ui.service" <<EOF
[Unit]
Description=Sliver UI (web console, offline bundle)
After=network-online.target sliver.service
Wants=network-online.target sliver.service

[Service]
Type=simple
User=${run_user}
Group=${run_group}
WorkingDirectory=${PREFIX}
EnvironmentFile=-${ENV_FILE}
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 45); do ss -ltn 2>/dev/null | grep -q ":31337 " && exit 0; sleep 1; done; exit 0'
ExecStart=${UI_BIN} --no-window --no-browser --addr ${ADDR} --profile ${PROFILE}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

mkdir -p "${PREFIX}/systemd"
cp -f "${UNIT_DIR}/sliver.service" "${PREFIX}/systemd/"
cp -f "${UNIT_DIR}/sliver-ui.service" "${PREFIX}/systemd/"

start_direct() {
  log "starting without systemd"
  if ! ss -ltn 2>/dev/null | grep -q ':31337 '; then
    nohup "$SERVER_BIN" daemon >/tmp/sliver-server.bundle.log 2>&1 &
    ok "sliver-server daemon pid $!"
    for i in $(seq 1 45); do
      ss -ltn 2>/dev/null | grep -q ':31337 ' && break
      sleep 1
    done
  else
    ok "port 31337 already listening"
  fi
  if ! ss -ltn 2>/dev/null | grep -Eq ":${ADDR##*:} "; then
    if [[ "$NO_AUTH" -eq 0 && -f "$ENV_FILE" ]]; then
      # shellcheck disable=SC1090
      set -a
      # shellcheck disable=SC1090
      . "$ENV_FILE"
      set +a
    fi
    nohup "$UI_BIN" --no-window --no-browser --addr "$ADDR" --profile "$PROFILE" \
      >/tmp/sliver-ui.bundle.log 2>&1 &
    ok "sliver-ui pid $!"
  fi
}

if [[ "$SKIP_SYSTEMD" -eq 1 ]]; then
  warn "skipped systemd"
  [[ "$NO_START" -eq 0 ]] && start_direct
elif [[ "$(uname -s)" == "Linux" ]] && have systemctl; then
  if systemctl link "${UNIT_DIR}/sliver-ui.service" >/dev/null 2>&1; then
    ok "linked sliver-ui.service"
  else
    warn "systemctl link sliver-ui failed — will try direct start"
  fi
  if [[ "$REPLACE_SERVER" -eq 1 ]] || ! systemctl show sliver.service -p LoadState --value 2>/dev/null | grep -qx loaded; then
    systemctl link "${UNIT_DIR}/sliver.service" >/dev/null 2>&1 && ok "linked sliver.service" \
      || warn "systemctl link sliver.service failed"
  else
    warn "sliver.service already loaded — pass --replace-server to overwrite"
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable sliver.service sliver-ui.service >/dev/null 2>&1 || true
  systemctl add-wants sliver.service sliver-ui.service >/dev/null 2>&1 || true
  if [[ "$NO_START" -eq 0 ]]; then
    systemctl start sliver.service >/dev/null 2>&1 || start_direct
    sleep 2
    systemctl restart sliver-ui.service >/dev/null 2>&1 || systemctl start sliver-ui.service >/dev/null 2>&1 || start_direct
    sleep 2
    if systemctl is-active --quiet sliver-ui.service 2>/dev/null || ss -ltn 2>/dev/null | grep -Eq ":${ADDR##*:} "; then
      ok "services up"
    else
      warn "UI may not be active — check journalctl -u sliver-ui -n 50"
    fi
  fi
else
  warn "no systemd — direct start"
  [[ "$NO_START" -eq 0 ]] && start_direct
fi

# Seed ms-update HTTP C2 when share file + curl available (non-fatal)
seed_ms_update() {
  [[ "$NO_AUTH" -eq 1 ]] && return 0
  [[ -f "${SHARE}/ms-update-http-c2.json" ]] || return 0
  have curl || return 0
  local port="${ADDR##*:}"
  local base="http://127.0.0.1:${port}"
  [[ "$ADDR" == 0.0.0.0:* ]] || base="http://${ADDR}"
  # wait for UI
  for i in $(seq 1 30); do
    curl -fsS -o /dev/null "${base}/" 2>/dev/null && break
    sleep 1
  done
  local cj
  cj="$(mktemp)"
  if curl -fsS -c "$cj" -H 'Content-Type: application/json' \
    -d "{\"username\":\"${UI_USER}\",\"password\":\"${UI_PASS}\"}" \
    "${base}/api/auth/login" >/dev/null 2>&1; then
    # Create first (overwrite=false). Some servers return NotFound on overwrite of missing name.
    if curl -fsS -b "$cj" -H 'Content-Type: application/json' \
      -d "{\"overwrite\":false,\"config\":$(cat "${SHARE}/ms-update-http-c2.json")}" \
      "${base}/api/http-c2-profiles" >/dev/null 2>&1 \
      || curl -fsS -b "$cj" -H 'Content-Type: application/json' \
      -d "{\"overwrite\":true,\"config\":$(cat "${SHARE}/ms-update-http-c2.json")}" \
      "${base}/api/http-c2-profiles" >/dev/null 2>&1; then
      ok "seeded HTTP C2 profile ms-update"
    else
      warn "could not seed ms-update (save it once from UI → HTTP C2)"
    fi
  fi
  rm -f "$cj"
}
[[ "$NO_START" -eq 0 ]] && seed_ms_update || true

UI_URL="http://${ADDR}/"
PORT="${ADDR##*:}"
[[ "$ADDR" == 0.0.0.0:* || "$ADDR" == "[::]:"* ]] && UI_URL="http://127.0.0.1:${PORT}/"

echo
ok "ready — open the UI and generate"
echo
printf '  Listen:   %s (all interfaces; no nginx required)\n' "$ADDR"
printf '  Local:    %s\n' "$UI_URL"
printf '  Remote:   http://<server-ip>:%s/\n' "$PORT"
printf '  Profile:  %s (UI↔teamserver on 127.0.0.1:31337)\n' "$PROFILE"
if [[ "$NO_AUTH" -eq 0 ]]; then
  printf '  Login:    %s / %s\n' "$UI_USER" "$UI_PASS"
  printf '  Env:      %s\n' "$ENV_FILE"
fi
echo
echo "  Open firewall for TCP ${PORT} if clients reach this host directly."
echo "  Next: Implants → windows/amd64 → format=shared → HTTPS + ms-update → Generate"
echo "        then Loaders → disk LoadLibrary wrap."
echo
