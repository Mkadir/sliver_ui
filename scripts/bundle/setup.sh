#!/usr/bin/env bash
# One-shot offline setup. On the server you only need:
#   tar xzf sliver-ui-bundle-*.tar.gz && cd sliver-ui-bundle-* && bash setup.sh
#
# This script:
#   1) installs OS deps (git, curl, …) — required for implant generate
#   2) removes any previous bundle/systemd install (full clean by default)
#   3) installs sliver-server + sliver-ui + operator wiring
#   4) starts services on 0.0.0.0:8080 (no nginx)
#   5) seeds ms-update HTTP C2 profile when possible
#
# Does NOT download this project's GitHub. Binaries must be in ./bin/.
#
# Flags:
#   --addr HOST:PORT   UI listen (default 0.0.0.0:8080)
#   --user / --pass    UI login (random pass if omitted; always regenerated on clean)
#   --no-auth          Disable UI login
#   --prefix DIR       Install prefix (default ~/.local/share/sliver-ui)
#   --keep-data        Do not wipe ~/.sliver / UI env / operator profile
#   --skip-systemd     Do not use systemd (direct nohup)
#   --no-start         Install only, do not start
#   -h, --help

set -euo pipefail

ADDR="0.0.0.0:8080"
UI_USER="admin"
UI_PASS=""
NO_AUTH=0
SKIP_SYSTEMD=0
NO_START=0
KEEP_DATA=0
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

usage() { sed -n '2,28p' "$0" | sed 's/^# \?//'; exit 0; }

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

# Run package commands as root when possible.
as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif have sudo; then
    sudo -n "$@" 2>/dev/null || sudo "$@"
  else
    return 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --addr) ADDR="${2:?}"; shift 2 ;;
    --user) UI_USER="${2:?}"; shift 2 ;;
    --pass) UI_PASS="${2:?}"; shift 2 ;;
    --no-auth) NO_AUTH=1; shift ;;
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --keep-data) KEEP_DATA=1; shift ;;
    --skip-systemd) SKIP_SYSTEMD=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --replace-server) shift ;; # always replaced on clean; kept for compat
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$(uname -s)" == "Linux" || "$(uname -s)" == "Darwin" ]] || die "Linux or macOS required (on Windows use setup.ps1 → WSL)"
[[ -n "${HOME:-}" ]] || die "HOME is not set"

for b in sliver-ui sliver-server sliver-client; do
  [[ -f "${BIN_SRC}/${b}" ]] || die "missing ${BIN_SRC}/${b} — unpack the full bundle"
done

INSTALL_BIN="${PREFIX}/bin"
UNIT_DIR="${HOME}/.local/lib/systemd/system"
CONFIG_DIR="${HOME}/.config/sliver-ui"
ENV_FILE="${CONFIG_DIR}/env"
CLIENT_CONFIGS="${HOME}/.sliver-client/configs"
UI_BIN="${INSTALL_BIN}/sliver-ui"
SERVER_BIN="${INSTALL_BIN}/sliver-server"
CLIENT_BIN="${INSTALL_BIN}/sliver-client"
CRED_FILE="${PREFIX}/CREDENTIALS.txt"
PORT="${ADDR##*:}"

# ---------- deps ----------
install_deps() {
  log "ensuring OS packages (git required for implant generate)…"
  local need=()
  have git || need+=(git)
  have curl || need+=(curl)
  have ss || need+=(iproute2)
  # ca-certificates often needed for HTTPS listeners later
  if [[ -d /etc/ssl/certs ]] || [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
    :
  else
    need+=(ca-certificates)
  fi
  if [[ ${#need[@]} -eq 0 ]]; then
    ok "deps already present (git=$(command -v git))"
    return
  fi
  if have apt-get; then
    as_root env DEBIAN_FRONTEND=noninteractive apt-get update -qq \
      && as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" \
      || warn "apt install failed for: ${need[*]}"
  elif have dnf; then
    as_root dnf install -y -q "${need[@]}" || warn "dnf install failed"
  elif have yum; then
    as_root yum install -y -q "${need[@]}" || warn "yum install failed"
  elif have brew; then
    brew install "${need[@]}" || warn "brew install failed"
  else
    warn "no package manager — install manually: ${need[*]}"
  fi
  have git || die "git is required for implant generate (garble uses git apply). Install git and re-run setup.sh"
  ok "git ok: $(command -v git)"
}

# ---------- purge previous install ----------
purge_old() {
  log "removing previous install (full clean)…"

  # Stop systemd units (user-linked or system).
  if have systemctl; then
    systemctl stop sliver-ui.service sliver.service >/dev/null 2>&1 || true
    systemctl disable sliver-ui.service sliver.service >/dev/null 2>&1 || true
    as_root systemctl stop sliver-ui.service sliver.service >/dev/null 2>&1 || true
    as_root systemctl disable sliver-ui.service sliver.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    as_root systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  # Kill leftover processes from old binaries / nohup starts.
  pkill -f '[s]liver-server daemon' >/dev/null 2>&1 || true
  pkill -f '[s]liver-ui --no-window' >/dev/null 2>&1 || true
  sleep 1

  # Remove unit files we own + common system link locations.
  rm -f "${UNIT_DIR}/sliver.service" "${UNIT_DIR}/sliver-ui.service" 2>/dev/null || true
  as_root rm -f /etc/systemd/system/sliver.service /etc/systemd/system/sliver-ui.service \
    /etc/systemd/system/multi-user.target.wants/sliver.service \
    /etc/systemd/system/multi-user.target.wants/sliver-ui.service >/dev/null 2>&1 || true

  # Install prefix + CLI symlinks.
  rm -rf "${PREFIX}"
  rm -f "${HOME}/bin/sliver" "${HOME}/bin/sliver-ui" "${HOME}/bin/sliver-server" "${HOME}/bin/sliver-client"
  as_root rm -f /usr/local/bin/sliver /usr/local/bin/sliver-ui /usr/local/bin/sliver-server /usr/local/bin/sliver-client \
    /etc/profile.d/sliver-ui.sh >/dev/null 2>&1 || true

  if [[ "$KEEP_DATA" -eq 0 ]]; then
    rm -rf "${CONFIG_DIR}"
    rm -f "${CLIENT_CONFIGS}/${PROFILE}.cfg" "${CLIENT_CONFIGS}/${PROFILE}.json"
    # Fresh teamserver state so operator/UI always match this binary set.
    rm -rf "${HOME}/.sliver"
    ok "wiped UI config, operator profile '${PROFILE}', and ~/.sliver"
  else
    warn "--keep-data: keeping ~/.sliver, ${CONFIG_DIR}, operator profile"
  fi

  if have systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    as_root systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  ok "previous install removed"
}

open_firewall() {
  # Best-effort: only if a firewall tool is already active.
  if have ufw && as_root ufw status 2>/dev/null | grep -qi 'Status: active'; then
    as_root ufw allow "${PORT}/tcp" >/dev/null 2>&1 && ok "ufw allowed TCP ${PORT}" || true
  fi
  if have firewall-cmd && as_root firewall-cmd --state 2>/dev/null | grep -qi running; then
    as_root firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 || true
    as_root firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld allowed TCP ${PORT}"
  fi
}

ensure_path() {
  export PATH="${HOME}/bin:${PATH}"
  mkdir -p "${HOME}/bin"
  # Idempotent PATH lines for common shells.
  for rc in "${HOME}/.profile" "${HOME}/.bashrc" "${HOME}/.zshrc"; do
    [[ -e "$rc" || "$rc" == "${HOME}/.profile" ]] || continue
    touch "$rc"
    if ! grep -q 'sliver-ui bundle' "$rc" 2>/dev/null; then
      printf '\n# sliver-ui bundle\nexport PATH="$HOME/bin:$PATH"\n' >> "$rc"
    fi
  done
}

# ---------- main ----------
log "offline one-shot setup (no GitHub)"
log "prefix=${PREFIX} addr=${ADDR}"

install_deps
purge_old
open_firewall
ensure_path

mkdir -p "$INSTALL_BIN" "$CONFIG_DIR" "$CLIENT_CONFIGS" "${HOME}/bin" "$UNIT_DIR"

cp -f "${BIN_SRC}/sliver-ui" "$UI_BIN"
cp -f "${BIN_SRC}/sliver-server" "$SERVER_BIN"
cp -f "${BIN_SRC}/sliver-client" "$CLIENT_BIN"
chmod 755 "$UI_BIN" "$SERVER_BIN" "$CLIENT_BIN"
ln -sfn "$UI_BIN" "${HOME}/bin/sliver-ui"
ln -sfn "$SERVER_BIN" "${HOME}/bin/sliver-server"
ln -sfn "$CLIENT_BIN" "${HOME}/bin/sliver-client"
ln -sfn "$CLIENT_BIN" "${HOME}/bin/sliver"
# System-wide CLI so `sliver` works in any shell/SSH without relying on ~/bin PATH.
if as_root true 2>/dev/null; then
  as_root ln -sfn "$UI_BIN" /usr/local/bin/sliver-ui
  as_root ln -sfn "$SERVER_BIN" /usr/local/bin/sliver-server
  as_root ln -sfn "$CLIENT_BIN" /usr/local/bin/sliver-client
  as_root ln -sfn "$CLIENT_BIN" /usr/local/bin/sliver
  as_root tee /etc/profile.d/sliver-ui.sh >/dev/null <<'EOF' || true
# sliver-ui offline bundle
export PATH="/usr/local/bin:$PATH"
EOF
  ok "system CLI: /usr/local/bin/sliver → sliver-client"
else
  warn "no root/sudo — CLI only in ${HOME}/bin (open a new login shell or: export PATH=\"\$HOME/bin:\$PATH\")"
fi
ok "installed binaries → ${INSTALL_BIN} (CLI: sliver → sliver-client)"

# Fresh operator profile after clean (or missing).
log "issuing operator ${PROFILE}"
"$SERVER_BIN" unpack >/dev/null 2>&1 || true
op_file="${CLIENT_CONFIGS}/${PROFILE}.cfg"
rm -f "$op_file" "${CLIENT_CONFIGS}/${PROFILE}.json"
if ! "$SERVER_BIN" operator --name "$PROFILE" --lhost 127.0.0.1 --lport 31337 --permissions all --save "$op_file" >/dev/null 2>&1; then
  die "could not issue operator config"
fi
ln -sfn "${PROFILE}.cfg" "${CLIENT_CONFIGS}/${PROFILE}.json"
ok "wrote ${op_file}"

# UI auth — on clean install always new password unless --pass / --keep-data with existing env.
if [[ "$NO_AUTH" -eq 1 ]]; then
  rm -f "$ENV_FILE"
  warn "UI auth disabled"
else
  if [[ "$KEEP_DATA" -eq 1 && -z "$UI_PASS" && -f "$ENV_FILE" ]] && grep -q '^SLIVER_UI_PASS=' "$ENV_FILE"; then
    UI_PASS="$(grep '^SLIVER_UI_PASS=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
    UI_USER="$(grep '^SLIVER_UI_USER=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
    UI_USER="${UI_USER:-admin}"
    ok "keeping existing UI credentials (--keep-data)"
  else
    [[ -n "$UI_PASS" ]] || UI_PASS="$(random_pass)"
  fi
  umask 077
  mkdir -p "$CONFIG_DIR"
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
Environment=PATH=${HOME}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 60); do ss -ltn 2>/dev/null | grep -q ":31337 " && exit 0; sleep 1; done; exit 0'
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
  nohup "$SERVER_BIN" daemon >/tmp/sliver-server.bundle.log 2>&1 &
  ok "sliver-server daemon pid $!"
  for i in $(seq 1 60); do
    ss -ltn 2>/dev/null | grep -q ':31337 ' && break
    sleep 1
  done
  if [[ "$NO_AUTH" -eq 0 && -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
  fi
  nohup "$UI_BIN" --no-window --no-browser --addr "$ADDR" --profile "$PROFILE" \
    >/tmp/sliver-ui.bundle.log 2>&1 &
  ok "sliver-ui pid $!"
}

if [[ "$SKIP_SYSTEMD" -eq 1 ]]; then
  warn "skipped systemd"
  [[ "$NO_START" -eq 0 ]] && start_direct
elif [[ "$(uname -s)" == "Linux" ]] && have systemctl; then
  # Always replace units after purge.
  if systemctl link "${UNIT_DIR}/sliver.service" >/dev/null 2>&1; then
    ok "linked sliver.service"
  else
    # Fall back to copying into /etc when link is blocked.
    as_root cp -f "${UNIT_DIR}/sliver.service" /etc/systemd/system/sliver.service \
      && ok "installed /etc/systemd/system/sliver.service" \
      || warn "could not install sliver.service"
  fi
  if systemctl link "${UNIT_DIR}/sliver-ui.service" >/dev/null 2>&1; then
    ok "linked sliver-ui.service"
  else
    as_root cp -f "${UNIT_DIR}/sliver-ui.service" /etc/systemd/system/sliver-ui.service \
      && ok "installed /etc/systemd/system/sliver-ui.service" \
      || warn "could not install sliver-ui.service"
  fi
  systemctl daemon-reload >/dev/null 2>&1 || as_root systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable sliver.service sliver-ui.service >/dev/null 2>&1 \
    || as_root systemctl enable sliver.service sliver-ui.service >/dev/null 2>&1 || true
  systemctl add-wants sliver.service sliver-ui.service >/dev/null 2>&1 || true
  if [[ "$NO_START" -eq 0 ]]; then
    systemctl restart sliver.service >/dev/null 2>&1 \
      || systemctl start sliver.service >/dev/null 2>&1 \
      || start_direct
    sleep 2
    systemctl restart sliver-ui.service >/dev/null 2>&1 \
      || systemctl start sliver-ui.service >/dev/null 2>&1 \
      || start_direct
    sleep 2
    if systemctl is-active --quiet sliver-ui.service 2>/dev/null || ss -ltn 2>/dev/null | grep -Eq ":${PORT} "; then
      ok "services up"
    else
      warn "UI may not be active — journalctl -u sliver-ui -n 50"
    fi
  fi
else
  warn "no systemd — direct start"
  [[ "$NO_START" -eq 0 ]] && start_direct
fi

seed_ms_update() {
  [[ "$NO_AUTH" -eq 1 ]] && return 0
  [[ -f "${SHARE}/ms-update-http-c2.json" ]] || return 0
  have curl || return 0
  local base="http://127.0.0.1:${PORT}"
  [[ "$ADDR" == 0.0.0.0:* || "$ADDR" == "[::]:"* ]] || base="http://${ADDR}"
  for i in $(seq 1 45); do
    curl -fsS -o /dev/null "${base}/" 2>/dev/null && break
    sleep 1
  done
  local cj
  cj="$(mktemp)"
  if curl -fsS -c "$cj" -H 'Content-Type: application/json' \
    -d "{\"username\":\"${UI_USER}\",\"password\":\"${UI_PASS}\"}" \
    "${base}/api/auth/login" >/dev/null 2>&1; then
    if curl -fsS -b "$cj" -H 'Content-Type: application/json' \
      -d "{\"overwrite\":false,\"config\":$(cat "${SHARE}/ms-update-http-c2.json")}" \
      "${base}/api/http-c2-profiles" >/dev/null 2>&1 \
      || curl -fsS -b "$cj" -H 'Content-Type: application/json' \
      -d "{\"overwrite\":true,\"config\":$(cat "${SHARE}/ms-update-http-c2.json")}" \
      "${base}/api/http-c2-profiles" >/dev/null 2>&1; then
      ok "seeded HTTP C2 profile ms-update"
    else
      warn "ms-update seed skipped — save once from UI → HTTP C2 if needed"
    fi
  fi
  rm -f "$cj"
}
[[ "$NO_START" -eq 0 ]] && seed_ms_update || true

UI_URL="http://127.0.0.1:${PORT}/"
[[ "$ADDR" != 0.0.0.0:* && "$ADDR" != "[::]:"* ]] && UI_URL="http://${ADDR}/"

# Persist credentials for the operator (easy to find after setup).
{
  echo "Sliver UI credentials (generated by setup.sh)"
  echo "Listen:  ${ADDR}"
  echo "Local:   ${UI_URL}"
  echo "Remote:  http://<server-ip>:${PORT}/"
  echo "Profile: ${PROFILE}"
  if [[ "$NO_AUTH" -eq 0 ]]; then
    echo "User:    ${UI_USER}"
    echo "Pass:    ${UI_PASS}"
    echo "Env:     ${ENV_FILE}"
  else
    echo "Auth:    disabled"
  fi
  echo "CLI:     sliver  (symlink → sliver-client in ${HOME}/bin)"
} > "$CRED_FILE"
chmod 600 "$CRED_FILE"

echo
ok "ready — extract + setup.sh is all that was required"
echo
printf '  Listen:   %s\n' "$ADDR"
printf '  Local:    %s\n' "$UI_URL"
printf '  Remote:   http://<server-ip>:%s/\n' "$PORT"
printf '  Profile:  %s (UI↔teamserver 127.0.0.1:31337)\n' "$PROFILE"
if [[ "$NO_AUTH" -eq 0 ]]; then
  printf '  Login:    %s / %s\n' "$UI_USER" "$UI_PASS"
  printf '  Saved:    %s\n' "$CRED_FILE"
fi
echo
echo "  Generate needs git (installed by this script). CLI: sliver / sliver-client"
echo "  Implants → windows/amd64 → shared → HTTPS + ms-update → Generate"
echo "  then Loaders → disk LoadLibrary."
echo
