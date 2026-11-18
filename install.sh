#!/usr/bin/env bash
# install.sh — install Sliver UI and (by default) a generator-patched sliver-server.
#
# Usage (from a clone):
#   git clone <repo> && cd <repo>
#   bash install.sh
#
# Optional flags:
#   --addr HOST:PORT     Listen address (default: 127.0.0.1:8080)
#   --profile NAME       sliver-client profile to auto-connect (auto-detect if omitted)
#   --user NAME          UI login username (default: admin)
#   --pass PASS          UI login password (random if omitted)
#   --no-auth            Disable UI login (leave SLIVER_UI_* unset)
#   --build              Force build from source even if a binary exists
#   --with-server        Build/install generator-patched sliver-server (default)
#   --no-server          Skip teamserver; wire UI to an existing sliver-client
#   --replace-server     Overwrite systemd sliver.service with the bundled unit
#   --prefix DIR         Install directory (default: ~/.local/share/sliver-ui)
#   --skip-systemd       Install files only; do not enable/start the service
#   --no-start           Enable the unit but do not start it now
#   -h, --help           Show help
#
# Requires: go + node/npm for source builds (or a prebuilt ./sliver-ui next to this script).
# Does NOT download this project's GitHub releases unless ALLOW_GITHUB_RELEASE=1.
# Integrates with: sliver-client configs in ~/.sliver-client/configs/
#                  and systemd unit sliver.service when present.
#
# Prefer: ./builder.sh install   or   offline pack: ./builder.sh pack

set -euo pipefail

REPO_OWNER="${REPO_OWNER:-9Insomnie}"
REPO_NAME="${REPO_NAME:-sliver_ui}"
RELEASE_TAG="${RELEASE_TAG:-latest}"
ALLOW_GITHUB_RELEASE="${ALLOW_GITHUB_RELEASE:-0}"

ADDR="127.0.0.1:8080"
PROFILE=""
UI_USER="admin"
UI_PASS=""
NO_AUTH=0
FORCE_BUILD=0
SKIP_SYSTEMD=0
NO_START=0
WITH_SERVER=1
REPLACE_SERVER=0
PREFIX="${HOME}/.local/share/sliver-ui"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED=$'\033[31m'
GRN=$'\033[32m'
YLW=$'\033[33m'
CYN=$'\033[36m'
DIM=$'\033[2m'
RST=$'\033[0m'

log()  { printf '%s[*]%s %s\n' "$CYN" "$RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YLW" "$RST" "$*"; }
die()  { printf '%s[x]%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

usage() {
  sed -n '2,28p' "$0" | sed 's/^# \?//'
  exit 0
}

have() { command -v "$1" >/dev/null 2>&1; }

need_cmd() {
  have "$1" || die "missing required command: $1"
}

random_pass() {
  if have openssl; then
    openssl rand -base64 18 | tr -d '/+=' | head -c 20
    return
  fi
  if have python3; then
    python3 - <<'PY'
import secrets, string
alphabet = string.ascii_letters + string.digits
print("".join(secrets.choice(alphabet) for _ in range(20)))
PY
    return
  fi
  # Last resort: /dev/urandom
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
}

detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "unsupported architecture: $m" ;;
  esac
}

detect_os() {
  case "$(uname -s)" in
    Linux) echo linux ;;
    Darwin) echo darwin ;;
    *) die "unsupported OS: $(uname -s) (use Linux/macOS)" ;;
  esac
}

download() {
  local url="$1" out="$2"
  if have curl; then
    curl -fsSL -o "$out" "$url"
  elif have wget; then
    wget -qO "$out" "$url"
  else
    die "need curl or wget to download release binary"
  fi
}

# --- args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --addr) ADDR="${2:?}"; shift 2 ;;
    --profile) PROFILE="${2:?}"; shift 2 ;;
    --user) UI_USER="${2:?}"; shift 2 ;;
    --pass) UI_PASS="${2:?}"; shift 2 ;;
    --no-auth) NO_AUTH=1; shift ;;
    --build) FORCE_BUILD=1; shift ;;
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --skip-systemd) SKIP_SYSTEMD=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --with-server) WITH_SERVER=1; shift ;;
    --no-server) WITH_SERVER=0; shift ;;
    --replace-server) REPLACE_SERVER=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ "$(uname -s)" == "Linux" || "$(uname -s)" == "Darwin" ]] || die "Linux or macOS required"
[[ -n "${HOME:-}" ]] || die "HOME is not set"

INSTALL_BIN="${PREFIX}/bin"
INSTALL_UNIT_DIR="${HOME}/.local/lib/systemd/system"
CONFIG_DIR="${HOME}/.config/sliver-ui"
ENV_FILE="${CONFIG_DIR}/env"
CLIENT_CONFIGS="${HOME}/.sliver-client/configs"
BIN_NAME="sliver-ui"
TARGET_BIN="${INSTALL_BIN}/${BIN_NAME}"

log "Sliver UI installer"
log "prefix=${PREFIX}"
log "addr=${ADDR}"

# --- locate / obtain binary ---
mkdir -p "$INSTALL_BIN" "$CONFIG_DIR"

obtain_binary() {
  local src=""
  if [[ "$FORCE_BUILD" -eq 1 ]]; then
    log "forced source build"
  elif [[ -x "${SCRIPT_DIR}/sliver-ui" ]]; then
    src="${SCRIPT_DIR}/sliver-ui"
    ok "using existing binary: $src"
    cp -f "$src" "$TARGET_BIN"
    chmod 755 "$TARGET_BIN"
    return
  fi

  if [[ "$FORCE_BUILD" -eq 1 || ! -x "$TARGET_BIN" ]]; then
    if [[ -f "${SCRIPT_DIR}/Makefile" && -d "${SCRIPT_DIR}/backend" && -d "${SCRIPT_DIR}/frontend" ]]; then
      if have go && have npm && have make; then
        log "building from source (make build)…"
        (cd "$SCRIPT_DIR" && make build)
        [[ -x "${SCRIPT_DIR}/sliver-ui" ]] || die "make build did not produce ./sliver-ui"
        cp -f "${SCRIPT_DIR}/sliver-ui" "$TARGET_BIN"
        chmod 755 "$TARGET_BIN"
        ok "built and installed ${TARGET_BIN}"
        return
      fi
      warn "source tree found but go/npm/make missing — falling back to release binary"
    fi
  fi

  if [[ -x "$TARGET_BIN" && "$FORCE_BUILD" -eq 0 ]]; then
    ok "reusing installed binary: $TARGET_BIN"
    return
  fi

  if [[ "$ALLOW_GITHUB_RELEASE" != "1" ]]; then
    die "no local ./sliver-ui and no source build — run: ./builder.sh install   or pack an offline bundle: ./builder.sh pack   (set ALLOW_GITHUB_RELEASE=1 only if you intentionally want a GitHub release binary)"
  fi

  local os arch url tmp
  os="$(detect_os)"
  arch="$(detect_arch)"
  if [[ "$RELEASE_TAG" == "latest" ]]; then
    url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/sliver-ui-${os}-${arch}"
  else
    url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}/sliver-ui-${os}-${arch}"
  fi
  tmp="$(mktemp)"
  log "downloading ${url} (ALLOW_GITHUB_RELEASE=1)"
  download "$url" "$tmp"
  mv -f "$tmp" "$TARGET_BIN"
  chmod 755 "$TARGET_BIN"
  ok "installed release binary → ${TARGET_BIN}"
  warn "upstream release may not include local patches. Prefer ./builder.sh pack for offline distribution."
}

obtain_binary

mkdir -p "${HOME}/bin"

SERVER_BIN="${INSTALL_BIN}/sliver-server"
CLIENT_BIN="${INSTALL_BIN}/sliver-client"

obtain_server() {
  [[ "$WITH_SERVER" -eq 1 ]] || { warn "skipping bundled sliver-server (--no-server)"; return; }
  if [[ ! -f "${SCRIPT_DIR}/scripts/build-sliver-server.sh" ]]; then
    warn "no scripts/build-sliver-server.sh — skip teamserver"
    WITH_SERVER=0
    return
  fi
  have go || die "go is required to build the bundled sliver-server"
  have git || die "git is required to fetch BishopFox/sliver v1.7.3"
  log "building generator-patched sliver-server (first run downloads assets, slow)…"
  (cd "$SCRIPT_DIR" && bash scripts/build-sliver-server.sh)
  [[ -x "${SCRIPT_DIR}/sliver-server" ]] || die "sliver-server build failed"
  cp -f "${SCRIPT_DIR}/sliver-server" "$SERVER_BIN"
  chmod 755 "$SERVER_BIN"
  ln -sfn "$SERVER_BIN" "${HOME}/bin/sliver-server"
  if [[ -x "${SCRIPT_DIR}/sliver-client" ]]; then
    cp -f "${SCRIPT_DIR}/sliver-client" "$CLIENT_BIN"
    chmod 755 "$CLIENT_BIN"
    ln -sfn "$CLIENT_BIN" "${HOME}/bin/sliver-client"
  fi
  ok "installed patched sliver-server → ${SERVER_BIN}"
}

provision_operator() {
  [[ "$WITH_SERVER" -eq 1 && -x "$SERVER_BIN" ]] || return
  mkdir -p "$CLIENT_CONFIGS"
  if [[ -n "$PROFILE" ]] && [[ -f "${CLIENT_CONFIGS}/${PROFILE}.json" || -f "${CLIENT_CONFIGS}/${PROFILE}.cfg" ]]; then
    ok "keeping existing profile ${PROFILE}"
    return
  fi
  local op_name="sliverui"
  local op_file="${CLIENT_CONFIGS}/${op_name}.cfg"
  log "issuing operator config ${op_name} (lhost 127.0.0.1:31337)"
  # v1.7.3 app dir is ~/.sliver (not ~/.sliver-server).
  if [[ ! -d "${HOME}/.sliver" ]]; then
    "$SERVER_BIN" unpack >/dev/null 2>&1 || true
  fi
  if "$SERVER_BIN" operator --name "$op_name" --lhost 127.0.0.1 --lport 31337 --permissions all --save "$op_file" >/dev/null 2>&1; then
    PROFILE="$op_name"
    if [[ ! -e "${CLIENT_CONFIGS}/${op_name}.json" ]]; then
      ln -sfn "${op_name}.cfg" "${CLIENT_CONFIGS}/${op_name}.json"
    fi
    ok "wrote ${op_file}"
  else
    warn "could not issue operator config — start sliver-server then: sliver-server operator --name sliverui --lhost 127.0.0.1 --permissions all --save ${op_file}"
  fi
}

write_server_unit() {
  [[ "$WITH_SERVER" -eq 1 && -x "$SERVER_BIN" ]] || return
  local run_user run_group
  run_user="$(id -un)"
  run_group="$(id -gn)"
  mkdir -p "$INSTALL_UNIT_DIR"
  cat > "${INSTALL_UNIT_DIR}/sliver.service" <<EOF
[Unit]
Description=Sliver C2 teamserver (generator-patched, from sliver-ui tree)
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
  mkdir -p "${PREFIX}/systemd" "${SCRIPT_DIR}/systemd"
  cp -f "${INSTALL_UNIT_DIR}/sliver.service" "${PREFIX}/systemd/sliver.service"
  cp -f "${INSTALL_UNIT_DIR}/sliver.service" "${SCRIPT_DIR}/systemd/sliver.service"
  ok "wrote systemd unit → ${INSTALL_UNIT_DIR}/sliver.service"
}

obtain_server
provision_operator

# --- PATH shim ---
mkdir -p "${HOME}/bin"
ln -sfn "$TARGET_BIN" "${HOME}/bin/sliver-ui"
ok "linked ${HOME}/bin/sliver-ui"

if ! printf '%s' ":$PATH:" | grep -q ":${HOME}/bin:"; then
  SHELL_RC=""
  case "${SHELL:-}" in
    */zsh) SHELL_RC="${HOME}/.zshrc" ;;
    */bash) SHELL_RC="${HOME}/.bashrc" ;;
    *) SHELL_RC="${HOME}/.profile" ;;
  esac
  if [[ -n "$SHELL_RC" ]] && ! grep -q 'export PATH="$HOME/bin:$PATH"' "$SHELL_RC" 2>/dev/null; then
    printf '\n# sliver-ui\nexport PATH="$HOME/bin:$PATH"\n' >> "$SHELL_RC"
    ok "added ~/bin to PATH in ${SHELL_RC}"
  fi
fi

# --- sliver-client integration ---
integrate_client() {
  if ! have sliver-client && ! have sliver; then
    warn "sliver-client not found in PATH — UI will install, but you must supply a profile later"
    return
  fi
  ok "found sliver-client: $(command -v sliver-client 2>/dev/null || command -v sliver)"

  mkdir -p "$CLIENT_CONFIGS"

  # UI only lists *.json; Sliver often writes *.cfg — mirror both ways.
  local f base
  shopt -s nullglob
  for f in "${CLIENT_CONFIGS}"/*.cfg "${CLIENT_CONFIGS}"/*.json; do
    [[ -e "$f" ]] || continue
    base="$(basename "$f")"
    case "$base" in
      *.cfg)
        base="${base%.cfg}"
        if [[ ! -e "${CLIENT_CONFIGS}/${base}.json" ]]; then
          ln -sfn "${base}.cfg" "${CLIENT_CONFIGS}/${base}.json"
          ok "profile mirror: ${base}.cfg → ${base}.json"
        fi
        ;;
      *.json)
        base="${base%.json}"
        if [[ ! -e "${CLIENT_CONFIGS}/${base}.cfg" && -f "${CLIENT_CONFIGS}/${base}.json" && ! -L "${CLIENT_CONFIGS}/${base}.json" ]]; then
          : # json-only is fine
        fi
        ;;
    esac
  done
  shopt -u nullglob
}

pick_profile() {
  if [[ -n "$PROFILE" ]]; then
    if [[ -f "${CLIENT_CONFIGS}/${PROFILE}.json" || -f "${CLIENT_CONFIGS}/${PROFILE}.cfg" ]]; then
      ok "using profile: ${PROFILE}"
      return
    fi
    die "profile not found: ${PROFILE} (looked in ${CLIENT_CONFIGS})"
  fi

  local names=()
  local f base
  shopt -s nullglob
  for f in "${CLIENT_CONFIGS}"/*.json "${CLIENT_CONFIGS}"/*.cfg; do
    [[ -e "$f" ]] || continue
    base="$(basename "$f")"
    base="${base%.*}"
    # de-dupe
    local seen=0 n
    for n in "${names[@]:-}"; do
      [[ "$n" == "$base" ]] && seen=1 && break
    done
    [[ "$seen" -eq 0 ]] && names+=("$base")
  done
  shopt -u nullglob

  if [[ "${#names[@]}" -eq 0 ]]; then
    warn "no sliver-client profiles in ${CLIENT_CONFIGS}"
    warn "generate one on the teamserver, then re-run or connect from UI Settings"
    PROFILE=""
    return
  fi

  # Prefer configs that point at localhost.
  local pref=""
  for base in "${names[@]}"; do
    local raw="${CLIENT_CONFIGS}/${base}.cfg"
    [[ -f "$raw" ]] || raw="${CLIENT_CONFIGS}/${base}.json"
    if grep -Eq '"lhost"[[:space:]]*:[[:space:]]*"(127\.0\.0\.1|localhost)"' "$raw" 2>/dev/null; then
      pref="$base"
      break
    fi
  done
  if [[ -n "$pref" ]]; then
    PROFILE="$pref"
  else
    PROFILE="${names[0]}"
  fi
  ok "auto-selected profile: ${PROFILE}"
  if [[ "${#names[@]}" -gt 1 ]]; then
    log "other profiles: ${names[*]}"
  fi
}

integrate_client
pick_profile

# --- UI auth env ---
if [[ "$NO_AUTH" -eq 1 ]]; then
  rm -f "$ENV_FILE"
  warn "UI auth disabled (--no-auth)"
else
  if [[ -z "$UI_PASS" ]]; then
    if [[ -f "$ENV_FILE" ]] && grep -q '^SLIVER_UI_PASS=' "$ENV_FILE"; then
      # Keep existing password on reinstall unless --pass was given.
      # shellcheck disable=SC1090
      UI_PASS="$(grep '^SLIVER_UI_PASS=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
      UI_USER="$(grep '^SLIVER_UI_USER=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
      UI_USER="${UI_USER:-admin}"
      ok "keeping existing UI credentials in ${ENV_FILE}"
    else
      UI_PASS="$(random_pass)"
    fi
  fi
  umask 077
  cat > "$ENV_FILE" <<EOF
SLIVER_UI_USER=${UI_USER}
SLIVER_UI_PASS=${UI_PASS}
EOF
  chmod 600 "$ENV_FILE"
  ok "wrote UI credentials → ${ENV_FILE}"
fi

# --- systemd unit ---
write_unit() {
  local profile_flag=""
  if [[ -n "$PROFILE" ]]; then
    profile_flag=" --profile ${PROFILE}"
  fi
  local run_user run_group
  run_user="$(id -un)"
  run_group="$(id -gn)"

  mkdir -p "$INSTALL_UNIT_DIR"
  cat > "${INSTALL_UNIT_DIR}/sliver-ui.service" <<EOF
[Unit]
Description=Sliver UI (web console)
After=network-online.target sliver.service
Wants=network-online.target sliver.service

[Service]
Type=simple
User=${run_user}
Group=${run_group}
WorkingDirectory=${PREFIX}
EnvironmentFile=-${ENV_FILE}
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 30); do ss -ltn 2>/dev/null | grep -q ":31337 " && exit 0; sleep 1; done; exit 0'
ExecStart=${TARGET_BIN} --no-window --no-browser --addr ${ADDR}${profile_flag}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  # Keep a copy next to the install for reference.
  mkdir -p "${PREFIX}/systemd"
  cp -f "${INSTALL_UNIT_DIR}/sliver-ui.service" "${PREFIX}/systemd/sliver-ui.service"
  # Also refresh in-repo template when installing from a checkout.
  if [[ -d "${SCRIPT_DIR}/systemd" ]]; then
    cp -f "${INSTALL_UNIT_DIR}/sliver-ui.service" "${SCRIPT_DIR}/systemd/sliver-ui.service"
  fi
  ok "wrote systemd unit → ${INSTALL_UNIT_DIR}/sliver-ui.service"
}

install_systemd() {
  [[ "$(uname -s)" == "Linux" ]] || { warn "systemd setup skipped (not Linux)"; return; }
  have systemctl || { warn "systemctl not found — skip service install"; return; }

  write_unit
  write_server_unit

  # Link into /etc if possible (same pattern that works without interactive sudo on many hosts).
  if systemctl link "${INSTALL_UNIT_DIR}/sliver-ui.service" >/dev/null 2>&1; then
    ok "linked sliver-ui.service into systemd"
  else
    warn "systemctl link failed — try: sudo cp ${INSTALL_UNIT_DIR}/sliver-ui.service /etc/systemd/system/"
  fi
  if [[ "$WITH_SERVER" -eq 1 && -f "${INSTALL_UNIT_DIR}/sliver.service" ]]; then
    if [[ "$REPLACE_SERVER" -eq 1 ]] || ! systemctl show sliver.service -p LoadState --value 2>/dev/null | grep -qx loaded; then
      if systemctl link "${INSTALL_UNIT_DIR}/sliver.service" >/dev/null 2>&1; then
        ok "linked sliver.service into systemd"
      else
        warn "systemctl link sliver.service failed — try: sudo cp ${INSTALL_UNIT_DIR}/sliver.service /etc/systemd/system/"
      fi
    else
      warn "sliver.service already loaded — bundled unit is at ${INSTALL_UNIT_DIR}/sliver.service (pass --replace-server to overwrite)"
    fi
  fi

  systemctl daemon-reload >/dev/null 2>&1 || warn "daemon-reload failed (retry later with: systemctl daemon-reload)"

  if systemctl enable sliver-ui.service >/dev/null 2>&1; then
    ok "enabled sliver-ui.service"
  else
    warn "could not enable sliver-ui.service"
  fi

  # Pull UI up whenever sliver.service starts.
  # Prefer LoadState over `systemctl cat` — unit files under /etc may be
  # mode 0600 root-only, which makes `cat` fail even when the unit is loaded.
  sliver_loaded=0
  if systemctl show sliver.service -p LoadState --value 2>/dev/null | grep -qx loaded; then
    sliver_loaded=1
  elif [[ -e /etc/systemd/system/sliver.service || -e /usr/lib/systemd/system/sliver.service ]]; then
    sliver_loaded=1
  fi

  if [[ "$sliver_loaded" -eq 1 ]]; then
    if systemctl add-wants sliver.service sliver-ui.service >/dev/null 2>&1; then
      ok "sliver.service → Wants=sliver-ui.service"
    else
      warn "could not attach UI to sliver.service (start UI with: systemctl start sliver-ui)"
    fi
    if systemctl is-enabled sliver.service >/dev/null 2>&1; then
      ok "sliver.service already enabled"
    else
      systemctl enable sliver.service >/dev/null 2>&1 && ok "enabled sliver.service" || warn "enable sliver.service manually if needed"
    fi
  else
    warn "sliver.service not found — UI will not auto-start with the teamserver"
  fi

  if [[ "$NO_START" -eq 0 ]]; then
    # Prefer starting teamserver first when available.
    if [[ "$sliver_loaded" -eq 1 ]]; then
      systemctl start sliver.service >/dev/null 2>&1 || warn "could not start sliver.service"
      sleep 1
    fi
    if systemctl restart sliver-ui.service >/dev/null 2>&1 || systemctl start sliver-ui.service >/dev/null 2>&1; then
      sleep 1
      if systemctl is-active --quiet sliver-ui.service; then
        ok "sliver-ui.service is active"
      else
        warn "sliver-ui.service failed to become active — check: journalctl -u sliver-ui -n 50"
      fi
    else
      warn "could not start sliver-ui.service"
    fi
  fi
}

if [[ "$SKIP_SYSTEMD" -eq 0 ]]; then
  install_systemd
else
  write_unit
  warn "skipped systemd enable/start (--skip-systemd)"
fi

# --- summary ---
UI_URL="http://${ADDR}/"
if [[ "$ADDR" == 0.0.0.0:* ]]; then
  UI_URL="http://127.0.0.1:${ADDR##*:}/"
fi

echo
ok "Sliver UI install complete"
echo
printf '  Binary:   %s\n' "$TARGET_BIN"
printf '  URL:      %s\n' "$UI_URL"
if [[ -n "$PROFILE" ]]; then
  printf '  Profile:  %s\n' "$PROFILE"
else
  printf '  Profile:  (none — connect in Settings)\n'
fi
if [[ "$NO_AUTH" -eq 0 ]]; then
  printf '  Login:    %s / %s\n' "$UI_USER" "$UI_PASS"
  printf '  Env file: %s\n' "$ENV_FILE"
else
  printf '  Login:    disabled\n'
fi
echo
printf '%sCommands:%s\n' "$DIM" "$RST"
echo "  systemctl status sliver-ui"
echo "  systemctl restart sliver-ui"
echo "  journalctl -u sliver-ui -f"
echo
