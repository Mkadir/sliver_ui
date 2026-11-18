#!/usr/bin/env bash
# Single entrypoint for offline install / packing.
#
#   ./builder.sh install     # from this tree: build (if needed) + install server+UI locally
#   ./builder.sh pack        # build binaries and write dist/sliver-ui-bundle-*.tar.gz
#   ./builder.sh pack --skip-build
#
# Install never downloads this project's GitHub releases.
# Pack output is what you give to others so they do not need your repo.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

cmd="${1:-}"
shift || true

case "$cmd" in
  install)
    export ALLOW_GITHUB_RELEASE="${ALLOW_GITHUB_RELEASE:-0}"
    # Prefer local binaries / source build; --with-server wires teamserver.
    exec bash "$ROOT/install.sh" --build --with-server --replace-server "$@"
    ;;
  pack)
    exec bash "$ROOT/scripts/pack-release-bundle.sh" "$@"
    ;;
  -h|--help|help|"")
    cat <<'EOF'
Usage:
  ./builder.sh install [install.sh flags…]
  ./builder.sh pack [--skip-build]

install  — build from this checkout and install sliver-server + sliver-ui (systemd).
pack     — produce an offline tar.gz under dist/ for other machines (no GitHub clone).

Examples:
  ./builder.sh install --addr 0.0.0.0:8080 --user admin
  ./builder.sh pack
EOF
    exit 0
    ;;
  *)
    echo "unknown command: $cmd (try ./builder.sh help)" >&2
    exit 1
    ;;
esac
