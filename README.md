# Sliver UI

<p align="center">
  <strong>Modern web &amp; desktop console for Sliver C2</strong><br>
  <em>Built for authorized red teaming, penetration testing, and adversary simulation</em>
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="./AUTHORIZED_USE.md"><img src="https://img.shields.io/badge/use-authorized%20only-important?style=flat-square" alt="Authorized use"></a>
  <a href="https://github.com/BishopFox/sliver"><img src="https://img.shields.io/badge/Sliver-v1.7.3-informational?style=flat-square" alt="Sliver"></a>
</p>

> **Authorized use only.** This project is an operator console for [Sliver](https://github.com/BishopFox/sliver), the open-source adversary-simulation framework. Use it only on systems you own or have **explicit written permission** to assess. See [AUTHORIZED_USE.md](./AUTHORIZED_USE.md).

Sliver UI connects to a Sliver teamserver over native gRPC (mTLS + token) and exposes day-to-day operations through a React web UI (or a Windows WebView2 window). The backend and frontend ship as a **single static Go binary** (`go:embed`).

```text
Browser / WebView2
        │  HTTP + WebSocket
        ▼
   Sliver UI (Go + embedded React)
        │  gRPC mTLS
        ▼
   Sliver teamserver
```

## Features

- **Sessions & beacons** — list, interact, tags, terminal (xterm.js)
- **Listeners & jobs** — start/stop common C2 listeners from the UI
- **Implant generation** — build payloads with C2 profiles, limits, and honest OPSEC notes
- **Host-side Loaders** — compile finished PE/ELF wrappers on the UI host (lab tooling; not an AV bypass claim)
- **HTTP C2 profiles** — edit and apply profiles; default fingerprint warnings in the UI
- **Operator auth** — optional UI login via environment credentials
- **i18n** — English and Simplified Chinese (lockstep keys)
- **Offline bundle** — pack server + UI for air-gapped / lab VPS install

## Quick start

### Prerequisites

- Go (version in `backend/go.mod`) and Node 20+ for builds from source
- A running [Sliver](https://github.com/BishopFox/sliver) teamserver and operator client config (`~/.sliver-client/configs/`)
- For Windows amd64/386 loaders: MinGW (`x86_64-w64-mingw32-gcc`)

### Development

```bash
make dev
# UI: http://127.0.0.1:5173  (proxies /api and /ws to :8080)
```

### Production binary

```bash
make build
./sliver-ui --addr 0.0.0.0:8080 --profile <operator-profile>
```

### Offline install (lab VPS)

```bash
./builder.sh pack          # on a build machine → dist/sliver-ui-bundle-*.tar.gz
# on the lab host:
tar xzf sliver-ui-bundle-*.tar.gz && cd sliver-ui-bundle-* && sudo bash setup.sh
```

`setup.sh` installs dependencies, wires a local patched teamserver + UI, and listens on `0.0.0.0:8080`. Prefer hosts with **≥2 GB RAM** for implant generation.

## Configuration

| Variable / flag | Purpose |
|---|---|
| `SLIVER_UI_USER` / `SLIVER_UI_PASS` | UI login (env file `~/.config/sliver-ui/env`) |
| `--profile` | Sliver operator config name |
| `--addr` | Listen address (default often `0.0.0.0:8080` for installers) |
| `--no-auth` | Disable UI login |
| `SLIVER_CLIENT_CONFIGS` | Alternate client config search path |

## Honest OPSEC

Obfuscate / evasion flags and unique hashes change **some** static indicators. They do **not** guarantee bypass of antivirus, EDR, sandboxes, or memory scanners. The UI states this explicitly for default HTTP C2 fingerprints and loader wraps. Do not market this project as “FUD” or “undetectable.”

## Documentation

| Doc | Contents |
|---|---|
| [AUTHORIZED_USE.md](./AUTHORIZED_USE.md) | Scope and responsible use |
| [docs/BUNDLED_SLIVER.md](./docs/BUNDLED_SLIVER.md) | Bundled / patched teamserver build |
| [docs/LOADER_AV_OPSEC_PLAN.md](./docs/LOADER_AV_OPSEC_PLAN.md) | Loader pipeline design notes |
| [docs/P1_OPERATOR_WORK.md](./docs/P1_OPERATOR_WORK.md) | Operator-console roadmap notes |
| [AGENTS.md](./AGENTS.md) | Notes for automated coding agents |

## Screenshots

| Dashboard | Sessions |
| :---: | :---: |
| ![Dashboard](Dashboard.png) | ![Sessions](Sessions.png) |
| **Implants** | **Terminal** |
| ![Implants](Implants.png) | ![Terminal](Terminal.png) |

## Development & CI

```bash
make test    # frontend vitest + backend go test
make vet     # go vet in backend/
```

GitHub Actions runs build and tests on push/PR. Releases can cross-compile with `CGO_ENABLED=0` (Windows GUI subsystem where applicable).

## Related projects

- [BishopFox/sliver](https://github.com/BishopFox/sliver) — C2 / adversary simulation framework this UI operates

## Contributing

Issues and pull requests that improve reliability, documentation, accessibility, and **authorized** operator workflows are welcome. Contributions that request covert malware distribution features or remove authorized-use warnings will be rejected.

## License

[MIT](./LICENSE)
