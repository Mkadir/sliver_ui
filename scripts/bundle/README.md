# Sliver UI offline bundle

This archive is **self-contained**. It does **not** download this project from GitHub.

## Contents

| Path | Role |
|---|---|
| `bin/sliver-server` | Generator-patched teamserver |
| `bin/sliver-ui` | Web UI (embeds frontend) |
| `bin/sliver-client` | Optional CLI |
| `setup.sh` | Linux/macOS installer |
| `setup.ps1` | Windows → WSL wrapper |
| `share/ms-update-http-c2.json` | Non-default HTTP C2 profile seed |

## Linux

```bash
tar xzf sliver-ui-bundle-linux-amd64-*.tar.gz
cd sliver-ui-bundle-linux-amd64
bash setup.sh
# optional:
# bash setup.sh --addr 127.0.0.1:8080   # localhost only
# bash setup.sh --replace-server
```

Default listen is **`0.0.0.0:8080`** (all interfaces, no nginx). Open `http://127.0.0.1:8080/` on the host or `http://<server-ip>:8080/` from another machine, log in, then:

1. **Listeners** → HTTPS (e.g. `:8443` if you are not root for `:443`)
2. **Implants** → windows/amd64 · `format=shared` · HTTPS · HTTP C2 `ms-update` → Generate
3. **Loaders** → disk LoadLibrary wrap → download EXE+DLL

## Windows

Binaries in this bundle are **Linux ELF**. Use **WSL2**:

```powershell
wsl --install -d Ubuntu   # once
# copy/extract the bundle into a path WSL can see, then:
cd \path\to\sliver-ui-bundle-linux-amd64
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Browse to `http://127.0.0.1:8080/` (or the Windows host IP on port 8080) from Windows.

## Notes

- First `sliver-server` start may unpack assets under `~/.sliver`.
- UI talks to the local teamserver via operator profile `sliverui` (`127.0.0.1:31337`).
- Reinstall keeps existing UI password in `~/.config/sliver-ui/env` unless you pass `--pass`.
- This is for authorized lab / engagement use only.
