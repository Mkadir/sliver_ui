# Sliver UI offline bundle

**Serverda faqat shu:**

```bash
tar xzf sliver-ui-bundle-linux-amd64-*.tar.gz
cd sliver-ui-bundle-linux-amd64-*
bash setup.sh
```

Boshqa hech narsa (`git`, PATH, eski service tozalash, systemd) — `setup.sh` o‘zi qiladi.

## What setup.sh does

1. Installs OS deps (`git`, `curl`, …) — **generate** fails without `git`
2. **Full clean** of previous install (systemd units, binaries, `~/.sliver`, UI env, operator profile). Use `--keep-data` only if you intentionally want to keep DB/creds
3. Installs `sliver-server` + `sliver-ui` + `sliver-client`
4. Creates CLI symlinks: `~/bin/sliver` and (with root/sudo) `/usr/local/bin/sliver` → `sliver-client`
5. Issues operator `sliverui`, starts services on **`0.0.0.0:8080`**
6. Seeds `ms-update` HTTP C2 when possible
7. Writes login to `~/.local/share/sliver-ui/CREDENTIALS.txt`

If `sliver: command not found` without root: `export PATH="$HOME/bin:$PATH"` (or new login shell). With sudo, `/usr/local/bin/sliver` works immediately.

Does **not** download this project from GitHub.

## Windows

Binaries are Linux ELF. Use WSL2:

```powershell
cd \path\to\extracted-bundle
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

## Optional flags

```bash
bash setup.sh --addr 127.0.0.1:8080   # localhost only
bash setup.sh --user admin --pass '…'
bash setup.sh --keep-data             # do not wipe ~/.sliver / env
bash setup.sh --skip-systemd          # nohup instead of systemd
```

## After setup

Open `http://<server-ip>:8080/` (or `http://127.0.0.1:8080/`), log in with credentials printed by setup (also in `CREDENTIALS.txt`).

Then: Implants → windows/amd64 → `shared` → HTTPS + `ms-update` → Generate → Loaders disk LoadLibrary.
