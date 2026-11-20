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
2. On **≤2GB RAM** VPS, creates a **2GiB swapfile** if swap is missing (otherwise `unpack` / daemon get OOM-killed → UI “unreachable”)
3. **Full clean** of previous install (systemd, binaries, `~/.sliver`, env, operator). `--keep-data` keeps DB/creds
4. Installs binaries + `/usr/local/bin/sliver` (with sudo) → `sliver-client`
5. Unpacks assets, issues operator `sliverui`, starts **`0.0.0.0:8080`**
6. **Refuses to say “ready”** unless both `:31337` and `:8080` are listening
7. Seeds `ms-update` when possible; writes `CREDENTIALS.txt`

`Connection to server failed context deadline exceeded` almost always means teamserver died (often OOM on 1GB hosts). Re-run `sudo bash setup.sh` after this build (swap auto).

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
