# P1 operator work — todo and done

Single tracking document for the P0/P1 operator-console slice of **Sliver UI** (`sliv`). This is an open-source BishopFox Sliver client (React + Go embed). Lab / authorized red-team use. Unique SHA-256 is hash-IOC hygiene only; it is not a sandbox or ML bypass. Do not claim FUD or VirusTotal 0/70.

Related: [reports/Sliver UI imkoniyatlar tahlili.md](../reports/Sliver%20UI%20imkoniyatlar%20tahlili.md), [LOADER_AV_OPSEC_PLAN.md](LOADER_AV_OPSEC_PLAN.md).

---

## Status

| Track | Item | State |
|---|---|---|
| P0 | Events WS + ring, beacon generate/tasking, sidebar IA | **Done** |
| P0 | `/api/external-builders`, Operators, ⌘K, HTTP C2 fingerprint | **Done** |
| P0 | Implant C2 vs jobs, SHA-256, screenshot/file→loot, canary, armory→aliases | **Done** |
| P1 slice 1 | Graph/files/loot, generate limits/external/spoof, encoders, reconfigure, BOF | **Done** |
| P1 remaining | Wasm Register/List/Exec (memfs, loot, session pipe drain) | **Done** |
| P1 remaining | `rportfwd` Start/Get/Stop (v1.7.3 RPC; teamserver owns reverse tunnels) | **Done** |
| P1 remaining | Local tags/notes/campaign, reactions (CLI `reactions.json`), who-ran-what, advisory lock | **Done** |
| P1 remaining | Session compare (UI-only over existing session fields + local tags) | **Done** |

JSON key `"builders"` on `GET /api/builders` stays ImplantBuilds. Route `/jobs` stays. Real `Builders()` is `GET /api/external-builders`.

**No go.mod bump.** `RegisterWasmExtension` / `ListWasmExtensions` / `ExecWasmExtension` and `StartRportFwdListener` / `GetRportFwdListeners` / `StopRportFwdListener` already exist on protobuf **v1.7.3**. Reverse-portfwd tunnel plumbing lives on the teamserver (`rtunnels.TrackListener`); the UI only issues the RPCs. Live lab is Sliver 1.7.9.

---

## Out of scope (still)

- In-tree Donut/ScareCrow, encrypt-at-rest redo, VT widget, FUD claims.
- Changing generate implant interval units (pre-existing seconds path that worked). Reconfigure **does** convert UI seconds → nanoseconds.
- Hard session lock, full multi-operator audit of other sliver-client processes (needs a new Sliver RPC).
- Interactive Wasm TTY (CLI `--pipe` to a live terminal). This UI drains the tunnel until exit or 60s.
- Cursed, MCP, AI, Crackstation, Crystal Palace / async BOF.

---

## P1 remaining — contracts

### Wasm (existing Sliver RPC)

Distinct from HTTP-C2 traffic-encoder Wasm.

- `GET /api/sessions/{id}/wasm` · `GET /api/beacons/{id}/wasm` → `{ names }` (beacon may be `{ async, task_id }`)
- `POST …/wasm` `{ name, wasm_b64 }` — gzip (Sliver BestSpeed) then `RegisterWasmExtension`
- `POST …/wasm/exec` `{ name, args|args_line, wasm_b64?, skip_registration, memfs{filename:b64}, pipe, loot }`
  - Register first unless `skip_registration`
  - `memfs` → `ExecWasmExtensionReq.MemFS`
  - `loot` → `LootAdd` stdout (text); incompatible with a live TTY, fine after drain
  - `pipe` **session only**: `CreateTunnel` + `Interactive=true`, drain until EOF/60s. Honest copy: not a live TTY. Beacons → 400.

Cap uncompressed module at 64 MiB in this UI (official CLI allows 1.5 GiB compressed; JSON POST is not that path).

### rportfwd (existing Sliver RPC)

Reverse of local `/api/portfwd`. Implant **listens**; teamserver dials **forward** address.

- `GET /api/sessions/{id}/rportfwd`
- `POST /api/sessions/{id}/rportfwd` `{ bind|bind_address|bind_host+bind_port, remote|forward_address|forward_host+forward_port }`
- `DELETE /api/sessions/{id}/rportfwd/{listenerID}`

Address normalize matches official CLI: port-only bind → `:port`; port-only remote → `127.0.0.1:port`. DNS ActiveC2 returns a warning and still starts.

### Local operator store (this UI host)

Path: `$SLIVER_UI_DATA` or `$XDG_DATA_HOME/sliver-ui` or `~/.local/share/sliver-ui/operator-store.json`.

Reactions **also** written to `~/.sliver-client/reactions.json` in official CLI shape (`event_type` + `commands`, no IDs) so `sliver-client reaction reload` can load them.

- Tags / comment / campaign keyed by Sliver UUID (session, beacon, host)
- Advisory lock keyed by **session ID** (`user` + Sliver operator name). Other CLI ignores it.
- MUTATE audit: `SLIVER_UI_USER` (cookie) + `Client.Profile` (Sliver operator). Other sliver-client operators are invisible.
- Reactions execute an **allowlist** of implant RPCs (`whoami`, `ps`, `pwd`, `ifconfig`, `screenshot`) on `session-connected` / `beacon-registered`. Arbitrary sliver-client command lines are skipped and logged.

Honest copy that must ship in the UI:

- “This UI does not see other sliver-client operators. Full audit needs a new Sliver RPC.”
- “This lock is advisory. sliver-client ignores it. A hard lock needs a new Sliver RPC.”
- “Reactions run whoami/ps/pwd/ifconfig/screenshot only. They are not a sliver-client REPL.”
- rportfwd: “The implant listens; the teamserver dials the forward address.”
- Wasm pipe: “Pipe collects tunnel output until the module exits or 60s. It is not a live TTY.”

---

## Agent partition (this slice)

| Agent | Files only |
|---|---|
| Wasm backend | `backend/internal/sliver/wasm.go`, `wasm_test.go` |
| rportfwd backend | `backend/internal/sliver/rportfwd.go`, `rportfwd_test.go` |
| Operator store | `backend/internal/operator/*.go` |
| Wasm UI | `frontend/src/components/session/WasmTab.tsx` |
| rportfwd UI | `frontend/src/components/session/RportfwdTab.tsx` |
| Notes / lock | `frontend/src/components/session/NotesPanel.tsx` |
| Reactions / audit | `frontend/src/components/OperatorOps.tsx` |

Parent owns: this doc, i18n, CSS, `server.go` routes, API handlers, `api.ts` / `types.ts`, page wiring, tests, build, deploy, verify.

---

## Honest copy (must keep)

- HTTP C2: “This still looks like default Sliver to public detectors.”
- Spoof metadata: resource clone of VERSIONINFO/icon. Not FUD, not AV bypass.
- Unique SHA-256: beats exact-hash lookup only. VT still sandboxes a new hash.
- Armory: install writes this UI process’s `aliases/` dir.
- Reconfigure: UI seconds; backend multiplies by `time.Second`. Generate interval stays seconds.

---

## Done — remaining slice (2026-11-16)

Deployed pid **181042** at `127.0.0.1:8080` (`--profile cup_127.0.0.1`). Embedded assets `index-C9yeAMtl.js` / `index-C60hyMQJ.css`.

### Backend
- `internal/sliver/wasm.go` — gzip BestSpeed, 64 MiB cap, session pipe drain 60s via existing `PortForwardManager.tm`, loot via `LootAdd`. Beacons: no pipe.
- `internal/sliver/rportfwd.go` — List/Start/Stop; port-only bind `:port`, remote `127.0.0.1:port`; DNS ActiveC2 warning still starts.
- `internal/operator` — JSON store at `$SLIVER_UI_DATA` or `~/.local/share/sliver-ui/operator-store.json`. Reactions also written to `~/.sliver-client/reactions.json` (`event_type` + `commands`, no IDs). Audit cap 500, reaction log 200.
- Handlers: `handlers_wasiext.go` (**not** `*_wasm.go` — Go treats that suffix as `GOARCH=wasm`), `handlers_rportfwd.go`, `handlers_operator.go`.
- Operator routes return **200 without a Sliver client**. Wasm/rportfwd stay 503.
- `withAudit` wraps mutate `/api/*` except `/api/auth/`. Actor = cookie `SLIVER_UI_USER` + `Client.Profile`.
- `BeaconView.UUID` filled from proto so notes can key by Sliver UUID.
- API tests isolate the store: `TestMain` sets `SLIVER_UI_DATA` + `SLIVER_UI_REACTIONS` to a temp dir. `CLIReactionsPath` honors `SLIVER_UI_REACTIONS`.

### Frontend
- Session tabs: **Reverse Portfwd** after Port Forward, **Wasm** after Advanced. Beacon detail mounts `WasmTab kind="beacon"` (no pipe checkbox).
- Sidebar `NotesPanel`: tags / campaign / comment + advisory lock.
- Settings `OperatorOps`: reactions allowlist + who-ran-what table.
- Sessions table: Tags column + Compare checkboxes (max 2). Compare diffs host/user/C2/tags; latency is not invented.

### Tests
- `go vet ./...` + `go test ./...` in `backend/`
- Frontend: `npx vitest run` 68 passed; `npx tsc --noEmit` clean
- Route fixture `frontend/src/lib/__fixtures__/routes.json` regenerated for wasm/rportfwd/operator routes

### Browser verify (Chromium puppeteer-core, login via `fetch POST /api/auth/login`)
Lab had **0 live sessions/beacons**. Settings, reactions add, audit table, honest copy were exercised against real APIs. Session compare / notes / lock / wasm / rportfwd tabs were clicked with a request interceptor on `GET /api/sessions` only; notes/lock/reactions writes hit the real operator store. Wasm list against the fake id returned Sliver `Invalid session ID` (expected). Files tab on that fake id same.

Honest copy confirmed on screen:
- Reactions: “They are not a sliver-client REPL.”
- Audit: “This UI does not see other sliver-client operators. Full audit needs a new Sliver RPC.”
- Lock: “This lock is advisory. sliver-client ignores it.”
- Wasm pipe: “It is not a live TTY.”
- rportfwd: “The implant listens on the bind address. The teamserver dials the forward address.”

CLI disk after UI add:
```json
[
  { "event_type": "session-connected", "commands": ["whoami"] },
  { "event_type": "beacon-registered", "commands": ["pwd"] }
]
```

### Gotchas
- Never name a Go file `*_wasm.go` on this module; it is ignored on amd64.
- Do not bump `github.com/bishopfox/sliver` past v1.7.3 for these RPCs; they already exist.
- Unique loader SHA-256 is hash-IOC only. Do not claim FUD.
- `GET /api/builders` JSON key stays `"builders"` (ImplantBuilds). Route `/jobs` stays.
