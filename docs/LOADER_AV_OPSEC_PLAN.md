# Plan: Loader / Shellcode section for AV-aware delivery

> Status: **Phases 0–4 + 6 + 7 implemented** (Phase 5 optional skipped). Loaders **Build EXE** compiles a finished PE/ELF/Mach-O on the sliver-ui host (`POST /api/loaders/build`); hide-console default on; startup persistence off by default. Linux PIC is mmap RWX + arch `CALL` trampoline (not `syscall.Syscall`); ELF uses memfd/exec. Windows always XOR-encrypts the embed, resolves APIs via runtime-decoded names (no plaintext `VirtualProtect`/`CreateThread`), allocates PAGE_NOACCESS→RW, decrypts off-heap, VirtualProtect RWX (`1<<6`) for Donut/SGN, then CALLs on an 8MiB stack. Each compile mints a unique nonce (mixed into the XOR key), 4–24KiB random padding, API-name encoding key, and Go `-buildid`, so SHA256 always changes even with the same operator XOR key. Pre-run Sleep+tick aborts some AV emulators. Unique hash is not a sandbox/ML bypass. The implant still needs a live listener on its C2 URL.  
> Repo: `Mkadir/sliver_ui` (`feat/ui-auth-opsec-installer` and follow-ups)  
> Scope: authorized red-team / lab / adversary-simulation only  
> Research backing: [`docs/SLIVER_UI_AV_OPSEC_RESEARCH.md`](./SLIVER_UI_AV_OPSEC_RESEARCH.md) (deep research synthesis)

## 1. Problem

`Obfuscate` (symbol renaming) and `Evasion` (limited in-implant tricks) are **compile-time implant knobs**. They do **not**:

- change the PE/DLL/shellcode **static signature** enough for modern AV/EDR
- provide a **loader** that decrypts/maps/executes the payload in memory
- apply **shellcode encoders** (SGN / XOR) after generation
- turn a **shared library** into reflective / PIC shellcode for injection
- guide operators through a delivery chain that looks like a normal app/update

Operators currently get raw `exe` / `service` / `shared` / `shellcode` downloads from **Implants**. That is usually enough for labs, and usually **not** enough against updated AV.

## 2. Goal

Add a first-class UI section (**Loaders** / **AV Delivery**) that:

1. Takes a Sliver build (`shared` DLL/SO or `shellcode` blob)
2. Runs post-processing available via Sliver RPC (and clearly documents external steps)
3. Emits a **loader-oriented artifact** + operator checklist
4. Sits beside HTTP C2 OPSEC (traffic lookalike) — host OPSEC is a separate layer

Success looks like:

```text
Implant profile (shared/shellcode)
        │
        ├─► Post-process (RDI / SGN / XOR) ──► inject / sideload
        │
        └─► Stage listener (HTTP/TCP + optional AES)
                │
                ▼
          Stage-0 stager / custom loader
          (fetch .woff → decrypt → exec in memory)
                │
                ├─ optional: hide console / GUI subsystem
                └─ optional: startup persistence (high-signal; toggle)
```

## 3. What already exists in this codebase

| Capability | Backend | UI | Notes |
|---|---|---|---|
| Generate `shellcode` / `shared` formats | Yes (`implants.go`) | Yes (Implants form) | Raw download only |
| `Obfuscate` / `Evasion` | Yes | Yes | Not a loader |
| HTTP C2 profiles / traffic encoders | Yes (new) | Yes (`/http-c2`) | Network OPSEC |
| Service format + install hints | Partial | Partial | Host persistence hygiene |
| **Shellcode RDI** (DLL → PIC) | Yes (`POST /api/shellcode/rdi`) | **No dedicated page** | API ready |
| Session `execute-shellcode` | Yes | Advanced tab / API | Needs prepared blob |
| **ShellcodeEncoder** (SGN / XOR / XOR_DYNAMIC) | **Not wrapped** | No | Sliver RPC exists |
| **ShellcodeEncoderMap** | **Not wrapped** | No | List available encoders/arch |
| `ImplantConfig.SGNEnabled` | **Not exposed** | No | Generate-time SGN flag |
| External packers (Donut, custom loaders, LLVM obfuscators) | No | No | Out of Sliver RPC — document only or plugin later |
| **Stage listener** (`stage-listener`) | **No** | No | Sliver RPC `StartTCPStagerListener` exists; HTTP/TCP + AES/RC4 in client CLI |
| **Generate stage / stager blob** | Stub only | Partial (`/api/msf/stage` errors) | `GenerateStage` RPC exists; old `MsfStage` removed — see `msf.go` |
| Startup persistence toggle on generate | No | No | Not a Sliver generate flag; service format + post-drop helpers |
| Auto-background / hide console | No | No | Loader-stub concern (GUI subsystem / `ShowWindow`); not implant C2 |

### Sliver 1.7 RPCs to wire

- `ShellcodeRDI(ShellcodeRDIReq{Data, FunctionName, Arguments})`
- `ShellcodeEncoder(ShellcodeEncodeReq{Encoder, Architecture, Iterations, BadChars, Data})`
  - Encoders: `NONE`, `SHIKATA_GA_NAI`, `XOR`, `XOR_DYNAMIC`
- `ShellcodeEncoderMap()` — which encoder/arch combos the server supports
- `StartTCPStagerListener(StagerListenerReq)` — stage-0 serving (TCP; HTTP path goes through C2 job helpers with profile + AES/RC4)
- `GenerateStage(GenerateStageReq)` — build staged implant bytes from profile
- `StageImplantBuild(ImplantStageReq)` — mark/expose a build for staging

## 4. Product design

### 4.1 Navigation

New sidebar item under **Payloads**:

- Path: `/loaders`
- Key: `loaders`
- Label: **Loaders** (en) / **加载器** (zh)

Optional: also a deep-link button on Implants build rows when `Format` is `SHARED_LIB` or `SHELLCODE` → “Send to Loaders”.

### 4.2 Page layout (`LoadersPage`)

Tabs or wizard paths:

**Path 1 — Transform (Phases 1–2)**

**Step A — Source**
- Pick existing implant build from server (filter `shared` / `shellcode`)
- Or upload local `.dll` / `.bin` (base64 to API)
- Show arch / OS / hash if known

**Step B — Transform**
- If source is DLL/shared:
  - **RDI**: function name (default export / `DllInstall` / custom), arguments
- Always (shellcode path):
  - **Encoder**: None / SGN / XOR / XOR_DYNAMIC
  - Architecture: `amd64` / `386` / …
  - Iterations
  - Bad chars (hex list)
- Generate-time option (when rebuilding): toggle `SGNEnabled` on implant config (separate from post-encode)

**Step C — Output**
- Download transformed `.bin`
- Copy size / SHA256
- Checklist (non-executable guidance):
  - Prefer HTTPS + HTTP C2 profile (link to `/http-c2`)
  - Prefer beacon + jitter over loud interactive session for initial
  - Inject via existing session tools (`execute-shellcode`, sideload, migrate) — links
  - Do **not** drop raw Sliver PE on disk if avoidable
  - Service / sideload naming hygiene (reuse Implants service hints)

**Path 2 — Stage-0 (Phase 6–7)**

**Step A — Profile + listener**
- Pick shellcode profile (or create via Implants/Profiles)
- Start stage-listener: URL, optional AES/RC4 + compress; show key/IV **once**
- Version note: Sliver 1.7.x client `stage-listener` is effectively **TCP-first**; HTTP encrypted stages may need `GenerateStage` / `profiles stage` + HTTP C2 stager handler ([#2009](https://github.com/BishopFox/sliver/issues/2009))
- Remind: default fetch ext `.woff` (link HTTP C2 `stager_file_ext`)

**Step B — Stager artifact**
- GenerateStage download **or** export custom stub (C/C#/PS/Go)
- Toggles: **Hide console** (default on), **Startup persistence** (default off + method)
- Optional advanced: “watchdog / re-fetch if dead” template (default off; §4.4 warning)

**Step C — Operator checklist**
- Staging host ≠ long-haul C2 when possible
- Test `curl https://staging/…/x.woff` size before delivery
- If AV burns the host: rotate URL, rebuild, re-deliver — do not expect silent self-heal

### 4.3 Stage-0 / stager delivery (new)

**Operator idea:** small loader lands on the host, downloads the matching stage-2 shellcode from the C2/staging server, and executes it in memory. This shrinks the first-drop artifact (KB vs multi-MB Go implant) and keeps the full implant off disk when possible.

**How Sliver already does this (no custom C2 required):**

1. `profiles new … --format shellcode` — implant definition (C2 endpoints, beacon/session, arch)
2. `stage-listener --url http(s)://host:port --profile <name> [--aes-encrypt-key …]` — serves stage-2
3. HTTP stages are fetched as any path ending in `stager_file_ext` (default **`.woff`**, set in HTTP C2 config)
4. `generate stager` / `GenerateStage` — MSFvenom-backed tiny stager shellcode **or** operator-written custom fetch+exec (preferred for OPSEC)

**UI design (Phase 6):**

| Surface | Behavior |
|---|---|
| **Stage Listeners** card (Loaders or Listeners) | Create/list/kill stage jobs; pick profile; URL scheme TCP/HTTP/HTTPS; optional AES key/IV (show once, never store in UI DB) |
| **Generate stager** | Call `GenerateStage` when server supports it; download raw/C/C# formats; warn that stock MSF stagers are signatured |
| **Custom stage-0 templates** | Lab stubs (C / C# / PowerShell / Go) that `GET …/*.woff`, optional AES decrypt, `VirtualAlloc`+exec or local inject; URL + key filled from the stage-listener form |
| Deep-link | From Implants/Profiles: “Stage this profile” |

Replace the dead `POST /api/msf/stage` stub with honest stage-listener + `GenerateStage` wiring (or keep stub error until Phase 6 ships).

References: [Sliver Stagers docs](https://sliver.sh/docs/?name=Stagers); [Dominic Breuker stagers](https://dominicbreuker.com/post/learning_sliver_c2_06_stagers/); BallisKit ShellcodePack HTTPS_STAGER + `.woff`.

### 4.4 AV-kill “auto re-download + execute” — honesty gate

**Operator idea:** if AV/EDR kills the implant, automatically download the payload again and re-execute.

**Reality for the plan:**

- Once the process is dead, **nothing inside that process can recover**. Auto-reload requires a **second survivor**: scheduled task, Run key, WMI subscription, separate watchdog binary, or an external dropper that still runs.
- That survivor must either (a) re-run a local copy or (b) **re-fetch from staging** and exec again — which means **ongoing staging-server dependency**, periodic network callbacks from a non-implant process, and classic persistence telemetry (Event 4698, Sysmon 13, schtask creation).
- EDR often treats “process died → child immediately re-downloads shellcode” as **high confidence malicious**. Lab-only; expect noise on Defender/Elastic.
- Sliver has **no built-in “AV-kill watchdog” RPC**. Wiring a checkbox that claims silent auto-heal would be dishonest product design.

**UI stance (checklist + optional advanced template, not a silent default):**

| Mode | What UI offers | Risk label |
|---|---|---|
| A — Document only | Checklist: “if burned, rotate stage URL, rebuild stager, re-deliver” | Low (guidance) |
| B — Persistence re-exec | Toggle on stage-0 stub: on first run write schtask/Run that re-launches **the same stager** | High — T1053 / T1547 |
| C — Watchdog pair | Export two artifacts: stager + tiny watchdog that polls stage URL if main PID missing | Very high — dual process + network |

Default: **Mode A**. Modes B/C require explicit operator opt-in, OPSEC warning banner, and cleanup notes for engagement close. Do **not** market as “AV bypass.”

### 4.5 Startup persistence toggle (generate / loader)

**Operator idea:** when generating a loader, optionally enable “add myself to startup.”

**Sliver native options today:**

- `--format service` — Windows service binary (persistence via service install / `psexec`, not Run key)
- No first-class `generate --persist-runkey` flag

**UI design:**

On **Loaders → stage-0 / EXE stub** (and optionally Implants when format is `exe`/`service`):

- Toggle: **Install startup persistence** (off by default)
- Method select (when on):
  - Windows: `HKCU Run` (user) | `schtasks ONLOGON` | Startup-folder LNK | Service (`format=service` path)
  - Linux: user systemd | cron | (root) system unit — checklist-first in v1
- Always show: artifact path/name fields, “document for cleanup”, MITRE tags (T1547 / T1053 / T1543)
- Implementation: persistence is compiled into the loader stub (`POST /api/loaders/build`). UI does not remotely install persistence without an existing session
- With an existing session: optional later “Apply persistence” action using `registry` / `execute schtasks` / armory SharPersist — separate from generate

### 4.6 Auto-background / hide window

**Operator idea:** loader should drop to background automatically (no console flash).

| Platform | Approach | UI control |
|---|---|---|
| Windows stage-0 EXE | `ShowWindow(SW_HIDE)` / compile as **Windows GUI subsystem** (`-H windowsgui` / VS “Windows Application”) | Toggle **Hide console** (default **on** for release stubs) |
| Windows service format | Runs as service — already headless | Prefer `service` when long-haul + admin |
| Linux | True daemonize is fragile in Go implants (historical Sliver daemonize PR; Windows unsupported). Prefer systemd user service / `nohup` / double-fork in **external** stub | Toggle **Daemonize stub** on Linux templates only; disclaimer |
| Shellcode inject | No window by nature | N/A |

Also document: hiding the console ≠ hiding from EDR; parent/child process trees and `conhost.exe` still matter.

### 4.7 Encrypt-at-rest → decrypt-in-memory (operator follow-up)

**Operator idea:** generate shellcode / shared / EXE as ciphertext on disk so AV hashing the file misses known implant hashes; stub decrypts in memory and executes.

**Research verdict** (full report: [`reports/Sliver encrypt at rest loaders.md`](../reports/Sliver%20encrypt%20at%20rest%20loaders.md)):

| Claim | Reality |
|---|---|
| Ciphertext changes file hash → static hash IOCs of **inner** implant miss | **True** (T1027 / T1027.013) |
| Therefore AV “won’t recognize it as a virus” | **Incomplete** — stub YARA, entropy/packer heuristics, sandbox detonation, post-decrypt EDR, memory scanners remain |
| Operators use this | **Yes** — standard OPSEC (Donut/ScareCrow/ShellcodePack/AES stage; Microsoft/HarfangLab/Hunter’s Ledger chains) |
| Sliver `generate` encrypts EXE/shared on disk | **No** — only garble + limited evasion; shellcode gets Donut `entropy=3` and/or SGN/XOR self-decoders |
| Sliver can serve encrypted stage-2 | **Yes** — AES-CBC / RC4 on stage (+ compress); stager must decrypt (IV prepended for AES) |

**Do not add** an Implants checkbox labeled “encrypt payload” for all formats — it would no-op on EXE/shared and conflate polymorphic encoders with keyed crypto.

**UI placement (under Loaders, honesty-first):**

| Priority | Deliverable | Notes |
|---|---|---|
| **A (Phase 6)** | Stage AES/RC4 + custom decrypting stage-0 stubs | Native Sliver; show key/IV once; never store in UI DB |
| **B (Phase 4–7)** | Post-process AES shellcode → downloadable lab stub project | External-style packaging inside UI templates; stubs age like Artifact Kit |
| **D (always)** | Checklist appendix: Donut `-e 3`, ScareCrow, PEzor, Nimcrypt2, ShellcodePack, env keying | BishopFox already points operators here |
| **Reject C** | Shell out to Donut CLI from UI host | Sliver already embeds Donut for `format shellcode`; host RCE surface |

**Implants generate knobs to expose (honest naming):**

- When format = `shellcode` (Windows): `shellcode_entropy` / Donut entropy (incl. encrypt module) — label as “Donut entropy / module encryption”, not “FUD”
- `SGNEnabled` / post-encode SGN·XOR — label as “polymorphic encode (self-decoder)”
- Stage listener form: AES key/IV optional — label as “stage obfuscation (AES-CBC-128)”

Banner: *Encrypt-at-rest hides the implant bytes from disk hash/string scanners. It does not stop behavioral EDR after decrypt. No UI option guarantees evasion.*

### 4.8 Explicit non-goals (v1)

- Shipping a full custom PE packer / commercial crypter inside the UI
- Claiming “FUD” or guaranteed AV bypass
- Implants “encrypt payload” toggle that pretends EXE/shared are ciphertext
- Silent AV-kill auto-heal without an explicit persistence/watchdog design
- Auto-attacking endpoints
- Storing AES stage keys or payloads in Sliver UI’s own DB (remain stateless; blobs stay in browser download / Sliver server builds)
- In-UI Donut CLI / host shell-out

## 5. Technical implementation plan

### Phase 0 — Docs & honesty (this file)

- Publish this plan in-repo
- Add README blurb pointing here
- Operator disclaimer on the page: lab/authorized use; Obfuscate≠AV evasion

### Phase 1 — Wire Sliver shellcode encoder APIs

**Backend**
- `backend/internal/sliver/shellcode_encode.go`
  - `ListShellcodeEncoders()`
  - `EncodeShellcode(req)`
- Routes:
  - `GET /api/shellcode/encoders`
  - `POST /api/shellcode/encode`
- Reuse existing `POST /api/shellcode/rdi`
- Extend `GenerateRequest` with `sgn_enabled bool` → `ImplantConfig.SGNEnabled`

**Frontend**
- `api.shellcodeEncoders()`, `api.shellcodeEncode(...)`
- Types for encoder enum / results

**Tests**
- Route fixture update
- Handler decode tests (no live Sliver required)

### Phase 2 — `LoadersPage` UI

- New page + nav + i18n (en + zh)
- Build picker (from `/api/builders`)
- Pipeline UI: Source → RDI (optional) → Encode → Download
- Persist last options in `localStorage` (not secrets)

### Phase 3 — Implants integration

- On generate success for `shared`/`shellcode`, show banner: “Continue in Loaders”
- Expose `SGNEnabled` checkbox when format is `shellcode`
- Build table actions: “RDI”, “Encode”

### Phase 4 — Loader templates (guidance + optional stubs)

Provide **operator templates** (markdown + downloadable stub sources) that are clearly marked as **examples for authorized labs**:

| Template | Role | Notes |
|---|---|---|
| `local-inject` checklist | Use session `execute-shellcode` | Uses existing API |
| `rdi-dll` checklist | shared → RDI → encode → inject | Uses Phase 1–2 |
| `sideload` checklist | DLL sideload naming / paths | Points to session Advanced / sideload |
| External tools appendix | Donut, custom loaders, etc. | Links + “run outside UI” |

Optional later: “Export loader project.zip” containing a **minimal** user-mode loader skeleton that reads an encrypted blob (key from UI). Treat as advanced Phase 5 — higher review bar.

### Phase 5 (optional) — Artifact workstation

- Server-side job to keep transformed blobs as named artifacts (if Sliver loot/files fit)
- Diff hashes before/after encode
- Multi-iteration encode presets (“light”, “noisy”)

### Phase 6 — Stage-0 / stage listeners + encrypt-at-rest (operator priority)

**Backend**
- Wrap `StartTCPStagerListener` (+ version-aware HTTP staging via `GenerateStage` / profiles stage when HTTP listener path differs — see #2009)
- Wrap `GenerateStage` / `StageImplantBuild`
- Pass AES key/IV / RC4 / compress through to stage job
- Expose shellcode Donut entropy on generate when format=shellcode
- Routes sketch:
  - `GET /api/stage-listeners` (via jobs filter) / `POST /api/stage-listeners` / `DELETE …`
  - `POST /api/stage/generate` → stager bytes
- Retire or rewire `POST /api/msf/stage` to the new path with a clear deprecation message

**Frontend**
- Stage Listeners panel (profile picker, URL, AES/RC4 optional, show key once, job id)
- “Generate stager” download + **decrypting** custom stage-0 templates matching Sliver AES framing
- Hide-console default on; persistence toggle off
- Checklist: `.woff` ext, separate staging host vs long-haul C2, rotate URL if burned, encrypt-at-rest ≠ EDR bypass (§4.7)

**Tests**
- Handlers return 503 without client; body decode tests; no live teamserver required

### Phase 7 — Persistence + background toggles on stubs

- Loader stub generator options:
  - `hide_console: true` (default)
  - `persistence: off | runkey_hkcu | schtask_logon | startup_lnk` (Windows)
  - Risk banner + cleanup markdown emitted beside the download
- Implants page: keep pointing at `format=service` for service-style persistence
- Explicit **non-default** for any “re-fetch on death” watchdog template (links to §4.4)

## 6. API sketch

```http
GET  /api/shellcode/encoders
→ { "encoders": { "SHIKATA_GA_NAI": ["amd64","386"], "XOR": ["amd64"], ... } }

POST /api/shellcode/rdi
{ "data_b64": "...", "function_name": "DllInstall", "arguments": "" }
→ { "DataB64": "...", "Size": 12345 }

POST /api/shellcode/encode
{ "data_b64": "...", "encoder": "SHIKATA_GA_NAI", "arch": "amd64", "iterations": 1, "bad_chars_hex": "" }
→ { "data_b64": "...", "size": 12400, "encoder": "SHIKATA_GA_NAI" }

# Phase 6+
POST /api/stage-listeners
{ "url": "http://staging.example:80", "profile": "win64-shellcode",
  "aes_key": "", "aes_iv": "", "compress": "" }
→ { "job_id": 3 }

POST /api/stage/generate
{ "lhost": "staging.example", "lport": 80, "arch": "amd64", "format": "raw",
  "protocol": "http" }
→ { "data_b64": "...", "size": 512, "filename": "stager.bin" }
```

Auth: same cookie session as the rest of the UI.

## 7. UX copy (important)

The page must say clearly:

- Obfuscate / Evasion **help with some static strings**, they are **not** a bypass chain
- SGN / XOR **mutate shellcode bytes**; EDRs still detect behavior (injection, unbacked RX, etc.)
- Best results come from **layered** OPSEC: HTTP C2 profile + staged shellcode + in-memory execution + bland host artifacts
- Guaranteed evasion is **impossible** to promise
- Stage-0 shrinks first drop; **stock MSF stagers are signatured** — prefer custom fetch+exec templates
- Persistence / watchdog “survive AV kill” options are **high-signal** and off by default
- Hide-console is hygiene, not evasion

## 8. File touch list (implementation)

```
docs/LOADER_AV_OPSEC_PLAN.md          # this plan
docs/SLIVER_UI_AV_OPSEC_RESEARCH.md   # research addendum (stage-0 / persist / bg)
README.md                             # link under OPSEC / Implants
backend/internal/sliver/shellcode_encode.go
backend/internal/sliver/stage.go             # Phase 6 listeners + GenerateStage
backend/internal/api/handlers_shellcode.go   # or extend handlers_implants.go
backend/internal/api/handlers_stage.go       # Phase 6
backend/internal/api/server.go
backend/internal/sliver/implants.go          # SGNEnabled
backend/internal/sliver/msf.go               # rewire stub → stage API
frontend/src/pages/LoadersPage.tsx
frontend/src/pages/StageListenersPanel.tsx   # or section inside Loaders
frontend/src/lib/api.ts
frontend/src/lib/types.ts
frontend/src/lib/nav.tsx
frontend/src/App.tsx
frontend/src/i18n/locales/en.ts
frontend/src/i18n/locales/zh.ts
frontend/src/lib/__fixtures__/routes.json
frontend/public/templates/stage0/            # optional lab stubs (Phase 6–7)
```

## 9. Verification checklist

1. Generate Windows `shared` implant → appears in Loaders source list  
2. RDI convert → download non-empty PIC blob  
3. Encode with SGN (if server supports arch) → size/hash changes  
4. Encode with bad chars → rejected or respected per Sliver behavior  
5. `SGNEnabled` generate path does not break exe/service builds  
6. UI login still required for new routes  
7. Routes contract test green  
8. Phase 6: create HTTP stage-listener against shellcode profile → `curl` `*.woff` returns bytes  
9. Phase 6: GenerateStage download non-empty; custom stub checklist renders URL/ext  
10. Phase 7: persistence toggle off by default; enabling shows risk + cleanup text  
11. Phase 7: hide-console default on for Windows EXE stub template  

## 10. Suggested build order

1. Phase 1 APIs (`encode` + `SGNEnabled`)  
2. Phase 2 `LoadersPage` MVP (RDI + encode + download)  
3. Phase 3 Implants deep-links  
4. Phase 4 checklists / templates  
5. **Phase 6 stage-0 listeners + GenerateStage** (high operator value; unblocks real delivery chains)  
6. **Phase 7 persistence / background toggles** on stubs (defaults safe)  
7. Phase 5 artifact store only if needed after real lab use  

## 11. Related work already done

- UI login (`SLIVER_UI_USER` / `SLIVER_UI_PASS`)
- `install.sh` + systemd integration
- HTTP C2 Profiles page + listener camouflage
- Implant OPSEC fields (profile, traffic encoders, limits, service hints)

Those cover **C2 traffic / install hygiene**. This plan covers **payload form factor / loader chain / stage-0** — the missing half for “Obfuscate is not enough.”

## 12. Research summary (stage-0, AV-kill, startup, background)

| Idea | Feasible in Sliver UI? | Approach | OPSEC note |
|---|---|---|---|
| Stage-0 fetch+exec from C2 | **Yes** via native stage-listener + custom/GenerateStage | Phase 6 | Prefer custom stager over stock MSF; customize `.woff` ext; gate HTTP vs TCP by server version |
| Encrypt-at-rest → decrypt in memory | **Partial native** (stage AES, Donut entropy, SGN/XOR); EXE/shared need external loader | Phase 6–7 + checklist | Defeats inner hash IOCs; not EDR bypass — see §4.7 |
| AV kills → auto re-fetch/exec | **Hard** — needs separate survivor | Checklist + optional watchdog/persist templates (opt-in) | High EDR signal; not a silent checkbox |
| Startup persistence toggle | **Yes** as stub option / service format | Phase 7; off by default | T1547/T1053; cleanup required |
| Auto background | **Yes** for stubs (hide console / GUI subsystem) | Phase 7; on by default for EXE stubs | Hygiene only; service format for true headless |
