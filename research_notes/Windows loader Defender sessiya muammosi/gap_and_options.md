# Gap: implemented Windows loader “AV hygiene” vs keeping a Sliver implant alive against Windows Defender (2026)

Product is a Sliver C2 GUI, not a crypter shop. This note ranks interventions by **impact on the two operator symptoms** versus **complexity, OPSEC honesty, and already-rejected work**. Do not recommend FUD-as-a-feature.

**Already rejected in this repo (do not reopen):** in-tree Donut/ScareCrow; Implants “FUD encrypt” checkbox; VirusTotal widget; FUD / 0/70 claims. Unique SHA-256 is hash-IOC only. Encrypt-at-rest is half-true (hides inner hashes, not EDR). — [README.md](file:///home/cup/Documents/personal/sliv/README.md); [LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md); [Sliver encrypt at rest loaders.md](file:///home/cup/Documents/personal/sliv/reports/Sliver%20encrypt%20at%20rest%20loaders.md)

**What this UI actually ships for Windows wrap:** host-compile Go stub; XOR `cfg.dat` + per-build nonce/padding/`-buildid`; API names XOR’d as `\xHH`; `PAGE_NOACCESS` → RW → **RWX (`1<<6`)**; decrypt in the allocation; assembly `CALL` on an 8MiB stack; **no `CreateThread` in stub source**; hide-console default **on** (`-H windowsgui`); persistence default **off**; pre-run `Sleep(1800)` + tick abort; `GlobalMemoryStatusEx` ≥ 1GiB or `os.Exit(0)`. Failures in `run()` are bare `return`. — [windows.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go); [loader_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)

---

## Symptom 1: generated Windows loader runs → no session

### Takeaway

In a **Defender-off** lab, “no session” is far more likely **operator C2/format/beacon mistakes plus silent loader exit** than missing FUD. Loaders **Build EXE** never logs, never matches a live listener, never surfaces `IsBeacon`, and **does not pass `rdi` / `function_name`** even though the API supports them. With Defender **on**, the same wrap is still a generic Go PE that allocates **unbacked RWX** and `CALL`s Donut/SGN — hygiene that 2025–2026 writeups already found **ineffective** against MDAV/Elastic after decrypt.

### Cited Findings

- BishopFox: AV evasion is **out of scope**; operators should use packers, crypters, and stagers. — [Sliver Docs: Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion)
- Generate defaults in this UI: `format='exe'`, `c2Type='https'`, `c2Host='127.0.0.1'`, `c2Port='443'`, `isBeacon=false`, `httpC2Profile='default'`, `obfuscate=true`, `shellcodeEntropy=2`. — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx)
- Empty C2 list falls back to `mtls://127.0.0.1:8888`. — [implants.go `buildImplantConfig`](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants.go)
- Implants page **does** warn `typedC2Missing` via `matchC2Job` (“implant will not call back until a listener is up”). Loaders page **does not** fetch jobs or call `matchC2Job`. — [en.ts `implants.typedC2Missing`](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts); [c2.ts](file:///home/cup/Documents/personal/sliv/frontend/src/lib/c2.ts); [LoadersPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx)
- C2 host auto-fill runs when host is `127.0.0.1`; **port auto-fill only if `c2Port === '8888'`**, but the default port is `'443'`, so detected HTTPS/mTLS ports are not applied on a fresh form. — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx)
- Loaders picker keeps only `SHELLCODE` / `SHARED`. Default **EXE** builds never appear. Upload of an MZ still auto-RDI on the backend. Wrap `buildExe()` omits `rdi` and `function_name` (API fields exist). Auto-RDI uses **empty** `FunctionName`. — [LoadersPage.tsx `isLoaderFormat` / `buildExe`](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx); [api.ts `loadersBuild`](file:///home/cup/Documents/personal/sliv/frontend/src/lib/api.ts); [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go)
- Sliver shared-library execution is documented around exports such as `StartW`, plus YARA’d names `DllInstall` / `VoidFunc` / `DllRegisterServer`. Empty RDI export is the wrong default for that path. — [Fortbridge 2025](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Windows stub silent exits: `enoughRAM()` false → `os.Exit(0)`; emulator check `t1-t0 < 1400` after `Sleep(1800)` → `os.Exit(0)`; `VirtualAlloc` / `VirtualProtect` failure → `return` with no log. Hide-console compiles `-H windowsgui`. Copy says hide-console “returns immediately — watch Sessions and Beacons”. — [windows.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [en.ts `loaders.runHint`](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- `jump_windows_*.s` `CALL`s shellcode then **RET** to Go `main`, which then returns (process exit). Linux trampolines `exit_group` after CALL. If Donut/RDI returns, the Windows host **exits** and kills in-process implant threads. — [source.go `jumpAsm`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/source.go)
- Upstream Donut defaults used by current Sliver `donut.go`: `defaultDonutExitOpt = DonutExitThread`, `defaultDonutBypass = DonutBypassContinue`. Donut `-x`: 1=exit thread (default), 2=exit process, 3=block indefinitely. — [BishopFox/sliver donut.go](https://raw.githubusercontent.com/BishopFox/sliver/master/server/generate/donut.go); [TheWover/donut README](https://github.com/TheWover/donut)
- UI generate exposes Donut **entropy 1–3** (default 2) and SGN; it does **not** expose Donut `Bypass` or `ExitOpt`. Moloch (Feb 2026) on #1759: generate flags can now control Donut bypass; this UI does not wire them. — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx); [BishopFox/sliver#1759](https://github.com/BishopFox/sliver/issues/1759)
- Tests **require** Windows wrap to use RWX (`1<<6`) “so Donut/SGN can write” and forbid plaintext `CreateThread` / `VirtualProtect` strings. README still admits the **Go runtime** contains `VirtualAlloc` / `CreateThread` / `kernel32.dll`. — [loader_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go); [README.md](file:///home/cup/Documents/personal/sliv/README.md)
- Official implant troubleshooting: generate `--debug` for connectivity. — [Sliver Troubleshooting](https://sliver.sh/docs/?name=Troubleshooting)
- 2025–2026 “got a session with Defender on” writeups use **custom** stagers/loaders (C++/DInvoke/.NET), often **Donut `-b 1` (no AMSI patch)** and **`-e 3`**, not a stock Go wrap EXE. Tyler Ramsbey (2026) demo: stager downloads `shellc.bin` then runs it. bytebl33d: FilelessPELoader / DInvoke + ThreatCheck. 0xPmCr: custom C++ stager. — [Ramsbey 2026 video](https://www.youtube.com/watch?v=g0R5A-xmHuU); [bytebl33d 2025-01](https://bytebl33d.github.io/blog/sliver-evasion/); [0xPmCr 2025-12](https://medium.com/@0xpmcr/bypassing-windows-defender-to-establish-command-and-control-5d883fe2f667)
- Fortbridge (Apr 2025, Elastic **and** Defender): embedding an encrypted implant in a loader, self-injection, and process hollowing were **ineffective**. Success was **protobuf/export string renames + LoadLibrary of a DLL from disk**, not VirtualAlloc unbacked shellcode. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)

### Inferences

Ranked **most likely causes of symptom 1** (Defender-off first, then Defender-on):

| Rank | Class | Cause | Why it looks like “ran, no session” | Fix class |
|---|---|---|---|---|
| 1 | Operator | C2 URL has no live job (wrong proto/host/port; `127.0.0.1`; mtls vs https) | Hide-console process appears to do nothing | UI: reuse `matchC2Job` on Loaders; block or hard-warn wrap |
| 2 | Product | Silent `os.Exit(0)` / `return` + GUI subsystem | No window, no log, no event | Backend: log + console lab preset; never silent-exit in lab |
| 3 | Operator | Watching **Sessions** for a beacon (or not waiting interval) | Callback is on Beacons after N seconds | UI: show `IsBeacon` + interval on selected build |
| 4 | Operator / product | Default generate **EXE**, then wrap/upload MZ with empty RDI export | RDI of EXE or DllMain-only DLL returns; `CALL` RETs; process exits | UI: refuse EXE as PIC; default RDI export `StartW`; warn format |
| 5 | Product | Donut `ExitOpt=thread` + wrap `CALL` then process teardown | Implant thread dies when host exits | Expose ExitOpt=3 (block); keep host alive; log if `jump` returns |
| 6 | Operator | `--debug` off, so implant connectivity is invisible | Same as (1) but unprovable | Checklist: debug build in Defender-off lab |
| 7 | Defender | On-access / cloud sandbox kills wrap before callback | Protection History has a threat name | Phase B: diagnose names; not more XOR |
| 8 | Defender | Donut default **AMSI/WLDP continue-on-fail** inside `format=shellcode` | Process starts then dies; #1759 / Elastic AMSI | Expose Bypass=1; do not add another patch |

**UI/backend changes that make failure visible (do these; they are not FUD):**

1. **Lab console preset** (hide-console **off**, `SLIV_BG` documented): print `enoughRAM`, sleep delta, `VirtualAlloc` addr, `VirtualProtect` result, “calling shellcode”, “shellcode returned — host will exit”. Today `pause()` / `enoughRAM()` / `run()` swallow errors. — [windows.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
2. **Do not `os.Exit(0)` without a breadcrumb** when hide-console is on. Lab: MessageBox / `%TEMP%\sliv-loader.log`. Production hide-console can stay quiet **after** a successful CALL.
3. **Require matching listener** on wrap: same `matchC2Job` as Implants. Copy already says “If nothing checks in, that build’s C2 has no listener” but does not **check**. — [en.ts `loaders.runHint`](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
4. **Warn if selected build `IsBeacon`**: watch Beacons, wait interval+jitter, do not expect an interactive session. Checkbox exists on generate; Loaders ignores it. — [en.ts `implants.beaconHint`](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
5. **Warn / refuse format that is not shellcode or complete DLL.** Truncated-PE error already exists; EXE-as-PIC should too. Pass `function_name` (default `StartW`) when auto-RDI. — [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go)
6. **Fix port auto-fill** (`8888`-only is a product bug given default `443`).
7. **Defender-off acceptance test** in the product checklist: `format=shellcode`, matching HTTPS job, hide-console off, debug implant, wrap, run, session **or** beacon within 2× interval. If that fails, stop talking about AV.

### Gaps

- This research did **not** execute the wrap EXE on a Windows box; Donut `Thread` vs `ExitOpt` interaction with `jump()` RET is inferred from upstream defaults, not traced in a debugger.
- sRDI behavior with **empty** `FunctionName` against a Sliver `SHARED_LIB` was not dynamically confirmed (high-probability bug, not proven).
- Exact Microsoft Defender **cloud sandbox** wait time in 2026 vs this stub’s 1.8s delay is not published as a stable number.

---

## Symptom 2: a session that opened (often via Beacon) is then killed by Defender

### Takeaway

Once a callback exists, Defender is hunting the **decrypted Go implant in memory** (protobuf / BishopFox strings, unbacked RX/RWX, `LoadLibraryExW` from unbacked memory, Donut AMSI patch), not the wrap’s SHA-256. Unique hash, XOR-at-rest, “no CreateThread”, and PAGE_NOACCESS-first do **not** address that. The 2025 Fortbridge result that actually got a callback on Elastic+Defender was **source-level string surgery + disk-backed DLL load**. Sleep obfuscation, sideload-into-signed-host, and RX-not-RWX belong **outside** this GUI except for honest checklists and one optional disk-DLL stub.

### Cited Findings

- Elastic `Multi_Trojan_Sliver` rules match protobuf method names (`ScreenshotReq`, `HTTPSessionInit`, `RequestResend`, `GetPrivInfo`, …), `github.com/bishopfox/sliver/protobuf`, and session-start/register byte patterns; **`scan_context = "file, memory"`**. — [Multi_Trojan_Sliver.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar)
- BishopFox maintainers: Garble **does not rename protobuf methods**; “easy signatures”. Cyb3r-Monk (Dec 2024): **“several Defender AV signatures detecting these strings.”** Moloch (Jan 2025): custom protobuf AST obfuscation in v1.6, **no ETA** for a comprehensive fix. Issue closed Jan 2026 as completed — **do not assume 1.7.9 implants are clean**; Elastic rules are still live. — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760)
- Fortbridge DefenderYara hits on disk/memory: `DllUnregisterServer`, `DllRegisterServer`, `DllInstall`, `GetJitter`, `VoidFunc`, `GetKill`, `AddTunnel`, `GetIsIOC`, `Go buildinf:`. After static clean, **“Network Library Loaded from Unbacked Memory”** (Go `LazyDLL` → `LoadLibraryExW`) still fired. Module stomping was **abandoned** because implants are **up to ~30 MB**. Encrypted-loader / hollowing / self-inject: **ineffective**. Working loader: **LoadLibrary from the same folder + export in a new thread**. Built-in post-ex commands still trigger Elastic later. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Microsoft (2022, still the public MDE hunting baseline): Sliver `migrate` / `sideload` / `spawndll` / `execute-assembly` use `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`; MDE alert **“A process was injected with potentially malicious code”**. Actors embed Sliver **shellcode in custom loaders** (Bumblebee/COLDTRAIN); hunt loader TTPs and **in-memory config**, not PE hashes. Sleep-mask style encryption is noted as a timing problem for memory scanners (Cobalt Strike comparison). — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Moloch on sleep obfuscation / syscalls (2023): **syscalls are most effective in the loader**; obfuscated sleep is **hard because of the Go runtime**. Community PoCs (goEkko, GoSleepyCrypt, PR #1805) require pausing goroutines; **not a shipped Sliver feature**. — [Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171)
- Donut AMSI/WLDP **continue-on-fail** is default and **signatured**. #1759: Elastic flagged AMSI/WLDP patching even with `--evasion` off. #2200 (2026): `execute-shellcode` of Donut (bypass none) still got **`Behavior:Win32/AMSI_PATCH_T.B12`**. Operators disable Donut AMSI (`-b 1`) for a reason. — [BishopFox/sliver#1759](https://github.com/BishopFox/sliver/issues/1759); [BishopFox/sliver#2200](https://github.com/BishopFox/sliver/issues/2200); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Default HTTP C2 extensions (`.woff` stager, `.js` poll, `.html` key exchange, `.php` session, `.png` close) are public. This UI already prints **“This still looks like default Sliver to public detectors.”** — [Sliver HTTPS C2](https://sliver.sh/docs/?name=HTTPS+C2); [en.ts `httpC2.defaultCopy`](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- Hunter’s Ledger (2026 open directory): PowerShell stager → ScareCrow (encrypted chunks, SysWhispers3) → Donut AES-128-CTR over Sliver PE → hollowed process. Hash IOCs rot in minutes; hunters still have **architectural** constants (SysWhispers seed, Donut VEH, sleep-mask/injection telemetry). — [Hunter’s Ledger](https://the-hunters-ledger.com/reports/sliver-open-directory/)
- BallisKit (May 2025): **do not rely on the C2’s own loader**; pack the C2 EXE/DLL with ShellcodePack. Faster/quieter generate: **`--disable-sgn --skip-symbols`** (no double-noise) then external pack. — [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)
- Havoc Demon: **“wasn’t designed to be evasive”**; interoperable with external loaders; sleep obfuscation (**Ekko / Foliage**) lives **in the agent**, plus indirect syscalls. That is the opposite of Sliver’s Go implant. — [Havoc Agent docs](https://havocframework.com/docs/agent)
- PEzor (BishopFox’s own external list): `-rx` (allocate RX), `-self` (same thread; **not compatible with SGN**), `-sleep=N` (example **120s**), `-syscalls`, `-unhook`, `-fluctuate=RW|NA` on Sleep, `-xorkey` environmental keying, `-format=dll -dll-sideload=version.dll`. — [PEzor README](https://raw.githubusercontent.com/phra/PEzor/master/README.md); [Sliver AV docs](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Anti-virus%20Evasion.md)
- ScareCrow: **sideload (not inject)** into a legitimate process; unhook via Disk/KnownDlls; AES/ELZMA/RC4; custom syscalls; **“binary loader does not benefit from any sideloading.”** In-tree ScareCrow is **rejected** here. — [Optiv ScareCrow](https://github.com/optiv/ScareCrow); [README rejected list](file:///home/cup/Documents/personal/sliv/README.md)
- Plan §4.4 already forbids silent AV-kill auto-heal: a dead process cannot resurrect; watchdog = second survivor = high EDR signal. — [LOADER_AV_OPSEC_PLAN.md §4.4](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md)

### Inferences

**Tradecraft vs this UI (honest split):**

| Technique | Helps symptom 2? | In this UI? | Verdict |
|---|---|---|---|
| Unique SHA-256 / XOR embed | **No** after decrypt; hash-IOC only | Shipped | Keep copy; stop implying emulator/ML bypass |
| PAGE_NOACCESS → RW → RWX + CALL, no CreateThread | **No** vs unbacked-exec + LazyDLL rules | Shipped | Hygiene; Elastic/MDE still see unbacked RX/RWX |
| 1.8s Sleep+tick | Maybe toy emulators; **not** 2026 MDAV cloud | Shipped | Do not market as sandbox bypass |
| HTTP C2 profile ≠ default + traffic encoders | **Yes** vs network/YARA on `.woff/.js/.html` | Shipped (`/http-c2`) | Use; default profile is still `default` on generate |
| Beacon + jitter vs interactive | **Partial** (less API noise; memory still readable while awake) | Shipped (`is_beacon`) | Prefer beacon for long-haul; does not hide protobuf in RAM |
| Donut entropy=3 | Hides **inner PE** strings on disk/in Donut module; memory after map still Sliver | Entropy UI default **2** | Offer 3 with honest label; not FUD |
| Donut Bypass=1 (no AMSI patch) | **Yes** vs `AMSI_PATCH_*` family | **Not exposed** | Wire generate flags; default skip patch for wrap |
| Sideload into **signed** host | **Yes** vs unknown-EXE reputation (ScareCrow/PEzor) | One-line guide only; wrap emits **unknown EXE** | Operator-external; optional DLL-sideload **export**, not in-tree ScareCrow |
| Disk `LoadLibrary` of cleaned **shared** DLL | **Yes** in Fortbridge’s Elastic+Defender lab | Not implemented (wrap is VirtualAlloc+CALL) | Only evidence-backed loader architecture change worth considering |
| RX not RWX | Helps some heuristics; Donut/SGN **need a write window**; PEzor `-rx` **incompatible with SGN** | Tests **require** RWX | Research-only; never with SGN |
| Sleep obfuscation **inside implant** | Helps idle memory YARA; Havoc has it; Sliver Go runtime does not | Out of scope | Operator-external / wait upstream; do not fake in wrap |
| Process inject into trusted process | Mixed; MDE hunts CRT inject; Fortbridge unbacked still alerts | Session Advanced `execute-shellcode` | Last resort; not initial access |
| Fork Sliver (rename proto/exports/`bishopfox`) | **Yes** vs static+memory YARA | Out of scope (would be a Sliver fork) | Operator-external (`slivercloak`, `better-sliver`) |
| External Donut `-e 3 -b 1` + Nim/C++/PEzor/ShellcodePack | What 2025–2026 operators actually publish | Rejected in-tree | Checklist appendix only |
| Persistence / watchdog | Recovers **process death**, advertises T1547/T1053 | Off by default | Keep off; not “survive Defender” |

**Do not put in the UI:** ScareCrow/PEzor/Nim crypter, AMSI/ETW patch stubs (those **are** the `AMSI_PATCH` detections), module stomping of 16–30 MB Go (Fortbridge could not find a host module), sleep-mask in the wrap, BYOVD “UnDefend” (out of product ethics and out of C2-GUI scope).

### Gaps

- No public, complete 2026 catalog of **Microsoft MDAV threat names** specifically `Trojan:Win64/Sliver.*`. Public hits: Elastic `Multi.Trojan.Sliver`; Kaspersky `Trojan.Win64.Sliver.*`; MDAV **`Behavior:Win32/AMSI_PATCH_T.B12`**. Operators must copy names from **Protection History / `Get-MpThreat`**.
- Whether Sliver 1.7.9 (this lab: commit `6cf3ad78…` per sibling inventory) actually shipped protobuf AST obfuscation sufficient to beat current DefenderYara is **unverified**.
- Module stomping “research” is **contra-indicated** by Fortbridge size data; do not spend product time on it without a new size-reduction story.

---

## Honesty audit: what the UI should stop implying

### Takeaway

Banners that say “lab only — not an AV bypass” are **correct**. Remaining overclaim is **technique-as-magic**: emulator delay, “no CreateThread”, PAGE_NOACCESS, unique SHA-256, and a sideload sentence that the wrap EXE does not implement. Default generate **EXE** + default HTTP **`default`** fight the Loaders guide that says the common path is `format=shellcode` + matching listener.

### Cited Findings

Honest / keep:

- `loaders.whatIsThis`: “Lab only — this is not an AV bypass.” — [en.ts](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- `loaders.xorUnique`: unique SHA-256 “only beats exact-hash blocks”; “VirusTotal still sandboxes a new hash.”
- `loaders.hideConsoleHint`: “Hiding the window is not hiding from EDR.”
- `loaders.toolsHint`: encoders “only change bytes (not a crypter).”
- `implants.opsecHint` / `spoofHint`: Obfuscate/Evasion compile-time; spoof metadata is VERSIONINFO/icon clone, not FUD.
- `httpC2.defaultCopy`: “This still looks like default Sliver to public detectors.”
- `implants.typedC2Missing`: missing listener (Implants only).

Overclaim / mismatch:

- `loaders.disclaimer`: “A short pre-run delay **skips some AV emulators**.” Implementation is 1800 ms + exit if Sleep is skipped. PEzor’s documented example is **120 seconds**. 2026 MDAV is cloud detonation, not a 2s emulator. — [windows.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [PEzor README](https://raw.githubusercontent.com/phra/PEzor/master/README.md)
- Same disclaimer: “**no CreateThread**” + PAGE_NOACCESS-first as if this were the evasion. Tests exist to keep those strings out of **stub source**; Go runtime **still** contains `VirtualAlloc`/`CreateThread`/`kernel32.dll`. Final protect is **RWX**. — [README.md](file:///home/cup/Documents/personal/sliv/README.md); [loader_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)
- `loaders.guide.sideload`: “Sideload: bland DLL name beside a signed host.” Wrap output is `*_loader.exe`, not a sideload DLL next to a signed host. ScareCrow docs: binary mode **does not** get sideload benefits. — [en.ts](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts); [ScareCrow](https://github.com/optiv/ScareCrow)
- `loaders.sub`: “Compile a finished EXE or ELF from implant shellcode” — “finished” reads as delivery-ready vs lab wrapper.
- Generate default `format=exe` vs `loaders.guide.wrap` “Most common: format=shellcode…”.
- `loaders.runHint` tells the operator to watch Sessions/Beacons but Loaders never says **which** page for **this** blob.
- Unique-hash language is honest in XOR hint; plan status line still pairs uniqueness with emulator delay in a way operators flatten to “AV hygiene.” — [LOADER_AV_OPSEC_PLAN.md status](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md)

### Inferences

**Stop implying:**

1. That wrap EXE is a ScareCrow-class sideload.
2. That 1.8s delay “skips AV emulators” in 2026.
3. That omitting `CreateThread` in stub source is material while RWX + Go runtime APIs remain.
4. That unique SHA-256 is anything but hash-IOC.
5. That default generate EXE + `default` HTTP profile is the OPSEC path.

**Copy edits (truthful, short):**

- Replace emulator sentence with: “Pre-run Sleep(1.8s) plus a tick check **exits** if Sleep returns too fast (toy emulators). It does not delay Microsoft cloud sandbox. Unique SHA-256 is hash-IOC only.”
- Replace “no CreateThread” boast with: “Stub CALLs locally after RWX protect. Donut/SGN still need a writable window. Go runtime still imports typical loader APIs. This is not an EDR bypass.”
- Sideload line: “Sideload (signed host + bland DLL) is **outside this UI** — PEzor `-dll-sideload` / ScareCrow / custom. This page builds an **unsigned wrap EXE**.”
- On wrap success toast: if `IsBeacon`, “Watch **Beacons**, not Sessions, after ~{{interval}}s”; else “Watch **Sessions**.” If `matchC2Job` fails, do not toast success-only.

### Gaps

- zh.ts must stay in lockstep (i18n test). This note lists English strings only.
- No user-analytics on which defaults operators actually click; ranking of overclaim impact is qualitative.

---

## Competitive: Havoc / Nim loaders / ScareCrow / PEzor / Sliver `--skip-symbols` / `-e` / Donut (what operators actually use 2025–2026)

### Takeaway

Published Defender-lab success in 2025–2026 is **almost never** “stock Sliver EXE” or “generic Go wrap with unique hash.” It is **(1) custom unique stub** (C++/Nim/.NET/DInvoke) or **commercial packer**, **(2) Donut with AMSI patch off and entropy 3**, **(3) skip Sliver’s own SGN/garble when an external packer will re-protect**, **(4) HTTP profile work**, and/or **(5) fork Sliver to kill YARA strings and load a DLL from disk**. Havoc is honest that Demon is not evasive and puts sleep-obfuscation **in the agent**. This UI should copy **Havoc’s honesty + Mythic-style packaging surface**, not ScareCrow’s feature list.

### Cited Findings

- Havoc: Demon not designed to be evasive; use external loaders/packers/stagers; agent-level **Ekko/Foliage** sleep obfuscation and indirect syscalls. — [Havoc Agent](https://havocframework.com/docs/agent)
- Sliver `--skip-symbols`: disables garble. BallisKit: generate **vanilla** `--disable-sgn --skip-symbols` when ShellcodePack will pack; faster and less double-signature. This UI defaults **Obfuscate on**, SGN off unless checked. — [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)
- Sliver `-e` / `--evasion`: limited userland unhooking; **does not** control Donut AMSI (`#1759`). — [BishopFox/sliver#1759](https://github.com/BishopFox/sliver/issues/1759)
- Sliver `format=shellcode`: Donut wrapper. Defaults historically Bypass=3, ExitOpt=thread; entropy configurable. Operators who care run **external** `donut -b 1 -e 3` on an EXE. — [bytebl33d](https://bytebl33d.github.io/blog/sliver-evasion/); [donut.go](https://raw.githubusercontent.com/BishopFox/sliver/master/server/generate/donut.go)
- PEzor: RX, 120s sleep, syscalls, unhook, fluctuate, env keying, **DLL sideload**. Listed by BishopFox themselves. — [PEzor](https://github.com/phra/PEzor)
- ScareCrow: sideload + unhook + encrypted shellcode; binary mode explicitly weaker. Threat actors still get hunted on loader constants (Hunter’s Ledger 2026). — [ScareCrow](https://github.com/optiv/ScareCrow); [Hunter’s Ledger](https://the-hunters-ledger.com/reports/sliver-open-directory/)
- Nim/.NET/C++ unique loaders: Numen (2023, dated) claimed language choice did not matter vs Defender if the **shellcode** was Sliver; 2025–2026 posts instead emphasize **unique stub + no default Donut AMSI + ThreatCheck**. YouTube “script kiddie” comments on Cyb3rMaddy (2025) show the commodity XOR+C++ loader is already burned in public. — [Numen 2023](https://www.numencyber.com/defeating-windows-defender-using-different-programming-languages-with-sliver-c2-shellcode/); [Cyb3rMaddy 2025](https://www.youtube.com/watch?v=lC9zh3_S-zg); [lainkusanagi Go loader 2026](https://medium.com/@luisgerardomoret_69654/using-a-golang-shellcode-loader-with-sliver-c2-for-evasion-43a95f5ebc35) (uses **external Donut of a beacon EXE**, not Sliver’s wrap)
- Fortbridge / `better-sliver` / `slivercloak`: **edit Sliver source**, not the GUI wrap. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Commodity “FUD + UnDefend / lock Defender signatures” stacks (e.g. public `pantha704/sliver-c2`) are **out of scope** for this product and are defender-visible. — [pantha704/sliver-c2](https://github.com/pantha704/sliver-c2) (cited as what **not** to copy)

### Inferences

**Operators in 2025–2026 Defender labs actually publish:** custom stage-0; Donut `-b 1 -e 3`; ThreatCheck/DefenderCheck loop; skip-symbols when packing externally; signed-host sideload **or** disk DLL; HTTP profile edits; sometimes a Sliver fork. They do **not** publish “unique Go wrap SHA-256” as sufficient.

**Product implication:** keep wrapping as a **lab convenience** with brutal diagnostics. Point OPSEC operators at **external** loaders (already in `loaders.guide.external`). Copy Havoc’s sentence structure, not its sleep-mask.

### Gaps

- No survey dataset of “what red teams used in 2026”; this is a synthesis of **public** writeups (Fortbridge, BallisKit, bytebl33d, Ramsbey, Hunter’s Ledger, GitHub issues). Private OST (Nighthawk NHLoader, etc.) is marketed, not fully documented.
- Nim-specific 2026 Defender results beyond generic “write your own loader” posts were thin in this pass.

---

## Phased plan (A lab sessions → B threat names → C honest hardening → D never FUD)

### Takeaway

**A** is the only phase that fixes “loader run → no session” for most operators and is entirely truthful. **B** is a runbook, not a feature. **C** is optional and must stay behind evidence (disk-DLL stub, Donut Bypass=1, maybe RX after decode). **D** is a standing non-goal: this repo already rejected the crypter-shop path.

### Cited Findings

- Success metric already chosen by this project: **fewer wrong packages**, not VT score. — [LOADER_AV_OPSEC_PLAN.md §7](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md); [Havoc Agent](https://havocframework.com/docs/agent)
- Encrypt-at-rest report: ciphertext ≠ EDR bypass. — [reports/Sliver encrypt at rest loaders.md](file:///home/cup/Documents/personal/sliv/reports/Sliver%20encrypt%20at%20rest%20loaders.md)
- Fortbridge: only disk-backed DLL + string clean beat Elastic+Defender in that lab; unbacked shellcode loaders did not. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- PEzor `-rx` incompatible with SGN; this stub’s tests require RWX for Donut/SGN. — [PEzor README](https://raw.githubusercontent.com/phra/PEzor/master/README.md); [loader_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)
- Sliver troubleshooting: `--debug`. — [Sliver Troubleshooting](https://sliver.sh/docs/?name=Troubleshooting)
- Threat names that **are** citable: `Behavior:Win32/AMSI_PATCH_T.B12`; Elastic `Multi.Trojan.Sliver`; DefenderYara string set in Fortbridge. — [#2200](https://github.com/BishopFox/sliver/issues/2200); [Multi_Trojan_Sliver.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar)

### Inferences

Ranked by **(impact on symptoms 1–2) / (complexity × honesty risk × rejected-overlap)**:

#### Phase A — make sessions work in Defender-off lab (do first; highest symptom-1 impact)

| ID | Change | Symptom | Complexity | Honesty |
|---|---|---|---|---|
| A1 | Lab loader logging; never silent `Exit(0)` when console visible; log if `jump` returns | 1 | Low | High |
| A2 | Loaders: `matchC2Job` hard-warn; show implant C2 URL | 1 | Low | High |
| A3 | Loaders: show `IsBeacon` + interval; tell operator which page to watch | 1 | Low | High |
| A4 | Pass `function_name` (default `StartW`); refuse EXE-as-PIC; keep truncated-PE error | 1 | Low | High |
| A5 | Hide-console **off** on a “Lab verify” preset; default wrap path should not be GUI-silent | 1 | Low | High |
| A6 | Fix Implants port auto-fill (`8888`-only bug) | 1 | Trivial | High |
| A7 | Checklist: debug implant, matching listener, wait 2× beacon interval | 1 | Copy only | High |
| A8 | Optional: default generate format toward shellcode when operator clicks “Continue in Loaders” (do not silently change EXE default without a prompt) | 1 | Low | High |

If A fails, the product has a **loader/C2 bug**, not an AV gap.

#### Phase B — diagnose Defender threat names (symptom 2, and symptom 1 with MDAV on)

| ID | Change | Notes |
|---|---|---|
| B1 | In-UI runbook (not a VT widget): Protection History, `Get-MpThreat`, Event 1116/5001, `MpCmdRun -Scan`; paste threat name into notes | Rejected: VirusTotal widget |
| B2 | Map names operators actually see: `AMSI_PATCH_*` → Donut Bypass; `Multi.Trojan.Sliver` / protobuf strings → need Sliver fork (external); generic “behavior / injection” → RWX/unbacked/CRT |
| B3 | ThreatCheck/DefenderCheck as **external** appendix (Rasta Mouse / matterpreter); do not shell out from the UI host |

#### Phase C — optional loader hardening that is still honest (only with evidence)

| ID | Change | Evidence | Do / don’t |
|---|---|---|---|
| C1 | Wire Donut **Bypass=1** (and ExitOpt=3 for wrap-host lifetime) on generate | #1759, #2200, Fortbridge, bytebl33d | **Do** — native flags, honest labels |
| C2 | Disk `LoadLibrary` stub for `format=shared` (no VirtualAlloc RWX) | Fortbridge **success** path | **Do as optional output**, labeled “disk DLL; still unsigned; still needs string-clean implant” |
| C3 | Longer sandbox delay (operator-set, default 0 in lab, e.g. 10–120s) | PEzor `-sleep`; Fortbridge still lost to behavior | **Optional**; copy must say cloud MDAV waits |
| C4 | RX after decode when encoder is NONE | PEzor `-rx`; Donut writes during decode | **Research only**; never with SGN |
| C5 | Module stomping | Fortbridge **failed** on 30 MB Go | **Don’t** until implants shrink |
| C6 | Sleep obfuscation in wrap/implant | #1171 Go runtime; Havoc does this in-agent | **Don’t** in this UI |
| C7 | AMSI/ETW patch in wrap | Those patches **are** the detections | **Don’t** |
| C8 | Sideload project export (DLL name + “put beside signed host”) | ScareCrow/PEzor | **Template/docs only** — not in-tree ScareCrow (rejected) |

#### Phase D — never promise FUD (standing)

- Do not reopen: in-tree Donut CLI, ScareCrow, VT 0/70, Implants encrypt-FUD checkbox, silent watchdog “AV heal”.
- Do not add: unique-hash as “sandbox/ML bypass”; “skips emulators” as evasion; UnDefend/BYOVD.
- Success metric remains: **correct package + visible failure**, not a detection count.

### Gaps

- Phase C2 (disk LoadLibrary stub) needs a small design spike: Go `syscall.LoadDLL` of a dropped Sliver `SHARED_LIB` vs keeping the current PIC wrap. Not implemented; Fortbridge’s sample was a **tiny C** loader, not a Go runtime host (Go host still has a large noisy runtime).
- No engagement-specific Defender cloud sample for **this** wrap EXE; Phase B is how the operator fills that gap.

---

## Ranked recommendations (executive)

1. **A1–A7 diagnostics** — highest impact on symptom 1, lowest complexity, fully honest.  
2. **A4 RDI export + refuse EXE-as-PIC** — probable product bug on shared wrap.  
3. **C1 Donut Bypass/ExitOpt plumbing** — native Sliver flags; helps `AMSI_PATCH_*` without a crypter.  
4. **HTTP C2 not `default` + beacon** — already built; make generate defaults and Loaders checklist use them.  
5. **B runbook for Protection History names** — required before any more “AV hygiene” code.  
6. **C2 optional disk-DLL stub** — only evidence-backed architecture change; still not FUD.  
7. **External loaders / Sliver fork** — where symptom 2 actually gets solved in 2025–2026 papers.  
8. **Do not:** more XOR, longer uniqueness, in-tree ScareCrow, RWX→marketing, module stomping, sleep-mask, VT.

The wrap’s implemented hygiene (unique hash, XOR names, no stub `CreateThread`, 1.8s sleep, PAGE_NOACCESS-first) is **real engineering and still the wrong layer** for “Defender killed my live Sliver.” That kill is **memory YARA + unbacked executable memory + default Donut AMSI + default HTTP fingerprints**. A C2 GUI should make the **callback path observable** and refuse to lie about the rest.
