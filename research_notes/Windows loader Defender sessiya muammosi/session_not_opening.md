# Why a Windows Sliver UI host-compiled loader EXE can fail to open a session (before or besides Defender)

Scope: authorized lab debugging of **this product** (`/home/cup/Documents/personal/sliv`). The Windows loader is a Go stub compiled on the sliver-ui host (`POST /api/loaders/build`) that XOR-embeds implant bytes, allocates RWX, and `CALL`s them on an 8 MiB stack. “Sessiya ochilmayapti” (no session appeared) has several **testable** causes that are not Defender. Defender silent kill is one bucket, not the only one.

This note enumerates concrete failure modes in six operator-visible classes: (1) payload format / execution, (2) C2 / listener mismatch, (3) process lifetime (hide-console / CALL return / Go exit), (4) implant type session vs beacon, (5) Defender silent kill, (6) architecture / OS / Wine mismatch. Persistence does **not** abort execution. A diagnostic decision tree is at the end.

---

## What implant format does POST /api/loaders/build expect? If the operator generated format=exe or shared instead of shellcode, what happens? RDI of full MZ+PE vs Donut PIC vs malasada?

### Takeaway
The wrap API expects **position-independent shellcode bytes**, not a process-image EXE. On Windows it **auto-converts any MZ payload via Sliver `ShellcodeRDI` (sRDI, DLL loader)** before compile. That is the correct converter for `format=shared` **only if an export name is supplied** (default implant export is `StartW`). It is the **wrong** converter for `format=exe` (Donut is). `format=shellcode` is already Donut PIC and must **not** be RDI’d. Empty-export RDI of a Sliver DLL is a confirmed “process runs ~2s then exits, no callback” bug.

### Cited Findings
- `POST /api/loaders/build` decodes `data_b64`, defaults OS to Windows, then if `req.RDI || loader.NeedsRDI(goos, payload)` it requires a full PE (`LooksLikeFullPE`) and calls `c.ShellcodeRDI(payload, req.FunctionName, "")`. Truncated MZ returns 400 `"payload looks like a truncated PE/DLL; generate format=shellcode or load a complete Windows DLL"`. No connected sliver-server returns 503. — [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go)
- `NeedsRDI` is `NormalizeOS(goos)=="windows" && LooksLikePE` (bytes `MZ` only). `LooksLikeFullPE` additionally checks `e_lfanew` and `PE\0\0`. — [options.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/options.go)
- The wrap tab’s `buildExe()` sends `data_b64`, `os`, `arch`, `name`, `hide_console`, `persistence`, `persist_name`, `xor_key`. It does **not** send `rdi` or `function_name`. The RDI checkbox / export field exist only on the Tools tab. — [LoadersPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx); [api.ts loadersBuild](file:///home/cup/Documents/personal/sliv/frontend/src/lib/api.ts)
- Wrap dropdown filters builds to format containing `SHELLCODE` or `SHARED` (`isLoaderFormat`). Operators can still **upload** an EXE/DLL. Selecting a shared build only sets `doRdi` local state; wrap compile still relies on backend MZ detection. — [LoadersPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx)
- Sliver RPC `ShellcodeRDI` is documented as converting a **DLL** via `ShellcodeRDIFromBytes`. Empty `functionName` packs hash `0x10` (not the hash of `StartW`). Bootstrap always `CALL`s the RDI stub then **`RET`s to caller**. — [rpc-generate.go ShellcodeRDI](https://github.com/BishopFox/sliver/blob/v1.7.3/server/rpc/rpc-generate.go); [srdi.go](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/srdi.go)
- sRDI maps the PE, calls `DllMain(base, DLL_PROCESS_ATTACH, 1)`, then if `dwFunctionHash != 0` searches exports by ROR13 hash. Hash `0x10` is truthy, so it searches and finds nothing for a Sliver DLL. Then it returns. — [monoxgas/sRDI ShellcodeRDI.c](https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c); [NetSPI sRDI](https://www.netspi.com/blog/technical-blog/adversary-simulation/srdi-shellcode-reflective-dll-injection/)
- Sliver Windows `DllMain` starts the implant **only** if `RunAtLoad` is set, and even then via `CreateThread(Start)` because calling `main()` from `DllMain` deadlocks. Default `--run-at-load` is **false**. UI generate never sends `RunAtLoad` or `exports`. Server fills empty exports with `["StartW"]` only. — [implant/sliver/main.c](https://github.com/BishopFox/sliver/blob/v1.7.3/implant/sliver/main.c); [generate/commands.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/generate/commands.go); [rpc-generate.go](https://github.com/BishopFox/sliver/blob/v1.7.3/server/rpc/rpc-generate.go); [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx)
- Shared-lib exports (`StartW`, `VoidFunc`, …) call `main()` / `runner.Main()`. If neither `DllMain`/`RunAtLoad` nor sRDI’s hashed export runs, the implant never starts. — [implant/sliver/main.go](https://github.com/BishopFox/sliver/blob/v1.7.3/implant/sliver/main.go)
- Windows `format=shellcode` is **not** sRDI: teamserver builds a Go **PIE EXE** (`-H=windowsgui` unless debug) then `DonutShellcodeFromFile`. File extension is `.bin`, so Donut `isDLL` is false (EXE module). PIC is prefixed with an 8-byte stack-align prologue (`and rsp,0xF0; add rsp,8`). — [binaries.go windowsShellcode](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/binaries.go); [donut.go](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/donut.go)
- Donut loads unmanaged PE/DLL from memory; it is the converter for EXE→PIC. sRDI is DLL→PIC. They are not interchangeable. — [TheWover/donut](https://github.com/TheWover/donut); [monoxgas/sRDI](https://github.com/monoxgas/sRDI)
- Linux `format=shellcode` is **malasada** (`ConvertSharedObject` of a `.so`), not Donut. Wrapping that blob as a Windows loader is a different architecture/OS class (see later). Lab inventory had one build: linux/amd64 SHELLCODE `OneDriveUpdateee`. — [binaries.go linuxShellcode](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/binaries.go); [current_product_inventory.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20UI%20imkoniyatlar%20tahlili/current_product_inventory.md)
- Tests: truncated MZ → 400; full PE without sliver client → 503; raw `0x90 0xC3` is not NeedsRDI. — [handlers_loaders_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders_test.go); [loader_test.go TestNeedsRDI](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)
- UI copy already says wrap `format=shellcode` (or shared with auto-RDI) and that the implant still needs a live listener. It does **not** warn that auto-RDI uses an empty export. — [en.ts loaders.whatIsThis / rdiAuto / runHint](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)

### Inferences
- **Intended happy path:** Implants → `os=windows`, `format=shellcode`, C2 matching a live listener → Loaders → Build EXE. Payload has no MZ → no RDI → Donut PIC is `CALL`ed.
- **Shared wrap (default UI generate):** MZ DLL → auto-RDI with `FunctionName=""` → DllMain does not `CreateThread` (`RunAtLoad=false`) → export hash `0x10` misses `StartW` → sRDI `RET` → Go `main` returns → process exits. **No session.** Test: Task Manager process gone after ~2s; no C2 packets.
- **Workaround for shared (testable):** Tools tab → RDI with function `StartW` (or `VoidFunc`) → then wrap the resulting `.bin` (no MZ, no second RDI). Or generate with `--run-at-load` in native sliver-client (not exposed in this UI).
- **EXE upload / wrapping `format=exe`:** `NeedsRDI` true → sRDI treats the EXE as a DLL and calls `AddressOfEntryPoint` as `DllMain`. sRDI does not check `IMAGE_FILE_DLL`. This is unsupported; crash or immediate return is the expected lab result. Correct converter is Donut (`format=shellcode` on generate), not this wrap path.
- **Already-Donut shellcode:** first bytes are `48 83 E4 F0` (stack check), not `MZ`. Auto-RDI does not fire. Good.
- **SGN-encoded shellcode:** also not MZ; loader `CALL`s the decoder in RWX (`PAGE_EXECUTE_READWRITE = 1<<6`). Good, as long as arch matches.
- **Compile-time vs run-time:** truncated PE and “not connected to sliver-server” fail at Build EXE (operator sees toast). Empty-export RDI **succeeds** at compile and fails only at run — that is why it presents as “I ran the loader and no session appeared.”

### Gaps
- This pass did not detonate a UI-wrapped `format=shared` DLL on a real Windows host, so the empty-export path is deduced from sRDI + Sliver `DllMain` source, not a captured Procmon trace.
- Whether sRDI-mapping a Go EXE sometimes “accidentally” runs `rt0` was not lab-verified; treat EXE-via-RDI as unsupported rather than “sometimes works.”
- Sliver 1.7.9 (lab server) vs module v1.7.3 (this UI’s Go dependency) may differ in wasm-donut defaults; Thread/ExitOpt behavior below uses v1.7.3 `donut.go` plus current UI `ShellcodeConfig` fields.

---

## Windows trampoline: CALL onto 8 MiB stack — calling convention, does Sliver Windows shellcode (Donut / sRDI) return, smash the stack, or need to run forever? EXITFUNC?

### Takeaway
The amd64 trampoline is a Microsoft x64 `CALL` with a dedicated 8 MiB stack, 16-byte alignment, and 32-byte shadow space. It **returns to Go** if the PIC returns. Linux trampolines `exit_group` after `CALL`; Windows does not. Donut default EXITFUNC is **exit thread**; UI-generated shellcode sets `ShellcodeConfig.Entropy` only, so Donut `Thread` is **false** (in-line EXE entry). A session/beacon implant that actually starts will block inside `runner.Main()` and the `CALL` never returns. sRDI of a DLL that does not start `StartW` **does** return, and that kills the host process.

### Cited Findings
- Comment on `jumpAsm`: Go 1.21+ func values are `funcval` pointers, so overlaying `func()` on a code address does not jump to the payload; goroutine stacks are also too small for Sliver PIC. Dedicated stack + assembly `CALL` is required. — [source.go jumpAsm](file:///home/cup/Documents/personal/sliv/backend/internal/loader/source.go)
- `jump_windows_amd64.s`: save Go `SP` in `R12`, switch to `stack`, `AND $~0xF`, `SUB $40`, `CALL AX`, restore `SP`, `RET`. `$40` = 32-byte shadow + 8 so that after `CALL`’s 8-byte return address the callee sees 16-byte-aligned `RSP` (Win64 ABI). — [source.go jump_windows_amd64.s](file:///home/cup/Documents/personal/sliv/backend/internal/loader/source.go)
- `jump_windows_386.s` / `jump_windows_arm64.s` also `CALL` then `RET`. `jump_windows_arm.s` is `B (R0)` (never returns). Linux amd64 after `CALL` does `SYS_exit_group` (231), not `RET`. — [source.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/source.go)
- Windows `run()`: `VirtualAlloc` NOACCESS then commit RW (or RW fallback), copy+XOR decrypt, `VirtualProtect` RWX (`1<<6`), `FlushInstructionCache`, allocate 8 MiB RW stack, 16-byte-align `stk = st + stackSize - 256`, `LockOSThread`, `SetGCPercent(-1)`, `jump(addr, stk)`. No `CreateThread`. If `VirtualAlloc`/`VirtualProtect` fails, `run()` **returns** (silent). — [windows.go run()](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- Tests require the 8 MiB stack, RWX, and the `jump` trampoline; they forbid `CreateThread`/`WaitForSingleObject` in stub source. Wine test payload is `xor eax,eax; ret` (`31 C0 C3`) and only asserts the loader **returns**. — [loader_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)
- Sliver Donut defaults: `defaultDonutExitOpt = DonutExitThread`, `DonutShellcodeFromFile` passes `createNewThread=true`, but `normalizeDonutConfig` **overwrites** `thread` with `config.Thread` whenever `ShellcodeConfig != nil`. — [donut.go](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/donut.go)
- This UI always sets `ShellcodeConfig{Entropy: entropy}` for shellcode builds (default entropy 2) and never sets `Thread` or `ExitOpt`. Protobuf zero ⇒ `Thread=false`, `ExitOpt` stays default (exit thread). — [implants.go buildImplantConfig](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants.go)
- Donut `-x`: 1=exit thread (`RtlExitUserThread`, default), 2=exit process (`RtlExitUserProcess`), 3=block indefinitely. `-t` runs unmanaged EXE entry as a **new thread** and patches IAT exit APIs to `RtlExitUserThread`. — [Donut README](https://github.com/TheWover/donut); [donut devnotes](https://github.com/TheWover/donut/blob/master/docs/devnotes.md)
- Donut also prepends stack check so `RSP` is 8-byte aligned but not 16-byte aligned before `LoadLibrary`. The UI trampoline already 16-aligns then `CALL`s; Donut’s prologue re-adjusts. — [donut.go addStackCheck](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/donut.go)
- sRDI x64 bootstrap: 16-align, `sub rsp, 0x30`, `CALL` RDI, restore `RSP`, **`ret`**. — [srdi.go convertToShellcode](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/srdi.go)
- Session implants call `sessionStartup()` which loops connections forever unless `ErrTerminate` or `MaxConnectionErrors`. Beacons call `beaconStartup()` which loops check-ins. Both are started from `runner.Main()` after `limits.ExecLimits()`. If those loops run, Donut’s in-line EXE entry does not return. — [runner.go](https://github.com/BishopFox/sliver/blob/v1.7.3/implant/sliver/runner/runner.go)
- `ExecLimits()` on mismatch does `os.Exit(1)` (hostname, username, domain-joined, datetime, file-exists, locale). That is process death **after** PIC start, with no C2. — [limits.go](https://github.com/BishopFox/sliver/blob/v1.7.3/implant/sliver/limits/limits.go)

### Inferences
- **Does the PIC need to run forever?** For a live session/beacon: yes, in the `CALL` thread (UI Donut `Thread=false`). The trampoline is not a fire-and-forget `CreateThread`.
- **If PIC returns:** Windows `jump` restores the Go stack and `RET`s into `run()` → `main` returns → Go runtime `ExitProcess` → **all implant threads die**. This is the empty-export sRDI case and the “Donut loaded PE that immediately exited” case.
- **If PIC `RtlExitUserThread`s the current thread** (Donut EXIT_THREAD after a short-lived payload): the Go main OS thread dies; remaining Go runtime threads may hang or the process may still exit. Either way the operator sees no lasting session if the implant never entered `sessionStartup`.
- **If PIC `RtlExitUserProcess`s:** host loader dies even if implant threads existed. UI does not set ExitOpt=process; default is thread.
- **Stack smash:** 8 MiB is sized for Go/Donut. The Wine fixture (`C3` ret) only proves the trampoline ABI for a function that returns; it does not prove Donut+Go stack use. A too-small stack would crash (process gone, often WER), not a quiet “no session.”
- **Win64 ABI:** trampoline matches Microsoft x64 (`CALL` + shadow). Donut/sRDI bootstraps also assume that. A raw `JMP` without shadow space would break Donut’s `LoadLibrary`; they used `CALL` on purpose.

### Gaps
- No Windows debugger capture of `RSP` at Donut `LoadLibrary` through this exact trampoline. Alignment math is from the assembly listing, not a live trace.
- Whether Go 1.22 PIE EXEs that Sliver Donut-wraps always have usable relocs on Windows 10/11 24H2 was not re-tested here. Donut documents “only files with relocation information.” — [Donut README](https://github.com/TheWover/donut)
- wasm-donut numeric values for `DonutExitThread` / `Thread` in Sliver 1.7.9 were not dumped; inference uses v1.7.3 `donut.go` + UI protobuf zeros.

---

## Hide console: `-H windowsgui` + `ShowWindow`. Does the process stay alive after CALL? If CALL returns, does the Go runtime exit and drop the implant?

### Takeaway
Hide-console does **not** daemonize on Windows. It only suppresses the console. The process is the loader itself. It stays alive **if and only if** `jump()` does not return (implant loop running). If `CALL` returns, Go `main` returns and the process exits — implant gone. Double-clicking a GUI-subsystem EXE looks like “nothing happened,” which operators read as “no session.”

### Cited Findings
- Default `hide_console` is **true** in the API (`hide := true` unless JSON pointer is set) and in the Loaders UI (`DEFAULTS.hideConsole: true`). — [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go); [LoadersPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx)
- Compile: `ldflags += " -H windowsgui"` when `GOOS==windows && HideConsole`. Also `-s -w` and optional unique `-buildid`. `CGO_ENABLED=0`. — [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go)
- Go `-H windowsgui` writes a Windows **GUI** PE subsystem: no console is created or attached; std handles are closed. This is expected and does not keep the process alive by itself. — [Go issue / SO: -H=windowsgui](https://stackoverflow.com/questions/23250505/how-do-i-create-an-executable-from-golang-that-doesnt-open-a-console-window-whe); [SO: printing with windowsgui](https://stackoverflow.com/questions/23743217/printing-output-to-a-command-window-when-golang-application-is-compiled-with-ld)
- Runtime `hideWindow()`: if `hideConsole`, `GetConsoleWindow` + `ShowWindow(hwnd, 0)` (`SW_HIDE`) + `FreeConsole`. On a GUI-subsystem binary `GetConsoleWindow` is typically 0, so this is a no-op. — [windows.go hideWindow](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- `main()` order: `hideWindow()` → `enoughRAM()` (else `os.Exit(0)`) → `pause()` (else `os.Exit(0)`) → `persist()` → `run()`. There is no Windows fork/re-exec. — [windows.go main](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- Linux hide-console **does** re-exec with `SLIV_BG=1` + `Setsid` and `os.Exit(0)` in the parent. Windows does not. UI copy “Hide-console returns immediately — watch Sessions and Beacons” is the Linux behavior, misleading for Windows. — [source.go unix daemonize](file:///home/cup/Documents/personal/sliv/backend/internal/loader/source.go); [en.ts hideConsoleHint / runHint](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- Sliver’s own Windows shellcode/EXE non-debug builds also use `-H=windowsgui`. — [binaries.go windowsShellcode](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/binaries.go)

### Inferences
- **Process lifetime table (Windows loader):**
  | After double-click | Meaning |
  |---|---|
  | No window, process **stays** in Task Manager >~2s | Stub passed RAM/pause; `CALL` has not returned (implant likely looping, or hung/crashed in a way that didn’t terminate) |
  | No window, process **gone** in <3s | `enoughRAM`/`pause` abort, `run()` alloc fail, PIC returned (empty-export RDI), PIC crashed + WER, or Defender killed it |
  | Console flashed | `hide_console` was off (console subsystem) |
- If `CALL` returns, Go runtime exit **does** drop the implant. There is no second process. Contrast Linux: parent exits, child holds PIC.
- Operators who “run and it returns immediately” on Windows are not seeing a successful background implant; they are seeing process death or a GUI binary with no window.

### Gaps
- Whether some Windows shells still attach a console to GUI binaries (rare `START` flags) was not tested; `GetConsoleWindow`+`ShowWindow` covers that if it happens.
- Go `ExitProcess` vs `RtlExitUserThread` interaction when Donut EXIT_THREAD fires on the locked OS thread was not traced with x64dbg.

---

## Persistence install at startup of the stub — could schtasks/reg fail and abort before jump?

### Takeaway
No. Persistence is best-effort and cannot abort `run()`. `persist()` returns on any API/`schtasks` failure; `main` always calls `run()` next (unless RAM/pause already `os.Exit`ed). Persistence is off by default.

### Cited Findings
- `persistByOS` Windows methods: `off` (default), `runkey_hkcu`, `schtask_logon`, `startup_lnk`, `all`. Empty persistence normalizes to `off`. — [options.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/options.go)
- `persist()`: if method is `""` or `"off"`, return. Else `os.Executable()`; on error, return. Each method is independent; `all` calls all three. — [windows.go persist](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- `persistRun`: `RegCreateKeyExW` HKCU `...\Run`; nonzero return or null handle → return (no abort of `main`). — [windows.go persistRun](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- `persistTask`: `schtasks /create /tn <name> /sc ONLOGON /tr <self> /rl LIMITED /f` with `HideWindow: true`; result discarded (`_ = cmd.Run()`). — [windows.go persistTask](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- `persistStartup`: copy self to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<name>.exe`; I/O errors ignored. — [windows.go persistStartup](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- `main` always `persist(); run()` after pause. Tests assert `"all"` dispatches all three functions. — [windows.go main](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [loader_test.go TestWindowsAllPersistCallsEveryMethod](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)
- UI: persistence off by default; warning copy present. — [LoadersPage.tsx DEFAULTS](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx); [en.ts persistHint](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)

### Inferences
- Do **not** spend lab time on “schtasks failed so implant never jumped.” It cannot explain a missing session on first run.
- Persistence can still **cause Defender/ASR** (schtasks, Run key, Startup drop) *after* the stub is already going to `CALL`. That is a Defender class, not an abort-before-jump class.
- `startup_lnk` is a full EXE copy, not a `.lnk`. Name is leftover from an older design.

### Gaps
- Whether `schtasks` with `HideWindow` still briefly flashes on some Windows SKUs is cosmetic, not a session blocker.

---

## Sleep 1.8s emulator skip — could this confuse operators timing a short test?

### Takeaway
Yes. Before PIC, the stub `Sleep(1800)` and `os.Exit(0)` if `GetTickCount` advanced `< 1400` ms (AV emulator skip). On real Windows the user sees **~2 seconds of nothing** (GUI binary). Killing the process during that window, or concluding “failed” at t=1s, is a false negative. `SLIV_BG=1` skips the check (Wine unit test uses this); a normal double-click does not.

### Cited Findings
- `pause()`: unless `os.Getenv("SLIV_BG")=="1"`, `Sleep(1800)` then if `t1>=t0 && t1-t0 < 1400` → `os.Exit(0)`. — [windows.go pause](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- `enoughRAM()`: unless `SLIV_BG=1`, `GlobalMemoryStatusEx` into 64-byte buffer; `ullTotalPhys` at offset 8 must be `>= 1<<30` (1 GiB). If the API fails (`r==0`), it **fail-opens** (returns true). — [windows.go enoughRAM](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- UI: “Windows waits ~2s before executing (emulator check).” — [en.ts runHint](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- Plan text: “Pre-run Sleep+tick aborts some AV emulators.” — [LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md)
- Wine PIC test sets `SLIV_BG=1`, so it never exercises pause/RAM on Wine. — [loader_test.go TestExecuteWindowsPICWine](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)

### Inferences
- **Operator timing trap:** hide-console + 1.8s sleep = double-click, no window, wait 1s, “it didn’t work.” Wait ≥5s and watch Task Manager / Sessions **and** Beacons.
- **Low-RAM VM:** 512 MiB Windows lab VM → silent `os.Exit(0)` **before** PIC. Test: process dies instantly, no 1116, no C2 packets. Raise VM RAM or set `SLIV_BG=1` for a controlled retest (lab only).
- **Emulator abort:** sandbox that stubs `Sleep` without advancing `GetTickCount` → stub exits, never calls implant. That is by design vs AV emulators; it also aborts some “detonate in VM with time acceleration” setups if ticks don’t move.
- `SLIV_BG` is **not** set by the Windows stub itself (Linux daemonize sets it for the child).

### Gaps
- Exact `MEMORYSTATUSEX` layout is assumed as MSVC (`dwLength` 4 + `dwMemoryLoad` 4 + `ullTotalPhys` 8). This matches the documented struct; a Wine quirk reporting 0 total RAM would fail-open only if the call returns 0, not if it returns success with a tiny number.
- Not measured: Defender’s own emulator vs this 1400/1800 heuristic on 24H2.

---

## C2: implant built for https://X:443 but listener is mtls:8888 — same class as Linux lab OneDriveUpdateee

### Takeaway
Yes, this class is fully alive on Windows. C2 URL is **baked at generate**, not at loader compile. The loader is a dumb PIC runner. Generate defaults in this UI are `https` / `127.0.0.1` / `443`. A live mTLS job on 8888 will not receive that implant. Empty C2 list on the backend even hardcodes `mtls://127.0.0.1:8888`. `127.0.0.1` on a Windows guest is the guest, not the Linux teamserver.

### Cited Findings
- Implants form defaults: `c2Type='https'`, `c2Host='127.0.0.1'`, `c2Port='443'`, `os='windows'`, `format='exe'`. Typed URL is `` `${c2Type}://${c2Host}:${c2Port}` ``. Warning when no job matches protocol+port: `typedC2Missing`. — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx); [en.ts typedC2Missing](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- `matchC2Job` requires job name/protocol in `{https,http}` for `https://` and **equal port**. mTLS job name `mtls` port 8888 does not match `https://host:443`. — [c2.ts](file:///home/cup/Documents/personal/sliv/frontend/src/lib/c2.ts)
- Backend `buildImplantConfig`: each C2 becomes `protocol://address`. If the list is empty after filtering, **force** `mtls://127.0.0.1:8888`. Interval is reconnect (session) or beacon interval. — [implants.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants.go)
- Loaders wrap does not rewrite implant C2. Disclaimer: “The implant still needs a live listener on its C2 URL.” — [en.ts loaders.disclaimer](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- Lab 2026-11-16: 0 sessions, 0 beacons, **3 jobs** (mtls 8881, mtls 8888, https 443), one build `OneDriveUpdateee` **linux/amd64 SHELLCODE**. Generate UI still defaulted Windows/https/443. Hosts table had Linux host `water`. — [current_product_inventory.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20UI%20imkoniyatlar%20tahlili/current_product_inventory.md)
- Default ports in UI helpers: https 443, http 80, mtls 8888, dns/wg 53. — [c2.ts DEFAULT_C2_PORT](file:///home/cup/Documents/personal/sliv/frontend/src/lib/c2.ts)
- Limit flags (`limit_hostname`, domain-joined, username, datetime, file exists, locale) cause `os.Exit(1)` inside the implant after PIC start — another “ran, no session” with possible short-lived process. — [limits.go](https://github.com/BishopFox/sliver/blob/v1.7.3/implant/sliver/limits/limits.go); [ImplantsPage.tsx buildConfig](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx)

### Inferences
- **Same-class failures on Windows (testable):**
  1. Implant `https://127.0.0.1:443` run on a Windows VM → connects to the VM, not the teamserver.
  2. Implant `https://<teamserver>:443` but only `mtls :8888` listening → TCP/TLS mismatch; Wireshark may show SYN/RST or TLS to the wrong port.
  3. Implant `https://x:443` vs HTTPS job on 8443.
  4. HTTP vs HTTPS scheme mismatch (listener `http` job vs `https://` URL).
  5. Wrapping `OneDriveUpdateee` (linux shellcode) as a Windows EXE (operator overrode OS dropdown) → PIC crash, not a C2 issue; if OS left as linux, the download is ELF, not a Windows loader.
- Loader compile success says **nothing** about C2. Check the **implant build’s** C2 column (`C2JobStatus` live/missing) and Listeners/Jobs.
- `Use` button on Implants copies detected listener host/port but host comes from an **existing session** (`sessions.find ActiveC2`), which is empty when you have 0 sessions — so host can stay `127.0.0.1` even when jobs exist.

### Gaps
- The exact C2 URL baked into lab `OneDriveUpdateee` was not dumped from the teamserver DB in this pass; inventory only shows OS/arch/format. The **class** (https generate default vs mtls listeners, linux build vs Windows run) is documented.

---

## Beacon vs session: if `is_beacon=true`, “session” never appears in Sessions (`sessiya ochilmayapti`)

### Takeaway
Confirmed product split. `is_beacon` is a checkbox on Implants (default **false**). Beacon implants register on `/beacons`, not `/sessions`. Default interval 60s + 20% jitter means a beacon can take over a minute to show. Looking only at Sessions after wrapping a beacon is a false “no session.”

### Cited Findings
- ImplantsPage: `isBeacon` state default `false`, sent as `is_beacon` on generate and profile save. Hint: “Beacon implants sleep and check in on this interval… Session implants stay interactive.” — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx); [en.ts isBeacon / beaconHint](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- Backend: `IsBeacon` true → `BeaconInterval`/`BeaconJitter`; false → `ReconnectInterval`. — [implants.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants.go)
- Implant: `runner.Main()` → `beaconStartup()` vs `sessionStartup()`. Beacons `BeaconRegister` then sleep `beacon.Duration()`. Sessions stay in `sessionMainLoop`. — [runner.go](https://github.com/BishopFox/sliver/blob/v1.7.3/implant/sliver/runner/runner.go)
- UI routes: `/sessions` vs `/beacons`. Lab snapshot: both empty, separate empty states. Beacon detail has “Open Interactive Session.” — [current_product_inventory.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20UI%20imkoniyatlar%20tahlili/current_product_inventory.md)
- Loaders `runHint` already says watch **Sessions and Beacons**. — [en.ts runHint](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- Generate defaults: interval `60`, jitter `20`. — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx)

### Inferences
- Operator language “sessiya” maps to Sessions page. If they ticked Beacon (or loaded a beacon profile), the callback is on Beacons, possibly after 60–72s.
- A **session** implant should appear on Sessions within reconnect (default 60s) of a successful C2 connect; often faster if the first connect works.
- Opening an interactive session from a beacon is a **second** RPC (`POST /beacons/{id}/open-session`); it is not automatic.

### Gaps
- Whether older notes that “ImplantsPage never sets is_beacon” are stale: **they are stale**. Current tree has the checkbox. Do not use those older RPC-coverage notes for this diagnosis.

---

## Wine vs Windows: Wine PIC test is not a Windows session test

### Takeaway
`TestExecuteWindowsPICWine` only proves the trampoline can `CALL` `xor eax,eax; ret` under Wine with `SLIV_BG=1` (skip pause/RAM). It does not run Donut, sRDI, Sliver C2, hide-console lifetime, or Defender. A green Wine test is **not** evidence a Windows session will open.

### Cited Findings
- Test payload `{0x31, 0xC0, 0xC3}`, `HideConsole: false`, `SLIV_BG=1`, `WINEDEBUG=-all`, timeout 20s; failure mode is “PIC was not called/returned.” — [loader_test.go TestExecuteWindowsPICWine](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)
- Linux PIC test uses `exit_group(42)` and asserts exit code 42 — that **does** prove PIC execution on Linux. There is no equivalent “Sliver callback” Windows test. — [loader_test.go TestExecuteLinuxPIC](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)
- Wine is not Windows: `Sleep`/`GetTickCount`, `GlobalMemoryStatusEx`, GUI subsystem, Win64 ABI, and TLS stacks differ; Sliver mTLS/HTTPS C2 is not a Wine conformance target.

### Inferences
- Use Wine only to check “did the stub compile and jump.” Session diagnosis requires a real Windows VM (or native host) plus a matching listener.
- If an operator “tested on Linux with Wine” and saw the process exit 0 (because the fixture `RET`s), that is **success of the trampoline**, and also a demonstration that **a returning PIC kills the Windows-style path** (jump RET → Go exit).

### Gaps
- Wine version in CI/dev was not recorded in this pass.

---

## Go cross-compile from Linux host (`GOOS=windows`): missing resources, GUI subsystem, debug

### Takeaway
Cross-compile is the supported loader path (`CGO_ENABLED=0`, `GOTOOLCHAIN=local`). It produces a real PE. Missing VERSIONINFO/icon is not a typical “no session” cause. GUI subsystem **is** a visibility issue (no console). Implant `debug` is a **generate** flag, not a loader flag; it does not add a console to the wrapper. `windowsgui` plus a returning PIC looks identical to a crash.

### Cited Findings
- `buildEnv`: `GOOS`, `GOARCH`, `CGO_ENABLED=0`, `GO111MODULE=on`, `GOTOOLCHAIN=local`. Timeout 3 minutes. — [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go)
- Tests compile windows/amd64, 386, arm64 loaders from whatever host OS the test runs on and assert MZ. — [loader_test.go TestBuildLinuxAndWindows / TestBuildWindowsOtherArch](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go)
- Unique hash: nonce mixed into XOR key, 4–24 KiB `n.bin` padding, name-encoding key, `-buildid`. Not a sandbox bypass. — [build.go mintUniqueness](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go); [LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md)
- Implant debug (`-d`) is on `GenerateRequest.Debug` / Implants checkbox; loader stub has no debug log. GUI loader cannot print errors. — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx); [windows.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- Go GUI binaries do not show panics on a console. — [SO windowsgui](https://stackoverflow.com/questions/23743217/printing-output-to-a-command-window-when-golang-application-is-compiled-with-ld)

### Inferences
- Cross-compiled PE from Linux is expected to **run** on Windows of matching arch. Failure to start at all is more often SmartScreen/Defender/arch than “Linux-built PE is invalid.”
- To see stub errors, rebuild with **hide console off** (console subsystem) for lab diagnosis only.
- Spoof-metadata on Implants clones VERSIONINFO onto the **implant PE**, not this host-compiled loader.

### Gaps
- SmartScreen / MOTW (“downloaded from internet”) blocking first run was not measured; that presents as a dialog, not a silent no-session, unless the user clicks Don’t run.

---

## Defender: process starts then dies in <1s with Event 1116/1117 — looks like “no session”

### Takeaway
Yes. Defender can kill the loader (or the decrypted PIC in RWX) so fast there is no callback and, with `windowsgui`, no window. Distinguish it with Protection History + Operational log 1116 (detect) / 1117 (action). Absence of 1116 means look at format/C2/lifetime classes first.

### Cited Findings
- Stub behavior Defender/EDR hunts: `VirtualAlloc` → write → `VirtualProtect` RWX → execute unbacked memory; no `CreateThread` (slightly less textbook) but still unbacked RX. Plan/docs already call this not an AV bypass. — [windows.go run](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md); [Elastic ETW call stacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- Event **1116** `MALWAREPROTECTION_STATE_MALWARE_DETECTED`: threat detected. Event **1117** `MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN`: quarantine/remove/block/allow. Channel `Microsoft-Windows-Windows Defender/Operational`. — [Microsoft Learn: Defender event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- Protection History in Windows Security retains events ~two weeks; needs admin to see threat details. — [Microsoft Support: Protection History](https://support.microsoft.com/en-us/windows/protection-history-f1e5fd95-09b4-46d1-b8c7-1059a1e09708)
- Query used in public runbooks: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,1118,1119}`. — [laptopjudge Protection History](https://laptopjudge.com/windows-11-protection-history-open-log/)
- 1118 = action failed; 1119 = critical action error. 1116 without successful 1117 can mean the process still ran (or was blocked by another control). — [EventPeeker 1117](https://www.eventpeeker.com/event-id/1117)
- Stock Sliver on-disk is YARA’d (`sliverpb`, BishopFox paths). This loader XOR-embeds the implant (`cfg.dat`) so **inner** strings are not plaintext, but the **stub** is still an unsigned unique Go PE doing RWX. — [SLIVER_UI_AV_OPSEC_RESEARCH.md](file:///home/cup/Documents/personal/sliv/docs/SLIVER_UI_AV_OPSEC_RESEARCH.md); [build.go xor embed](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go)

### Inferences
- **Defender-shaped lab signature:** process appears in Task Manager (or 4688) then vanishes in <1s; 1116+1117 at the same second; file quarantined (gone from disk); **no** outbound C2 in Wireshark (or a single failed connect if kill was slightly late).
- **Not Defender:** no 1116, process lives for minutes, still no Sessions/Beacons → C2/beacon/limits/format.
- **Not Defender:** no 1116, process dies at ~2.0s exactly → pause completed, PIC returned (empty-export RDI) or `os.Exit` after limits.
- **Not Defender:** process dies at t≈0 with no 1116 → `enoughRAM` fail, or never started (SmartScreen, wrong arch: “This app can’t run on your PC”).
- Cloud-delivered protection can delay 1116 a few seconds; still check the log before assuming “format bug.”

### Gaps
- No current VT/Defender signature name for *this* stub is claimed; hashes change every compile. Do not treat a past “Win32/…” name as stable.
- ASR rules (e.g. untrusted unsigned, Office child, WMI) can kill without a classic 1116 in some configurations; if Protection History is empty, check `Microsoft-Windows-Windows Defender/Operational` for 1121/1122 (ASR) as well. ASR IDs were not fully re-audited in this pass.

---

## Architecture / OS mismatch

### Takeaway
Loader `GOARCH` must match PIC arch and the Windows host. UI copies os/arch from the selected build but the dropdowns remain editable. Running an amd64 loader on 32-bit Windows, or wrapping linux malasada as windows, crashes or “can’t run.” That looks like no session.

### Cited Findings
- `NormalizeArch` maps x64→amd64, x86→386, aarch64→arm64. Unsupported arch rejected at `Normalize`. — [options.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/options.go)
- `applyBuildMeta` sets wrap os/arch from the implant build. User can still change the selects before Build EXE. — [LoadersPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx)
- Windows shellcode generate supports **amd64 and 386 only** (not arm64). Shared/EXE can be arm64. Wrapping Windows arm64 **shellcode** is already invalid at implant generate. — [binaries.go windowsShellcode](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/binaries.go)
- sRDI `is64BitDLL` uses COFF Machine (`0x8664` / IA64) only, not DLL characteristic — a 64-bit **EXE** still takes the x64 bootstrap. — [srdi.go is64BitDLL](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/srdi.go)
- Lab build `OneDriveUpdateee` is linux/amd64 SHELLCODE. Loaders would default `os=linux` for that row (ELF output), unless overridden to windows. — [current_product_inventory.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20UI%20imkoniyatlar%20tahlili/current_product_inventory.md)

### Inferences
- amd64 PIC in a 386 loader (or the reverse) = crash at `CALL`.
- Windows 11 on ARM can run amd64 PE via emulation; 386 via WOW64 on amd64. arm64 PIC on x64 Windows will not run.
- Always read the payload bar: `windows/amd64 → name_loader.exe` must match the VM.

### Gaps
- ARM64 Windows + amd64 loader was not tested.

---

## How to distinguish these using Task Manager, Defender Protection History, Sliver jobs/listeners, Wireshark, Event Viewer

### Takeaway
Walk the tree below on the **Windows target** and the **teamserver UI** at the same clock time. One observation (process live? 1116? C2 packets? which page?) separates the six classes without guessing.

### Cited Findings
- Windows stub `main` sequence and silent exits: RAM, pause, persist (ignored errors), run/jump. — [windows.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go)
- Sessions vs Beacons pages; C2 job match; listeners list. — [current_product_inventory.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20UI%20imkoniyatlar%20tahlili/current_product_inventory.md); [c2.ts](file:///home/cup/Documents/personal/sliv/frontend/src/lib/c2.ts)
- Defender 1116/1117 Operational log. — [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- Implant C2 baked at generate; loader does not change it. — [implants.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants.go); [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go)

### Inferences — diagnostic decision tree (operator)

**0. Before run (UI, 30 seconds)**
1. Open the implant row used as wrap input. Note **OS / Arch / Format / C2 URL / IsBeacon / limits**.
2. Format should be `SHELLCODE` for Windows wrap. If `SHARED`, you must have RDI’d with export `StartW` (Tools tab) **before** wrap, or expect a 2s exit. If `EXECUTABLE`, do not wrap — generate shellcode instead.
3. Listeners/Jobs: a job whose **name/protocol and port** match the C2 URL (`C2JobStatus` live). `https://host:443` ≠ `mtls :8888`.
4. C2 host must be reachable **from the Windows box** (not `127.0.0.1` unless teamserver is that same Windows OS).
5. If Beacon is checked, watch **Beacons**, wait ≥ interval×(1+jitter). Default ≥ ~60s.

**1. Run the loader on Windows (hide-console on is OK; for debug, rebuild with hide-console off)**
6. Start a clock. Watch Task Manager (Details: the loader name).
7. Optional: Wireshark/pktmon filter `host <c2-host> and port <c2-port>`.
8. Event Viewer: `Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational` (or Protection History).

**2. Branch on process lifetime**

```
t = 0 .. 3s, process gone, file disappeared, 1116+1117
  → (5) Defender (or SmartScreen if a dialog was clicked away)
  → Confirm quarantine; this is not a trampoline ABI mystery.

t = 0 .. 0.5s, process gone, NO 1116, file still on disk
  → enoughRAM (<1 GiB VM) OR “this app can’t run” (arch) OR never started
  → Check Settings → System → About RAM; file Properties → CPU arch.
  → Retest with SLIV_BG=1 (skips RAM+sleep) to isolate.

t ≈ 2.0s, process gone, NO 1116, file still on disk
  → pause() completed; PIC returned or run() alloc failed
  → Most likely (1) empty-export RDI of SHARED, or EXE-via-RDI
  → Confirm: wrap input was MZ DLL/EXE. Fix: format=shellcode, or RDI function_name=StartW
  → Less likely: emulator check fired (ticks <1400). Unlikely on real Windows.

t > 5s, process STILL ALIVE, no 1116
  → Stub did not return. Implant loop or hang inside PIC.
  → Look at Wireshark:
       no packets → limits.ExecLimits os.Exit may still be pending? (usually exits)
                    or implant not actually started (hang in Donut/Go runtime)
                    or wrong host (packets to 127.0.0.1 on the guest)
       packets to correct host:port, no UI callback
         → listener protocol/profile/cert/HTTP C2 mismatch
         → or beacon: wait, open /beacons
         → or IsBeacon false but operator looking at wrong server profile
       TLS to 443 while job is mtls 8888 → (2) C2 class (OneDriveUpdateee-class)

t > 5s, process alive, Wireshark OK, still nothing
  → (4) Beacon page / interval
  → Events page on UI (session/beacon connected events)
```

**3. Confirm C2 class (independent of process)**
9. On Implants, the build’s C2 column vs Jobs. Reproduce the documented mismatch: generate `https://X:443` vs only `mtls :8888` (or linux shellcode vs Windows host).
10. `curl`/`Test-NetConnection` from the **Windows** host to C2 host:port.

**4. Confirm format class**
11. If the wrap source SHA-256 blob starts with `MZ`, backend RDI’d it. If you did not type `StartW`, assume empty-export failure until proven otherwise.
12. If blob starts `4D 5A` and format was SHELLCODE, something is wrong (you loaded an EXE). If blob starts `48 83 E4 F0`, that is Donut stack-check — correct Windows shellcode.

**5. Wine**
13. If the “Windows” test was Wine on Linux: invalid as a session test. Repeat on a Windows VM.

**6. Hide-console confusion**
14. No window is **normal**. Use Task Manager, not “did a console stay up.”
15. Linux hide-console parent-exit does not apply.

### Suggested lab retest matrix (authorized)

| # | Change one variable | Expect |
|---|---|---|
| A | Generate windows/amd64 **shellcode** + C2 = live https listener host (not 127.0.0.1) + is_beacon **off** + wrap + run | Session on `/sessions` if Defender allows; process stays |
| B | Same but is_beacon **on** | Row on `/beacons` after interval, not Sessions |
| C | Wrap **shared** with no Tools RDI export | Process dies ~2s; no callback |
| D | Tools RDI `function_name=StartW` then wrap shared | Process stays (if Defender allows) |
| E | C2 https:443, only mtls:8888 listening | Process may stay; no session; Wireshark to 443 |
| F | C2 127.0.0.1 from a guest VM | Packets to guest loopback; no teamserver session |
| G | VM RAM 512 MB | Instant exit; no 1116 |
| H | Real Defender, default policy | 1116/1117; process <1s; file quarantined |
| I | Hide-console off (console subsystem) | Same lifetime; can see if Go panics |

### Gaps
- Tree is inferred from source + public Defender IDs; it was not executed end-to-end on a Windows 11 lab during this research pass.
- `Microsoft-Windows-Windows Defender/Operational` ASR event IDs (1121/1122) should be added if a lab shows kills without 1116.

---

## Cross-cutting product facts (for the report writer)

### Takeaway
The Windows loader is a host-compiled Go PIC runner with XOR-at-rest, RWX `CALL`, 1.8s emulator gate, 1 GiB RAM gate, and optional persistence. It will not fix a wrong implant format, wrong C2, or a beacon watched on the Sessions page. The highest-likelihood **non-Defender** “sessiya ochilmayapti” bugs in *this* tree are: (a) auto-RDI of `shared` with empty export, (b) C2 `127.0.0.1` / protocol mismatch, (c) GUI-subsystem + 2s sleep looking like a no-op, (d) watching Sessions for a beacon.

### Cited Findings
- Wrap API and Windows stub as cited in sections above. — [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go); [windows.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [source.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/source.go)
- Sliver Windows shellcode = Donut(PIE EXE); shared = DLL with `StartW`; RDI = sRDI. — [binaries.go](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/binaries.go); [srdi.go](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/srdi.go); [main.c](https://github.com/BishopFox/sliver/blob/v1.7.3/implant/sliver/main.c)

### Inferences
- Product fix candidates (out of scope to implement here): pass `function_name=StartW` on auto-RDI; refuse `NeedsRDI` unless `IMAGE_FILE_DLL` or format=shared; warn when wrapping MZ EXE; default generate C2 host away from `127.0.0.1` when a remote listener exists; Windows-specific hide-console copy (process stays vs Linux parent exit).

### Gaps
- No Windows detonation log attached to this note; follow the retest matrix on the operator’s VM to confirm which bucket hit.
