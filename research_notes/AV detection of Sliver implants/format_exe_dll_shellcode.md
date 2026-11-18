# AV detection of Sliver implants by generate format (EXE vs SHARED vs shellcode vs Linux ELF)

Authorized detection-engineering notes, 2022–2026 public sources. Not a FUD claim that any format is “undetected.” After Donut/sRDI/malasada unpack, Windows EXE, SHARED, and shellcode carry the **same Go implant image** (runtime + protobuf); format only changes the **wrapper** scanners see at rest and the **memory type / call stack** they see at first execution.

---

## What scanners see at rest vs at run, per format

### Takeaway
On disk, `exe` and `shared` are PE/ELF with MZ/`0x7fELF`, a real IAT, and Go buildinfo; `shellcode` is raw PIC (Donut on Windows, malasada on Linux) with **no** MZ unless a loader wraps it. At run, EXE/DLL loaded by the OS are `MEM_IMAGE` (file-backed); Donut PIC executed from `VirtualAlloc`/`mmap` is unbacked/`MEM_PRIVATE` until Donut’s own PE mapper runs. Elastic and Fortbridge treat the **shellcode/unbacked** path as the noisier Windows behavioral surface; Defender static YARA also keys SHARED export names that EXE does not need.

### Cited Findings
- Microsoft (Aug 2022) lists default Sliver payload formats as **shellcode, executable, shared library/DLL, and service**, plus smaller stagers; operators can skip default EXE/DLL and embed shellcode in a custom loader (Bumblebee cited) — [Looking for the ‘Sliver’ lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Current Sliver matrix: Windows `{386,amd64}` first-class for EXE/SHARED/shellcode/service; Linux `{amd64,arm64}` EXE/SHARED/shellcode (linux/386 shellcode unsupported); service is Windows-only — [Payload Compatibility](https://sliver.sh/docs?name=Payload+Compatibility).
- Windows `generate --format shellcode` compiles a **PIE EXE** then converts it with Donut (`DonutShellcodeFromFile`); PIE is required for Donut relocations. Older `SliverShellcode` even returned an error for non-Windows — [binaries.go `SliverShellcode`](https://github.com/BishopFox/sliver/blob/master/server/generate/binaries.go); [先知 community source walkthrough](https://xz.aliyun.com/t/15460).
- BallisKit (Sep 2025): “Instead of EXE we could have generated a sliver Raw Shellcode but **that raw shellcode is a wrapper over a PE anyway**.” They recommend loading the C2-generated **DLL or EXE** with a third-party packer rather than Sliver’s own Donut wrapper — [Tutorial: Sliver C2 with BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).
- `generate --format shared` is CGO `c-shared`: Windows `.dll`, Linux `.so`, Darwin `.dylib`. Windows `DllMain` only starts the implant on `DLL_PROCESS_ATTACH` if `RunAtLoad` is set, via `CreateThread` → first export (default `StartW`). Linux uses `.init_array`; Darwin uses a constructor. Exports are generated from `--exports` — [implant/sliver/main.c](https://raw.githubusercontent.com/BishopFox/sliver/master/implant/sliver/main.c); [implant/sliver/main.go](https://github.com/BishopFox/sliver/blob/master/implant/sliver/main.go).
- Stock CLI default exports: `StartW,VoidFunc,DllInstall,DllRegisterServer,DllUnregisterServer`. `StartW` is the rundll32-style entry; `VoidFunc` is for PowerSploit `Invoke-ReflectivePEInjection`; COM names are for `regsvr32` — [BishopFox/sliver#1782](https://github.com/BishopFox/sliver/issues/1782) (`StartW` replaced `RunSliver`); historical `//export` comments in [sliver.go v1.2.1](https://github.com/bishopfox/sliver/blob/v1.2.1/sliver/sliver.go).
- Fortbridge extracted Defender-oriented YARA strings from a SHARED implant: `DllUnregisterServer`, `DllRegisterServer`, `DllInstall`, `VoidFunc`, plus protobuf/Go strings `GetJitter`, `GetKill`, `AddTunnel`, `GetIsIOC`, ` Go buildinf:` — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Elastic `Multi_Trojan_Sliver` is `scan_context = "file, memory"` and `os = "multi"`: protobuf method names (`ScreenshotReq`, `HTTPSessionInit`, `InvokeSpawnDllReq`, `RequestResend`, …) and `github.com/bishopfox/sliver/protobuf/sliverpb`, plus bytecode of the session-start / register loop (`Multi_Trojan_Sliver_3d6b7cd3`) — [Multi_Trojan_Sliver.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar).
- Immersive Labs **file** YARA requires a PE/ELF/Mach-O magic **and** `sliverpb` + `github.com/bishopfox/` + `chacha20poly1305`. Their **memory** rule is `sliverpb` alone, because the file rule’s magic/offsets miss unpacked images — [sliver.yar](https://raw.githubusercontent.com/Immersive-Labs-Sec/SliverC2-Forensics/main/Rules/sliver.yar); [threat hunter’s guide](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- Typical size: Immersive ~**16 MB** Go implant; Fortbridge “up to **30 MB**”; Joe Sandbox Linux sample **31,850,644 bytes** — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [Joe Sandbox ELF](https://www.joesandbox.com/analysis/1848290/0/pdf?download=1).
- Dominic Breuker (Feb 2023) on `sideload`: Sysmon events **10** (process access) and **8** (CreateRemoteThread) from Sliver’s classic injection; “with regards to the activity of Donut itself I did not spot any tell-tale events” in that Sysmon set — [Learning Sliver C2 (10) – Sideload](https://dominicbreuker.com/post/learning_sliver_c2_10_sideload/).

### Inferences
- **At rest:** EXE = MZ + PE IAT + Go sections; SHARED = same plus export directory names that several Defender/YARA families treat as Sliver-specific; shellcode = Donut/malasada blob (no PE magic, so Immersive `sliver_binary_native` and PE-ML that require MZ miss it until a loader wraps it).
- **At run (OS loader):** EXE entry is the Go runtime; SHARED is `DllMain` (optional thread) then `StartW`/`rundll32`. Both are image-backed if loaded from disk.
- **At run (PIC):** a host `VirtualAlloc`/`mmap` + CALL/CreateThread of Donut/malasada PIC is unbacked executable memory **before** the inner PE is mapped. That is a different detector class than “unsigned Go PE on disk.”
- SHARED is **not** inherently quieter than EXE on disk: Fortbridge’s Defender hits on COM/PowerSploit export names are SHARED-specific. EXE still has `sliverpb` / `Go buildinf` / protobuf methods.

### Gaps
- No public 2022–2026 side-by-side MDAV/Elastic **detection-rate table** for otherwise-identical Sliver builds as EXE vs DLL vs Donut `.bin` under the same cloud protection level.
- `sliver.sh/docs?name=Generate` did not render usable content in this pass (JS app shell). Format flags were taken from Payload Compatibility, Stagers, `commands.go`, and `binaries.go`.

---

## Stock `generate --format exe` vs `--format shared` vs `--format shellcode`: what Donut adds

### Takeaway
EXE and SHARED are native Go images. Windows shellcode is **those bytes plus a Donut loader stub**: hashed API resolve, optional AMSI/WLDP/ETW patches (`VirtualProtect` on `amsi.dll` exports), PE map (`NtCreateSection`/`NtMapViewOfSection`), IAT fill, header wipe, then CALL of the Go entry. Stock Sliver defaulted Donut **Bypass=3 (continue on fail)** until generate flags existed (closed Feb 2026). SGN, when applied, is a **self-modifying decoder that requires RWX**.

### Cited Findings
- Current `server/generate/donut.go` defaults: `DonutEntropyNone`, `DonutCompressNone`, `DonutExitThread`, **`DonutBypassContinue`**, `DonutHeadersOverwrite`. `DonutShellcodeFromPE` passes those into wasm-donut; result is prefixed with an 8-byte stack-align prologue (`and rsp,0xfffffffffffffff0` / `add rsp,0x8`) because “Check stack is 8 byte but not 16 byte aligned or else errors in LoadLibrary” — [donut.go (master)](https://raw.githubusercontent.com/BishopFox/sliver/master/server/generate/donut.go).
- Issue #1759 (Aug 2024): `generate --format shellcode` produced Elastic detections for **AMSI and WLDP patching** even with `--evasion` off. Maintainer: “`--evasion` has no impact… most of the Donut loader options are hardcoded: `Bypass: 3`.” Workaround: run upstream Donut with `-b1`. moloch (Feb 2026): generate flags now control this — [BishopFox/sliver#1759](https://github.com/BishopFox/sliver/issues/1759).
- Stagers docs (current): `--shellcode-bypass` 1=none, 2=abort on fail, 3=continue (Windows only); also `--shellcode-entropy`, `--shellcode-headers` 1=overwrite / 2=keep, `--shellcode-exitopt`, `--shellcode-thread`, `--shellcode-compress` — [Stagers](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Stagers.md).
- Upstream Donut `-b`: 1=None, 2=Abort on fail, 3=Continue on fail **(default)**. Features: AMSI/WLDP patch, ETW patch, PE header overwrite, **storing native PEs in MEM_IMAGE**, exit-API patch, optional module overloading decoy — [TheWover/donut README](https://github.com/TheWover/donut).
- Donut `DisableAMSI`: resolve `amsi.dll` / `AmsiScanBuffer` / `AmsiScanString`, `VirtualProtect(..., PAGE_EXECUTE_READWRITE)`, memcpy stub, restore protection (same for WLDP/ETW when bypass ≠ none) — [DeepWiki Donut bypass](https://deepwiki.com/thewover/donut); original AMSI-in-CLR writeup — [Introducing Donut (TheWover)](https://thewover.github.io/Introducing-Donut/).
- Donut unmanaged PE path **without decoy**: `NtCreateSection(..., SEC_COMMIT, PAGE_EXECUTE_READWRITE)` then `NtMapViewOfSection` RW, copy sections, relocate, **resolve IAT** via `LoadLibrary`/`GetProcAddress` equivalents, wipe or restore headers, remap, `VirtualProtect` per section, TLS, then `DllMain(cs, DLL_PROCESS_ATTACH)` or EXE entry/`CreateThread` — [DeepWiki RunPE](https://deepwiki.com/thewover/donut); [loader/inmem_pe.c](https://github.com/TheWover/donut/blob/master/loader/inmem_pe.c).
- Donut **with decoy** (`-j`): `NtCreateSection(..., SEC_IMAGE)` against a file, producing **MEM_IMAGE**; headers copied from the decoy. Without decoy the view is pagefile-backed `SEC_COMMIT` — [DeepWiki section paths](https://deepwiki.com/thewover/donut).
- Fortbridge: “Sliver leverages Donut to generate shellcode as a `.bin` file, which it allocates in **Read/Write/Execute** memory. By default, Sliver enables Donut’s AMSI bypass, which has **heavy signature detection**.” They patched `donut.go` Bypass 3→1 — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Defender family **`Behavior:Win32/AMSI_PATCH_T.B13`** / **`.B12`** reported against Sliver Donut shellcode even when operators believed bypass was off: #1814 (Nov 2024) “no option to disable AMSI patch”; #2200 (Mar 2026) `execute-shellcode` of Donut PIC with `-b 1` still flagged `.B12` (moloch: upstream Donut; C# Donut vs C++ Donut differed) — [BishopFox/sliver#1814](https://github.com/BishopFox/sliver/issues/1814); [BishopFox/sliver#2200](https://github.com/BishopFox/sliver/issues/2200).
- Elastic **AMSI Bypass via Unbacked Memory**: `VirtualProtect`/`WriteProcessMemory` targeting `amsi.dll` from a call stack whose final user module is `Unbacked`; action `kill_process`. References Odzhan’s AMSI/WLDP post (the same research Donut cites) — [defense_evasion_amsi_bypass_via_unbacked_memory.toml](https://github.com/elastic/protections-artifacts/raw/refs/heads/main/behavior/rules/windows/defense_evasion_amsi_bypass_via_unbacked_memory.toml).
- moloch (Sep 2023): “By default Sliver also uses the **SGN encoder which requires RWX**” — [BishopFox/sliver#1410](https://github.com/BishopFox/sliver/issues/1410).
- Jan 2026 issue: `generate beacon -f shellcode` still printed “Encoding shellcode with shikata ga nai”; `-G` (`--disable-sgn`) skipped it. SGN failure could write a 0-byte file — [BishopFox/sliver#2099](https://github.com/BishopFox/sliver/issues/2099).
- `execute-shellcode` client: `--shikata-ga-nai` **refuses unless `--rwx-pages`**; Task RPC field `RWXPages` — [execute-shellcode.go](https://github.com/BishopFox/sliver/blob/master/client/command/exec/execute-shellcode.go).
- PEzor documents the same constraint in loader terms: default alloc is **RWX**; `-rx` is RW then `PAGE_EXECUTE_READ`; **`-self` requires RX and is not compatible with `-sgn`** because the decoder writes itself — [phra/PEzor README](https://github.com/phra/PEzor); [inject.cpp RX vs RWX](https://github.com/phra/PEzor/blob/master/inject.cpp).
- Stock EXE/SHARED do **not** include the Donut stub. They still import the Go Windows stack (`syscall.NewLazyDLL` → `LoadLibraryExW`) once the process is running — Fortbridge’s next detection after disabling AMSI bypass — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).

### Inferences
- Extra **on-disk** bytes in `--format shellcode` vs EXE: Donut PIC (API-hash bootstrap + encrypted/compressed module + optional SGN decoder) + Sliver’s 8-byte RSP prologue. Extra **runtime APIs** vs a disk EXE: `VirtualAlloc`/`NtCreateSection`/`NtMapViewOfSection`/`VirtualProtect`, hashed `LoadLibrary`/`GetProcAddress`, optional **AMSI/WLDP/ETW patches**, IAT rewrite, header zeroing, then the same Go `main`.
- EXE/SHARED at rest already have a real IAT; Donut PIC at rest has **no IAT** until the stub writes one. Scanners that score “tiny IAT + high entropy + no MZ” see shellcode; scanners that score “Go PE + protobuf strings” see EXE/DLL.
- SGN and Donut-without-decoy both push **RWX self-modify** (SGN decoder; Donut `SEC_COMMIT` + `PAGE_EXECUTE_READWRITE` and/or AMSI `VirtualProtect`). That is independent of Sliver `--evasion` (userland unhook).
- Default Bypass=Continue means a **failed** AMSI patch still continues — the patch **attempt** is still visible to Elastic `AMSI Bypass via Unbacked Memory` and Defender `AMSI_PATCH_T.*`.

### Gaps
- wasm-donut vs upstream Donut v1.1 byte-for-byte stub is not published as a Sliver diff; treat AMSI/ETW behavior as “Donut-class,” not a pinned opcode listing.
- Whether current master still auto-applies SGN on `generate -f shellcode` vs only `--shellcode-encoder shikata_ga_nai` is version-dependent (#2099 vs Stagers “optional encoder”). Operators must check the console line “Encoding shellcode with shikata ga nai.”

---

## sRDI / reflective DLL and the Microsoft 2017 detector

### Takeaway
Microsoft’s 2017 ATP model did **not** signature Stephen Fewer’s reflective loader blob. It scored **abnormal executable `VirtualAlloc`/`VirtualProtect`** in high-risk processes, including large RWX regions with PE-like content and no backing module. That class of detector is still live in 2025–2026 as Elastic “Unbacked” call stacks and MDE injection alerts. Sliver **implant** Windows shellcode is Donut, not sRDI; **sideload** docs still say sRDI while 2023 source analysis says Donut — treat sRDI as the generic reflective-DLL detector surface, not as Sliver’s generate-shellcode encoder.

### Cited Findings
- Microsoft (13 Nov 2017): reflective DLL loading maps a DLL without the Windows loader / `LoadLibrary`, so the image need not touch disk and may be invisible in the module list. **Primary signal:** procuring executable memory (`VirtualAlloc` / `VirtualProtect`). Creators Update instrumented those APIs for Defender ATP. Model: baseline a process’s normal executable allocations, then flag deviations (size, history, thread, flags) plus network. Example: Word macro → C2 → reflectively loaded DLL; memory forensics showed **several larger RWX sections without a corresponding DLL** — [Detecting reflective DLL loading with Windows Defender ATP](https://www.microsoft.com/en-us/security/blog/2017/11/13/detecting-reflective-dll-loading-with-windows-defender-atp/).
- sRDI (monoxgas): converts a DLL to PIC by prepending a reflective PE loader; supports section permissions, TLS, `DllMain` then optional export; flags include `SRDI_CLEARHEADER` / `SRDI_CLEARMEMORY`. Derived from Staples/Fewer reflective DLL injection — [monoxgas/sRDI](https://github.com/monoxgas/sRDI).
- Historical Sliver `SliverShellcode` comment: “Generates a sliver shellcode **using sRDI**” then the implementation called `DonutShellcodeFromFile` (sRDI call commented out) — [binaries.go @ ea6a17c](https://github.com/BishopFox/sliver/blob/ea6a17c3e6c51da2c89f23cc8465424e2c0f57d2/server/generate/binaries.go).
- Current **Third Party Tools** docs still say: on Windows, `sideload` converts the DLL to shellcode **via sRDI** and injects into a sacrificial process — [Third Party Tools](https://sliver.sh/docs/?name=Third%20Party%20Tools). Dominic Breuker (Feb 2023) traced the same command to **`DonutShellcodeFromPE` / go-donut** — [Learning Sliver C2 (10)](https://dominicbreuker.com/post/learning_sliver_c2_10_sideload/).
- `spawndll` expects a Fewer-style **`ReflectiveLoader` export**, then `DllMain(DLL_PROCESS_ATTACH)` — [Learning Sliver C2 (11) – SpawnDLL](https://dominicbreuker.com/post/learning_sliver_c2_11_spawndll/).
- Microsoft 2022 on Sliver post-ex: `migrate` / `sideload` / `spawndll` / `execute-assembly` use `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`; MDE alert example **“A process was injected with potentially malicious code”** — [Looking for the ‘Sliver’ lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Elastic 2025–2026: **Network Module Loaded from Suspicious Unbacked Memory** (`ws2_32`/`wininet`/`winhttp` with `call_stack_contains_unbacked`); **Network Connect API from Unbacked Memory**; **AMSI Bypass via Unbacked Memory**; **Rundll32 or Regsvr32 Loaded a DLL from Unbacked Memory**; **Parallel NTDLL Loaded from Unbacked Memory**. Almond (Nov 2025) cites the network-module rule as Elastic’s catch for “shellcode loading a network module” — [network_module_loaded_from_suspicious_unbacked_memory.toml](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_network_module_loaded_from_suspicious_unbacked_memory.toml); [Almond: evading Elastic call stack signatures](https://offsec.almond.consulting/evading-elastic-callstack-signatures.html).
- ATT&CK DET0300 (2026): Windows analytic looks for in-process alloc → copy → protect-to-exec → thread, **no** matching file; mutable element `MemoryRegionPermissions` (RWX) — [DET0300](https://attack.mitre.org/detectionstrategies/DET0300).
- Hasherezade (2024–2026): manually mapped PEs land in **MEM_PRIVATE**; a legitimate loader mapping is **MEM_IMAGE**. Win11 24H2 hotpatch path calls `ZwQueryVirtualMemory(MemoryImageExtensionInformation)` which **fails on MEM_PRIVATE** (`STATUS_INVALID_ADDRESS`) — [hasherezade, 1001 nights](http://hasherezade.github.io/).
- Brute Ratel (2021): Fewer’s reflective loader still `VirtualAlloc(RWX)` even if the outer region was RX; EDRs that scan for RWX after `VirtualAlloc` flag injected DLLs — [PE Reflection: The King is Dead](https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/).

### Inferences
- The 2017 blog is still the **conceptual** detector for in-memory DLL maps: executable memory that is not a loaded module. Elastic “Unbacked” and MDE injection alerts are the 2022–2026 operational forms, not a YARA on the sRDI bootstrap blob.
- Generating `--format shared` and `LoadLibrary`’ing it **does not** hit the 2017 reflective-DLL model (Windows loader, `MEM_IMAGE`, module list populated). Generating `--format shellcode` and `VirtualAlloc`+CALL **does**, whether the inner mapper is Donut or sRDI.
- Docs vs code: do not assume `sideload` is sRDI on a given Sliver tag; confirm `DonutShellcodeFromPE` vs `ShellcodeRDI` in that tree. Implant `generate -f shellcode` on current master is Donut.

### Gaps
- No public Microsoft writeup after 2017 that says “we still detect sRDI by name.” Continuity is inferred from ETW-Ti alloc/protect instrumentation and Elastic unbacked-memory rules, not from a new MS blog titled “sRDI.”
- Whether Defender ATP’s 2017 **process-specific allocation ML** (Winword 0x4000 page-aligned RX) still ships in MDE 2025–2026 is not documented.

---

## Why Fortbridge’s working path was disk `LoadLibrary` of a DLL (`MEM_IMAGE`)

### Takeaway
Fortbridge’s Donut/self-inject path died on Elastic **“Network Library Loaded from Unbacked Memory”** after Go `LazyDLL`/`LoadLibraryExW` ran from private executable memory. Module stomping a 16–30 MB implant had no realistic sacrificial `.text`. Writing a **SHARED** implant to disk and `LoadLibrary`/`GetProcAddress(StartW)` put the same Go code in **file-backed MEM_IMAGE**, so the network-DLL call stack was no longer `Unbacked`. That is a **memory-type** change, not evidence that DLLs are FUD: they still had to strip Defender YARA strings (`VoidFunc`, COM exports, protobuf names, `Go buildinf`) before disk drop survived.

### Cited Findings
- Fortbridge sequence: (1) rename protobuf / init-loop to beat Elastic YARA including `Multi_Trojan_Sliver_3d6b7cd3`; (2) packers/self-inject/hollowing of stock Sliver “proved ineffective” vs Elastic+Defender; (3) Donut `.bin` in RWX + default AMSI bypass = “heavy signature detection”; Bypass 3→1; (4) HTTP beacon still loaded `ws2_32`/`wininet` via Go `NewLazyDLL` → `LoadLibraryExW` from the PIC; Elastic: **Network Library Loaded from Unbacked Memory**; (5) “The normal solution … load a sacrificial library and overwrite its text section … **due to the size of sliver binaries I couldn’t find any candidates to attempt module stomping**”; preloading DLLs and HW-BP `GetModuleHandle` hooks did not clear the alert; (6) “writing an implant **dynamic library to disk** was the simplest solution”; (7) disk still hit Defender YARA on export/protobuf/`Go buildinf` strings; after string edits, a loader that `LoadLibrary`s the DLL, resolves the export, and `CreateThread`s it got a callback on a host with Elastic agent; LitterBox clean — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Elastic rule that matches Fortbridge’s quoted name (public artifact title is **Network Module Loaded from Suspicious Unbacked Memory**): library load of `ws2_32.dll` / `wininet.dll` / `winhttp.dll` where `process.thread.Ext.call_stack_contains_unbacked == true` and the call-stack summary is one of a short list ending in `Unbacked` (e.g. `ntdll.dll|kernelbase.dll|Unbacked`). `kill_process` — [toml](https://raw.githubusercontent.com/elastic/protections-artifacts/main/behavior/rules/windows/defense_evasion_network_module_loaded_from_suspicious_unbacked_memory.toml).
- Almond (Nov 2025): that rule is “a step most C2 implants will have to take”; “typical behaviour of shellcode”; they evade by inserting extra **image-backed** frames, not by shrinking the implant — [Evading Elastic EDR’s call stack signatures](https://offsec.almond.consulting/evading-elastic-callstack-signatures.html).
- Windows loader maps a DLL as **MEM_IMAGE** (file-backed section). Donut without decoy uses **SEC_COMMIT** (not `SEC_IMAGE`) — [Donut README / DeepWiki](https://github.com/TheWover/donut); Hasherezade contrast MEM_PRIVATE vs MEM_IMAGE — [1001 nights](http://hasherezade.github.io/).
- Fortbridge implant `DllMain`/`StartW` notes: they **removed** unused exports and **renamed** `StartW` because those names were in Defender YARA; the final loader still used an export + new thread — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Cybersecuritynews (Apr 2025) paraphrase of the same paper: customized implants “evaded detection both on disk and in memory” against Elastic and Defender **in that test** — aggregator, not independent lab — [cybersecuritynews.com](https://cybersecuritynews.com/sliver-framework-customized/).

### Inferences
- The Fortbridge win is **call-stack provenance**: `LoadLibrary` of a disk DLL means `LoadLibraryExW` of `winhttp.dll` later has `sliver.dll` (image) on the stack, not `Unbacked`. VirtualAlloc+CALL of Donut PIC keeps the implant in private executable memory for its lifetime (or until Donut maps a still-unbacked PE).
- That does **not** mean SHARED is quieter than EXE: an EXE started with `CreateProcess` is also `MEM_IMAGE`. Fortbridge chose DLL because their **packer** story was “load a library from the same folder,” not because EXE is inherently hotter.
- Disk SHARED still faces **static** Defender/Elastic YARA (exports + protobuf + buildinfo). Fortbridge had to change the compiler output; format alone was insufficient.

### Gaps
- Fortbridge does not publish the Elastic agent version, the exact rule ID, or whether Smart App Control / ASR were on. Replication on 2026 Elastic artifacts may differ (rule version on the network-module toml is `1.0.59`).
- They do not show a failed EXE-on-disk vs successful DLL-on-disk A/B with identical strings. The documented contrast is **unbacked PIC vs image-backed DLL**, not EXE vs DLL.

---

## Module stomping of a ~16–30 MB Go implant: reported failures

### Takeaway
Public Sliver writeups that tried stomping **failed on size**: a full Go implant does not fit in typical sacrificial `.text` (e.g. `amsi.dll` / `dbghelp.dll`). No 2022–2026 source reports a successful stomp of a stock ~16–30 MB Sliver. Stagers exist **because** the implant is large (~10 MB in Sliver’s own docs).

### Cited Findings
- Fortbridge: “due to the size of sliver binaries I couldn’t find any candidates to attempt module stomping.” Pain point: “large binary sizes (up to 30 MB!) and the lack of a sleep mask” — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Immersive: “statically compiled Go binary … average file size of **16 Mb**”; memory detection is easier because “the **entire Go binary must be unpacked into memory** regardless of any packing” — [Detecting and decrypting Sliver C2](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- Sliver Stagers: “payloads can be pretty big (**around 10MB**), you may sometime require the use of stagers” — [Stagers.md](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Stagers.md).
- Joe Sandbox Linux implant **31.8 MB** ELF — [analysis 1848290](https://www.joesandbox.com/analysis/1848290/0/pdf?download=1).
- Donut supports **module overloading** (`-j decoy`) which is related to stomping (map a decoy as `SEC_IMAGE`, overwrite). Decoy file must be **≥ SizeOfImage** of the payload — [Donut README](https://github.com/TheWover/donut); [DeepWiki](https://deepwiki.com/thewover/donut). A 16–30 MB decoy is an unusual signed system DLL.
- BallisKit: generate a “vanilla” implant (`--disable-sgn --skip-symbols`) then pack with ShellcodePack to shrink (examples 9 MB / 6 MB packed EXE; staged 90–250 KB) — [BallisKit tutorial](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19). That is packing, not stomping.

### Inferences
- Stomping is a poor fit for **stock** Sliver PIC/EXE: there is no commonly loaded 16+ MB RX section to overwrite. Donut decoy/`-j` has the same size floor.
- Size reduction (stager, third-party packer, `--skip-symbols`) is the publicly documented path if an operator wants a stomping-sized payload — still not a report of stomping Sliver itself.

### Gaps
- No cited red-team report of successfully stomping a **trimmed** Sliver (e.g. HTTP-only, skip-symbols, custom protobuf) into a large third-party DLL. Absence of reports ≠ impossibility.

---

## After decrypt: does format still matter for memory YARA of `sliverpb`?

### Takeaway
**Mostly no.** EXE, SHARED, and Donut-unpacked shellcode all run the same Go runtime and the same `sliverpb` / protobuf method names in process memory. Immersive’s memory rule is literally `sliverpb`. Elastic `Multi_Trojan_Sliver` is `file, memory` and `os = multi`. Format still matters for **how** that image got there (unbacked vs `MEM_IMAGE`, Donut AMSI stub, SGN RWX) and for **SHARED-only export strings**, not for whether `sliverpb` is present once the implant is plaintext.

### Cited Findings
- Immersive: “Memory detection is easier as the entire Go binary must be unpacked into memory regardless of any packing of the binary or staged delivery.” Memory YARA: `$str1 = "sliverpb"` — [guide](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [sliver.yar](https://raw.githubusercontent.com/Immersive-Labs-Sec/SliverC2-Forensics/main/Rules/sliver.yar).
- Elastic `Windows_Trojan_Sliver_*` and `Multi_Trojan_Sliver_*`: `scan_context = "file, memory"`; strings include protobuf names and `B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb`; `3d6b7cd3` is **bytecode** of the beacon/session loop (format-agnostic once compiled) — [Windows_Trojan_Sliver.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_Sliver.yar); [Multi_Trojan_Sliver.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar).
- Square (Mar 2024): osquery + YARA on `/proc/<pid>/map_files` using Immersive’s `sliverpb` / `bishopfox` / `chacha20poly1305` rules found a **Linux** Sliver in memory, including `on_disk = 0` processes — [Leveraging Linux Internals to Supercharge Osquery](https://developer.squareup.com/blog/leveraging-linux-internals-to-supercharge-osquery-malware-detection/).
- Joe Sandbox Linux ELF: YARA `Multi_Trojan_Bishopsliver_42298c4a` (`RequestResend`, `GetPrivInfo`) hit both the **file** and **process memory dumps** (`5497.1.*.rw-.sdmp`) — [Joe Sandbox](https://www.joesandbox.com/analysis/1848290/0/pdf?download=1).
- Fortbridge: after beating **file** YARA they still had a **runtime** YARA hit until they globally replaced `bishopfox`; the implant was a DLL loaded from disk — i.e. format did not hide the string in memory — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Donut: “After the file is loaded and executed in memory, the original reference is erased to deter memory scanners”; default **overwrite PE headers** (zero or decoy). The **code/data** of the native PE remains — [Donut README](https://github.com/TheWover/donut).
- malwrforensics (Apr 2025): on-disk Sliver PE identified via `Go build ID`, `.data` buildinfo containing `sliver`, and zlib `78 01` streams — file-format analysis of an **EXE**, not a claim that shellcode lacks those bytes after unpack — [Demystify golang malware](https://malwrforensics.com/en/2025/04/17/demystify-golang-malware-how-to-recognize-bishop-foxs-sliver/).
- BishopFox #1760 (2024–2025): garble often **fails to obfuscate protobuf methods**; “several Defender AV signatures detecting these strings” — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760).

### Inferences
- Choosing `--format shellcode` to “avoid PE YARA” only helps **at rest** (no MZ, possibly encrypted Donut module). After Donut RunPE, `sliverpb`, protobuf names, and Go runtime strings are in the process the same way as a disk EXE.
- SHARED-only export strings (`VoidFunc`, `DllRegisterServer`, …) are **not** in a pure EXE; they **are** in a SHARED build even after `LoadLibrary`. Memory YARA that keys those exports is format-specific; `sliverpb` is not.
- Sleep-mask absence (Fortbridge) means idle beacons keep plaintext Go/protobuf resident — a format-independent memory-scan problem.

### Gaps
- No public dump comparing YARA hit offsets for the same implant as EXE vs Donut-unpacked PIC in a single process snapshot.
- Whether Donut header wipe plus `SRDI_CLEARHEADER`-style tricks change Elastic **bytecode** rules (`3d6b7cd3`) is untested in public; those rules match code, not DOS headers.

---

## Linux ELF / mmap RWX vs Windows — public Sliver AV notes

### Takeaway
Public Linux Sliver detection is **mostly the same family YARA** (`sliverpb`, protobuf methods) on ELF files and `/proc` maps, plus generic **anonymous RWX / `mprotect`** behavioral rules. There is far less vendor narrative than for Windows Donut/AMSI/unbacked. Current Sliver Linux shellcode is **malasada** (`.so` → PIC, `mmap` + jump, **intentionally avoids `memfd`**). Stock Linux SHARED uses `LD_PRELOAD` + `memfd_create` for **sideload**, which is a different (and more documented) detector surface than `generate --format shellcode`.

### Cited Findings
- Payload matrix: linux/amd64 and linux/arm64 support EXE, SHARED, and shellcode; linux/386 shellcode is ❌ — [Payload Compatibility](https://sliver.sh/docs?name=Payload+Compatibility).
- pkg.go.dev: `SliverShellcode` = “Windows: Donut, macOS: beignet, **Linux: malasada**” — [generate package](https://pkg.go.dev/github.com/bishopfox/sliver@v1.7.6/server/generate). Older `binaries.go` still said shellcode was Windows-only; Stagers.md now documents Linux `--format shellcode --shellcode-compress` (other `--shellcode-*` Windows-only) — [Stagers.md](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Stagers.md).
- malasada (sliverarmory, created Feb 2026): “Donut for Linux”; converts ELF `.so` to PIC “by copying it into an `mmap`’d region and jumping to it as a function pointer”; **“intentionally avoids `memfd` (`memfd_create`, `execveat` on memfd, etc)”**; stage0 “hands off to ld-linux”; `--compress` uses aPLib-style depack — [sliverarmory/malasada](https://github.com/sliverarmory/malasada).
- Linux SHARED `main.c`: `.init_array` constructor unsets `LD_PRELOAD` / `LD_PARAMS`, optionally calls the first export — [main.c](https://raw.githubusercontent.com/BishopFox/sliver/master/implant/sliver/main.c).
- `sideload` on Linux (docs): write `.so` to a **memfd**, `LD_PRELOAD` into a sacrificial process (`/bin/ls` default) — [Third Party Tools](https://sliver.sh/docs/?name=Third%20Party%20Tools).
- Elastic (created 2024-03-13, updated 2026-09-18): **Unknown Execution of Binary with RWX Memory Region** — `mprotect` granting RWX on a previously unknown unix binary; “RWX permissions on memory is in many cases overly permissive” — [execution_unknown_rwx_mem_region_binary_executed.toml](https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_unknown_rwx_mem_region_binary_executed.toml).
- ATT&CK DET0300 Linux analytic AN0839: `mmap` + `mprotect` writable→executable without a corresponding ELF on disk — [DET0300](https://attack.mitre.org/detectionstrategies/DET0300).
- Square: in-memory Sliver on Linux via YARA on `/proc/pid/map_files` (Immersive rules) — [osquery post](https://developer.squareup.com/blog/leveraging-linux-internals-to-supercharge-osquery-malware-detection/).
- Joe Sandbox 2026: Linux Sliver ELF classified MAL, YARA `JoeSecurity_Sliver` + `Multi_Trojan_Bishopsliver_42298c4a` on file **and** RW- memory dump; size 31.8 MB — [Joe Sandbox](https://www.joesandbox.com/analysis/1848290/0/pdf?download=1).
- MalwareBazaar: Elastic `Linux_Generic_Threat_b8b076f4` and Google `Sliver__Implant_64bit` both match **ELF samples tagged sliver** through 2026 — [Linux_Generic_Threat_b8b076f4](https://bazaar.abuse.ch/browse/yara/Linux_Generic_Threat_b8b076f4/); [Sliver__Implant_64bit](https://bazaar.abuse.ch/browse/yara/Sliver__Implant_64bit/).
- Elastic “Potential Linux Hack Tool Launched” includes **`sliver-client` / `sliver-server` process names**, not implant ELFs — [detection-rules-explorer](https://elastic.github.io/detection-rules-explorer/rules/1df1152b-610a-4f48-9d7a-504f6ee5d9da).
- Generic Linux mmap guidance (2026 FAQ-style): flag anonymous executable mappings, RWX, write-then-`mprotect` to exec — [nhimg mmap detection](https://nhimg.org/faq/how-can-security-teams-detect-linux-mmap/). Not Sliver-specific.
- DeepSec 2026 talk (Bertocchi): Linux EDR pillars = syscall tracepoints, userland hooks, static ELF analysis; fileless path discussed is **`memfd_create` + `fexecve`**, which malasada **avoids** — [DeepSec 2026](https://blog.deepsec.net/deepsec-2026-talk-the-linux-evasion-stack-breaking-all-three-edr-pillars-with-io_uring-and-elf-packing-massimo-bertocchi/).

### Inferences
- Linux **EXE** is a large unsigned ELF: YARA/`sliverpb` and “Go ELF shape” dominate public reports; there is no Donut AMSI stub.
- Linux **SHARED** on disk is a `.so` with constructor/export; `sideload`’s **memfd+LD_PRELOAD** is the noisy documented technique (memfd is a known EDR feature, which is why malasada refuses it).
- Linux **shellcode** (malasada) looks like Windows Donut at the OS layer: anonymous `mmap` + jump / `mprotect` RX/RWX, then the Go image is in memory for YARA. Elastic’s RWX-`mprotect` rule is the closest public behavioral analog to Windows unbacked+RWX, but it is **not** titled “Sliver.”
- Public “Linux Sliver AV” literature is thin compared with Windows Defender/Elastic Donut writeups. Do not extrapolate Windows AMSI_PATCH / unbacked-network-DLL rules to Linux.

### Gaps
- No public Elastic/CrowdStrike/Defender-for-Linux case study that says “we caught Sliver **because** it was malasada PIC rather than ELF.”
- malasada’s actual `mmap` flags (RWX vs RW→RX) are not quoted from source in this pass; README only says copy into `mmap`’d region and jump.
- Windows Defender for Linux / MDE Linux memory scanning of `sliverpb` is not documented in the Microsoft 2022 Sliver hunt (that article is Windows-centric).

---

## Which format is cited as noisier for Defender / Elastic?

### Takeaway
**Windows Donut shellcode (unbacked PIC) is the format public EDR writeups call out as behaviorally noisier** — AMSI/WLDP patch signatures, RWX/SGN, Elastic unbacked network-module loads. **Disk EXE/DLL** are noisier for **static** PE ML / family YARA (MZ, IAT, exports, `Go buildinf`). Fortbridge’s lab: PIC path failed Elastic; image-backed DLL + string edits passed **that** Elastic/Defender pair. That is one cited path, not a general “DLL is quieter” law.

### Cited Findings
- Elastic #1759: stock `generate --format shellcode` → AMSI/WLDP patch detection — [issue 1759](https://github.com/BishopFox/sliver/issues/1759).
- Defender `Win32/AMSI_PATCH_T.B12/.B13` on Donut/Sliver shellcode — [#1814](https://github.com/BishopFox/sliver/issues/1814), [#2200](https://github.com/BishopFox/sliver/issues/2200).
- Fortbridge: Donut RWX + AMSI bypass “heavy signature detection”; unbacked `LoadLibraryExW` = deal-breaker; disk DLL + export/protobuf edits = callback with Elastic present — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Microsoft 2022: hunting focus is **injection API sequence** and in-memory config, not “EXE vs DLL vs shellcode” ranking; they note custom loaders embedding shellcode to dodge **file-based** detection — [Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Dominic Breuker: Defender `Behavior:Win32/Sliver.A!sms` on a Windows lab; “occasionally detects” even with obfuscation notes — [SpawnDLL post](https://dominicbreuker.com/post/learning_sliver_c2_11_spawndll/).
- Numen (Sep 2022, **dated**): claimed Defender evasion for Sliver shellcode in C#/Go/Nim loaders on Win10; VT screenshots of loaders, not a 2025–2026 EDR — [Numen Cyber Labs](https://medium.com/@numencyberlabs/defeating-window-defender-using-different-programming-languages-with-sliver-c2-shellcode-d233f75a4d14). Treat as stale relative to AMSI_PATCH_T and Elastic unbacked rules.

### Inferences
- Rank **behavioral** noise (Elastic/MDE, 2024–2026): `shellcode` (Donut+optional SGN, unbacked) > injected SHARED/EXE via `sideload`/`spawndll` (remote VirtualAllocEx sequence) > disk EXE/DLL started by the OS (`MEM_IMAGE`).
- Rank **static** noise (MDAV YARA/ML, Elastic file YARA): disk EXE/DLL (especially SHARED with default COM/`VoidFunc` exports) > raw `.bin` (no MZ; may still match Donut/SGN stubs if unencrypted).
- After unpack, **memory YARA (`sliverpb`)** does not rank formats.

### Gaps
- No vendor scorecard “EXE 80% / DLL 40% / shellcode 95%.” Citations are qualitative (issue trackers, one Fortbridge engagement, Elastic public rules).
- Numen 2022 and similar Medium “Defender bypass with Sliver shellcode” posts conflict with 2024–2026 AMSI_PATCH_T issues; prefer the later primary sources.
