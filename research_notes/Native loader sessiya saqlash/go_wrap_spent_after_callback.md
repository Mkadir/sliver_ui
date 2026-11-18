# Go wrap EXE is spent after first callback: stub PE vs live Sliver implant

Authorized lab / product OPSEC research. Scope is **post-callback**: Microsoft Defender Antivirus (inbox MDAV / `MsMpEng`, not only MDE) already allowed the first beacon or session check-in, then later killed the live implant. The operator claim under test: **“if Defender still kills the session after it opens, the Go loader contribution is useless.”**

**MDAV vs MDE (keep this split):** inbox Microsoft Defender Antivirus is built into Windows 10/11 (`WinDefend` / `MsMpEng.exe`) and runs in **Active** mode when it is the primary AV — no Defender for Endpoint license is required ([Microsoft Defender Antivirus in Windows](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows); [compatibility without MDE](https://learn.microsoft.com/en-us/defender-endpoint/defender-antivirus-compatibility-without-mde)). Memory scanning is a **client** engine with **no cloud counterpart** ([Advanced technologies of MDAV](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav)). Client behavioral blocking can stop a **running** artifact after execution has started (`Behavior:Win32/CommandAndControl.*!ml` and sibling MITRE-named families) ([Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking); [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)). MDE (`MsSense`) adds EDR telemetry, portal alerts, and **EDR in block mode** (off by default). A lab box with `OnboardingState=0` can still 1117-kill a live implant.

Current Windows wrap (`windowsSource()` in `backend/internal/loader/windows.go`): XOR-decrypt embedded `cfg.dat` into a private allocation, `VirtualProtect` **RWX (`1<<6`)**, assembly `CALL` of Donut/sRDI PIC, then `hang()` (`Sleep(0xffffffff)` loop). Pre-jump gates: hide-console, `HAL9TH` computer-name exit, RAM ≥ **2 GiB**, `Sleep(1800)` + tick abort. Windows trampoline `CALL AX` then **RET** (`jump_windows_amd64.s`). Unique SHA-256 is mint-uniqueness (`n.bin`, nonce, `-buildid`), not a content bypass.

---

## After XOR decrypt + CALL of Donut/sRDI PIC, what does Defender scan: wrap PE hash, or the in-memory Go implant?

### Takeaway
After first callback, the object under scan is **the process address space**, not the wrap EXE’s SHA-256. Inbox MDAV’s memory-scanning engine reads running-process memory to expose obfuscated code; public Sliver YARA is written `file, memory` and keys on implant strings (`sliverpb`, protobuf RPC names, `Go buildinf`) that exist only **after** Donut/sRDI maps the ~16–30 MB Go image. Unique wrap hash is a **cache key** for an already-allowed file, not the verdict on the live implant.

### Cited Findings
- Microsoft: the **memory scanning engine** “scans the memory space used by a running process to expose malicious behavior that could be hiding through code obfuscation.” It is listed as a **client** function; the cloud column for memory scanning is **N/A** (“no cloud counterpart for the memory-scanning engine”). Hybrid stack also includes client behavior monitoring, emulation (unpack + scan memory **at end of emulation**), and cloud behavior-ML on process trees — [Advanced technologies of MDAV](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav) (page updated 2026-10).
- Microsoft: MDAV “can also stop threats based on their behaviors and process trees **even when the threat has started execution**. A common example … is fileless malware.” — [Microsoft Defender Antivirus in Windows](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows).
- Client behavioral blocking: MDAV detects suspicious behavior / fileless / in-memory attacks, sends process trees to cloud ML, and **blocks the running artifact** in almost real time. Behavior names follow MITRE, including `Behavior:Win32/CommandAndControl.*!ml`. Documented stopped techniques include **cross-process injection**, **process hollowing**, and **contacting C2 to download payloads** — [Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking); [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment) (updated 2026-05-06).
- Immersive Labs: “Memory detection is easier as the **entire Go binary must be unpacked into memory regardless of any packing of the binary or staged delivery**.” Average implant ~**16 MB**. File YARA `sliver_binary_native` matches PE/ELF/Mach-O magic plus `sliverpb`, `github.com/bishopfox/`, `chacha20poly1305`. Separate **memory** rule `sliver_memory` matches **only** `sliverpb` because the file rule’s header offsets fail in dumps — [Detecting and decrypting Sliver C2](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide) (2023-04-24); [sliver.yar](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.yar).
- Fortbridge: stock implants hit extracted Defender-oriented ASCII including `DllUnregisterServer`, `DllRegisterServer`, `DllInstall`, `GetJitter`, `VoidFunc`, `GetKill`, `AddTunnel`, `GetIsIOC`, and ` Go buildinf:`. Implant size **up to ~30 MB**. “Large binary size and **lack of sleep mask** leave memory-resident implants easy to YARA-scan while idle.” Encrypted implant in a loader / self-inject / hollowing was **ineffective** against Elastic+Defender until source-level string edits — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/) (2025-04-01).
- Elastic `Multi_Trojan_Sliver` rules set `scan_context = "file, memory"` and key on `).RequestResend`, `).GetPrivInfo`, `InvokeSpawnDllReq`, `NetstatReq`, `HTTPSessionInit`, `ScreenshotReq`, `RegistryReadReq`, package path `github.com/bishopfox/sliver/protobuf/sliverpbb`, plus x86/x64 session-start/register bytecode — [Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar).
- BishopFox maintainers: Garble **does not pick up protobuf methods** → “easy signatures.” A reporter ran Elastic’s YARA against a **live beacon** and matched those strings **in the binary and in memory**. Cyb3r-Monk: “**several Defender AV signatures detecting these strings.**” Moloch (Jan 2025): custom protobuf AST obfuscation in v1.6, no comprehensive ETA. Issue closed Jan 2026 as completed — do **not** assume current stock implants are clean vs Elastic (rules still live) — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760).
- Microsoft (MDE hunting, 2022, still the public baseline): Sliver decrypts/de-obfuscates configuration **in memory**; hunters extract config from process memory after load. Stagers shrink **on-disk** first stage; the full implant still lands in RAM — [Looking for the ‘Sliver’ lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Hash uniqueness vs architecture: cloud metadata ML / BAFS use SHA-256 to **look up and cache** a verdict; unknown hashes are classified by PE features, emulation, detonation, and behavior, not treated as trusted — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [Cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission); [Block at first sight](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus).
- This wrap after `run()`: private RWX holds **plaintext** PIC; `cfg.dat` ciphertext is a disk/embed concern only until XOR. Jump is local `CALL` (`jump_windows_amd64.s`). Hang-after-jump keeps the Go host alive if PIC returns — local [`windows.go`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [`source.go` `jumpAsm`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/source.go).

### Inferences
- **Callback is proof the wrap PE was allowed to run**, not proof the implant is invisible. From that moment, scanners that matter are: (1) process-memory content (protobuf / `sliverpb` / `Go buildinf` / Donut leftovers), (2) unbacked executable VAD + `LoadLibraryExW` from it (implant Go `LazyDLL`), (3) C2/behavior ML on the **same PID**, (4) optional later 1117 of the **on-disk wrap file** if cloud retrains the hash.
- XOR + unique SHA-256 never rewrite implant strings. They are spent at decrypt.
- Do not claim unique hash or XOR is a Defender bypass. Hash is the cache; content + behavior are the verdict.

### Gaps
- Microsoft does not publish the live MDAV VDM/YARA that ships in cloud signatures, nor a public `Trojan:Win64/Sliver.*` catalog. Fortbridge inferred Defender strings from extracted rules ([roadwy/DefenderYara](https://github.com/roadwy/DefenderYara)), which lag cloud.
- No public A/B “same Sliver PIC, Go wrap vs tiny C host, time-to-kill after first callback” under inbox MDAV-only.
- Whether MDAV memory scan enumerates **all** private executable VADs or only regions recently touched by VirtualProtect/thread-create is unpublished (independent RE of `TriggerEmsScan` is not Microsoft documentation).

---

## Do Formidable (2026) and Praetorian (2026) Wacatac.B!ml / gopclntab findings apply to the stub only, or also to the live implant?

### Takeaway
**Primarily the on-disk / pre-execution Go PE**, i.e. the **stub** (or any unsigned Go EXE), not memory YARA of the decrypted implant. `Wacatac.B!ml` is Microsoft’s **static PE-ML** family (`!ml` = classifier, not a byte signature). Formidable’s benign Wails GUI had **0 dynamic sandbox detections**. Praetorian’s `gopclntab` dilution moved **VirusTotal / cloud Wacatac** on compiled Go files. After callback, those findings explain **first-run / delayed file quarantine of the wrap**, not `sliverpb` in RAM. A live Donut-mapped implant **is** still a Go image, so `Go buildinf:` **string** YARA (Fortbridge/DefenderYara) can hit the **implant** in memory; that is a different detector than Wacatac PE-ML.

### Cited Findings
- Formidable (23 May 2026): benign Wails 3 + Go 1.25 `Formidable.exe` flagged `Trojan:Win32/Wacatac.B!ml`. VT sandboxes CAPA/CAPE/Jujubox/Zenbox returned **0 dynamic detections**. `!ml` = static ML on PE structure, sections, imports, entropy, strings, metadata — **not** “Defender saw it execute something malicious.” Author’s diagnosis: classifier weights **Go PE shape** (large `.text`, `gopclntab`, `runtime.morestack_noctxt` / `runtime.gcWriteBarrier`, statically linked, no CRT) because Go malware volume since ~2020 (explicitly including **Sliver C2**) trained “Go-shaped unsigned EXE” as a positive malware feature. VersionInfo, Win10/11 manifest, dropping `-s -w`, reproducible `-buildid=`, NSIS polish, FP submission: **no score change**. Proposed remaining levers: Authenticode, or launcher+DLL split so the **EXE** is not Go-shaped — [Defender, Wacatac.B!ml, and the Go-binary problem](https://formidable.tools/posts/defender-wacatac-go-binary/).
- Praetorian (28 May 2026): modern EDR hits on **Go binaries** dominated by statistical ML (`Wacatac.B!ml`, `ML.Attribute.HighConfidence`, `MalwareX-gen`, `Evo-gen`) rather than fixed-byte YARA. `-ldflags="-s -w"` **increased** detections (CrowdStrike/Symantec). ML over-indexes on **`gopclntab`**: a small runtime-only table looks like minified malware; a large project-like table dilutes it. Ghost-profile bakeoff: moving to a substantially larger profile cut **Microsoft Wacatac from ~95% to ~20%** on otherwise-identical payloads. Fake MSVC Rich header / patched linker version made detections **worse** (“Don’t fight the toolchain”). Microsoft **cloud** ML is “substantially more aggressive” than local `MpCmdRun.exe`; a 100% Wacatac VT hit can be **clean locally**. Wacatac retrains on roughly a **daily** cadence. AhnLab `Trojan/Win.Sliver.R774471` in that work was a **fixed-string YARA on fake Authenticode subject**, not gopclntab. Next research: wrap an existing tool (Sliver/Chisel) compiled to **WASM** inside an outer Go binary **without modifying a single line of the tool’s source** — i.e. **stub disguise**, implant unmodified — [Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/).
- This wrap compiles `GOOS/GOARCH CGO_ENABLED=0`, `-s -w`, optional `-H windowsgui`, unique `-buildid` — the exact strip flags Praetorian found **worsened** ML. The stub is a small Go PE with a high-entropy XOR embed (`cfg.dat`) plus 4–24 KiB `n.bin`. That is **Formidable’s Go-shape problem plus packed-section entropy**, independent of Sliver strings — local [`windows.go`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [`build.go`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go).
- Fortbridge DefenderYara hit ` Go buildinf:` as an **ASCII string** in the **implant**, not as PE-ML on the loader. Elastic `Multi_Trojan_Sliver` does not mention `gopclntab` or Wacatac; it mentions protobuf method names and bishopfox paths — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar).

### Inferences
- **Map detectors to objects:**

  | Detector | Object | When it matters |
  |---|---|---|
  | `Wacatac.B!ml` / cloud PE-ML / `gopclntab` size | **On-disk wrap PE** (and any other Go EXE) | First run, BAFS, delayed re-scan/quarantine of the file |
  | Elastic/Immersive/DefenderYara protobuf / `sliverpb` / `GetJitter` / `Go buildinf:` | **Decrypted implant bytes** (file or memory) | After XOR+CALL, including post-callback |
  | `Behavior:Win32/CommandAndControl.*!ml` | **Process tree + C2 behavior** | After implant talks |

- If Protection History Name is `Trojan:Win32/Wacatac.B!ml` **on the wrap path**, nativizing or signing the **stub** can still matter even after a callback (cloud retrain → 1117 of the running image). That is **not** the operator’s “memory YARA killed my session” story, but it is a real delayed-kill path.
- If the name is protobuf-family / `Behavior:Win32/…` / unbacked-library, Wacatac work on the stub is **already spent**.
- Praetorian’s WASM-outer-Go plan is explicit evidence that 2026 “make Sliver runnable again” research often still attacks the **outer file**, not implant protobuf.

### Gaps
- No public measurement that MDAV runs the **same PE-ML model** on a Donut-unpacked PE in private memory (as opposed to string/YARA memory scan). Do not assert Wacatac fires on the PIC in RAM.
- Formidable signing follow-up (Certum in queue as of the post) was not checked for a later update in this pass.
- Praetorian “no problems on MDE machines when VT Wacatac is low enough” is **file-run** testimony, not post-callback session survival.

---

## Elastic Multi_Trojan_Sliver, Immersive sliver_memory, Fortbridge DefenderYara — do these fire on a tiny C host that has already jumped to Sliver PIC?

### Takeaway
**Yes, if the PIC is a stock (or insufficiently string-cleaned) Sliver image.** Those rules match **implant content in the process**, not the host compiler. A tiny C EXE that `VirtualAlloc`s and `CALL`s Donut/sRDI PIC still has `sliverpb` / `ScreenshotReq` / `GetJitter` / `Go buildinf:` in **private executable memory of that PID**. Fortbridge’s working path was **not** “C host + stock PIC”; it was **source-renamed implant DLL + `LoadLibrary` from disk** so the implant sat in **backed** image memory. Unbacked PIC in a C process still tripped Elastic **“Network Library Loaded from Unbacked Memory”** because **implant Go `LazyDLL` → `LoadLibraryExW`** runs from the PIC, not from the stub.

### Cited Findings
- Elastic rules: `scan_context = "file, memory"`; strings are protobuf RPC names and `github.com/bishopfox/sliver/protobuf/sliverpbb`; third rule is session-start/register **bytecode** in the implant, not in a C trampoline — [Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar).
- Immersive `sliver_memory`: single string `sliverpb`; authored specifically because the file rule’s PE/ELF magic offsets fail in dumps. “Entire Go binary must be unpacked into memory **regardless of packing or staged delivery**” — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [sliver.yar](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.yar).
- BishopFox #1760 reproduction: generate Windows beacon, **run it**, run Elastic YARA with `yara64.exe` against the **live** process; matches listed in-memory — [sliver#1760](https://github.com/BishopFox/sliver/issues/1760).
- Fortbridge vs Elastic+Defender: staged/self-inject/pack of **stock** Sliver “proved ineffective.” HTTP beacon init via Go `LazyDLL` → `LoadLibraryExW` from **unbacked memory** → Elastic **“Network Library Loaded from Unbacked Memory.”** Module stomping abandoned because implants are **up to ~30 MB**. Pre-loading libraries before shellcode failed because `NewLazyDLL()` still calls `LoadLibraryExW`. Hardware-breakpoint hook of that API did **not** bypass the alert. Disk write of a **cleaned** implant DLL plus “a **simple program that just loads the implant dynamic library from the same folder**, finds the entry point export and runs it in a **new thread**” was the path that got a callback. Export/string surgery (`VoidFunc`, `GetJitter`, unused `DllRegisterServer`/`DllInstall`/`DllUnregisterServer`, protobuf names) was done **in Sliver source**, not in the C loader. After that, **built-in commands still triggered Elastic behavioral alerts** — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Cyb3r-Monk on #1760: several **Defender AV** signatures on those protobuf strings — same strings a C host cannot strip from PIC — [sliver#1760](https://github.com/BishopFox/sliver/issues/1760).
- This product’s wrap is the **unbacked** architecture Fortbridge found ineffective: `VirtualAlloc` private RWX + XOR + `CALL`, not disk `LoadLibrary` of a shared DLL — [`windows.go` `run()`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go).

### Inferences
- Host language is orthogonal to **content YARA**. Tiny C vs Go wrap vs Nim: if the bytes in RWX are stock Sliver, Immersive `sliverpb` and Elastic protobuf rules can match. Switching the wrap to C **without** implant surgery does not answer post-callback family YARA.
- What a tiny C host **can** change: (i) on-disk Wacatac/gopclntab of the **file** (no Go PE shape), (ii) one fewer Go runtime mapped as the **image** of the process (the stub’s `gopclntab` goes away), (iii) if the C host uses **disk `LoadLibrary`** of a DLL, the implant may be **backed** (Fortbridge’s actual win vs unbacked `LoadLibraryExW`). Item (iii) is **loader architecture**, not “C instead of Go.” A C host that still `VirtualAlloc`s PIC remains unbacked.
- Fortbridge still lost to **behavior** on built-in commands after YARA-clean + disk DLL. Nativizing host is not a session-lifetime guarantee.

### Gaps
- Fortbridge’s “simple program” is described as a small LoadLibrary stub (C-class); the post does not publish the full source in the HTML extract used here. Treat “tiny C” as the author’s description of a minimal disk-DLL loader, not a measured LOC count.
- No public confirmation that **inbox MDAV** ships the exact Elastic string set; the citable Defender-side overlap is Cyb3r-Monk’s “several Defender AV signatures” on protobuf strings plus Fortbridge’s extracted DefenderYara list (`GetJitter`, `VoidFunc`, `AddTunnel`, `Go buildinf:`).
- Whether Sliver 1.7.9 (this lab’s tree) shipped enough protobuf AST obfuscation to beat current Elastic/DefenderYara is **unverified** in this pass (#1760 closed 2026-01 as completed; Elastic rules remain).

---

## Does skipping CreateThread, unique SHA-256, hide-console, HAL9TH, 2 GiB RAM, or hang-after-jump change post-callback memory YARA / Behavior:Win32/CommandAndControl?

### Takeaway
**No for memory YARA and C2-behavior classification.** Those tricks are **pre-execution / emulator / process-lifetime** controls. After callback, plaintext implant strings and the implant’s own network/`LazyDLL` behavior are unchanged. Hang-after-jump can keep the **PID alive if PIC returns** (correctness, class A in the earlier report); it does not encrypt or rename implant memory. Unique SHA-256 does not apply to RAM. HAL9TH / 2 GiB / 1.8 s sleep only run **before** `run()`. Hide-console is a window, not EDR. Skip-CreateThread avoids a thread-start heuristic; ETW-Ti `ALLOCVM`/`PROTECTVM` and memory scan of the RWX VAD remain.

### Cited Findings
- **Unique SHA-256:** SmartScreen/BAFS treat a new hash as **unknown**, then classify by features/emulation/detonation; hash caches the verdict — [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation); [BAFS](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus); [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav). Praetorian: unique hashes + garble + strip **did not** beat Microsoft/CrowdStrike ML — [Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/).
- **Skip CreateThread / local CALL:** ETW-Ti logs local `ALLOCVM` / `PROTECTVM` independent of thread create — [EtwTiViewer](https://github.com/adanto/EtwTiViewer). Elastic (same provider class): `sensitive_api` / `execute_shellcode` are **call-stack** properties of non-image executable memory, not CreateThread — [Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks). gatari (Mar 2024, dated lab): XOR beat **on-disk**; `VirtualAlloc(RWX)` + **direct CALL** (no CreateThread) was **still process-killed** at runtime by MDAV — [A Trip Down Memory Lane](https://gatari.dev/posts/memory-lane/). Microsoft’s 2022 Sliver CRT chain is about **stock implant post-ex**, not a claim that CRT-less loaders are invisible — [Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- **Hide-console / `-H windowsgui`:** Formidable used `-H windowsgui` on a **benign** GUI and still got Wacatac; dynamic sandboxes were clean — i.e. subsystem bit is not a behavior hide — [Formidable](https://formidable.tools/posts/defender-wacatac-go-binary/). Product copy already: hiding the window is not hiding from EDR.
- **HAL9TH:** this stub exits if `GetComputerNameW` equals `HAL9TH` (emulator/sandbox hostname folklore, MITRE T1497.001). It runs in `sandbox()` **before** `run()`. A live operator PC is not named HAL9TH; the check never runs post-callback — [`windows.go`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go). Microsoft’s `MP_FORCE_USE_SANDBOX` is a **different** Defender content-process sandbox, not this hostname — [Sandboxing MDAV](https://learn.microsoft.com/en-us/defender-endpoint/sandbox-mdav).
- **2 GiB RAM:** `enoughRAM()` requires `GlobalMemoryStatusEx` total ≥ `2 << 30` or `os.Exit(0)`. Toy emulators with tiny RAM exit **before** decrypt. Cloud detonation and real lab PCs have more RAM; Microsoft documents cloud **detonation** as a real sandbox with deep-learning on observed behaviors, default BAFS lock **10 s** (up to 60) — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [cloud block timeout](https://learn.microsoft.com/en-us/defender-endpoint/configure-cloud-block-timeout-period-microsoft-defender-antivirus). Tests in this tree require the 2 GiB constant — [`loader_test.go`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go).
- **Hang-after-jump:** `hang()` infinite `Sleep(0xffffffff)` after `jump()`. Windows trampoline **RET**s to Go if PIC returns; Linux trampoline `exit_group`. Hang is a **host-lifetime** fix so Donut `ExitOpt=thread` / sRDI `DllMain` return does not `ExitProcess` the implant threads. It does not alter PIC bytes, C2, or YARA — [`windows.go`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [`jump_windows_amd64.s`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/source.go). BishopFox: “If the process is terminating you may have a bug in your loader code” — [sliver#1410](https://github.com/BishopFox/sliver/issues/1410).
- **1.8 s Sleep + tick:** client **emulation** engine unpacks packers; Sleep-skip is a 2018-class emulator game. Cloud detonation is a **separate** engine. PEzor’s documented example delay is **120 s**, not 1.8 s — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [PEzor README](https://github.com/phra/PEzor).
- **C2 behavior:** default HTTP extensions (`.woff`/`.html`/`.js`/`.php`/`.png`) and nonce encoder are **compiled into the implant**. Loader XOR does not rewrite them. `Behavior:Win32/CommandAndControl.*!ml` is named for that tactic — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking).
- **Sleep mask:** stock Sliver does not ship Ekko; moloch: obfuscated sleep is hard because of the Go runtime; PR #1805 unmerged. Interactive session is **awake** (long-poll) — [Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171); [PR #1805](https://github.com/BishopFox/sliver/pull/1805); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).

### Inferences
- Table for **post-callback** (symptom: session opened, then died):

  | Trick (this wrap) | Post-callback memory YARA | `Behavior:Win32/CommandAndControl` | What it can still do |
  |---|---|---|---|
  | XOR + unique SHA-256 | No | No | Hash-IOC of **file**; delayed 1117 of wrap path if cloud burns hash |
  | No `CreateThread` in stub source | No | No | Fewer Sysmon 8 / CRT-start heuristics **at launch** |
  | Hide-console | No | No | User window |
  | HAL9TH | Never runs after `run()` | No | Toy emulator hostname |
  | RAM ≥ 2 GiB | Never runs after `run()` | No | Tiny emulator VM |
  | Sleep 1.8 s + tick | Never runs after `run()` | No | Sleep-skipping **client** emulator |
  | Hang-after-jump | No | No | **PID lifetime** if PIC returns (not Defender) |
  | RWX `1<<6` | **Worsens** unbacked-exec optics | Indirect | Required for some Donut/SGN write windows |

- Operator claim holds for **this list vs memory YARA / C2 ML**. It does **not** make hang-after-jump useless: that is a loader-correctness contribution, not an AV contribution.

### Gaps
- No Microsoft public A/B of CreateThread vs local CALL vs APC under 2026 MDAV.
- Exact 2026 mpengine emulator instruction budget and which Win32 APIs are fully emulated is unpublished (Bulazel 2018 is dated).
- Whether a later RTP/scheduled scan of the **wrap file** (Wacatac retrain) vs a memory scan of PIC is what killed a given lab session cannot be known without Protection History **Name + Path**.

---

## Is `interactive` / Open Session a new process or the same PID goroutine?

### Takeaway
**Same PID, new goroutine.** Official tutorial: `interactive` “will spawn a goroutine running session connection loop **in the same beacon process**.” Implant source `MsgOpenSession` → `go openSessionHandler` → `go func() { StartConnectionLoop; sessionMainLoop }`. This UI’s `OpenSessionFromBeacon` sends `C2S: []`, `Delay: 0` — native defaults. No new PE is generated. Killing “the session” kills **that process** (beacon included), unless the operator later `migrate`s / `execute-shellcode`s into another PID (that **is** CRT inject, Microsoft 2022).

### Cited Findings
- Sliver tutorial: sessions = long-polling / constantly maintained TCP; beacons = periodic callback + sleep. “Session can be spun up in our beacon process using the `interactive` command. **Under the hood this will spawn a goroutine running session connection loop in the same beacon process.**” SOCKS5 and high-bandwidth commands are session-only — [2 – Beacons vs Sessions](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions).
- Getting Started: beacons may open interactive sessions over **any C2 protocol they were compiled with**; `close` closes the session (beacon remains). Cannot open HTTP session from an implant compiled without HTTP — [Getting Started](https://sliver.sh/docs?name=Getting+Started).
- Implant: `task.Type == sliverpb.MsgOpenSession { go openSessionHandler(task.Data) }`; `openSessionHandler` unmarshals `OpenSession`, optional `Delay` sleep, then `go func() { connections := transports.StartConnectionLoop(...); sessionMainLoop(connection) }` — [BishopFox `implant/sliver/sliver.go` / runner](https://github.com/BishopFox/sliver/blob/master/implant/sliver/sliver.go) (handler also in [runner.go](https://raw.githubusercontent.com/BishopFox/sliver/master/implant/sliver/runner/runner.go)).
- This UI: `OpenSessionFromBeaconOpts` → RPC `OpenSession` with operator `C2S` (empty = current C2) and `Delay`; comment: “instructs a beacon to open a new interactive session on its next check-in.” `CloseSession` “closes an interactive session **without killing the remote process**.” — [`beacon_ops.go`](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/beacon_ops.go).
- Operator guides: `interactive` leaves the original beacon intact (dual-mode) — [Hackers Arise](https://hackers-arise.com/sliver-building-command-and-controlc2-during-a-cyb/) (2025-07-17).
- Commands that **do** create another process / CRT inject (often run *after* opening a session): `execute-shellcode` (default `notepad.exe` + VirtualAllocEx/WPM/VirtualProtectEx/CreateRemoteThread), `execute-assembly`, `migrate`, `getsystem` → `spoolsv.exe`, `spawndll` / `sideload`. MDE example alert: “A process was injected with potentially malicious code.” — [Microsoft Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/); [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver).
- ASR “Block Office applications from injecting code into other processes” is **Office-only**; it is not a generic CRT block for a wrap EXE — [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference).

### Inferences
- Mental model to discard: “loader was unique → Open Session downloads a new implant → Defender hashes a new file.” Correct model: **same decrypted Go image, louder C2 loop (long-poll vs sleep), same PID.**
- Why sessions die more often than quiet beacons (OPSEC, not a named MDAV rule): long-lived connection, hotter working set, operators immediately run high-signal post-ex. Sleep-encrypt, even if it existed, would **not** cover the interactive window.
- If the lab wrap injected into a host process, Protection History `Path` may show that host EXE, not `*_loader.exe`.

### Gaps
- No Microsoft-published signature that keys specifically on “HTTP long-poll vs beacon interval.” Visibility difference is documented as operator OPSEC and network fingerprinting (Immersive default `.js` long-poll), not as a named inbox family.

---

## Honest sentence: nativizing the stub vs nativizing the implant

### Takeaway
**Nativizing the stub** (rewrite the wrap in C/Nim/Rust, or Formidable’s C launcher + Go DLL, or Praetorian’s outer disguise) can change **first-run PE-ML** (`Wacatac.B!ml` / `gopclntab`) and remove a second Go runtime from the **image** of the process; it does **not** remove `sliverpb` / protobuf RPC names / `Go buildinf:` from decrypted PIC, nor implant `LazyDLL`→`LoadLibraryExW` from unbacked memory, nor `Behavior:Win32/CommandAndControl` on C2. **Nativizing the implant** means source-level identity scrub (protobuf/exports/`bishopfox`) **and** preferably **disk-backed `LoadLibrary` of a cleaned `shared` DLL** — that is the combination Fortbridge actually used to get a callback past Elastic+Defender, and even then built-in commands still alerted. BishopFox’s own policy: AV evasion is **out of Sliver’s scope**; packers/stagers are a delivery layer — [Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion).

### Cited Findings
- Fortbridge: encrypt-in-loader / hollowing / self-inject **ineffective**; success = **rename implant strings/exports + LoadLibrary from the same folder** (tiny host, implant as DLL on disk). Unbacked shellcode loaders failed on `LoadLibraryExW` from private memory. 30 MB blocked stomping. Post-ex commands still hit Elastic behavior — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Formidable: the **EXE shape** is the Wacatac problem; proposed **C launcher + `c-shared` DLL** so the launcher is not Go-shaped. The Go code would still exist in the DLL (scored differently as a DLL, not proven) — [Formidable](https://formidable.tools/posts/defender-wacatac-go-binary/).
- Praetorian: keep **tool source unmodified**; disguise the **outer** Go file (ghost `gopclntab`, upcoming WASM wrap). Explicitly a stub/outer problem. `-s -w` on a Go file **hurt** — [Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/).
- Immersive: packing/staging does not prevent full Go image in RAM — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- Elastic + #1760: protobuf method names survive Garble **in memory of the implant** — [Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar); [sliver#1760](https://github.com/BishopFox/sliver/issues/1760).
- moloch: direct syscalls “typically … most effective to implement **in your loader**”; obfuscated sleep is hard **because of the Go runtime** — [Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171).
- This wrap: Go host + unbacked RWX PIC + `-s -w` + unique hash. That is **stub-side hygiene on the architecture Fortbridge already called ineffective** for live Sliver vs Elastic+Defender — [`windows.go`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go).

### Inferences
- **One sentence:** nativizing the **stub** is how you try to **get the first callback** past Go PE-ML and a noisy Go IAT; nativizing the **implant** (strings + form factor) is how you try to **keep** the callback against memory YARA and unbacked-library behavior — and even that is not a FUD switch, only a different detection surface.
- Product implication: rewriting `windows.go` in C, adding HAL9TH/2 GiB/hang, or skipping CreateThread does **not** substitute for a Sliver fork / disk-DLL path. Hang-after-jump is still worth doing as **correctness**. Unique hash must not be described as keeping a session.
- Dual-Go cost of the current wrap: after jump, the PID contains **stub Go runtime (mapped image)** plus **implant Go runtime (private RWX)**. A C VirtualAlloc host removes only the first. A C `LoadLibrary` host of a cleaned DLL can remove unbacked PIC **if** the DLL is the implant.

### Gaps
- No 2026 public matrix of “C VirtualAlloc+stock PIC vs C LoadLibrary+cleaned DLL vs Go wrap+stock PIC” under **inbox MDAV-only** (Fortbridge’s lab was Elastic **and** Defender).
- Module stomping remains contra-indicated at 16–30 MB; do not reopen it without a size-reduction story.
- Compatibility: protobuf/export renames break stock client/server pairing unless the **teamserver is the same fork**.

---

## Operator claim: “if Defender still kills the session after it opens, the Go loader contribution is useless”

### Takeaway
**Mostly confirmed, with two refinements.** Once a callback exists, XOR / unique SHA-256 / no-CreateThread / hide-console / HAL9TH / 2 GiB / 1.8 s sleep have already done their job or never applied to RAM; they cannot keep a decrypted Sliver image alive against inbox MDAV memory scan + behavior/C2 ML. **Refinement 1:** hang-after-jump is a **lifetime/correctness** contribution, not AV — still useful if PIC returns. **Refinement 2:** delayed 1117 of the **on-disk Go wrap** (`Wacatac.B!ml` cloud retrain) can kill the same PID without memory YARA; that path **is** still stub PE-ML, so nativizing/signing the stub is not always zero after callback. Record Protection History **Name + Path** before attributing the kill.

### Cited Findings
- Inbox MDAV without MDE is Active on Win10/11 when it is primary AV; it remediates (unlike MDE-only passive mode) — [MDAV in Windows](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows); [compatibility without MDE](https://learn.microsoft.com/en-us/defender-endpoint/defender-antivirus-compatibility-without-mde).
- Memory scan is client-only; behavior blocking can stop a **started** process; C2 contact is a documented behavioral technique — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking); [behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment).
- Implant must unpack fully; public YARA is memory-capable; Defender signatures on protobuf strings reported by operators — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [Elastic YARA](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar); [sliver#1760](https://github.com/BishopFox/sliver/issues/1760).
- Encrypt-in-loader ineffective vs Elastic+Defender until implant source + disk LoadLibrary — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Wacatac is static PE-ML on Go files; can be clean dynamically and still flag; cloud more aggressive than local MpCmdRun; daily retrain — [Formidable](https://formidable.tools/posts/defender-wacatac-go-binary/); [Praetorian](https://www.praetorian.com/blog/llm-edr-signature-reduction/).
- `interactive` is same-process goroutine — [Beacons vs Sessions](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions); implant `openSessionHandler`; [`beacon_ops.go`](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/beacon_ops.go).

### Inferences
- **If Name is protobuf / `sliverpb` / `Go buildinf` / `Behavior:Win32/CommandAndControl` / unbacked library:** Go wrap contribution to **that kill** is spent. Next work is implant identity + form factor (external fork / disk DLL), not more XOR.
- **If Name is `Wacatac.B!ml` (or generic Go ML) and Path is the wrap EXE:** stub still in play; `-s -w` may be hurting; C launcher or signing is the Formidable/Praetorian lever. Still not a claim of unique-hash bypass.
- **If process died ~2 s, no 1116, file still on disk:** hang/trampoline/RDI — not Defender. Do not blame AV.
- Honest product line: this wrap is a **lab host** that must stay alive after `CALL`. It is not the layer that keeps a live Sliver session in front of inbox Defender’s memory and behavior engines.

### Gaps
- This pass did not detonate the wrap on Windows 11 with Defender on; kill-class attribution in a real lab **requires** 1116/1117 Name+Path+Process (and `Get-MpComputerStatus` `OnboardingState` / `AMRunningMode`).
- Exact current MDAV family string for stock Sliver-in-memory is not in Microsoft Learn; do not invent `Trojan:Win64/Sliver.*`.
