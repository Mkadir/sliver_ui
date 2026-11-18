# Microsoft Defender detection layers vs Go shellcode loaders and live Sliver (2025–2026)

Authorized red-team / adversary-simulation research notes. Current as of 2026-11. Older claims are marked dated. Every non-obvious claim has an inline source URL. No exploit PoCs, no “paste this to FUD.”

**Scenario (a):** unsigned custom Go EXE that allocates RW, decrypts an embedded blob, flips RW→RWX (or RX), then CALLs PIC on a private stack (no CreateThread).

**Scenario (b):** live Sliver session/beacon already in memory after callback (Go runtime + protobuf implant, network, post-ex).

Defender here means the stack that actually runs on a Windows 10/11 endpoint: Microsoft Defender Antivirus (MDAV / `MsMpEng` + `mpengine` + `WdFilter`) plus optional Microsoft Defender for Endpoint (MDE) EDR, Attack Surface Reduction (ASR), SmartScreen / Smart App Control, AMSI, ETW-Ti, and cloud-delivered protection (MAPS / Block at First Sight).

---

## Layer map: what would fire on (a) the Go loader vs (b) a live Sliver beacon

### Takeaway
Defender is a hybrid of **pre-execution** (local PE ML, VDM/YARA heuristics, emulator, cloud metadata + optional sample detonation, SmartScreen hash/publisher reputation, ASR) and **post-execution** (behavior monitoring, ETW-Ti on alloc/protect/write, memory scanning of process address space, AMSI only when a supported host feeds it, network/C2 ML). A unique XOR’d blob and a unique SHA-256 defeat **only** exact-hash VDM / SmartScreen hash reputation; they do not defeat PE-feature ML, emulator unpack, ETW-Ti on `NtProtectVirtualMemory`, or in-memory family YARA once the implant is plaintext.

### Cited Findings
- Microsoft documents hybrid client+cloud engines: client ML (PE-specific), behavior monitoring, memory scanning, AMSI, heuristics, emulation, network, command-line scanning; cloud metadata ML, behavior ML, AMSI-paired ML, full-file classification ML, detonation ML, reputation ML (SmartScreen), smart rules — [Advanced Technologies at the Core of Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav).
- Memory protection is explicitly a **client** function (behavior monitoring, AMSI, emulation, memory scanning). There is **no** cloud counterpart for the memory-scanning engine — [adv-tech-of-mdav, “Memory protection and memory scanning”](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav).
- Cloud metadata sent on inconclusive local verdicts includes PE attributes, multiple hashes (SHA-1/256, ImpHash, fuzzy hashes), signer info, process/parent, MotW, download IP/URL, **API calls**, and **process injection** — [Cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission).
- Block at First Sight (BAFS) only consults the cloud backend for files from the **Internet zone**; default lock is **10 seconds** (extendable to 60) while the cloud detonates — [Configure block at first sight](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus); [Cloud block timeout](https://learn.microsoft.com/en-us/defender-endpoint/configure-cloud-block-timeout-period-microsoft-defender-antivirus).
- Behavior-based detections are named by MITRE tactic, e.g. `Behavior:Win32/Execution.*!ml`, `Behavior:Win32/DefenseEvasion.*!ml`, `Behavior:Win32/CommandAndControl.*!ml`. Client behavioral blocking can stop a process **after it has started**. Engine event **1015** `MALWAREPROTECTION_BEHAVIOR_DETECTED` is distinct from file-hash 1006 / cloud 1116; event **2050** is sample submission — [Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking); [Defender event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus).
- Documented post-execution techniques Microsoft says behavioral blocking has stopped include **cross-process injection**, **process hollowing**, **C2 payload download**, LSASS dumping, AV tampering — [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment).
- Microsoft (2022, still the primary vendor Sliver hunt): default Sliver `migrate` / `sideload` / `spawndll` / `execute-assembly` is `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`; MDE alert example **“A process was injected with potentially malicious code”** — [Looking for the ‘Sliver’ lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Fortbridge (Apr 2025) vs Elastic+Defender: staged/self-inject/pack of stock Sliver “proved ineffective”; extracted Defender YARA keyed on `GetJitter` / `VoidFunc` / `AddTunnel` / `GetIsIOC` / ` Go buildinf:` plus DLL exports; Elastic then alerted **“Network Library Loaded from Unbacked Memory”** when Go `LazyDLL`/`LoadLibraryExW` ran from private executable memory — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Kernel ETW-Ti (`Microsoft-Windows-Threat-Intelligence`) logs local **and** remote `ALLOCVM`, `PROTECTVM`, `MAPVIEW`, `WRITEVM`, `QUEUEUSERAPC`, `SETTHREADCONTEXT` from inside `ntoskrnl` (`EtwTiLogAllocExecVm`, `EtwTiLogProtectExecVm`). Subscribers must be PPL-Antimalware (Defender is one) — [adanto/EtwTiViewer](https://github.com/adanto/EtwTiViewer); [MeekoLab ETW-TI intro](https://research.meekolab.com/introduction-into-microsoft-threat-intelligence-drivers-etw-ti); Elastic 8.11 call-stack rules — [Doubling Down: Kernel ETW Call Stacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).

### Inferences
- For **(a) the Go loader**: first-run of a new MotW EXE hits SmartScreen (unknown hash, unsigned) **and** MDAV local PE ML + emulator + cloud metadata; if the cloud cannot decide, BAFS can lock and upload the sample for detonation. If the file is not MotW (USB copy, internal share, `CreateProcess` from a trusted parent), SmartScreen is skipped but MDAV still scans. Runtime: ETW-Ti sees `NtAllocateVirtualMemory` + `NtProtectVirtualMemory` even with no `CreateThread`. Memory scan / behavior ML can still fire on decrypted PIC in private RX/RWX.
- For **(b) live Sliver**: on-disk family YARA is irrelevant once the implant is only in memory; remaining kills are **memory YARA** (protobuf / `sliverpb` / bishopfox / `Go buildinf`), **unbacked executable memory + network DLL load**, **injection API sequence** on post-ex (`migrate`, `execute-assembly`), and C2 network heuristics. Lack of sleep-mask (Fortbridge) leaves plaintext Go/protobuf in idle memory for periodic/triggered scans.
- Hash uniqueness is a **reputation** control, not a **content** control. Cloud ML and the emulator operate on PE structure, imports, entropy, unpacked bytes, and observed APIs.

### Gaps
- Microsoft does not publish the live feature weights of the PE ML models, the exact mpengine YARA that ships in VDM, or a public list of `Behavior:Win32/*` subfamilies beyond the MITRE-tactic prefix. Extracted rules (e.g. [roadwy/DefenderYara](https://github.com/roadwy/DefenderYara)) lag the cloud.
- Exact names `Exploit:Win32/ShellCode` and `Behavior:Win32/AllocatedAndExecute` were **not found** in current Microsoft Learn or WDSI threat pages during this pass; do not treat them as confirmed 2025–2026 MDAV family names. Kaspersky publishes `Exploit.Win32.Shellcode.*` as **their** family — [Kaspersky Exploit.Win32.Shellcode.cgod](https://threats.kaspersky.com/en/threat/Exploit.Win32.Shellcode.cgod/).
- `VirTool:Win32/OffensiveGo` was **not found** as a Microsoft family. Closest public names: Elastic `Multi.Trojan.Goffloader` / `Multi_Trojan_Sliver`; Kaspersky `Trojan.Win64.OffensiveGolang.*`; Microsoft generic `Trojan:Win32/Wacatac.B!ml`, `VirTool:Win32/Obfuscator.*`, `Trojan:Win32/CryptInject`, and the AMSI-stub name **`Win32/AMSI_Patch_T.B13`**.

---

## What does Defender look at for unsigned Go binaries with high-entropy .data/.rdata embeds?

### Takeaway
Unsigned Go EXEs are scored as **PE files** by type-specific client and cloud ML (size, section entropy, import sparsity, `gopclntab`/buildinfo, lack of Authenticode), plus generic heuristics for packed/high-entropy sections and any remaining **string/YARA** (protobuf, bishopfox, Donut stub, `Go buildinf`). High entropy in `.data`/`.rdata` is a **suspicious feature**, not a kill by itself; combining it with a tiny IAT, no signature, and atypical `gopclntab` is what pushes `Wacatac` / `ML.Attribute.HighConfidence`-class verdicts.

### Cited Findings
- Client ML includes “specialized models and features … built for specific file types,” with PE as the first example; cloud metadata ML uses file-type-specific, feature-specific, and **adversary-hardened monotonic** models, stacked into a pre-execution allow/block — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); original 2019 writeup of the same architecture — [Inside out (2019, dated but still the canonical engine list)](https://www.microsoft.com/en-us/security/blog/2019/06/24/inside-out-get-to-know-the-advanced-technologies-at-the-core-of-microsoft-defender-atp-next-generation-protection/).
- Cloud metadata examples include ImpHash, several CRC/fuzzy hashes, SHA-256, FileSize, FileName, Authenticode fields, process/parent, MotW, API calls, process injection — [Cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission).
- Praetorian (28 May 2026): modern EDR hits on Go binaries are **dominated by statistical ML** (`Wacatac.B!ml`, `ML.Attribute.HighConfidence`, `MalwareX-gen`, `Evo-gen`) rather than fixed-byte YARA; stripping `-s -w` **increased** detections; ML over-indexes on **`gopclntab`** (a small, runtime-only symbol table looks like minified malware; a large, project-like table dilutes it). Diluting `gopclntab` with a large “ghost profile” dropped Microsoft Wacatac from ~95% to ~20% on otherwise-identical payloads. Microsoft **cloud** ML is “substantially more aggressive” than local `MpCmdRun.exe`; a 100% Wacatac VT hit can be clean locally. Wacatac retrains on roughly a **daily** cadence, so yesterday’s control is not a valid A/B. Fake MSVC Rich header / patched linker version made detections **worse** (“Don’t fight the toolchain”) — [Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/); skill README — [praetorian-inc/reduce-golang-detections-skill](https://github.com/praetorian-inc/reduce-golang-detections-skill).
- Formidable (23 May 2026): a **benign** Wails 3 + Go 1.25 GUI (`Formidable.exe`) was flagged `Trojan:Win32/Wacatac.B!ml` on VT (Microsoft + Trapmine on the NSIS installer). Four VT sandboxes (CAPA/CAPE/Jujubox/Zenbox) returned **0 dynamic detections**. VersionInfo, Win10/11 manifest, dropping `-s -w`, reproducible `-buildid=`, NSIS polish, and an FP submission **did not** change the score. Author’s diagnosis: the classifier weights **Go PE shape** (large `.text`, `gopclntab`, `runtime.morestack_noctxt` / `runtime.gcWriteBarrier`, statically linked, no CRT) because Go malware volume since ~2020 (BlackCat, Sliver, stealers) trained “Go-shaped unsigned EXE” as a positive malware feature. Same product as Electron had never been flagged — [Formidable: Defender, Wacatac.B!ml, and the Go-binary problem](https://formidable.tools/posts/defender-wacatac-go-binary/).
- Fortbridge (2025) extracted Defender-oriented YARA hitting ASCII `DllRegisterServer`/`DllUnregisterServer`/`DllInstall`, `GetJitter`, `VoidFunc`, `GetKill`, `AddTunnel`, `GetIsIOC`, and ` Go buildinf:` — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Elastic `Multi_Trojan_Sliver` (file+memory) keys on protobuf method strings (`ScreenshotReq`, `HTTPSessionInit`, `InvokeSpawnDllReq`, …) and `github.com/bishopfox/sliver/protobuf` — [Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar).
- Immersive Labs YARA matches PE/ELF plus `sliverpb`, `github.com/bishopfox/`, `chacha20poly1305`; a separate **memory** rule matches `sliverpb` alone — [sliver.yar](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.yar); [Immersive writeup](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- BishopFox maintainers: garble often **fails to obfuscate protobuf methods**, “easy signatures”; a later maintainer comment notes **several Defender AV signatures detecting these strings** — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760) (opened 2024-08; moloch comment 2025-01-06).
- Dated (2022) but still the project policy: “AV evasion is out of scope”; ThreatCheck on default `generate beacon` found a **static Defender signature** — [BishopFox/sliver#833](https://github.com/BishopFox/sliver/issues/833). Dated (2021): DefenderCheck isolated **`sliverpb`** as the hit — [BishopFox/sliver#481](https://github.com/BishopFox/sliver/issues/481).
- Typical Sliver Windows implant is large (~16 MB Immersive; up to ~30 MB Fortbridge), which raises on-disk visibility and blocks module stomping — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Heuristics engine: “identify file characteristics that have similarities with known malicious characteristics” (generic packed/modified-known-threat catch) — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav).
- Emulation engine “dynamically unpacks malware and examines how they would behave at runtime”; scans **behavior during emulation and memory content at the end of emulation** to defeat packers and polymorphic malware — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav).
- SmartScreen for unsigned files: each new hash starts at **zero reputation**; warning “Windows protected your PC”; enterprise policy can forbid “Run anyway.” Smart App Control on Windows 11 **blocks unsigned files unless they already have positive reputation**, and those signature checks apply to **all** executables, not only MotW downloads — [SmartScreen reputation for developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation); [SmartScreen overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/).

### Inferences
- A custom Go loader that XOR-embeds a high-entropy blob in `.rdata` looks, to PE ML, like **packed malware**: high section entropy + unusual size + unsigned + Go runtime + sparse/suspicious imports (`VirtualAlloc`/`VirtualProtect`/`CreateThread` if present). XOR does not lower entropy of the ciphertext blob (XOR with a repeating or short key can even raise it). Formidable shows **even a clean GUI Go EXE** can trip `Wacatac.B!ml` on PE shape alone; adding an encrypted blob does not make that better.
- Stock Sliver on disk is still primarily a **string/YARA** problem (`sliverpb`, bishopfox, protobuf names, `Go buildinf`, DLL exports). A *custom* loader that never contains those strings shifts the static problem onto **ML + entropy + unsigned + emulator**.
- `Wacatac.B!ml` is a generic Microsoft ML family widely seen on Go tooling; it is not Sliver-specific. Praetorian’s 2026 result is the best public evidence that **Go structural features** (gopclntab, strip flags, entropy) move that classifier.

### Gaps
- Microsoft has not published that it specifically scores “Go `.data` entropy > 7.0.” Entropy as a packed-file heuristic is industry-standard and is listed by Intel AMS as one of the offloaded scan features ([Wikipedia TDT / AMS](https://en.wikipedia.org/wiki/Intel_Threat_Detection_Technology)), but the exact MDAV PE-model feature list is closed.
- No public 2025–2026 quantitative MDAV detection rate for “hello world Go EXE vs XOR-embedded blob Go EXE” under identical cloud protection levels.

---

## How effective is XOR + unique SHA-256 + random buildid against cloud ML / VDM / SmartScreen?

### Takeaway
**Hash uniqueness is weak.** A new SHA-256 resets SmartScreen *file-hash* reputation and misses exact-hash VDM entries, but: (1) unsigned files still warn/block on publisher reputation; (2) cloud ML scores **features**, not the hash; (3) BAFS can upload the new hash for detonation; (4) XOR of a known family (Donut stub, Sliver PIC) is what the **emulator and memory scanner** exist to undo; (5) random `buildid` does not rename protobuf or `gopclntab` runtime symbols. Praetorian 2026: fighting the Go toolchain (fake MSVC Rich header, strip all symbols) **increased** ML detections.

### Cited Findings
- SmartScreen evaluates **publisher reputation** (Authenticode) **and** **file-hash reputation**. Unsigned: reputation must be rebuilt **for every new version**, starting at zero. “There is no exact threshold, but it can take several weeks and hundreds of clean installs.” EV certificates **no longer** confer instant positive reputation — [SmartScreen reputation for developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation) (updated 2026-05).
- Changing one bit moves a file from SmartScreen “Known Bad” to “Unknown”; SmartScreen is **not antivirus**. MDAV still scans content and behavior — [SmartScreen Application Reputation, with Pictures (Eric Law, 2023; still accurate vs 2026 Learn)](https://textslashplain.com/2023/08/23/smartscreen-application-reputation-in-pictures/).
- BAFS: hash is checked in the cloud; if unknown **and Internet-zone**, the file is locked and a copy uploaded; cloud “heuristics, machine learning, and automated analysis” / detonation decide allow-or-block for **all future encounters of that hash** — [Configure BAFS](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus).
- Default sample policy is **Send safe samples automatically**; `.exe`/`.dll` are “safe samples” (no PII prompt). Disabling sample submission disables BAFS sample analysis; **metadata is still sent** — [Cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission).
- 11–12 Nov 2026: Defender uploaded **217 samples** from one developer PC over ~3 months under default `SubmitSamplesConsent=1` (Send safe samples); **201 were builds of the same unreleased Go test program**. Event **2050** = “antimalware platform submitted a file for sample analysis.” Setting `SubmitSamplesConsent=2` (Never send) was logged as event 5007 and later flipped back to 1. Microsoft: Never send **disables BAFS sample analysis**; metadata is still sent. Values: 0 always prompt, 1 send safe (default), 2 never, 3 send all — [Privacy Affairs writeup of Stimpson logs](https://www.privacyaffairs.com/microsoft-defender-sample-submission/); [Cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission); [Defender event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus).
- Emulation unpacks and scans **memory at end of emulation**; XOR/packer stubs that decode in the first N emulated instructions are in-scope — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav).
- Sleep-based anti-emulation is an old, known cat-and-mouse: AV emulators skip or collapse `Sleep`/`NtDelayExecution` (Bulazel BH USA 2018 RE of Defender’s emulator; dated but the engine still exists) — [Windows Defender Emulator Tools](https://github.com/0xAlexei/WindowsDefenderTools); [BH USA 2018 slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf).
- Praetorian 2026: unique hashes + garble + strip **did not** beat Microsoft/CrowdStrike ML; larger legitimate-looking `gopclntab` did more than XOR/string rename; “Don’t fight the toolchain” — [Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/).
- AhnLab `Trojan/Win.Sliver.R774471` in that same work was a **fixed-string YARA** on a fake Authenticode subject — a reminder that **signing can add** signatures even as it helps SmartScreen — [Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/).
- Fortbridge: default Donut AMSI bypass inside Sliver shellcode generation is **itself signatured**; they had to change Donut bypass 3→1 — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Donut GitHub #165 (Dec 2024–2025): stock Donut C stub started getting MDAV kills on `CreateRemoteThread` inject even after encoder changes; maintainers attributed it to the **AMSI-bypass stub**, not just the PIC bytes — [TheWover/donut#165](https://github.com/TheWover/donut/issues/165).
- BishopFox/sliver#1814 (Nov 2024): operators reported MDAV family **`Win32/AMSI_Patch_T.B13`** killing Sliver; the reporter attributed it to the **built-in AMSI patch** with no generate-time disable switch — [sliver#1814](https://github.com/BishopFox/sliver/issues/1814).
- gatari (Mar 2024, **dated** lab vs MDAV): XOR of msfvenom PIC beat **on-disk** signatures; `VirtualAlloc(PAGE_EXECUTE_READWRITE)` + `RtlMoveMemory` + **direct CALL** of the RWX region was then **killed at runtime** (behavior, not a byte offset). After the sample was uploaded to VirusTotal, local `MpCmdRun` later treated the **entire file hash** as known-bad (“bad bytes at the very end” / no isolatable offset) — cloud analysis, not a new VDM string. Author explicitly warns that Defender cloud protection / sample submission will do the same on a target even if you never used VT — [A Trip Down Memory Lane](https://gatari.dev/posts/memory-lane/).

### Inferences
- XOR + new SHA-256 + random Go buildid is the 2018 playbook. In 2025–2026 it buys: (i) no exact-hash hit, (ii) SmartScreen “Unknown” instead of “Known Bad.” It does **not** buy: PE-ML clean, emulator-clean, BAFS-skip (if MotW), memory-scan-clean after decrypt, or ETW-Ti-quiet alloc/protect.
- If the first MotW run is detonated in the cloud and the emulator reaches the decrypted PIC / Sliver strings / VirtualProtect sequence, **that hash becomes Known Bad globally** via feedback-loop blocking — [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment) (feedback-loop / rapid protection).
- Randomizing `buildid` is near-zero cost and near-zero benefit against Defender: ` Go buildinf:` as a **format marker** still exists; protobuf and `gopclntab` dominate.

### Gaps
- No public Microsoft statement of emulator instruction budget or which Win32 APIs are fully emulated in 2025–2026 mpengine (Bulazel’s offsets are 2018).
- No public figure for “what fraction of first-seen unsigned Go EXEs are sample-uploaded vs metadata-only.” Stimpson’s logs show **Go EXEs are in the upload class** under default policy.

---

## Memory scanning: private RWX / PIC (Sliver, Donut, Cobalt-like)

### Takeaway
Yes — MDAV has a dedicated **memory scanning engine** that reads target-process memory (`ReadProcessMemory` from `mpengine`) and matches signatures (researchers describe BM/string matching, i.e. the same class of content as file VDM). Triggers include module-load notifications from `WdFilter`, behavioral events, and (on Intel clients) GPU-offloaded Accelerated Memory Scanning. Private RWX/RX containing decrypted Donut/Sliver/CS PIC is in-scope. Family names that actually appear in public sources: Elastic `Multi_Trojan_Sliver` (memory), Joe/ANY.RUN `DonutLoader` memory YARA, Microsoft `HackTool:Win32/Mikatz!dha` as the documented reflective-DLL example, MDE “process was injected…”, `Behavior:Win32/*!ml`, `Trojan:Win32/Wacatac.B!ml` (Go PE ML, including **benign** unsigned Go), `Win32/AMSI_Patch_T.B13` (Sliver/Donut AMSI stub, Nov 2024). Microsoft does **not** publish a current `Trojan:Win64/Meterpreter`, `Behavior:Win32/CobaltStrike`, `VirTool:Win32/OffensiveGo`, `Exploit:Win32/ShellCode`, or `Behavior:Win32/AllocatedAndExecute` catalog entry in the pages reviewed; those names circulate in third-party blogs / Kaspersky catalogs and should be treated as **unverified MDAV family strings** unless seen in Protection history.

### Cited Findings
- Official: “Memory scanning engine … scans the memory space used by a running process to expose malicious behavior that could be hiding through code obfuscation.” Client-only (no cloud memory-scan engine). AMSI is listed as a **separate** memory-protection engine. Reflective DLL loading is the documented example — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [AMSI on MDAV](https://learn.microsoft.com/en-us/defender-endpoint/amsi-on-mdav) (“Detecting reflective DLL injection through enhanced memory scanning techniques and behavioral monitoring”).
- Independent RE (Chinese-language analysis of `mpengine` 4.18.2209-era, still the most detailed public map): `WdFilter` module-load → `MpRtp.dll` thread pool → `mpengine!TriggerEmsScan` / `CEMSContext::EmsScan`; implementation is `ReadProcessMemory` + signature match. Removing WdFilter’s **module-load** callback stopped the scan; removing other callbacks did not. Other `SignatureHandler::HandleNotification` events exist (not fully enumerated) — [WeChat/RE writeup of Defender memory scan](https://mp.weixin.qq.com/s/C6CePu9albvGTj3_9aUxeg).
- Intel TDT **Accelerated Memory Scanning** (since 2018, default when MDAV is on, Windows 10/11 client, Intel 6th-gen+ iGPU): extra memory scanning for fileless attacks, offloaded to GPU; detections still surface as MDAV Event **1116**. Features described for AMS generally include pattern matching, entropy, string extraction — [Hardware acceleration and MDAV](https://learn.microsoft.com/en-us/defender-endpoint/hardware-acceleration-and-mdav); [Intel TDT](https://www.intel.com/content/www/us/en/architecture-and-technology/vpro/vpro-security/threat-detection-technology.html).
- BorderGate (2022, **dated** but widely cited): Defender scanned memory when `CreateProcess` / `CreateRemoteThread` ran; classic CRT inject of RWX shellcode was killed at thread start. Their workaround (PAGE_NOACCESS around the scan window) is a **known, likely signatured** trick in 2025 — [Windows Defender Memory Scanning Evasion](https://www.bordergate.co.uk/windows-defender-memory-scanning-evasion/).
- Fortbridge 2025: Sliver in unbacked memory loading network DLLs → Elastic **Network Library Loaded from Unbacked Memory**; implant too large to stomp; **no sleep mask** → idle memory is YARA-scannable — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Immersive: memory detection remains strong because the **full Go implant must unpack into memory** regardless of packing — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- Elastic 8.11+ behaviors on the same ETW-Ti stream Defender consumes: `unbacked_rwx`, `shellcode`, `allocate_shellcode`, `execute_shellcode`, `execute_fluctuation`, `write_fluctuation`, `hidden_code` (`PAGE_NOACCESS` on executable memory), `guarded_code` (`PAGE_GUARD`), `sensitive_api` from non-image executable memory — [Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- Donut: ANY.RUN/Joe Sandbox 2025–2026 reports match **DonutLoader YARA in memory dumps** of injected processes, independent of on-disk hash — e.g. [ANY.RUN DonutLoader trend](https://any.run/malware-trends/donutloader/); [Triage donutloader memory rule](https://tria.ge/251105-ajhb9afn9x/behavioral1).
- Microsoft 2022 Sliver hunt: MDE alerts on injected code; hunt GetSystem into `spoolsv.exe`, default sacrificial `notepad.exe`, PsExec service named “Sliver” / “Sliver implant” under `%WINDIR%\Temp` — [Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Elastic `Multi_Trojan_Sliver` ships **file and memory** rules — [protections-artifacts](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar).

### Inferences
- For **(a)**: after XOR decrypt, PIC bytes sit in `MEM_PRIVATE` RX/RWX. That region is visible to: (1) ETW-Ti alloc/protect events, (2) behavior engine, (3) memory scanner (periodic, module-load-triggered, or CreateThread-triggered), (4) Intel AMS on supported CPUs. Direct CALL (no new thread) avoids **thread-create** triggers but does **not** hide the pages.
- For **(b)**: a live Sliver beacon is a multi-MB Go image in private or image memory with `sliverpb` strings. Memory YARA is the cheap durable detector. Sleep-mask absence is an explicit Fortbridge pain point.
- PAGE_NOACCESS / sleep-encrypt (Cobalt-style sleep mask) maps onto Elastic’s `hidden_code` / `execute_fluctuation` / `write_fluctuation` behaviors. Microsoft has not published equivalent public rule names, but ETW-Ti `PROTECTVM` fires on every flip.

### Gaps
- Microsoft has not published whether memory scans enumerate **all** private executable VADs or only regions touched by recent VirtualProtect/CreateThread. The WeChat RE shows module-load as one trigger, not the only one.
- Public confirmation that MDAV ships **Cobalt Strike / Meterpreter / OffensiveGo** memory signatures under those exact names was **not found** in Microsoft Learn / WDSI in this pass.
- No 2025–2026 Microsoft blog that says “we YARA-scan RWX for Donut PIC” in those words; the capability (memory scanning + family YARA in memory) is documented, the specific PIC signatures are inferred from Donut issue #165 and sandbox YARA.

---

## Does RW → RWX (or RW → RX) itself get behavioral detections?

### Takeaway
The permission flip is a **first-class telemetry event**, not a no-op. ETW-Ti logs `PROTECTVM_LOCAL` from `nt!EtwTiLogProtectExecVm` on `NtProtectVirtualMemory`. Elastic (same provider) labels `execute_fluctuation` / `write_fluctuation` / `unbacked_rwx` / `hook_unbacked` / `hollow_unbacked`. Microsoft’s published behavior names are MITRE-tactic `Behavior:Win32/*!ml`, not a public `AllocatedAndExecute` family. The flip **alone** is common in JIT/game/runtime code so it is rarely a sole block; combined with **unsigned process + private memory + subsequent execution or sensitive API from that region**, it is a standard shellcode-loader graph.

### Cited Findings
- ETW-Ti keywords include `KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL` / `_REMOTE` and `ALLOCVM_*`; `VirtualAlloc` RWX is called out as the “bad” example that fires `EtwTiLogAllocExecVm` — [EtwTiViewer](https://github.com/adanto/EtwTiViewer); [fluxsec ETW-TI](https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer); [paragmali ETW substrate (2026)](https://paragmali.com/blog/etw-how-windows-2000s-performance-hack-became-the-edr-substr/).
- Elastic 8.11: `execute_fluctuation` = “PAGE_EXECUTE protection is unexpectedly fluctuating”; `write_fluctuation` = write perm of executable memory fluctuating; `unbacked_rwx`; `allocate_shellcode`; `hook_unbacked` / `hollow_unbacked` on VirtualProtect of non-image executable memory — [Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- Microsoft lists **cross-process injection** and **process hollowing** among techniques behavioral blocking has stopped — [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment).
- r-tec (Feb 2025): Defender raises an alert and **kills the process** when `AmsiScanBuffer` (or several other security functions) is made writable and patched — i.e. a **VirtualProtect + write** on a sensitive image region is already a high-confidence behavior, via ETW-Ti then a memory scan of the function — [Bypass AMSI in 2025](https://www.r-tec.net/r-tec-blog-bypass-amsi-in-2025.html).
- Cloud metadata explicitly can include **API calls** and **process injection** — [Cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission).

### Inferences
- RW→RWX in the loader’s **own** process is noisier than RW→RX (W^X-shaped), but **both** generate `PROTECTVM`. Staying at RWX from `VirtualAlloc` is often *worse* (single ALLOCVM-exec event + “allocated RWX” heuristic).
- A private-stack CALL after the flip is still “execute from non-image memory.” Elastic names that `execute_shellcode` / `sensitive_api`. Microsoft’s equivalent is folded into behavior ML + memory scan, not a separately documented family.
- Do not expect “we never called VirtualProtectEx on another process” to hide a **local** flip; ETW-Ti has LOCAL and REMOTE variants.

### Gaps
- No Microsoft public signature literally named `Behavior:Win32/AllocatedAndExecute` or `Exploit:Win32/ShellCode` was found. Treat those as **unconfirmed folklore names**.
- No public ROC curve for “local RW→RX in a signed vs unsigned Go process.”

---

## CreateThread vs direct CALL: does skipping CreateThread evade Defender in 2025–2026?

### Takeaway
**No, not against kernel telemetry.** Skipping `CreateThread`/`CreateRemoteThread` avoids: thread-notify callbacks, Sysmon Event 8, the historical “scan on CreateRemoteThread” memory-scan trigger, and MDE’s documented CRT-sequence alert. It does **not** avoid: ETW-Ti `ALLOCVM`/`PROTECTVM`/`WRITEVM`, WdFilter/behavior engines, memory scanners walking executable private VADs, Intel AMS, or call-stack based “sensitive API from unbacked memory.” Direct CALL of PIC is the *local* analogue of threadless inject; Elastic already has rules for unbacked callers. Microsoft’s 2022 Sliver writeup still keys on CRT because **stock Sliver uses CRT**; that is a stock-implant fact, not a guarantee that CRT-less loaders are invisible.

### Cited Findings
- ETW-Ti fires from `MiAllocateVirtualMemory` / protect / map / write paths **independent of thread creation**. `QUEUEUSERAPC` and `SETTHREADCONTEXT` are additional, not required, events — [MeekoLab](https://research.meekolab.com/introduction-into-microsoft-threat-intelligence-drivers-etw-ti); [EtwTiViewer](https://github.com/adanto/EtwTiViewer).
- Elastic: `sensitive_api` = “Executable non-image memory is unexpectedly calling a sensitive API”; `shellcode` = same with extra suspicion; `execute_shellcode` = non-image executable memory executed in an unexpected fashion. These are **call-stack** properties, not CreateThread properties — [Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- Microsoft 2022: Sliver *migrate* uses VirtualAllocEx + WriteProcessMemory + VirtualProtectEx + **CreateRemoteThread**; MDE alert “A process was injected with potentially malicious code.” Other commands (Sideload, SpawnDll, Execute-Assembly) “also rely on this combination” **as of that writing** — [Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/). Dated: 2022; TTP still matches current Sliver defaults per Fortbridge 2025 and Hunt & Hackett 2024 (`execute-shellcode` → notepad + VirtualAllocEx RW → WPM → VirtualProtectEx RX → CRT; Sysmon 1/8/10) — [Hunting for a Sliver in a haystack](https://www.huntandhackett.com/blog/hunting-for-a-sliver).
- gatari (2024, **dated**): **direct CALL** of local RWX PIC (no CreateThread) was **still process-killed** by MDAV after XOR beat the on-disk scan. Switching to EarlyBird APC into notepad then “worked” in that lab — that is **remote inject**, which Microsoft’s 2022 Sliver hunt and Elastic unbacked/CRT rules exist to catch. Treat the APC “win” as a single dated lab, not a 2026 strategy — [A Trip Down Memory Lane](https://gatari.dev/posts/memory-lane/).
- Donut #165 (2024-12): even after stub changes, **CreateRemoteThread inject** still “fast fails” MDAV; a different (pe-to-shellcode) payload with the **same** CRT API did not — i.e. the kill was **content + CRT trigger**, not CRT alone — [donut#165](https://github.com/TheWover/donut/issues/165).
- BorderGate 2022 (**dated**): memory scan on CreateRemoteThread — [BorderGate](https://www.bordergate.co.uk/windows-defender-memory-scanning-evasion/).
- ThreadlessInject is detected by Elastic via **WriteProcessMemory to ntdll/kernelbase in a remote process** (export hook), not via CreateRemoteThread — [Doubling Down, “Windows System Module Remote Hooking”](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).

### Inferences
- Direct CALL of local PIC is a **detection-surface reduction**, not an evasion. It is the correct OPSEC relative to CRT (fewer alerts, no Sysmon 8), but 2025–2026 kernel ETW + memory scan still see the pages and the first sensitive API from them (WinINet/WinHTTP/LoadLibrary from the PIC, or Go `LazyDLL` as in Fortbridge). gatari 2024 is a concrete counter-example to “CALL instead of CreateThread = Defender-blind”: MDAV killed the RWX+CALL graph **without** a new thread.
- For **(b)**, once the beacon is running, subsequent Sliver post-ex that still uses CRT (`migrate`, default `execute-assembly` fork-and-run) reintroduces the 2022 MDE alerts even if the loader itself never called CreateThread.

### Gaps
- No public Microsoft 2025–2026 paper that A/B tests “same PIC, CreateThread vs direct CALL vs APC vs fiber” under MDAV+MDE. Elastic’s rule pack is the closest open analog of what ETW-Ti consumers *can* do.
- Whether MDAV’s memory scanner still **special-cases** `NtCreateThreadEx` in 24H2 (BorderGate 2022 behavior) is unverified in primary Microsoft docs.

---

## AMSI: native Go EXE vs later Beacon / BOF / .NET

### Takeaway
**AMSI is not in the path of a native Go EXE or native PIC/BOF.** Microsoft lists AMSI hosts as PowerShell, JScript, VBScript, WSH, WMI, **.NET Framework 4.8+ (all assemblies)**, and Office VBA/JS/XLM. Native code is covered by PE scan, emulator, ETW-Ti, and memory scan instead. AMSI **re-enters** when Sliver/`execute-assembly` reflectively loads a .NET assembly, when a PowerShell stager runs, or when Donut’s built-in AMSI/WLDP/ETW patches execute (those patches are themselves signatured). Putting an AMSI bypass in a native Go loader is extra IOC for no benefit.

### Cited Findings
- Supported AMSI languages: PowerShell, Jscript, VBScript, WSH, **.NET Framework 4.8 or newer (scanning of all assemblies)**, WMI; Office JS/VBA/XLM. Not Python/Perl. Enable via script scanning. AMSI “doesn’t currently support Python or Perl” — [AMSI on MDAV](https://learn.microsoft.com/en-us/defender-endpoint/amsi-on-mdav) (updated 2026-05).
- CoreCLR: `Amsi::IsBlockedByAmsiScan` is documented to run on **in-memory loads** (`Assembly.Load(byte[])`); “Loads from disk are already instrumented by Defender, so calling AmsiScanBuffer wouldn’t do anything” — [dotnet/runtime `amsi.cpp`](https://github.com/dotnet/runtime/blob/main/src/coreclr/vm/amsi.cpp).
- r-tec Feb 2025: “if you are using a C2 framework’s payload and are mainly running BOF’s or COFF’s … you will **never need to bypass AMSI at all**. If you do implement a bypass in your loader, you will only increase the IoCs.” Classic `AmsiScanBuffer` entrypoint patch: Defender now **kills the process** via ETW-Ti + memory scan of the function prologue — [Bypass AMSI in 2025](https://www.r-tec.net/r-tec-blog-bypass-amsi-in-2025.html).
- IBM X-Force (2025): AMSI scans reflectively loaded assemblies; traditional patches leave CoW bytes in `amsi.dll`. CLR hosting `Load_2` (pretend disk load) skips AMSI in their tests; some EDRs still AMSI disk loads — [Being a good CLR host](https://www.ibm.com/think/x-force/being-a-good-clr-host-modernizing-offensive-net-tradecraft).
- Donut default AMSI bypass is signatured (Fortbridge 2025; donut#165 2024-12). Sliver operators independently reported MDAV **`Win32/AMSI_Patch_T.B13`** on the implant/shellcode path (Nov 2024) — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [donut#165](https://github.com/TheWover/donut/issues/165); [sliver#1814](https://github.com/BishopFox/sliver/issues/1814).
- Elastic rule **AMSI and WLDP Memory Patching**: VirtualProtect writable or WriteProcessMemory targeting `amsi.dll` / `mpoav.dll` / `wldp.dll` — [Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- ASR “Block execution of potentially obfuscated scripts” **depends on AMSI + cloud protection** and supports PowerShell — [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference).

### Inferences
- Scenario **(a)** native Go loader: **AMSI = N/A**. Do not ship Donut’s default AMSI patch “just in case.”
- Scenario **(b)** after callback: AMSI matters on `execute-assembly` / `inline-execute-assembly` / PowerShell post-ex / Office macros. BOF/COFF/native PIC still skip AMSI.
- Patching AMSI from a Go implant is one of the **highest-confidence** 2025 Defender kills (r-tec: process killed). Hardware-breakpoint AMSI bypasses are less often killed but ETW-Ti `SETTHREADCONTEXT` is now used by some vendors (Praetorian Jan 2025 on hardware breakpoints).

### Gaps
- No Microsoft document titled “AMSI heap scanning in 24H2.” CLR `AmsiScanBuffer` of assembly bytes is real; a distinct 24H2 *heap-walk* AMSI feature was **not found** in Learn. The claim “Windows 11 version 24H2 introduces AMSI heap scanning; allocate with PAGE_NOACCESS, decrypt in place, then switch to PAGE_EXECUTE_READ” appears as an **unsourced bullet** in a public offensive checklist, not in Microsoft docs — [SnailSploit/offensive-checklist `shellcode.md`](https://github.com/SnailSploit/offensive-checklist/blob/main/shellcode.md). Treat it as **folklore** unless a primary source appears.
- Whether Sliver’s own Go HTTP stack ever calls AMSI: no — it is native.

---

## Cloud-delivered protection / automatic sample submission: is first-run of a new hash still sandboxed?

### Takeaway
**Yes, for Internet-zone executables, when BAFS + cloud + auto sample submission are on (the enterprise default).** Flow: local ML → metadata query (milliseconds) → if inconclusive, lock file, upload sample, **detonate + deep ML**, then allow or block that hash everywhere. Default wait **10 seconds** (max 60). `.exe`/`.dll` upload without a PII prompt under “Send safe samples automatically.” Files **not** from the Internet zone (USB, internal share, compiled locally) skip BAFS’s cloud hash lock but can still be metadata-queried and later sample-submitted if behavior looks suspicious (Stimpson: local Go builds were uploaded). “Do not send samples” disables BAFS *sample* analysis; **metadata still goes**.

### Cited Findings
- Full flow and metadata table — [Cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission) (Learn updated 2026-09).
- BAFS prerequisites: cloud on, samples automatic, engine up to date. Internet-zone only. Lock + upload if cloud cannot decide. “Reduce response time for new malware from hours to seconds.” — [Configure BAFS](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus).
- Timeout: 10 s default, +0–50 s — [Cloud block timeout](https://learn.microsoft.com/en-us/defender-endpoint/configure-cloud-block-timeout-period-microsoft-defender-antivirus).
- Detonation-based ML: “Suspicious files are detonated in a sandbox. Deep learning classifiers analyze the observed behaviors.” File-classification ML can **hold the file from running** and submit full content — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav).
- Feedback-loop blocking: once detonated/classified malicious, other endpoints block the artifact — [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment).
- Default `SubmitSamplesConsent` = Send safe samples; `.bat` `.scr` `.dll` `.exe` are the documented examples — same cloud-protection article.
- 11–12 Nov 2026: 217 uploads of unpublished Go builds (201 of one test program); Event 2050; `SubmitSamplesConsent=2` later flipped back to 1; Never send disables BAFS sample analysis — [Privacy Affairs](https://www.privacyaffairs.com/microsoft-defender-sample-submission/).
- gatari 2024 (**dated**): a loader that was disk-clean became **whole-hash known-bad** after VT/sandbox detonation; local MpCmdRun then refused to isolate a byte offset. Same mechanism as BAFS feedback-loop blocking — [A Trip Down Memory Lane](https://gatari.dev/posts/memory-lane/); [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment).
- Separate from MAPS: MDE portal can still collect samples for deep analysis; automated investigation can collect suspicious files — [Cloud protection and sample submission, “Other file sample submission scenarios”](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission).

### Inferences
- A brand-new Go loader hash is **not** “unknown therefore allowed.” It is “unknown therefore interrogated.” If the emulator/sandbox reaches decrypt+VirtualProtect+network, the hash burns **globally**.
- Sleep-delay-to-skip-emulator is aimed at the **client emulator** (seconds, instruction budget). Cloud detonation is a **real OS sandbox** with a longer budget. Sleep that beats mpengine emulation often still fails BAFS detonation (and vice versa).
- USB/internal drop: BAFS Internet-zone gate is the main gap; ASR “untrusted unsigned from USB” and “executables unless prevalent/aged/trusted” can close it (see ASR section).

### Gaps
- Microsoft does not publish sandbox dwell time or whether the detonation VM has MDE sensors vs MDAV-only.
- Whether cloud detonation always runs for unsigned Go EXEs or only when local ML is “suspicious” is not quantified. Stimpson shows **inconclusive metadata is enough** to request the sample.

---

## Windows 11 24H2: AMSI heap scanning / W^X / CET vs this loader (PAGE_NOACCESS then decrypt)

### Takeaway
**CET and kernel W^X are mostly orthogonal to a user-mode Go loader that CALLs its own PIC.** User-mode CET shadow stacks require CPU + `/CETCOMPAT` in the PE + process mitigation; stock Go binaries are typically **not** CETCOMPAT, so IBT/`endbr64` and shadow stacks do not apply to the loader’s own returns. Kernel-mode Hardware-enforced Stack Protection is a **kernel** ROP mitigation (22H2+, optional, HVCI required); it does not block user `VirtualAlloc`. Windows does **not** enforce process-wide W^X in user mode; HVCI W⊕X is kernel. `PAGE_NOACCESS` on the payload maps to Elastic `hidden_code` and still generates ETW-Ti `PROTECTVM`. A 24H2-specific “AMSI heap scanning” feature was **not documented** by Microsoft in sources reviewed; AMSI still scans **buffers submitted by hosts** (CLR `Assembly.Load(byte[])`, PowerShell, etc.), not arbitrary Go heaps.

### Cited Findings
- CET: Hardware-enforced Stack Protection is opt-in per app; forcing it on an incompatible binary crashes it. Kernel-mode variant: Win11 22H2+, Intel 11th-gen / AMD Zen 3, VBS+HVCI — [Kernel-mode Hardware-enforced Stack Protection](https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection).
- Academic 2026 (XMemGuard): CFG does not constrain VirtualAlloc/VirtualProtect executable pages; CET IBT “can make it harder for shellcode without a valid `endbr64` landing pad”; **neither** constrains how executable memory is acquired — [Real-Time Detection of Windows Shellcode Injection via the Cross-Process W^X Principle](https://link.springer.com/article/10.1186/s42400-026-00690-4).
- SSTIC-class analysis: at writing, kernel shadow stack was **not enabled by default** on 24H2 even on capable hardware (driver compatibility); ntoskrnl 24H2 lacked `ENDBR64` — cited via [Jullian/Aulnette kernel shadow-stack paper discussion](https://t.co/dfKIpTYIfU) (treat as 2025 snapshot, may have drifted).
- HVCI: kernel pages that are executable cannot be made writable again (W⊕X in the **secure kernel**). User-mode RW→RX is still allowed — [Humanativa 2025 Win11 exploit-mitigation note](https://security.humanativaspa.it/from-arbitrary-pointer-dereference-to-arbitrary-read-write-in-latest-windows-11).
- Elastic `hidden_code`: “Executable memory was unexpectedly marked as PAGE_NOACCESS”; `guarded_code`: PAGE_GUARD — [Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- BorderGate 2022 used PAGE_NOACCESS to fail a CreateRemoteThread-time scan (**dated**; expect this pattern to be watched) — [BorderGate](https://www.bordergate.co.uk/windows-defender-memory-scanning-evasion/).
- CLR AMSI path is `AmsiScanBuffer(flatImageBytes, size)` on in-memory assemblies, not a general heap crawler — [dotnet runtime amsi.cpp](https://github.com/dotnet/runtime/blob/main/src/coreclr/vm/amsi.cpp).
- Intel AMS is GPU-offloaded **memory scanning**, not AMSI — [Hardware acceleration and MDAV](https://learn.microsoft.com/en-us/defender-endpoint/hardware-acceleration-and-mdav).
- **Arbitrary Code Guard (ACG)** is the real user-mode W^X knob: `VirtualAlloc`/`VirtualProtect` with an execute flag fails with `STATUS_DYNAMIC_CODE_BLOCKED`. It is **per-application Exploit Protection**, not a 24H2 default for unsigned Go EXEs. JIT/dynamic-code apps are incompatible; browsers had to move JIT out of the protected process. **Code integrity guard** (Microsoft-signed images only) and **EAF** (blocks shellcode walking ntdll/kernel32/kernelbase EAT) are the same class: opt-in, high FP on real software — [Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference) (updated 2026-07).

### Inferences
- PAGE_NOACCESS-then-decrypt is a **sleep-mask / scan-race** trick. It may dodge a *synchronous* scan that happens to occur while the page is NOACCESS (BorderGate 2022 CRT case). It **advertises** itself to ETW-Ti protect events and to any engine that flags execute-permission fluctuation or hidden executable memory. The checklist that sells PAGE_NOACCESS as a 24H2 AMSI-heap dodge is **not** a Microsoft feature description.
- Direct CALL into PIC on a private stack: CET IBT would only matter if the **process** has user CET enabled and the call is an indirect branch without `endbr64`. Stock unsigned Go: CET likely off. Kernel CET: irrelevant to user PIC.
- Do not plan on 24H2 W^X as a user-mode loader killer **unless** an enterprise applied ACG/CIG via Exploit Protection XML or WDAC. Default Win11 24H2 user mode still allows RW→RX/RWX. Plan on ETW-Ti + memory scan + behavior ML.

### Gaps
- **No primary Microsoft source** for “Windows 11 24H2 AMSI heap scanning” as a named feature. Closest public origin found: unsourced SnailSploit checklist bullet. If operators heard this in a conference talk, it was not corroborated in Learn.
- Default user-mode CET state for unsigned Go EXEs on 24H2/25H2 was not measured in this pass (`Get-ProcessMitigation` would be the lab check).
- Whether 24H2 changed WdFilter memory-scan triggers relative to 22H2 is unpublished.

---

## ASR rules that would kill this loader (only if applicable)

### Takeaway
A **user-launched unsigned Go EXE from disk** is not blocked by the Office/email/script ASR rules. The ASR rules that actually apply are situational: **USB unsigned**, **prevalence/age/trusted-list** (cloud), **PSExec/WMI child processes** (if the loader or Sliver `psexec` is used that way), **email/webmail dropped EXE**, and **obfuscated scripts** (stager only). Standard-protection LSASS rule matters for **(b)** credential dump, not for the loader. ASR is **not** on by default on home Windows; it is policy in enterprise / MDE.

### Cited Findings
All from [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) (Learn updated 2026-09) and [ASR overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview):

| Rule | GUID | Applies to (a)/(b)? | Why |
|---|---|---|---|
| Block untrusted and unsigned processes that run from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | **(a) if USB** | Blocks unsigned/untrusted `.exe/.dll/.scr` from removable media; **also blocks after copy-from-USB onto disk at execute time** (Microsoft wording in the reference; some third-party blogs claim the opposite — prefer Microsoft). Demo file: `UNSIGNED_ransomware_test_exe.exe` — [ASR demonstrations](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules). |
| Block executable files from running unless they meet a prevalence, age, or trusted list criterion | `01443614-cd74-433a-b99e-2ecdc07bfc25` | **(a) if enabled** | Requires **cloud protection**. A unique new hash of an unsigned Go EXE fails prevalence/age. High FP; Microsoft provides no demo file. |
| Block executable content from email client and webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | **(a) if mailed** | Blocks `.exe/.dll/.scr/.ps1/.vbs/.js/.zip` originating from Outlook/webmail. |
| Block process creations originating from PSExec and WMI commands | `d1e49aac-8f56-4280-b9ba-993a6d77406c` | **(b) if Sliver psexec/WMI** | Lateral-movement rule. Stock Sliver PsExec-style service was explicitly hunted by Microsoft in 2022 — [Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/). |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | **stager only** | AMSI + cloud; PowerShell. Not the native Go EXE. |
| Block JavaScript or VBScript from launching downloaded executable content | `d3e037e1-3eb8-44c8-a917-57927947596d` | **stager only** | Script host downloading the loader. |
| Block all Office apps from creating child processes / creating executable content / injecting | `d4f940ab-…`, `3b576869-…`, `75668c1f-…` | **macro dropper only** | Not the Go EXE itself. |
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | **(b) dump** | Blocks LSASS memory access. No Warn mode. |
| Use advanced protection against ransomware | (see reference) | possible generic | Heuristic; not loader-specific. |

- ASR is an MDAV feature configurable on any Windows edition that includes Defender; MDE adds reporting. Client behavioral blocking is **on by default** in MDE; ASR is **not** all-on by default — [Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking); [ASR overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview).
- USB rule STIG: CAT II, GUID must be `1` (Block) — [STIG SV-278649](https://www.stigqter.com/stigs/SV-278649r1192810_rule.html) (2026 Defender Antivirus STIG).

### Inferences
- For a lab EXE copied from a share or built locally: **USB and email ASR do not fire.** Prevalence/age is the only ASR that generically kills “never-before-seen unsigned EXE,” and many enterprises leave it off because of line-of-business software.
- For Sliver **(b)**: `psexec` / WMI jump and LSASS dump are the ASR-relevant post-ex. Default service name “Sliver” is additionally a **hunt IOC**, not an ASR signature.

### Gaps
- Live enterprise prevalence of the prevalence/age rule vs USB rule was not surveyed. DISA STIG requires USB; prevalence/age is often audit-only.
- Microsoft’s USB-rule text (“files copied from USB to disk are blocked when executed”) **conflicts** with some JP/community writeups that say copy-then-run is allowed. This notes file follows the **2026-09 Learn reference**.

---

## Public writeups 2024–2026: Defender vs Sliver, Go loaders, ScareCrow/Donut, sleep-delay

### Takeaway
By 2025, **stock Sliver on disk is considered burned** (Fortbridge: “years ago stock payloads often survived; by 2025 tools detect OOTB implants much faster”). Remaining Defender-class kills are: protobuf/export/`Go buildinf` YARA (including extracted Defender rules), Donut’s **default AMSI-bypass stub**, unbacked executable memory + `LoadLibrary` from it, CRT injection, and cloud ML on Go structure (`Wacatac`). ScareCrow-class sideload still leaves AMSI/ETW patch, unhook, and sleep-mask telemetry. Sleep-delay to skip the **client emulator** is a 2014–2018 trick; Microsoft’s current stack adds **cloud detonation** and **post-execution** engines that do not care about the emulator budget.

### Cited Findings
- Fortbridge Apr 2025: full practical map against Elastic + Defender; staged/self-inject/pack **ineffective** until protobuf/export/`bishopfox` source edits; then a **disk DLL + thin LoadLibrary loader** was the workable path; many built-in commands still alerted — [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Praetorian 28 May 2026: Go ML (`Wacatac.B!ml`) dominates; garble/strip made things worse; Sliver obfuscation pipeline hit AhnLab `Trojan/Win.Sliver.R774471` on **fake Authenticode strings**; VT is not ground truth vs local MDAV; cloud Wacatac is more aggressive than `MpCmdRun` — [Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/).
- Formidable 23 May 2026: **benign** unsigned Go GUI flagged `Trojan:Win32/Wacatac.B!ml` with clean dynamic sandboxes — [Formidable Wacatac post](https://formidable.tools/posts/defender-wacatac-go-binary/).
- gatari Mar 2024 (**dated**): ired.team-style XOR+direct-CALL loader: static XOR worked, **RWX+CALL runtime kill**, VT upload burned the **hash**; EarlyBird APC then “worked” in that lab (remote inject; not a 2026 recommendation) — [A Trip Down Memory Lane](https://gatari.dev/posts/memory-lane/).
- BishopFox Nov 2024: `Win32/AMSI_Patch_T.B13` on Sliver attributed to AMSI-patch bytes — [sliver#1814](https://github.com/BishopFox/sliver/issues/1814).
- Donut #165 Dec 2024–2026: stock C stub + CRT inject started failing MDAV ~Nov 2024; attributed to **AMSI bypass technique**, not only encoder; OLLVM stub was clean on disk and **still died on CreateRemoteThread** until bypass swapped — [TheWover/donut#165](https://github.com/TheWover/donut/issues/165).
- r-tec Feb 2025: AMSI bypass in a **native loader is wasted IOC**; Defender process-kill on classic AmsiScanBuffer patch — [Bypass AMSI in 2025](https://www.r-tec.net/r-tec-blog-bypass-amsi-in-2025.html).
- Elastic Jan 2024 (still the open ETW-Ti rulebook used through 2026): unbacked RWX, fluctuation, AMSI/ETW patch, direct syscall, call-stack spoof — [Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- Microsoft Aug 2022 (**dated**, still the vendor hunt bible for Sliver): injection sequence, notepad sacrificial, PsExec “Sliver implant”, stagers, JARM/headers, Bumblebee+Sliver shellcode — [Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- DFIR Report Aug 2024: in-the-wild garble’d Sliver still versioned via **protobuf strings** — [Threat Actors' Toolkit](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/).
- Hunter’s Ledger (2026): ScareCrow+Sliver open directory — ETW/AMSI patch, sleep mask, PPID spoof, module stomping, fraudulent signing still hunted — [sliver-open-directory](https://the-hunters-ledger.com/reports/sliver-open-directory/).
- BallisKit 2025: Sliver shellcode in commercial packers; **EXE stagers bypassed some EDRs and were caught by others on stage-2 in memory** — [BallisKit tutorial](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).
- Pretera 2025: small WinINet stager + CRT inject; claimed no Defender block **in their lab** for that injector — still the classic API pattern Microsoft documents — [Pretera](https://www.pretera.com/sliver-bullet-staging-shellcode-process-injection/). Treat as **single-lab, not general**.
- Sleep/anti-emulation: Bulazel 2018 RE of Defender emulator (dated); BruCON 2014 packer talk on Sleep vs emulator skip (dated). Microsoft 2025 Learn still lists the **emulation engine** as current. Cloud **detonation** is a separate, later stage — [adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [WindowsDefenderTools](https://github.com/0xAlexei/WindowsDefenderTools).
- BishopFox: AV bypass is **out of Sliver’s scope**; operators pointed at packers/crypters/stagers — [Sliver Docs Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion); discussion that sleep obfuscation/direct syscalls belong in the **loader** — [sliver#1171](https://github.com/BishopFox/sliver/discussions/1171).
- CTFPacker-class 2025 blogs claiming “raw Sliver shellcode vs Defender” are **signature-only VT screenshots** plus a home-lab demo; authors themselves say they are not EDR-grade — [mochabyte 2025](https://mochabyte.xyz/2025/06/11/evade-modern-avs-in-2025). Prefer Fortbridge/Praetorian/Microsoft over these.

### Inferences
- The 2024–2026 public record agrees: **byte encoders and unique hashes are not an evasion strategy** against Defender. What still moves the needle in *authorized* labs is (i) source-level identity scrub of the implant, (ii) not using Donut’s default bypass, (iii) backed/image memory or a trusted host+DLL rather than unbacked RWX, (iv) looking like a real Go binary to ML, (v) not doing stock CRT migrate/execute-assembly. None of that is “FUD.”
- Sleep-delay-to-skip-emulator is **insufficient** against BAFS detonation + post-execution memory scan + ETW-Ti. It may still dodge a *short* client emulator window; that is not the same as surviving the endpoint.

### Gaps
- No controlled 2025–2026 matrix of the **same** Sliver build under MDAV-only vs MDE EDR-in-block-mode vs ASR-on vs Smart App Control.
- ScareCrow’s current MDAV detection names were not pulled from WDSI in this pass; Hunter’s Ledger covers hunter telemetry more than MDAV family strings.
- VirusTotal community comments on Sliver were **not** scraped (assignment: do not upload anything; VT UI comments are noisy). Praetorian’s named families (`Wacatac.B!ml`, `Trojan/Win.Sliver.R774471`, `Multi.Trojan.Goffloader`) are the usable VT-derived facts.

---

## Cross-cutting inferences for scenarios (a) and (b)

### (a) Custom Go EXE: RW alloc → decrypt → RWX/RX → CALL PIC on private stack

Layers that can fire, in order:

1. **SmartScreen / Smart App Control** — unknown unsigned hash (MotW or SAC). Hash uniqueness = unknown, not trusted.
2. **ASR** — USB unsigned; prevalence/age if enabled; email drop if mailed.
3. **Local PE ML + heuristics + VDM** — Go structure, entropy of embed, unsigned, IAT; leftover Donut/Sliver strings.
4. **Emulator** — unpack XOR if decode is in budget; scan unpacked buffer.
5. **BAFS cloud** — metadata (PE, hashes, parent, MotW, APIs); possible 10–60 s lock + sample detonation.
6. **ETW-Ti** — `ALLOCVM` + `PROTECTVM` (and `WRITEVM` if remote). Independent of CreateThread.
7. **Behavior ML** — `Behavior:Win32/Execution|DefenseEvasion.*!ml`; injection/hollowing if remote.
8. **Memory scan / Intel AMS** — decrypted PIC in private RX/RWX; Donut/Sliver/CS YARA if those bytes match.
9. **Network engine** — first C2 connect from the PIC/Go runtime.

CreateThread skip removes (part of) 7’s CRT-sequence and one historical scan trigger. It does not remove 6, 8, or 5. gatari 2024: skip CreateThread and still die on RWX+CALL.

### (b) Live Sliver after callback

1. On-disk hash no longer matters if the implant never touched disk.
2. **Memory YARA** on `sliverpb` / protobuf / bishopfox / `Go buildinf` while idle (no sleep mask).
3. **Unbacked executable memory + LoadLibraryExW** (Go LazyDLL) — Fortbridge’s Elastic alert; MDE has equivalent “injected / unbacked” optics.
4. **Post-ex**: CRT migrate, notepad execute-assembly, PsExec “Sliver”, LSASS, AMSI patch → documented MDE/MDAV/ASR kills.
5. **Network**: default HTTP paths/extensions, JARM, unusual JA3; not the focus of this note but still live.

### Why XOR + unique hash + random buildid fails as a strategy

It addresses **exact-hash reputation** only. Defender’s published architecture is explicitly built so that polymorphic / never-seen PE files are classified by **features, emulation, detonation, and behavior**, with the hash used to **cache the verdict**, not to be the verdict.

---

## Sources used (primary / high quality)

- [Microsoft Learn: Advanced technologies of MDAV](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav) (2025-01, page updated 2026-10)
- [Microsoft Learn: Cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission) (2026-09)
- [Microsoft Learn: Configure Block at First Sight](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus)
- [Microsoft Learn: Cloud block timeout](https://learn.microsoft.com/en-us/defender-endpoint/configure-cloud-block-timeout-period-microsoft-defender-antivirus)
- [Microsoft Learn: AMSI on MDAV](https://learn.microsoft.com/en-us/defender-endpoint/amsi-on-mdav) (2026-05)
- [Microsoft Learn: Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking)
- [Microsoft Learn: Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)
- [Microsoft Learn: ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) (2026-09)
- [Microsoft Learn: Hardware acceleration / Intel TDT AMS](https://learn.microsoft.com/en-us/defender-endpoint/hardware-acceleration-and-mdav)
- [Microsoft Learn: SmartScreen reputation for developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation) (2026-05)
- [Microsoft Learn: SmartScreen overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/)
- [Microsoft Learn: Kernel-mode Hardware-enforced Stack Protection](https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection)
- [Microsoft Security Blog: Looking for the Sliver lining (2022, dated)](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- [Fortbridge: Reforging Sliver (2025-04)](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- [Praetorian: Adversarial Oracles / Go ML (2026-05-28)](https://www.praetorian.com/blog/llm-edr-signature-reduction/)
- [Formidable: Wacatac.B!ml on a benign Go GUI (2026-05-23)](https://formidable.tools/posts/defender-wacatac-go-binary/)
- [Hunt & Hackett: Hunting for a Sliver (2024-04)](https://www.huntandhackett.com/blog/hunting-for-a-sliver)
- [gatari: A Trip Down Memory Lane (2024-03, dated)](https://gatari.dev/posts/memory-lane/)
- [BishopFox/sliver#1814 Win32/AMSI_Patch_T.B13 (2024-11)](https://github.com/BishopFox/sliver/issues/1814)
- [BishopFox/sliver#833 AV evasion out of scope (2022, dated)](https://github.com/BishopFox/sliver/issues/833)
- [Microsoft Learn: Exploit protection / ACG (2026-07)](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)
- [Microsoft Learn: Defender event IDs (1015/2050)](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [Privacy Affairs: Defender sample submission / Stimpson (2026-11-12)](https://www.privacyaffairs.com/microsoft-defender-sample-submission/)
- [Elastic Security Labs: Doubling Down ETW call stacks (2024-01)](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- [r-tec: Bypass AMSI in 2025](https://www.r-tec.net/r-tec-blog-bypass-amsi-in-2025.html)
- [TheWover/donut#165 (2024-12)](https://github.com/TheWover/donut/issues/165)
- [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760)
- [Elastic Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar)
- [Immersive Labs Sliver hunt](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)
- [dotnet/runtime amsi.cpp](https://github.com/dotnet/runtime/blob/main/src/coreclr/vm/amsi.cpp)
- [adanto/EtwTiViewer](https://github.com/adanto/EtwTiViewer)
