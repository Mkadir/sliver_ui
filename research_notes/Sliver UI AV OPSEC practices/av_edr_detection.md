# Modern AV/EDR Detection of Sliver-like C2 Implants (2024–2026)

Authorized red-team / adversary-simulation framing. Notes for report synthesis; every non-obvious claim cites a primary or technical source.

## What do AV engines typically catch on disk for Sliver/Cobalt Strike-style implants (PE headers, Go binaries, entropy, imports)?

### Takeaway
Out-of-the-box Sliver implants are caught primarily by **string/YARA signatures on protobuf-generated names and BishopFox package paths**, not by PE-header novelty alone; Go’s large static binaries, `go.buildid`/`Go buildinf`, export names (`DllRegisterServer`, `GetJitter`, `VoidFunc`), and high section entropy from packing/obfuscation are secondary static features widely used by AV and public rules.

### Cited Findings
- Immersive Labs YARA for unmodified implants matches PE/ELF/Mach-O headers plus strings `sliverpb`, `github.com/bishopfox/`, and `chacha20poly1305`; a separate memory rule matches `sliverpb` alone — [Immersive Labs SliverC2-Forensics `sliver.yar`](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.yar); writeup — [Immersive Labs blog](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- Elastic `Multi_Trojan_Sliver` rules (file+memory) key on protobuf method/name strings such as `).RequestResend`, `).GetPrivInfo`, `InvokeSpawnDllReq`, `NetstatReq`, `HTTPSessionInit`, `ScreenshotReq`, `RegistryReadReq`, and the package path `B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb`, plus bytecode patterns for session start/register — [Elastic protections-artifacts `Multi_Trojan_Sliver.yar`](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar).
- Community/playbook YARA similarly combines `go.buildid`, `github.com/bishopfox/sliver`, `sliverpb`, `SliverHTTPC2`, and listener strings (`StartMTLSListener`, `StartWGListener`, `PivotListener`) with MZ check — [isMalicious playbook (2026)](https://ismalicious.com/playbooks/detecting-c2-beacons-yara).
- Fortbridge (Apr 2025): stock implants hit many Elastic YARA hits; dominant signatures live in `.proto` / generated `sliver.pb.go` (e.g. `ScreenshotReq`); Defender-oriented extracted rules also hit ASCII exports/`GetJitter`/`VoidFunc`/`AddTunnel`/`GetIsIOC` and ` Go buildinf:` — [Fortbridge “Reforging Sliver”](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- BishopFox maintainers acknowledge garble often **fails to obfuscate protobuf methods**, leaving strings that enable easy signatures (issue still open as known bug, Aug 2024) — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760); earlier garble protobuf regression — [burrowers/garble#704](https://github.com/burrowers/garble/issues/704).
- DFIR Report (Aug 2024): real-world Sliver sample obfuscated with garble; analysts still versioned it via **protobuf definition string analysis** because protobuf is “luckily aren’t as easily obfuscated” — [The DFIR Report](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/); VT hash in that post shows multi-AV hits on disk.
- Typical Sliver Windows implant size is large (Immersive: ~16 MB average; Fortbridge: up to ~30 MB), which increases on-disk visibility and complicates module stomping — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Canary domains (if enabled) appear **cleartext** in the binary while real C2 is encrypted — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- Shannon entropy >~7.0 on sections is widely treated as packed/encrypted indicator (generic malware heuristic; not Sliver-specific) — e.g. [EntropyCalc_Go / Practical Security Analytics framing](https://github.com/yutianqaq/EntropyCalc_Go); Elastic’s Go tooling discusses section entropy for obfuscated/packed Go binaries — [elastic/toutoumomoma docs](https://deepwiki.com/elastic/toutoumomoma/2.4-section-analysis-and-entropy).
- Wazuh published a YARA rule matching `sliverpb`, `/sliver/`, `github.com/bishopfox/sliver/`, and protocol byte patterns, `filesize < 50MB` — [Wazuh blog](https://wazuh.com/blog/detecting-sliver-c2-framework-with-wazuh/).
- Joe Sandbox / MalwareBazaar samples (2024) routinely show “Yara detected Sliver Implants” plus multi-AV hits on large ELF/EXE Sliver binaries — e.g. [MalwareBazaar sample](https://bazaar.abuse.ch/sample/d46eb24e02e250f2955bc192e1b40cf0268491b0cb11b4a337d9d21180dac4f2/).

### Inferences
- For stock Sliver, **string/YARA on protobuf + bishopfox paths** is the primary on-disk kill; PE structure alone (MZ, Go sections) is corroborative.
- Light packing that raises entropy without renaming protobuf exports often **increases** heuristic suspicion while leaving the strongest Sliver-specific strings intact.
- Cobalt Strike–style PE/import heuristics (reflective load stubs, known config blocks) differ from Sliver’s Go/protobuf signature surface; defenders hunt both brand-specific strings and shared techniques.

### Gaps
- No public, current quantitative VT detection rates for default vs `--obfuscate` Sliver builds across major AV engines in 2025–2026 were found in primary sources during this pass.
- Exact Defender cloud ML feature weights for large Go binaries are not published; Fortbridge inferred Defender YARA from extracted rules ([roadwy/DefenderYara](https://github.com/roadwy/DefenderYara)), which may lag live cloud signatures.

## What do EDR products flag at runtime (process injection, unbacked executable memory, AMSI, ETW, parent-child, network)?

### Takeaway
Modern EDR (Microsoft Defender for Endpoint, Elastic Agent, etc.) reliably flags Sliver’s **default process-injection API sequence**, **network DLLs loaded from unbacked/private executable memory**, sacrificial-process spawn+inject patterns, default PsExec/service artifacts, AMSI/ETW tampering when present, and beaconing/parent-child anomalies—often even when on-disk YARA is beaten.

### Cited Findings
- Microsoft (2022, still foundational for Sliver hunting): Sliver `migrate` / `Sideload` / `SpawnDll` / `Execute-Assembly` use classic `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`; MDE alerts e.g. “A process was injected with potentially malicious code” — [Microsoft Security Blog – Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Same Microsoft guidance: hunt GetSystem (SeDebug + remote thread into `spoolsv.exe`), default sacrificial `notepad.exe` spawn+inject, and PsExec service defaults (`DisplayName`/`Description` “Sliver” / “Sliver implant”, `ImagePath` under `%WINDIR%\Temp\<10 alnum>.exe`) — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Fortbridge vs Elastic (2025): HTTP beacon init via Go `LazyDLL` → `LoadLibraryExW` from implant running in unbacked memory produced Elastic behavioral alert **“Network Library Loaded from Unbacked Memory”**; module stomping failed due to implant size — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Unbacked executable memory (MEM_PRIVATE/MEM_MAPPED, not MEM_IMAGE) for thread start addresses is a standard injection/shellcode detector used across EDR research and tooling — [Black Lantern Security – Detecting Process Injection (2024)](https://blog.blacklanternsecurity.com/p/detecting-process-injection); [Fibratus rule – thread context from unbacked memory](https://fibratus.io/rules/defense_evasion_thread_context_set_from_unbacked_memory).
- NHIMG Sliver/Havoc/Brute Ratel detection guide (2026): prioritize technique over brand—remote process injection (Sysmon ID 8), service-based lateral movement, in-memory DLL loads without disk file, LSASS access, ISO/archive → signed binary loading adjacent DLL, Temp execution — [NHIMG guide](https://nhimg.org/sliver-havoc-brute-ratel-detection-guide).
- Sliver default shellcode path uses Donut with AMSI bypass enabled by default; that bypass is heavily signatured (Fortbridge disabled Donut bypass 3→1 in source) — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- ScareCrow-class loaders (often paired with Sliver/CS shellcode) explicitly patch AMSI/ETW and unhook ntdll/kernel32/kernelbase; defenders still hunt the unhook/patch behaviors and anomalous module loads — [optiv/ScareCrow README](https://github.com/optiv/ScareCrow); campaign analysis of Sliver+ScareCrow with ETW/AMSI patch, sleep mask, PPID spoof, module stomping — [Hunter’s Ledger open-directory report](https://the-hunters-ledger.com/reports/sliver-open-directory/).
- Network: default HTTP C2 path/extension patterns (`.woff` stager, `.html` key exchange, `.js` long-poll, `.php` session, `.png` close), nonce query params, custom Base32/58/64 alphabets, English-words encoder; Immersive published Snort + Sigma — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [SliverC2-Forensics Rules](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics). DNS C2 produces very high subdomain/byte volume — same Immersive writeup. Microsoft notes JARM/HTTP header anomalies for listeners — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Sysmon Event ID 8 (CreateRemoteThread) and ID 3 (network) are practical free telemetry for Sliver stager injection demos — [Dominic Breuker – Sliver stagers/process injection](https://dominicbreuker.com/post/learning_sliver_c2_06_stagers_process_injection).
- Fortbridge conclusion: after static evasion, **many built-in Sliver commands still trigger Elastic behavioral alerts** — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).

### Inferences
- Beating file YARA is insufficient: **injection + unbacked RX/RWX + LazyDLL network loads** are durable EDR signals for Go implants and loaders.
- Stock Sliver post-ex (`migrate`, `getsystem`, default PsExec naming) is intentionally easy for MDE-style hunts; customized naming/paths only shift to technique-level detections.
- AMSI matters most for script/.NET staging; Sliver’s native Go EXE may skip AMSI, but Donut/shellcode and PowerShell stagers reintroduce it.

### Gaps
- Vendor-specific alert names/severity beyond MDE and Elastic for 2025–2026 (CrowdStrike, SentinelOne, etc.) were not exhaustively documented in the primary sources fetched.
- Live comparison of kernel ETW vs usermode-hook EDR against HalosGate/indirect syscalls was only covered in campaign writeups, not controlled vendor tests.

## Why are "obfuscate symbols" and light "evasion" flags insufficient against 2024–2026 AV/EDR?

### Takeaway
`--obfuscate`/garble and light `--evasion` do not rename protobuf wire/schema strings that AV YARA keys on, do not remove Go runtime/`buildinf` tells, do not implement sleep masking by default, and do not change the high-signal **behavioral** footprint (injection APIs, unbacked network library loads, default post-ex); public research shows stock builds are widely signatured and that meaningful evasion requires **source-level protobuf/export renames** plus custom loaders—after which post-ex still trips EDR.

### Cited Findings
- Garble does not reliably obfuscate protobuf-generated method/type strings used by Elastic Multi_Trojan_Sliver; BishopFox: “Garble is not picking up the protobuf methods, which makes for easy signatures” — [sliver#1760](https://github.com/BishopFox/sliver/issues/1760).
- Fortbridge: years ago stock payloads often survived disk scans; by 2025 “security tools now detect out-of-the-box implants much faster” due to static signatures; symbol obfuscation alone left protobuf and Defender string hits; staged/self-inject/pack approaches against Elastic+Defender were “ineffective” until deep source edits — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Pain points called out explicitly: **large binary size** and **lack of sleep mask** leave memory-resident implants easy to YARA-scan while idle — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/). (Upstream Ekko sleep-obfuscation work exists as PR/discussion, not a substitute for default operator hygiene — [sliver#1805](https://github.com/BishopFox/sliver/pull/1805).)
- Default Donut AMSI bypass inside Sliver shellcode generation is itself signatured — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Microsoft: hunting guidance targets **techniques and default configs**, not only family strings; customized loaders (e.g. Bumblebee + Sliver shellcode) still expose injection/C2 behaviors — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- NHIMG: “Hunt the behaviour, not the brand” — Microsoft-style technique detections survive framework swaps — [NHIMG guide](https://nhimg.org/sliver-havoc-brute-ratel-detection-guide).
- Even after Fortbridge’s full rename/`bishopfox` scrub and DLL-on-disk loader achieved clean LitterBox + Elastic callback for **execution**, they state many implant **commands** still alert — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Third-party forks (`better-sliver`, `slivercloak`) exist specifically because stock flags are insufficient — cited in [Fortbridge conclusion](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).

### Inferences
- Treating “obfuscate symbols + evasion” as OPSEC-complete is a 2020-era mental model; 2024–2026 AV/EDR stacks pair **open-source YARA** with **behavioral graphs**.
- Any detection engineering that keys on protobuf schema names will keep hitting rebuilds until operators fork and rename the schema (compatibility cost with stock clients/servers).

### Gaps
- Official BishopFox Anti-virus Evasion wiki page redirects to sliver.sh docs; the live docs page did not return usable content in this research fetch, so built-in flag semantics were taken from generate code/PRs and third-party operator guides rather than the canonical wiki prose — [wiki redirect](https://github.com/BishopFox/sliver/wiki/Anti-virus-Evasion).

## What delivery forms fare better: on-disk EXE vs service EXE vs DLL sideload vs shellcode inject vs staged loaders?

### Takeaway
**Plain on-disk EXE/service** fares worst against AV YARA and default-service hunts; **staged small loaders**, **DLL sideload into trusted apps**, and **shellcode via mature evasion loaders (ScareCrow-class / custom)** fare better against static AV but shift risk to EDR behavioral/memory and loader-family signatures; stageless huge Go implants are awkward for stomping/sleep-mask and often need disk DLL + thin loader as a pragmatic compromise.

### Cited Findings
- Microsoft: formats include shellcode, EXE, DLL/shared, service; **stagers** shrink initial payload and complicate file-based detection; motivated actors embed Sliver shellcode in custom loaders (e.g. Bumblebee) — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Default Sliver **service/PsExec** artifacts (`Sliver` / `Sliver implant`, Temp random EXE) are explicitly hunted — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Fortbridge: pure in-memory stage/pack/self-inject against Elastic+Defender failed in their tests; **writing a renamed shared library to disk + simple LoadLibrary/export thread loader** was the workable path after signature scrubbing — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- ScareCrow: designed for **sideloading** (not classic inject) into legitimate processes, AES-encrypted shellcode, EDR unhook (Disk/KnownDLL), custom syscalls, AMSI/ETW options; loaders include control/excel/msiexec/wscript/dll/binary — [optiv/ScareCrow](https://github.com/optiv/ScareCrow). Used in the wild with Sliver (process hollowing, PPID spoof, sleep mask, fraudulent signing) — [Hunter’s Ledger](https://the-hunters-ledger.com/reports/sliver-open-directory/).
- BallisKit MacroPack/ShellcodePack tutorial (2025): wrapping Sliver shellcode with EDR bypass profiles; stageless implant steathier for some EDRs but huge; **EXE stagers** bypassed some EDRs but were caught by others when second stage loaded in memory — [BallisKit / Medium](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).
- Pretera Sliver staging (2025): small injector + WinINet fetch of shellcode (e.g. via `.woff`); classic VirtualAllocEx/WriteProcessMemory/CreateRemoteThread; claimed no Defender block in their lab for that injector—still classic EDR-detectable API pattern — [Pretera](https://www.pretera.com/sliver-bullet-staging-shellcode-process-injection/).
- Immersive: memory detection remains strong because **full Go implant must unpack into memory** regardless of packing/staging — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- NHIMG: DLL sideload and signed-binary-from-ISO/archive chains are common for Brute Ratel/Havoc and transferable hunts; watch image-load provenance and parent-child — [NHIMG](https://nhimg.org/sliver-havoc-brute-ratel-detection-guide).

### Inferences
- Relative OPSEC (static AV → behavioral EDR), rough ordering for **authorized** emulation planning: customized sideload/DLL or mature shellcode loader ≥ staged shellcode inject ≫ stock shellcode with Donut AMSI ≫ stock on-disk EXE ≫ stock service with default metadata.
- “Never touch disk” is attractive but **hard for multi-MB Go implants** against EDRs that alert on unbacked RX + network module loads; hybrid (small trusted host process + cleaned DLL) appears in successful public red-team writeups.
- Delivery success is environment-specific; BallisKit’s split results (some EDRs catch stage-2) warn against single-tool claims.

### Gaps
- No single controlled 2025–2026 matrix comparing identical Sliver builds across EXE / service / sideload / ScareCrow / staged under the same EDR set was found; conclusions are synthesized across labs.
- Code-signing / Authenticode reputation effects on each form were only anecdotally covered (fraudulent VMware cert in Hunter’s Ledger).

## Any published detections/YARA/blog posts about Sliver specifically?

### Takeaway
Yes—multiple primary detection packs and vendor/research blogs exist: Elastic Multi_Trojan_Sliver YARA, Immersive Labs YARA/Snort/Sigma + decrypt tooling, Microsoft Defender hunting blog + KQL, Wazuh rules, Fortbridge evasion (inverse detection map), DFIR Report casework, and 2025–2026 campaign/detection guides (NHIMG, Hunter’s Ledger, isMalicious).

### Cited Findings
- **Microsoft** – hunting TTPs, injection, PsExec defaults, stagers, JARM/headers (2022): [Looking for the ‘Sliver’ lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- **Immersive Labs** – binary/memory YARA, HTTP Snort, Sigma, PCAP/mem decryptors (2023): [blog](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [GitHub SliverC2-Forensics](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics).
- **Elastic Security** – `Multi_Trojan_Sliver_*.yar` (file+memory): [protections-artifacts](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar).
- **Fortbridge** – practical map of Elastic/Defender static strings and Elastic “Network Library Loaded from Unbacked Memory” (2025): [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- **The DFIR Report** – in-the-wild Sliver + garble + protobuf versioning (2024): [Threat Actors' Toolkit](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/).
- **Wazuh** – custom rules + YARA implant detection: [Detecting Sliver C2 with Wazuh](https://wazuh.com/blog/detecting-sliver-c2-framework-with-wazuh/).
- **NHIMG** – Sliver/Havoc/Brute Ratel technique-oriented detection guide (2026): [guide](https://nhimg.org/sliver-havoc-brute-ratel-detection-guide).
- **Hunter’s Ledger** – Sliver + ScareCrow open directory, Sigma/YARA for loader/signing chain (2026): [report](https://the-hunters-ledger.com/reports/sliver-open-directory/); [detections page](https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/).
- **isMalicious** – playbook YARA for CS/Sliver/Metasploit (2026): [playbook](https://ismalicious.com/playbooks/detecting-c2-beacons-yara).
- **BishopFox issues** documenting signature surface (protobuf/garble): [#1760](https://github.com/BishopFox/sliver/issues/1760).
- MITRE ATT&CK techniques commonly mapped in these writeups: T1055 (process injection), T1055.002 (PE injection), T1574.001 (DLL side-loading), T1620 (reflective code loading), T1569.002 (service execution), T1027 (obfuscation), T1071 (application layer C2), T1003.001 (LSASS) — see Microsoft/NHIMG mappings above.

### Inferences
- Public detection content is mature enough that **unmodified Sliver is a known-bad family** in AV/EDR content pipelines; red teams should assume stock generate output is labeled.
- Best defensive coverage combines **family YARA** (cheap) with **technique telemetry** (survives forks).

### Gaps
- NCSC/SVR advisory referenced by Microsoft was not re-fetched in full in this pass (secondary citation only via Microsoft).
- Comprehensive SigmaHQ rule inventory for Sliver was asserted by tertiary blogs; individual SigmaHQ rule URLs were not verified file-by-file here (Immersive’s `Sliver-http.yml` was verified via repo listing).
