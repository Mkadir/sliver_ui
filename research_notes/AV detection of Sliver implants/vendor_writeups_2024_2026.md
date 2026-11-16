# Public vendor and hunter detections of Sliver C2 (2021–2026)

Research notes for report synthesis. Scope is **Sliver-specific** public detections (not generic “C2 frameworks”), with product names, detection names, type (file-hash / YARA / ML / behavior / network), and named APIs/functions. Dates and URLs on every claim. Failed or JS-only fetches are marked.

**Fetch notes**
- Microsoft Security Blog live page is JS-rendered; body recovered via `browse_page` (2022-08-24 article) plus WDSI encyclopedia pages. The blog appendix list of MDAV names was truncated in fetch; encyclopedia pages supply the named detections.
- `https://sliver.sh/docs?name=Anti-virus+Evasion` returned only “Loading documentation…” (SPA). Canonical AV-evasion docs not captured.
- Huntress.com blog search returned no dedicated Sliver C2 writeup (2024–2026).
- CrowdStrike.com public blogs returned no named Sliver family detections (paywalled Falcon content not accessed).
- SentinelOne.com returned no named implant detections; only CVE-database entries about the *teamserver*.
- Corelight May 2023 post fetch returned mostly related-post chrome; claims below use search snippets plus the May 4 2023 date from Corelight.
- Cybereason post now lives at LevelBlue (Jan 19 2023); full body fetched.
- Red Canary Dec 2025 BYOVM post now hosted on Zscaler (`redcanary.com` redirects).

---

## Timeline of public Sliver-specific detections (vendors, hunters, open rules)

### Takeaway
From 2021 through 2026 the public record moves from **default-config fingerprints** (HTTP URI extensions, protobuf strings, JARM, `CreateRemoteThread` into `notepad.exe`/`spoolsv.exe`) to **still-working default HTTP/TLS catches** (Proofpoint ETPRO, Immersive Snort, Palo Alto TLS 1.3 ML in 2025, Vectra encoder-rotation ML in 2026) **plus string-only static YARA that operators can rename**. No public CrowdStrike or SentinelOne *implant family name* was found. Microsoft still publishes both **post-ex behavior hunts** and **file/behavior family names** (`Trojan:Win64/Sliver`, `Behavior:Win32/Splinter.A`, `ALF:Trojan:Win32/Sliver.A`).

### Cited Findings

**Chronological table (public, named, Sliver-specific)**

| Date | Vendor / hunter | Product | Detection name(s) | Type | What it keys on | Source |
| --- | --- | --- | --- | --- | --- | --- |
| 2021-09-04 | pat_h/to/file (independent) | Hunt notes | (unnamed) JARM + HTTP routers | Network | mTLS JARM `28d28d28d00028d00043d28d28d43d47390d982d099a542ccbc90628951062`; HTTP `.txt/.jsp/.php/.js/.png/.woff` | [Hunting Sliver](https://blog.tofile.dev/2021/09/04/sliver.html) |
| 2021-10-20 | Proofpoint / Emerging Threats | ETPRO | `ETPRO MALWARE Sliver Framework HTTP C2 sessionInit` | Network (IDS) | Default HTTP session-init | [TA551 Uses SLIVER](https://www.proofpoint.com/us/blog/security-briefs/ta551-uses-sliver-red-team-tool-new-activity) |
| 2021-10-20 | Elastic Security | Elastic Endpoint YARA | `Multi_Trojan_Sliver_42298c4a` / threat_name `Multi.Trojan.Sliver` | YARA file+memory | Protobuf method strings `).RequestResend`, `).GetPrivInfo`, `).GetReconnectIntervalSeconds`, `).GetPivotID`, `name=PrivInfo` | [Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar) |
| 2021-11-26 (updated 2022-08-29) | Microsoft | Microsoft Defender Antivirus | `Trojan:Win64/Sliver.D` | File (family) | Sliver implant family | [WDSI Trojan:Win64/Sliver.D](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Sliver.D&threatId=-2147161988) |
| ~2021 (NCSC PDF) | NCSC UK | YARA (advisory) | `sliver_github_file_paths_function_names`, `sliver_proxy_isNotFound_retn_cmp_uniq`, `sliver_nextCCServer_calcs` | YARA | `/sliver/`, `sliverpb.`, `ScreenshotReq`, `SideloadReq`, `InvokeMigrateReq`, bytecode CMPs | [gist from NCSC PDF](https://gist.github.com/ecapuano/2c59ff1ea354f1aae905d6e12dc8e25b); original [NCSC SVR advisory PDF](https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf) |
| 2022-08-24 | Microsoft Defender Experts | MDE / MDAV / Advanced Hunting | MDE alert *A process was injected with potentially malicious code*; hunts for GetSystem / Shell / Sideload / PsExec; appendix MDAV (truncated in fetch) | Behavior + hunting KQL | `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`; default `notepad.exe` / `spoolsv.exe`; service DisplayName `Sliver` | [Looking for the ‘Sliver’ lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/) |
| 2022-08-29 | Microsoft | MDAV | `Behavior:Win32/Splinter.A`; also `ALF:Trojan:Win32/Sliver.A`, `ALF:Trojan:Win32/SliverServer.A`, `VirTool:Win64/Splinter.A` | Behavior + file | Named Sliver/Splinter family detections | [Behavior:Win32/Splinter.A](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Behavior:Win32/Splinter.A&threatId=0) |
| 2022-08-31 | Elastic | Elastic Endpoint YARA | `Multi_Trojan_Sliver_3bde542d` | YARA file+memory | `B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb`; `InvokeSpawnDllReq`, `NetstatReq`, `HTTPSessionInit`, `ScreenshotReq`, `RegistryReadReq` | [Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar) |
| 2022-12-01 (last_modified 2023-09-20) | Elastic | Elastic Endpoint YARA | `Multi_Trojan_Sliver_3d6b7cd3` | YARA bytecode | Session-start + register x86/x64 instruction sequences (not strings) | [same .yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar); still matching samples on [MalwareBazaar 2026](https://bazaar.abuse.ch/browse/yara/Multi_Trojan_Sliver_3d6b7cd3/) |
| 2022-12-08 | Microsoft | MDAV | `Trojan:Win64/Sliver` | File (family) | Encyclopedia family for implants | [WDSI Trojan:Win64/Sliver](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Sliver) |
| 2023-01-13 | VMware TAU | Network/lateral | (unnamed) SMB copy + `CreateServiceW` + `StartServiceW` | Behavior / network | Default PsExec service name “Sliver” is **not** recommended as the durable signal | [Detection of Lateral Movement with the Sliver C2 Framework](https://blogs.vmware.com/security/2023/01/detection-of-lateral-movement-with-the-sliver-c2-framework.html) |
| 2023-01-19 | Cybereason GSOC (now LevelBlue) | Cybereason Defense Platform + hunts | Shell cmdline; CreateRemoteThread→notepad; CreateRemoteThread→spoolsv; service name “Sliver”; TCP/8888; UDP/51820; JARM | Behavior + network | Unique default post-ex + infra fingerprints | [Sliver C2 Leveraged by Many Threat Actors](https://www.levelblue.com/blogs/spiderlabs-blog/sliver-c2-leveraged-by-many-threat-actors) |
| 2023-04-05 | Wazuh | Wazuh + YARA | rule `sliver_client` | YARA | `sliverpb`, `/sliver/`, `github.com/bishopfox/sliver/`, protocol byte patterns, `filesize < 50MB` | [Detecting Sliver C2 framework with Wazuh](https://wazuh.com/blog/detecting-sliver-c2-framework-with-wazuh/) |
| 2023-04-24 | Immersive Labs | YARA + Snort + Sigma | `sliver_binary_native`, `sliver_memory`; Snort sids 1000001–1000004; `Sliver-http.yml` | YARA + network | Unmodified implant strings `sliverpb` + `github.com/bishopfox/` + `chacha20poly1305`; default HTTP `.html/.php/.js/.png` + cookies | [Detecting and decrypting Sliver C2](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [Rules](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics) |
| 2023-05-04 | Corelight Labs | Corelight C2 Collection package “Sliver” | package “Sliver” notices | Network | Claimed coverage of all 4 primary listeners including encrypted/VPN; customer red-team hit | [New Sliver C2 Detection Released](https://corelight.com/blog/new-sliver-c2-detection-released-redteam-detected) (body thin on fetch; title/date from Corelight) |
| 2023-12 (cedowens list; Nuclei still ships it) | Nuclei / C2-JARM | `sliver-c2-jarm` | Network (JARM) | JARM `2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811adc883` | [nuclei-templates sliver-c2-jarm.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/network/jarm/c2/sliver-c2-jarm.yaml); [cedowens/C2-JARM](https://github.com/cedowens/C2-JARM) |
| 2024-04-25 | Hunt & Hackett | Velociraptor + Sysmon + JARM hunts | (unnamed hunts) | Behavior + network | Shell cmdline; `OpenProcessToken`/`ImpersonateLoggedOnUser`/`DuplicateTokenEx`; `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`; CN=multiplayer / O=operators | [Hunting for a Sliver in a haystack](https://www.huntandhackett.com/blog/hunting-for-a-sliver) |
| 2024-08-12 | The DFIR Report | Threat Feed + private Sigma (10 new rules, private) | Open-dir sample `WILD_PRIDE.exe` tagged Sliver | File-hash / intel feed | Stock implant in ransomware toolkit alongside PoshC2 | [Threat Actors' Toolkit](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/) |
| 2024-12-06 | cyber.wtf | Suricata | `C2-Sliver: Suspicous Keywords detected in HTTP POST` | Network | Default HTTP POST + English-word encoder tokens (ICTERICAL, STARFISH, …) | [Detection of C2 using Suricata](https://cyber.wtf/2024/12/06/detection-of-c2-using-suricata/) |
| 2025-04-01 | Fortbridge | Elastic YARA + extracted Defender YARA + Elastic Agent behavior | Elastic `Multi_Trojan_Sliver_*`; extracted Defender strings; Elastic **“Network Library Loaded from Unbacked Memory”** | YARA (strings) + behavior | Protobuf `ScreenshotReq`; Defender ASCII `GetJitter`/`VoidFunc`/`DllRegisterServer`/`Go buildinf:`; Go `LazyDLL`→`LoadLibraryExW` from unbacked memory | [Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/) |
| 2025-05-06 | BallisKit | Commercial packers vs “several EDRs” (names withheld) | (unnamed EDR hits on stage-2 in memory) | Behavior (runtime) | Stageless EXE “could run commands without being detected” on tested EDRs; **EXE stagers caught by some EDRs when second stage loaded in memory** | [Tutorial: Sliver C2 with MacroPack and ShellcodePack](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19) |
| 2025-06 | Palo Alto Networks | Advanced Threat Prevention Inline Cloud Analysis | **Threat ID 89961 \| Evasive Sliver C2 Traffic Detection**; SSL Command Control Detector | ML / network (TLS 1.3, no decrypt) | Sequence-based neural net over multiple TLS records; PAN-OS 11.2.7 + content 9006-9569 (demo video also cites 904-9564) | [ATP June 2025](https://docs.paloaltonetworks.com/content/techdocs/en_US/advanced-threat-prevention/new-features/by-date/advanced-threat-prevention/june-2025.html) |
| 2025-07-12 | NetWitness | Application rules | Stager App Rule; C2 Traffic App Rule | Network | `.woff` returning Windows executable magic; default HTTP path prefixes `/static/ /www/ /assets/…` | [Sliver C2 – Network and Endpoint Detection with NetWitness](https://community.netwitness.com/s/article/689643) |
| 2025-12-09 | Red Canary Intelligence (Zscaler-hosted) | Red Canary / Shodan / YARA / VMray | Shodan product=Sliver via cert `CN=multiplayer` issuer `O=operators`; YARA identified `1HTTPS.EXE` / `2MTLS.EXE` as Sliver | Network cert + YARA + sandbox | HTTPS implant → `marnyonline[.]com`; mTLS implant → `45[.]61[.]169[.]127:8443` | [Beyond the bomb (BYOVM)](https://www.zscaler.com/blogs/cybersecurity-best-practices/email-bombing-virtual-machine) |
| 2026-02-17 | Palo Alto (YouTube demo) | ATP SSL detector + DL | same Threat ID 89961 family | ML / network | “detect sliver C2 operating over TLS 1.3” without decrypt | [Detect Encrypted C2 with ATP](https://www.youtube.com/watch?v=CgqWJ5_jTsI) |
| 2026-02-28 | The Hunter’s Ledger | Sigma + YARA (campaign) | `sihost.exe` outbound 443/8443; ScareCrow Go loader YARA | Behavior + YARA | Injected Sliver beacon in `sihost.exe`; **no Suricata** because mTLS “indistinguishable from ordinary TLS without captured JARM/JA3S” | [Sliver C2 / ScareCrow open-directory detections](https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/) |
| 2026-07-20 | Vectra AI | Vectra AI Platform | (unnamed) C2/beaconing models | ML / network behavior | Packet lengths, timing, direction; **encoder rotation** produces multi-band sizes that break simple beacon clustering | [Detecting Sliver C2](https://www.vectra.ai/blog/detecting-sliver-c2-when-advanced-beaconing-tries-to-hide-in-plain-sight) |
| Ongoing 2024–2026 | Kaspersky | KAV | `Trojan.Win64.Sliver.*` (e.g. `.ht` 2024-02-01, `.io` 2024-02-25, `.oz` 2025-01-07) | File (family) | Family verdicts on VT/OpenTIP | [Kaspersky Trojan.Win64.Sliver.ht](https://threats.kaspersky.com/en/verdict/Trojan.Win64.Sliver.ht/) |
| Ongoing | ReversingLabs / Hybrid Analysis / Joe Sandbox | Multi-AV | `Win64.Trojan.SliverMarte`, `Win64.Backdoor.SliverMarte`, “Yara detected Sliver Implants” | File-hash / YARA / sandbox | Community + vendor family names on MalwareBazaar samples | e.g. [MalwareBazaar sample](https://bazaar.abuse.ch/sample/76fcc7de4d18b697a31318fd75ccffcda3afc056756aea7019e44d32b95c68c9/) |
| Community Falcon query (undated repo) | Unofficial | CrowdStrike LogScale | “Detect In-Memory .Net Assembly Modules Loaded from C2 Frameworks such as SilverC2, Metasploit” | Behavior (generic) | CLR DLLs `mscoree.dll`/`clr.dll` — **not a Falcon family name**; typo “SilverC2” | [Mikoyan-Dee/CrowdStrike-Queries](https://github.com/Mikoyan-Dee/CrowdStrike-Queries) |

**“We still catch default HTTP C2” vs “strings only” (dated)**

- **Still catch default HTTP C2 (network, not just strings):** Proofpoint ETPRO `Sliver Framework HTTP C2 sessionInit` (2021-10-20) — [Proofpoint](https://www.proofpoint.com/us/blog/security-briefs/ta551-uses-sliver-red-team-tool-new-activity). Immersive Snort 2023 still matches default `.html/.php/.js/.png` + cookie names — [sliver.snort](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.snort). Immersive explicitly: “all of these paths and extensions can be configured by the server operator” — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide). cyber.wtf Suricata 2024 still hunts English-word encoder tokens in HTTP POST — [cyber.wtf](https://cyber.wtf/2024/12/06/detection-of-c2-using-suricata/). NetWitness 2025 still documents `.woff` stager returning MZ — [NetWitness](https://community.netwitness.com/s/article/689643). Palo Alto June 2025 **still claims encrypted TLS 1.3 Sliver C2** via ML, no decrypt — [ATP June 2025](https://docs.paloaltonetworks.com/content/techdocs/en_US/advanced-threat-prevention/new-features/by-date/advanced-threat-prevention/june-2025.html). Vectra July 2026: encoder rotation evades *simple* size clustering but their DL models still target Sliver-style beaconing — [Vectra](https://www.vectra.ai/blog/detecting-sliver-c2-when-advanced-beaconing-tries-to-hide-in-plain-sight).
- **Strings only (static YARA, easily renamed):** Elastic `Multi_Trojan_Sliver_3bde542d` is protobuf/path strings; Fortbridge Apr 2025 renamed `ScreenshotReq`→`ScShotReq` and the string hits dropped — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/). Immersive `sliver_binary_native` is `sliverpb` + `github.com/bishopfox/` + `chacha20poly1305` — [sliver.yar](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.yar). NCSC `ScreenshotReq`/`SideloadReq` list — [gist](https://gist.github.com/ecapuano/2c59ff1ea354f1aae905d6e12dc8e25b). **Not strings only:** Elastic `Multi_Trojan_Sliver_3d6b7cd3` is bytecode of session-start/register (Fortbridge patched `GetMaxConnectionErrors()` to dodge it) — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- **Default implant callback vs post-ex:** Microsoft 2022 hunts **do not** key on the idle HTTP/mTLS callback itself; they key on **post-ex API sequences and default configs**. MDE’s *A process was injected with potentially malicious code* is the injection combo, not the beacon. Network-side default-HTTP catches are mostly third-party IDS (ETPRO, Immersive Snort, Corelight, PAN ATP).

### Inferences
- Public **brand-specific** coverage of Sliver is concentrated in Microsoft, Elastic (open YARA + unbacked-memory behavior), Immersive/Wazuh/NCSC YARA, Proofpoint ET, Palo Alto ATP, Vectra, Cybereason, Corelight, and DFIR/Red Canary incident blogs. CrowdStrike and SentinelOne did not publish comparable family names.
- Two durable layers coexist in 2025–2026: (1) **default HTTP/TLS fingerprints and ML on encrypted sessions** still fire on stock profiles; (2) **protobuf/export-string YARA** is acknowledged as bypassable by source rename (Fortbridge).
- “Default HTTPS 443” is rarely used as a *high-fidelity* detector (Cybereason: 443 too common); hunters prefer 8888/51820/31337, JARM, cert CN, or URI/extension patterns.

### Gaps
- Microsoft blog appendix “MDAV detects Sliver as the following malware” list was truncated in the JS-rendered fetch; encyclopedia names above are complete for those pages but may not be the full appendix.
- Elastic Security Labs (elastic.co/security-labs) had **no dedicated 2024–2026 Sliver analysis post** in search; detections live in `protections-artifacts`, not a narrative blog.
- Corelight package internals (exact signatures) are not in the public blog body that fetched.
- BallisKit withholds the EDR product names they tested.

---

## Microsoft 2022 “Sliver lining”: post-ex APIs vs default implant callback

### Takeaway
Microsoft’s 24 Aug 2022 hunting piece treats **default post-exploitation commands** (`migrate`, `sideload`, `spawndll`, `execute-assembly`, `getsystem`, `psexec`, `shell`) as the high-signal surface, implemented with the classic **`VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`** chain. It does **not** publish a hunt for the idle implant’s default HTTP/mTLS callback. File/family detections (`Trojan:Win64/Sliver*`, `Behavior:Win32/Splinter.A`, `ALF:Trojan:Win32/Sliver.A`) sit beside those behavioral hunts.

### Cited Findings
- Microsoft observed Sliver used by nation-state actors, ransomware affiliates (DEV-0237), and Bumblebee/COLDTRAIN loaders as a Cobalt Strike alternative since Dec 2020 — [Microsoft Security Blog 2022-08-24](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Infrastructure hunting is **listener fingerprinting** (unique HTTP header combinations and **JARM**), citing RiskIQ methodology, not implant-callback URIs — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Payload formats listed: shellcode, executable, shared library/DLL, service, plus **stagers**; motivated actors embed Sliver shellcode in custom loaders (Bumblebee) — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Named post-ex commands that use process injection: **migrate, spawndll, sideload, msf-inject, execute-assembly, getsystem**, plus BOF/alias extensions — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Named Windows APIs for `migrate` (and also Sideload, SpawnDll, Execute-Assembly): **`VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`**. MDE alert example: **“A process was injected with potentially malicious code”** — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- GetSystem hunt: `SeDebugPrivilege` (constant 1048576) added, then **`CreateRemoteThreadApiCall` into `spoolsv.exe`** within 30s, excluding `csrss.exe` — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Shell hunt: exact command line `powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8` — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Sideload/SpawnDll/Execute-Assembly hunt: same process **creates and injects `notepad.exe` within 10 seconds** via `CreateRemoteThreadApiCall` — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- PsExec hunt: registry `ImagePath` matching `[drive]:\windows\temp\[10 alnum].exe`, **DisplayName `Sliver`**, **Description `Sliver implant`**; or ServiceInstalled with ServiceName `Sliver` — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Guidance is explicitly for the **official, non-customized Sliver codebase as of writing** — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- MDE security-center titles listed as *indicators of C2-framework activity* (generic, not Sliver-branded): “Process hollowing detected”, “A process was injected with potentially malicious code”, “Abnormal Remote Service Execution”, “Suspicious file dropped”, etc. — [same](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- MDAV family names published around the same campaign: `Trojan:Win64/Sliver` (2022-12-08) — [WDSI](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Sliver); `Trojan:Win64/Sliver.D` (2021-11-26) — [WDSI](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Sliver.D&threatId=-2147161988); `Behavior:Win32/Splinter.A` plus **`ALF:Trojan:Win32/Sliver.A`, `ALF:Trojan:Win32/SliverServer.A`, `VirTool:Win64/Splinter.A`** (2022-08-29) — [WDSI Splinter.A](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Behavior:Win32/Splinter.A&threatId=0).
- Encyclopedia repeats the same injection API list and notes cloud-delivered protection / ML for unknown threats, without claiming the idle callback is the MDAV trigger — [WDSI Trojan:Win64/Sliver](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Sliver).

### Inferences
- For Microsoft in 2022, **the implant sitting idle and calling back over default HTTP/HTTPS is not the published hunt**. The published hunts are **post-ex techniques and default service/process names**.
- `execute-assembly` is grouped with Sideload/SpawnDll as **sacrificial `notepad.exe` + CreateRemoteThread**, not as a distinct CLR-load hunt in that blog (community Falcon queries later hunt CLR module loads generically).
- `Behavior:Win32/Splinter.A` / `VirTool:Win64/Splinter.A` are Microsoft’s **behavioral/file labels** for Sliver-related activity (name “Splinter” ≠ “Sliver”); `ALF:Trojan:Win32/Sliver*` looks like cloud/ALF signatures for implant and **server**.

### Gaps
- The live blog’s MDAV appendix list (“detects Sliver threat components as the following malware”) did not fully render; additional variant names beyond encyclopedia pages may exist.
- Microsoft did not publish a default HTTP URI/extension hunt in that article (contrast Immersive/Proofpoint).
- No Microsoft 2024–2026 follow-up blog dedicated to Sliver detections was found; encyclopedia pages were last updated 2022.

---

## Huntress / Red Canary / DFIR: process names, default HTTPS 443, `.woff`

### Takeaway
**Huntress published no dedicated Sliver C2 detection blog** in the searched 2024–2026 corpus. **Red Canary (Dec 2025)** identified Sliver from a BYOVM case via Shodan cert `CN=multiplayer` / `O=operators` and YARA on `1HTTPS.EXE` (HTTPS → `marnyonline[.]com`) and `2MTLS.EXE` (mTLS → `45.61.169.127:8443`) — not via default 443 or `.woff`. **The DFIR Report (Aug 2024)** found a stock implant named `WILD_PRIDE.exe` (Sliver’s random two-word name) in an open directory; they track Sliver in a C2 threat feed but did not document `.woff` or 443 as the detection. Default **HTTPS 443 is widely called too common** to be a detector; **`.woff` is the documented default *stager* extension**, used by NetWitness, BallisKit, Pretera, and Immersive — not by Huntress/Red Canary/DFIR in these posts.

### Cited Findings
- Huntress.com threat-research index and blog search (2024–2026) returned C2-implant stories (AhsayCBS Python implant, RedCurl, Havoc) but **no Sliver-titled post** — [Huntress threat research](https://www.huntress.com/blog-categories/threat-research); [Huntress blog](https://www.huntress.com/blog).
- Red Canary Intelligence (post dated Dec 9 2025, now on Zscaler): IP `45[.]61[.]169[.]127` associated with Sliver on Shodan because team-server mode defaults to SSL cert **subject `CN=multiplayer`, issuer `O=operators`** — [Beyond the bomb](https://www.zscaler.com/blogs/cybersecurity-best-practices/email-bombing-virtual-machine). Same fact used by Hunt & Hackett (Apr 2024) citing Shodan `product:sliver` — [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver).
- Inside the adversary QEMU VM, prefetch showed `1HTTPS.EXE`, `2MTLS.EXE`, `SOCKS.EXE`. YARA: `1HTTPS.EXE`/`2MTLS.EXE` = Sliver, “likely obfuscated using gobfuscate”. VMray: `1HTTPS.EXE` beaconed to `marnyonline[.]com`; `2MTLS.EXE` to `45[.]61[.]169[.]127` **port 8443** (not 443) — [Beyond the bomb](https://www.zscaler.com/blogs/cybersecurity-best-practices/email-bombing-virtual-machine).
- The DFIR Report 2024-08-12: open dir contained **`WILD_PRIDE.exe` — “Sliver C2 framework executable”**; VT collections linked the IP to PoshC2 **and** Sliver; DFIR Threat Feed tracked 94.198.53.143 for PoshC2/Sliver since Sep 2023 — [DFIR Report](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/).
- Cybereason 2023 lab implant was named **`nasty_roast.exe`** (Sliver random adjective_noun) and called back on **TCP 8888** (default mTLS), not 443 — [LevelBlue/Cybereason](https://www.levelblue.com/blogs/spiderlabs-blog/sliver-c2-leveraged-by-many-threat-actors).
- Cybereason default ports: **TCP 8888 mTLS, UDP 51820 WireGuard, TCP 443 HTTPS**; “communications on port 443 are too common to be a detection factor”; 8888 and 51820 are detection opportunities — [same](https://www.levelblue.com/blogs/spiderlabs-blog/sliver-c2-leveraged-by-many-threat-actors).
- Microsoft PsExec default drop path: `%WINDIR%\Temp\<10 alnum>.exe`; sacrificial process **`notepad.exe`**; GetSystem target **`spoolsv.exe`** — [Microsoft 2022](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- Official HTTP C2 docs: **`stager_file_ext` default `.woff`**; message-type extensions **`.woff` stagers, `.js` long-poll, `.html` key exchange, `.php` session, `.png` close** — [Sliver HTTPS C2 docs](https://sliver.sh/docs/?name=HTTPS+C2).
- NetWitness 2025: “WOFF is the default extension used to fetch the stage 2 payload”; rule `(directory contains ‘.woff’ || filename contains ‘.woff’) && file.type=’windows executable’` — [NetWitness](https://community.netwitness.com/s/article/689643).
- BallisKit 2025: “By default; Sliver stagers URLs have to end with `.woff`” — [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).
- Pretera 2025: “Any file ending in `.woff` will deliver staged shellcode” — [Pretera](https://www.pretera.com/sliver-bullet-staging-shellcode-process-injection/).
- Hunter’s Ledger 2026 campaign: injected beacon expected from **`sihost.exe`** outbound **443 or 8443** (ScareCrow/process-hollowing host, not Sliver’s own process name) — [Hunter’s Ledger detections](https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/).
- Shodan/RedPacket still tag **product “Sliver C2” on TCP 31337** (multiplayer/gRPC default) as of Nov 2026 — e.g. [RedPacket example](https://www.redpacketsecurity.com/sliver-c2-detected-104-207-93-111-port-31337/).

### Inferences
- **Process names in the wild are Sliver’s generated two-word names** (`WILD_PRIDE`, `nasty_roast`) or operator-chosen (`1HTTPS.EXE`), not a fixed `sliver.exe`. Detection by filename is weak; Microsoft/Cybereason instead hunt **notepad/spoolsv injection** and **Temp\10-char.exe**.
- **Default HTTPS 443 is not a Huntress/Red Canary/DFIR Sliver tell.** When 443 appears, it is either generic web or a customized port (Red Canary mTLS on **8443**).
- **`.woff` is a stager-URI tell**, documented by BishopFox and used by network vendors (NetWitness, Immersive), not by the three IR blogs in this question.

### Gaps
- Huntress may have private SOC detections; nothing public was found.
- DFIR’s 10 Sigma rules from the 2024 open-dir report are **private** (“added to our private sigma ruleset”) — [DFIR Report](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/). Contents not public.
- Red Canary did not publish the YARA rule text that labeled `1HTTPS.EXE` as Sliver.

---

## Default Sliver HTTP C2 profile URIs and JA3/JARM

### Takeaway
Default HTTP C2 is **procedural**: random paths under a small wordlist, **file extension encodes message type**, **nonce query parameter selects encoder**, cookies from a small set. **JARM hashes have been published several times but disagree** (Go/TLS version and mTLS vs HTTPS change the hash). **No widely cited JA3 client hash for the implant** was found in these sources; hunters use **JARM (server), JA3S rarely, and cert CN=multiplayer**.

### Cited Findings

**HTTP URI / profile (default)**

- Immersive 2023 (default config): extensions **`.woff` stagers, `.html` key exchange, `.js` long poll, `.php` session, `.png` close session**; “a random path is created for each request” but “a fixed number of default paths and filenames”; **all configurable** — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- Official docs match those five extensions and document `stager_file_ext` default `.woff` — [Sliver HTTPS C2](https://sliver.sh/docs/?name=HTTPS+C2).
- Older router comments (2021 source): `.txt` rsakey, `.jsp` start, `.php` session, `.js` poll, `.png` stop, `.woff` shellcode — [pat_h/to/file](https://blog.tofile.dev/2021/09/04/sliver.html). (Superseded in part by later `.html` key-exchange.)
- Immersive Snort (default path prefixes + cookies + nonce `?[a-zA-Z]=`):
  - Session start: POST `/(php|api|upload|actions|rest|v1|auth|…)/(login|signin|api|samples|rpc|index|admin|register|sign-up).html`
  - Session message: same with **`.php`**
  - Poll: GET `/(js|umd|assets|bundle|…)/(bootstrap|jquery|route|app|…).js`
  - Close: GET `/(static|www|assets|images|icons|…)/(favicon|sample|example).png`
  - Cookies: `PHPSESSID|SID|SSID|APISID|csrf-state|AWSALBCORS`
  — [sliver.snort](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.snort).
- Encoder selected per message; **nonce query parameter**; alphabets for Base32/58/64 are **modified**; English-words encoder uses 1,420 hardcoded words — [Immersive](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide).
- NetWitness C2 rule also lists prefixes `/static/ /www/ /assets/ /images/ /icons/ /image/ /icon/ /png/` plus “HTTP/1.1 without referer header” — [NetWitness](https://community.netwitness.com/s/article/689643).
- Proofpoint ETPRO: `Sliver Framework HTTP C2 sessionInit` (URI details not in the brief) — [Proofpoint 2021-10-20](https://www.proofpoint.com/us/blog/security-briefs/ta551-uses-sliver-red-team-tool-new-activity).

**JARM / JA3**

- Microsoft 2022: hunt listeners with **JARM hashes** and unique HTTP headers; cites RiskIQ (link in blog is a Defender TI article, not fetched here) — [Microsoft](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- pat_h/to/file 2021 mTLS (hardcoded `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, TLS 1.2): JARM **`28d28d28d00028d00043d28d28d43d47390d982d099a542ccbc90628951062`** — [Hunting Sliver](https://blog.tofile.dev/2021/09/04/sliver.html).
- cedowens C2-JARM (Go 1.15.2 linux/amd64): **`2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811adc883`** — [C2-JARM](https://github.com/cedowens/C2-JARM). Nuclei template still matches that exact hash — [sliver-c2-jarm.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/network/jarm/c2/sliver-c2-jarm.yaml).
- Cybereason 2023 (HTTPS beacon mode): JARM **`3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910` OR `00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01`**; “does not work for mTLS”; combine with HTTP/1.1 400 Bad Request — [Cybereason/LevelBlue](https://www.levelblue.com/blogs/spiderlabs-blog/sliver-c2-leveraged-by-many-threat-actors).
- port9.org 2024 lab: JARM **`3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910`** (matches Cybereason first hash) — [Fingerprinting TLS servers](https://blog.port9.org/posts/fingerprinting-tls-servers/).
- Hunt & Hackett 2024: monitor TLS on **port 31337** with issuer **`CN=operators`** and subject **`CN=multiplayer`**; “monitor … based on a JARM signature” (no hash quoted) — [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver).
- Hunter’s Ledger 2026: **no Suricata** for that campaign because “Sliver mTLS channel is indistinguishable from ordinary TLS at the packet level without a captured JARM/JA3S fingerprint” — [Hunter’s Ledger](https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/).
- Palo Alto ATP 2025: does **not** publish a JARM; uses **TLS handshake pre-filter + sequence NN on TLS 1.3 records**, Threat ID **89961** — [ATP June 2025](https://docs.paloaltonetworks.com/content/techdocs/en_US/advanced-threat-prevention/new-features/by-date/advanced-threat-prevention/june-2025.html).
- Vectra 2026: no JA3/JARM; **behavioral DL** on sizes/timing — [Vectra](https://www.vectra.ai/blog/detecting-sliver-c2-when-advanced-beaconing-tries-to-hide-in-plain-sight).

### Inferences
- Treat **URI extensions + nonce + cookie names** as “default HTTP C2 still detectable in 2023–2025” **only if the operator left `http-c2.json` stock**. Immersive, NetWitness, and BishopFox all say the profile is configurable.
- **Do not treat a single JARM as “the” Sliver hash.** Published values already split by protocol (mTLS vs HTTPS) and Go/TLS stack. Nuclei’s 2021-era Go 1.15 hash is still in templates in 2026 and will miss newer stacks.
- **JA3 (client)** is essentially unpublished for Sliver in these sources; **JA3S** is mentioned only as a missing fingerprint in Hunter’s Ledger.

### Gaps
- No primary source in this pass published a **JA3** (client hello) hash for a Sliver implant.
- RiskIQ/Microsoft Defender TI JARM article linked from the 2022 blog (`ti.defender.microsoft.com/articles/…`) was not fetched (portal).
- Exact default `http-c2.json` path/filename wordlists were shown as screenshots in Immersive (not fully OCR’d here); Snort regex is the best textual stand-in.

---

## Did renaming protobuf or disk LoadLibrary drop MDAV kills in 2025?

### Takeaway
**Fortbridge (1 Apr 2025) is the only detailed public 2025 writeup.** They report that **protobuf/export-string replacement dropped Elastic YARA and extracted-Defender-YARA hits**, that **in-memory/self-inject/pack against Elastic+Defender “proved ineffective”**, and that a **disk DLL + thin `LoadLibrary`/export-thread loader** then got a **callback on a system with Elastic Agent** and a **clean LitterBox** scan. They **do not publish a live Microsoft Defender cloud/MDAV “0 detections after rename” screenshot with product version/date**; Defender evidence is **extracted rules from `roadwy/DefenderYara`**, plus a claim that **writing the implant to disk was still detected until those ASCII strings were removed**. So: **rename + disk LoadLibrary is documented against Elastic Agent and extracted MDAV YARA in 2025; a controlled “MDAV cloud killed → then didn’t” is not independently published.**

### Cited Findings
- Fortbridge pain point: years ago stock payloads often survived disk; by 2025 “security tools now detect out-of-the-box implants much faster” because of static signatures — [Fortbridge 2025-04-01](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Staged download / encrypted embed / self-inject / hollowing **“tested … against Elastic EDR and Windows Defender, but—without revealing too much—they proved ineffective”** — [same](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Elastic YARA hits concentrated in `.proto` / generated `sliver.pb.go`; example string **`ScreenshotReq`**. sed-rename to **`ScShotReq`** and regenerate; “generated payloads no longer contained the string signatures” — [same](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Elastic rule **`Multi_Trojan_Sliver_3d6b7cd3`** (bytecode of init) bypassed by inlining `const maxConnectionErrors = 1000` instead of `transports.GetMaxConnectionErrors()` — [same](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); rule definition — [Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar).
- After Elastic YARA was clean, **implants were still detected when written to disk**. Hypothesis: Defender internal YARA. Used [roadwy/DefenderYara](https://github.com/roadwy/DefenderYara). Culprit **ASCII strings in byte form**: `DllUnregisterServer`, `DllRegisterServer`, `DllInstall`, **`GetJitter`**, **`VoidFunc`**, `GetKill`, `AddTunnel`, `GetIsIOC`, **` Go buildinf:`** — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- `DllRegisterServer`/`DllUnregisterServer`/`DllInstall` = regsvr32 exports; `VoidFunc` = PowerSploit `Invoke-ReflectivePEInjection` export. Fortbridge **removed unused exports** and renamed `StartW` / protobuf member `Jitter`→new name so `GetJitter` vanished — [same](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Runtime Elastic behavior: HTTP beacon init via Go **`LazyDLL` → `LoadLibraryExW`** produced **“Network Library Loaded from Unbacked Memory”**. Module stomping failed due to **~30 MB** size. Hooking `LoadLibraryExW` with hardware breakpoints “did not bypass the alert” — [same](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Elastic’s public analog is **`Network Module Loaded from Suspicious Unbacked Memory`** (loads of `ws2_32.dll`/`wininet.dll`/`winhttp.dll` with unbacked call stack) — [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_network_module_loaded_from_suspicious_unbacked_memory.toml). Related: **`Network Connect API from Unbacked Memory`** — [same repo](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/command_and_control_network_connect_api_from_unbacked_memory.toml).
- Workaround: **write implant DLL to disk**, load with a small program that `LoadLibrary`s it, finds the export, runs it on a new thread. After also replacing all **`bishopfox`** strings, LitterBox “comes out clean” and they “get a callback on a system with an elastic agent running” — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- Fortbridge X post: “bypassing **Windows Defender and Elastic EDR** with minimal code edits” (marketing claim, 2025-04-01) — [FORTBRIDGE on X](https://x.com/FORTBRIDGE/status/1906977277155614965).
- Aggregators (GBHackers/CybersecurityNews 2025-04-01/02) repeat “zero detections” and “callbacks on Elastic Agent without behavioral detections” but add no new primary evidence — [GBHackers](https://gbhackers.com/sliver-framework-customized-enhances-evasion/amp/); [CybersecurityNews](https://cybersecuritynews.com/sliver-framework-customized/amp/).
- BishopFox issue still open Aug 2024: “Garble is not picking up the protobuf methods, which makes for easy signatures” — [sliver#1760](https://github.com/BishopFox/sliver/issues/1760).
- DFIR Report Aug 2024: garble-obfuscated real-world sample **still versioned via protobuf definition strings** because protobufs “aren’t as easily obfuscated” — [DFIR Report](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/).
- bytebl33d 2025-01-04: **custom stagers** (FilelessPELoader / DInvoke / encrypted `.woff` stager + process hollowing of `svchost.exe`) claimed **ThreatCheck/DefenderCheck clean and a session “without Defender stopping us”** — this is **loader-side**, not protobuf rename, and is a homelab claim with DefenderCheck (static) — [bytebl33d](https://bytebl33d.github.io/blog/sliver-evasion/).
- BallisKit May 2025: wrapping stock 1.7.3 implant with ShellcodePack; **`--shellcode-bypass 1` to disable Donut AMSI** (same Donut issue Fortbridge patched in source); stagers **caught by some EDRs at stage-2 in memory**; they **refuse to name the EDRs** — [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).

### Inferences
- **Protobuf rename is a documented 2025 bypass for Elastic’s string YARA (`ScreenshotReq` etc.) and for extracted Defender string rules (`GetJitter`, `VoidFunc`, `DllRegisterServer`).** That is “strings only.”
- **Disk LoadLibrary is documented as the path that avoided Elastic’s unbacked-memory *network-library* behavior**, not as a magic MDAV cloud bypass. Fortbridge’s own narrative: **disk was the problem (Defender YARA) until strings were stripped; memory was the problem (Elastic unbacked load) until they put a DLL on disk.**
- Claims that “MDAV no longer kills after rename” in 2025 rest on **extracted YARA + LitterBox + an X post**, not a dated Microsoft Security Intelligence / MDE portal screenshot.

### Gaps
- No public 2025 paper shows **live Microsoft Defender Antivirus cloud ML** (`!ml` / cloud-delivered) going from detect → miss on a protobuf-renamed implant with build hashes and definition version.
- `roadwy/DefenderYara` is community-extracted and **may lag live cloud signatures** (Fortbridge acknowledges Defender rules aren’t open source).
- Fortbridge does not name the Elastic Agent version or whether **post-callback commands** still alert (their TOC promised “many built-in commands still trigger” in aggregator copies; the fetched body ends during “See Our Leading Research Insights”).
- `https://sliver.sh/docs?name=Anti-virus+Evasion` **failed to load** (SPA stub).

---

## CrowdStrike or SentinelOne public Sliver detections (names only)

### Takeaway
**No public CrowdStrike Falcon or SentinelOne Singularity *family/detection name* for Sliver implants was found** in non-paywalled vendor blogs, encyclopedias, or release notes. SentinelOne’s public Sliver material is **teamserver CVEs**, not endpoint detections. CrowdStrike public material is generic OverWatch hunting; a community LogScale query mentions “SilverC2” only as a generic CLR-load hunt. Do not invent Falcon/S1 names.

### Cited Findings
- CrowdStrike developer docs describe generic `falcon_search_detections` APIs, not a Sliver threat name — [CrowdStrike detections module](https://developer.crowdstrike.com/falcon-mcp/modules/detections/).
- CrowdStrike OverWatch datasheets/blogs in this pass discuss MITRE emulation and hands-on-keyboard hunting, **without naming Sliver** — e.g. [OverWatch data sheet](https://www.crowdstrike.com/en-us/resources/data-sheets/crowdstrike-falcon-adversary-overwatch-endpoint-threat-hunting/); [OverWatch MITRE blog](https://www.crowdstrike.com/en-us/blog/how-falcon-overwatch-spots-threats-in-mitre-adversary-emulation/).
- Unofficial GitHub “CrowdStrike-Queries” contains a LogScale hunt titled “Detect In-Memory .Net Assembly Modules Loaded from C2 Frameworks such as **SilverC2**, Metasploit” keyed on `mscoree.dll`/`clr.dll` — **community, typo’d, not an official Falcon detection name** — [Mikoyan-Dee/CrowdStrike-Queries](https://github.com/Mikoyan-Dee/CrowdStrike-Queries).
- SentinelOne public site: **CVE-2026-34227** and **CVE-2026-102507** are vulnerabilities **in the Sliver teamserver**, not endpoint detections of implants — [CVE-2026-34227](https://www.sentinelone.com/vulnerability-database/cve-2026-34227/); [CVE-2026-102507](https://www.sentinelone.com/vulnerability-database/cve-2026-102507/).
- SentinelOne marketing (Wayfinder, chained detections, MITRE 2024) does not list a Sliver family — e.g. [Wayfinder TDR](https://www.sentinelone.com/blog/managed-defense-reimagined-introducing-wayfinder-threat-detection-and-response/).
- BallisKit 2025 tested “several EDRs” with Sliver 1.7.3 and **explicitly withholds names** (“if you want to know the names of the EDRs we tested”) — [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).
- YouTube comment on a 2025 Defender test video claims “I bypassed Defender and Crowdstrike Falcon using sliver C2 implants” — **anecdotal, not a vendor detection name** — [Lsecqt video](https://www.youtube.com/watch?v=cfXgzjCeBuY).
- Cybereason (now LevelBlue, later announced as a SentinelOne Wayfinder delivery partner) **did** publish Sliver hunts in 2023, but those are **Cybereason platform hunts**, not SentinelOne product names — [Cybereason/LevelBlue](https://www.levelblue.com/blogs/spiderlabs-blog/sliver-c2-leveraged-by-many-threat-actors).

### Inferences
- Absence of public Falcon/S1 **names** is not evidence those products miss Sliver; it is evidence they **did not publish Sliver-branded detection names** in the open web corpus searched here.
- Where EDR names appear in 2025 red-team blogs, they are **Elastic Agent** and **Microsoft Defender** (Fortbridge) or **unnamed** (BallisKit).

### Gaps
- Falcon OverWatch customer notifications and S1 Storyline threat names are behind product consoles / paywalls; **not accessed**.
- No MITRE ATT&CK Evaluations round in this pass used Sliver as the named adversary (not searched exhaustively).
- Huntress EDR: no public Sliver detection name found (see previous section).

---

## Named APIs and functions (index for the writer)

### Takeaway
Public hunts repeatedly name the same Windows APIs and Sliver protobuf/export symbols. Network detections name URI handlers and TLS fingerprints, not Win32 APIs.

### Cited Findings
- **Injection / post-ex (Microsoft, Cybereason, Hunt & Hackett):** `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`; Sysmon Event ID 8; MDE `CreateRemoteThreadApiCall`; targets `notepad.exe` (sideload/spawndll/execute-assembly/migrate default), `spoolsv.exe` (getsystem) — [Microsoft 2022](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/); [Cybereason](https://www.levelblue.com/blogs/spiderlabs-blog/sliver-c2-leveraged-by-many-threat-actors); [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver).
- **Token theft (Hunt & Hackett):** `OpenProcessToken`, `ImpersonateLoggedOnUser`, `DuplicateTokenEx`, `AdjustTokenPrivileges`; privileges `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege`, `SeDebugPrivilege` — [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver); Microsoft GetSystem uses `SeDebugPrivilege` — [Microsoft 2022](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).
- **PsExec / service (Microsoft, VMware, Cybereason):** `CreateServiceW`, `StartServiceW`; DisplayName/Description **`Sliver` / `Sliver implant`** — [Microsoft](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/); [VMware](https://blogs.vmware.com/security/2023/01/detection-of-lateral-movement-with-the-sliver-c2-framework.html).
- **Shell:** `powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8` — [Microsoft](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/); [Cybereason](https://www.levelblue.com/blogs/spiderlabs-blog/sliver-c2-leveraged-by-many-threat-actors).
- **Go HTTP beacon vs Elastic:** `LazyDLL` / `NewLazyDLL()` → **`LoadLibraryExW`** — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- **Protobuf / YARA strings:** `ScreenshotReq`, `InvokeSpawnDllReq`, `NetstatReq`, `HTTPSessionInit`, `RegistryReadReq`, `RevToSelfReq`, `IfconfigReq`, `SideloadReq`, `InvokeMigrateReq`, `KillSessionReq`, `ImpersonateReq`, `NamedPipesReq`, `GetJitter`, `GetKill`, `AddTunnel`, `GetIsIOC`, `sliverpb`, `github.com/bishopfox/sliver` — [Elastic YARA](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar); [NCSC gist](https://gist.github.com/ecapuano/2c59ff1ea354f1aae905d6e12dc8e25b); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- **DLL exports:** `DllRegisterServer`, `DllUnregisterServer`, `DllInstall`, `VoidFunc`, `StartW` — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/).
- **Donut:** AMSI bypass level 3→1 (`--shellcode-bypass 1` / source `donut.go`) — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).
- **HTTP handlers (historical source names):** `rsaKeyHandler`, `startSessionHandler`, `sessionHandler` — [pat_h/to/file](https://blog.tofile.dev/2021/09/04/sliver.html).

### Inferences
- A writer can split detections into **(A) Win32 injection/token/service APIs**, **(B) protobuf/export strings**, **(C) HTTP extension/cookie/nonce**, **(D) JARM/cert/port**, **(E) ML on encrypted TLS** — and date when each was still claimed to work.

### Gaps
- Exact MDE internal rule IDs behind “A process was injected with potentially malicious code” are not published.
- JA3 client hashes: none found (see HTTP/JARM section).
