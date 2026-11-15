# Encrypt-at-rest crypter/packer/loader tradecraft for C2 implants (Sliver, Cobalt Strike, Mythic)

Authorized red-team / lab framing. Notes for synthesis; every non-obvious claim has a URL. Prefer 2023–2026 sources; older foundational tool docs cited where still the primary reference.

## Do operators routinely encrypt shellcode/EXE/DLL at rest so static AV hash/YARA misses the file on disk?

### Takeaway
Yes. Encrypting (or packing/encoding) the implant blob on disk—and decrypting only in memory at runtime—is standard both for authorized red teams and for malware authors deploying Sliver, Cobalt Strike, and similar C2s; the goal is defeating static hash/YARA/signature scanning of the on-disk artifact while accepting that behavioral/memory detection remains the harder problem.

### Cited Findings
- MITRE ATT&CK T1027 (Obfuscated Files or Information) states adversaries encrypt, encode, or otherwise obfuscate executable/file contents on the system or in transit to evade defenses; payloads may be compressed, archived, or encrypted to avoid detection. — [MITRE T1027](https://attack.mitre.org/techniques/T1027/)
- Sub-technique T1027.013 (Encrypted/Encoded File, created Mar 2024) explicitly covers encrypting/encoding file content to conceal malicious artifacts so static signatures miss content that is only revealed at execution (T1140 Deobfuscate/Decode). — [MITRE T1027.013](https://attack.mitre.org/techniques/T1027/013/)
- T1620 (Reflective Code Loading) notes that reflectively loading payloads into memory can avoid disk artifacts “while also enabling malware to keep these payloads encrypted (or otherwise obfuscated) until execution.” — [MITRE T1620](https://attack.mitre.org/versions/v17/techniques/T1620)
- Microsoft (Aug 2022) observed threat actors generating Sliver shellcode and embedding it in custom loaders (e.g. Bumblebee/COLDTRAIN) that run the implant on the compromised system; they note detection engineers can create loader-specific detections or, if the shellcode isn’t obfuscated, rules for the embedded shellcode. — [Microsoft Looking for the Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Donut’s documented design optionally encrypts the module with the Chaskey block cipher and a 128-bit random key, with the module either staged over HTTP or embedded in the loader; after in-memory load/execute, the original reference is erased to deter memory scanners. — [TheWover/donut README](https://github.com/TheWover/donut)
- ScareCrow encrypts input shellcode (AES-256, ELZMA, or RC4; default historically ELZMA/AES depending on version) before embedding it in a Go loader that decrypts at runtime, unhooks EDR hooks, and executes via custom syscalls—explicitly framed as protecting shellcode from on-disk EDR/AV analysis. — [optiv/ScareCrow README](https://github.com/optiv/ScareCrow); [Optiv ScareCrow overview](https://www.optiv.com/insights/source-zero/tools/scarecrow-payload-creation-framework)
- BallisKit’s May 2025 Sliver tutorial states that for evasion it is “generally a good practice to load the C2 generated DLL or EXE with ShellcodePack and not rely on the C2 own loader,” packing Sliver EXE/shellcode into an evasive loader rather than dropping a vanilla Sliver PE. — [BallisKit: Sliver + MacroPack/ShellcodePack](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)
- Sliver’s own staging path supports AES (CBC; key-length-dependent block size / PreludeEncrypt) and optional compression (zlib/gzip/deflate9) when serving stage2, so the bytes on the wire / fetched by a stager are not plaintext implant shellcode; docs include a C# Decrypt template. — [Sliver Stagers docs (search/wiki lineage)](https://sliver.sh/docs/?name=Stagers); [BishopFox issue #1317 clarifying AES-CBC wording](https://github.com/BishopFox/sliver/issues/1317)
- Public malware ops using open-source stacks: HarfangLab (Jun 2024) “Supposed Grasshopper” delivered Donut-wrapped Sliver (~15 MB stage combining Donut + Sliver), with Donut configured to patch AMSI/WLDP then map/execute the embedded payload. — [HarfangLab Supposed Grasshopper](https://harfanglab.io/insidethelab/supposed-grasshopper-operators-impersonate-israeli-gov-private-companies-deploy-open-source-malware/)
- Hunter’s Ledger (Mar 2026) documented a live attacker build workspace: PowerShell stager → ScareCrow-wrapped loader → Donut shellcode bootstrap → Sliver beacon; ScareCrow decoded Sliver shellcode from encrypted chunks embedded inline; Donut instance held AES-128-CTR key/nonce and encrypted Sliver PE content. — [Hunter’s Ledger: Sliver + ScareCrow open directory](https://the-hunters-ledger.com/reports/sliver-open-directory/)
- Red-team / community tooling consistently documents encrypt-then-VirtualAlloc patterns for Sliver (custom AES loaders, XOR-encrypted `.bin` next to a stub, FilelessPELoader + aes.py cipher.bin/key.bin, Crystal Palace / PalaceKit ChaCha20 or XOR embed). — [bytebl33d Sliver AV evasion blog](https://bytebl33d.github.io/blog/sliver-evasion/); [Sliver-Evasion-Suite / Crystal Palace patterns](https://github.com/panwnvda/SliverC2-Evasion-Suite/)

### Inferences
- “Routine” for OPSEC-conscious operators means: vanilla Sliver/CS EXE on disk is treated as a lab/demo artifact; production initial access almost always goes through a crypter/packer/loader or AES-staged shellcode so static AV signatures of the C2 PE miss.
- Encryption-at-rest is necessary but not sufficient: Fortbridge (Apr 2025) and Microsoft both emphasize that after static YARA/string evasion, behavioral/EDR telemetry (injection, sleep, network) becomes the binding constraint—packers buy time against hash/YARA, not against mature EDR.

### Gaps
- No public quantitative survey (e.g. “X% of authorized red-team engagements encrypt implants at rest in 2024–2026”); evidence is qualitative from tool docs, vendor blogs, and DFIR case studies.
- Elastic-specific long-form writeups on encrypted Sliver loaders were not retrieved in this pass beyond Fortbridge’s Elastic EDR test claims; treat Elastic coverage as thinner than Microsoft/HarfangLab/Hunter’s Ledger here.

## What tools are standard 2023–2026 (Donut, ScareCrow, PEzor, Nimcrypt2, ShellcodePack, Amber, custom AES, CS Artifact Kit, Mythic wrappers)?

### Takeaway
The dominant public stack for wrapping C2 implants is Donut (shellcode generation + optional Chaskey encrypt) combined with a second-stage loader/packer (ScareCrow, PEzor, Nimcrypt2, ShellcodePack, Amber, or custom AES/XOR stubs); Cobalt Strike still centers on Artifact Kit templates with encrypted beacon blobs; Mythic uses payload wrappers / IA loaders (e.g. Erebus) with compression→encryption→encoding pipelines. ScareCrow’s upstream Optiv repo was archived Aug 2023; active forks (e.g. Tylous) and continued in-the-wild use (2026) keep it relevant.

### Cited Findings
- **Donut (TheWover)** — PIC shellcode that loads .NET, PE EXE/DLL, VBS/JS from memory; optional Chaskey 128-bit encryption; entropy levels include “random names + symmetric encryption”; AMSI/WLDP/ETW patch options; widely used as the PE→shellcode step before ScareCrow/PEzor/custom loaders. Still the primary reference through 2025–2026 operator writeups. — [github.com/TheWover/donut](https://github.com/TheWover/donut)
- **ScareCrow (Optiv / Tylous)** — Go payload framework: AES / ELZMA / RC4 encrypt shellcode, EDR unhook (Disk or KnownDlls), indirect syscalls, AMSI/ETW patch, code-signing (fake or cloned), sideload formats (dll/cpl/excel/wscript/binary). Optiv repo archived 2023-08-18 with pointer to Tylous/ScareCrow; still observed wrapping Sliver in 2026 DFIR. — [optiv/ScareCrow](https://github.com/optiv/ScareCrow); [Hunter’s Ledger Mar 2026](https://the-hunters-ledger.com/reports/sliver-open-directory/)
- **PEzor (phra)** — Open-source shellcode & PE packer wrapping Donut (+ SGN, syscalls, unhook, antidebug); supports self-inject, RX vs RWX, fluctuate RW/NOACCESS during sleep, and `-xorkey` that retrieves key at runtime via `GetComputerNameExA(ComputerNameDnsFullyQualified)` (environmental keying). — [github.com/phra/PEzor](https://github.com/phra/PEzor)
- **Nimcrypt2 (icyguider)** — Nim PE/.NET/raw-shellcode packer/loader: AES with dynamic key generation, direct syscalls (NimlineWhispers2 / GetSyscallStub), ntdll unhook, sandbox checks, PPID spoof, string encryption; commonly cited in Sliver operator cheat sheets alongside ScareCrow/Donut. — [github.com/icyguider/Nimcrypt2](https://github.com/icyguider/Nimcrypt2)
- **ShellcodePack (BallisKit)** — Commercial/pro packer used in published 2025 Sliver tutorials to load Sliver EXE/DLL with EDR bypass profiles (indirect syscalls, spoof callstack); explicitly recommended over relying on Sliver’s native loader. — [BallisKit tutorial May 2025](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)
- **Amber (EgeBalci)** — Reflective PE packer: converts native PE to PIC reflective payload; historically RC4/XOR key encryption + SGN encoding; in-memory map/relocate/execute; still listed in packer ecosystems (~1.4k stars). — [github.com/EgeBalci/amber](https://github.com/EgeBalci/amber)
- **Custom AES / XOR loaders** — Ubiquitous in Sliver red-team blogs: FilelessPELoader + aes.py → cipher.bin/key.bin; simple loader.exe reading XOR’d `sliver.bin`; Crystal Palace / PalaceKit ChaCha20-Poly1305 or XOR embed of Sliver shellcode into PIC. — [bytebl33d](https://bytebl33d.github.io/blog/sliver-evasion/); [SliverLoader AES Decrypt template lineage](https://github.com/Cyb3rDudu/SliverLoader); [Sliver stage-listener AES](https://sliver.sh/docs/?name=Stagers)
- **Cobalt Strike Artifact Kit** — Licensed arsenal source framework that builds EXE/DLL templates which embed/patch the beacon; modern kits use encrypted payload blobs (e.g. “Phear”-style header + key + encrypted payload), stack spoofing defaults, and community Rust Artifact Kit research with XOR-rotating encrypted containers. — [Internal All The Things – Artifact Kit](https://swisskyrepo.github.io/InternalAllTheThings/command-control/cobalt-strike-kits/); [SilentStrike Rust Artifact Kit research Sep 2025](https://blog.silentstrike.io/posts/Advanced-Evasion-in-Rust-ArtifactKit/)
- **Mythic wrappers** — Mythic’s modular agents are often paired with initial-access wrappers; e.g. Erebus converts shellcode into phishing/IA formats with Shellcrypt chain: compression (LZNT1/RLE) → encryption (RC4/XOR/AES-ECB/AES-CBC) → encoding (BASE64/ASCII85/…), and accepts Mythic or external C2 shellcode (CS/Havoc/Sliver/msfvenom). — [Whispergate/Erebus](https://github.com/Whispergate/Erebus)
- Sliver operator guides list the common wrap set explicitly: “wrap with: donut, ScareCrow, Nimcrypt2, or custom Go loader.” — [gravanon Sliver operator guide](https://gravanon.com/)
- Fortbridge (Apr 2025) “Reforging Sliver” notes default Sliver shellcode generation relied on Donut’s AMSI bypass (heavily signatured); they disabled that path and introduced custom shellcode loaders that map payloads into memory dynamically when testing against Defender and Elastic. — [Fortbridge Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr)

### Inferences
- Tool popularity is layered: Donut is the near-universal PE→shellcode converter; ScareCrow/PEzor/Nimcrypt2/ShellcodePack/Amber are competing “stub + decrypt + execute” layers; Artifact Kit is CS-specific; Mythic prefers per-payload containers + community IA wrappers.
- Archive status (ScareCrow Optiv) does not equal obsolescence—DFIR still sees ScareCrow+Donut+Sliver chains in 2026.

### Gaps
- Immersive Labs public writeups on Sliver encrypt-at-rest were not located in this research pass (suggested source; may be gated/training-only).
- Relative prevalence of commercial ShellcodePack vs free Nimcrypt2/PEzor in authorized red teams is not publicly quantified.

## Typical chain: generate implant → encrypt → stub decrypts → VirtualAlloc/map → execute (variants)

### Takeaway
The canonical OPSEC chain is: generate C2 implant (often as PE or raw shellcode) → convert/pack (Donut/Amber/etc.) → encrypt blob → deliver stub that decrypts into allocated memory (VirtualAlloc / NtAllocateVirtualMemory / section map) → protect RX → create thread / APC / fiber / export call. Variants differ by whether the encrypted blob is embedded in the stub, adjacent on disk, or fetched as a stage2 over the network (Sliver stage-listener AES).

### Cited Findings
- **Embedded encrypt-at-rest (single file):** ScareCrow embeds AES/ELZMA/RC4 ciphertext in the Go loader; at runtime decrypt → load via RtlCopy / VirtualAlloc / NtQueueApcThreadEx / process injection templates. — [ScareCrow README Encryption + Exec sections](https://github.com/optiv/ScareCrow)
- **Donut module path:** Generator builds encrypted (Chaskey) module either embedded in loader PIC or staged from HTTP; loader maps PE / hosts CLR / runs script in memory, optionally overwrites PE headers, patches AMSI/WLDP/ETW. — [Donut README](https://github.com/TheWover/donut)
- **Split file (stub + blob):** Community Sliver kits ship `loader.exe` + XOR’d `sliver.bin`; loader reads file, XOR decrypts, VirtualAlloc, memcpy, CreateThread. — [pantha704/sliver-c2 attack chain description](https://github.com/pantha704/sliver-c2)
- **Staged AES (network encrypt-at-rest for stage2):** Sliver `stage-listener --aes-encrypt-key/--aes-encrypt-iv` (+ optional `-C` compress) serves encrypted shellcode; custom stagers (C#/PowerShell/C++) download, AES-decrypt, then allocate/execute—plaintext implant never sits as a static PE on disk for initial access. — [Sliver Stagers](https://sliver.sh/docs/?name=Stagers); [Medium: Sliver PowerShell stager AES Jul 2024](https://medium.com/@youcef.s.kelouaz/writing-a-sliver-c2-powershell-stager-with-shellcode-compression-and-aes-encryption-9725c0201ea8)
- **PEzor PE→shellcode→packed EXE:** Input EXE → Donut → packer options (syscalls, unhook, sleep, fluctuate) → output EXE/DLL that self-injects or injects. — [PEzor README](https://github.com/phra/PEzor)
- **Four-stage observed malware chain (2026):** stager.ps1 → ScareCrow loader (decrypt encrypted chunks) → Donut bootstrap (AES-128-CTR encrypted Sliver PE) → Sliver beacon in hollowed process (e.g. sihost.exe). — [Hunter’s Ledger](https://the-hunters-ledger.com/reports/sliver-open-directory/)
- **Shared library / DLL variants:** ScareCrow/dll and Sliver `--format shared` / DLL sideload; exports (DllRegisterServer, etc.) used with rundll32/regsvr32; Fortbridge’s final step was a small program that loads the implant DLL from the same folder and runs the entry export in a new thread. — [ScareCrow Loader types](https://github.com/optiv/ScareCrow); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr)
- **Shellcode vs EXE vs .NET:** Donut unifies these: native PE custom loader vs Unmanaged CLR Hosting for assemblies vs IActiveScript for VBS/JS; Nimcrypt2 `-t csharp/raw/pe` mirrors the same trichotomy. — [Donut](https://github.com/TheWover/donut); [Nimcrypt2](https://github.com/icyguider/Nimcrypt2)
- **In-memory sleep re-encryption (related, not disk):** Sliver evasion suites and CS sleep_mask XOR/encrypt implant memory during sleep then decrypt on wake—orthogonal to disk encrypt-at-rest but same “ciphertext until needed” idea. — [Microsoft on CS sleep_mask](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/); [Sliver-Evasion-Suite MaskKit](https://github.com/panwnvda/SliverC2-Evasion-Suite/)

### Inferences
- Authorized red teams often prefer staged AES (small stager on disk / in macro, encrypted stage2 over HTTPS) for size and reduced static footprint; cybercrime kits more often ship large ScareCrow/Donut monoliths signed with fake certs.
- “VirtualAlloc → memcpy → CreateThread” is the pedagogical minimum; production loaders favor indirect syscalls, RW→RX (avoid RWX), APC/fiber, or module stomping.

### Gaps
- No single canonical BishopFox “official” encrypt-at-rest loader beyond stage-listener AES templates—operators are expected to bring their own stub (by design).
- Detailed Mythic agent-native encrypt-at-rest (vs wrapper-layer Shellcrypt) varies by agent and was not exhaustively inventoried.

## Environmental keying (decrypt only if hostname/domain matches) — how common?

### Takeaway
Environmental keying (MITRE T1480.001) is a well-documented execution-guardrail technique and appears in several public packers (notably PEzor’s `-xorkey` via DNS FQDN, ScareCrow sandbox `IsDomainJoined`, research forks adding domain-keying), but it is less “default on every implant” than simple AES-with-embedded-key; it is more common in targeted malware and high-OPSEC red-team packages than in casual lab wraps.

### Cited Findings
- MITRE T1480.001: adversaries derive decryption keys from target-specific values (AD domain, hostname, shares, files, IP, etc.) so the encrypted payload only decrypts in the intended environment; frustrates sandboxing and AV sample sharing. — [MITRE T1480.001](https://center-for-threat-informed-defense.github.io/mappings-explorer/attack/attack-16.1/domain-enterprise/techniques/T1480.001/); [ATT&CK DET0474 detection strategy](https://attack.mitre.org/versions/v19/detectionstrategies/DET0474)
- PEzor documents `-xorkey=KEY` to encrypt the payload with multibyte XOR and retrieve the key at runtime using `GetComputerNameExA(ComputerNameDnsFullyQualified)`—direct hostname/FQDN environmental keying in a mainstream red-team packer. — [PEzor README / help](https://github.com/phra/PEzor)
- ScareCrow `-sandbox` enables sandbox evasion using `IsDomainJoined` checks (domain-joined gate, not full crypto keying); community ScareCrow forks (2023) added explicit domain-keying for sandbox evasion. — [ScareCrow -sandbox](https://github.com/optiv/ScareCrow); [ptr0x1 ScareCrow Part II](https://ptr0x1.com/posts/edr-evasion-part-ii-scarecrow/)
- Classic red-team tooling: Ebowla / GoGreen-style environmental keying for scripts (username, computername, domain, paths hashed into AES keys) remains the conceptual ancestor cited in ATT&CK. — [adapt-and-attack GoGreen 2017](https://adapt-and-attack.com/2017/11/15/keying-payloads-for-scripting-languages/); [ATT&CK citations to Ebowla / Gauss]
- Huntress (2021) documented in-the-wild PowerShell malware keyed on COMPUTERNAME/USERNAME/USERDOMAIN/IP so automated analysis fails without the victim environment. — [Huntress keyed malware](https://www.huntress.com/blog/threatops-analysis-keyed-malware)
- NHIMG FAQ (2026): attackers place keying early—before decrypt/decode—so sandboxes see inert stubs. — [nhimg.org environmental keying](https://nhimg.org/faq/how-do-attackers-use-environmental-keying/)

### Inferences
- For Sliver specifically, public default tooling (stage-listener AES, stock ScareCrow) usually embeds the key with the stub; true env-derived keys show up when operators deliberately enable PEzor `-xorkey` or custom loaders.
- Env keying is “common enough to be a MITRE sub-technique and packer feature,” not “universal in every 2024–2026 Sliver drop.”

### Gaps
- No reliable public statistic on how often authorized red teams enable env keying on Sliver vs CS Artifact Kit in 2023–2026.
- Cobalt Strike Artifact Kit stock templates’ use of env-derived keys (vs static XOR) was not confirmed from primary Arsenal docs in this pass (licensed material).

## What do public Microsoft / Elastic / DFIR writeups say about encrypted Sliver / custom loaders (Bumblebee-style)?

### Takeaway
Vendor and DFIR reporting consistently describes Sliver as delivered via custom or commodity loaders that keep shellcode encrypted/obfuscated until runtime (Bumblebee historically; Donut+ScareCrow chains through 2024–2026), and urge defenders to hunt loader behavior and in-memory config rather than static Sliver PE hashes alone.

### Cited Findings
- **Microsoft (Aug 2022):** Actors historically tied to human-operated ransomware delivered Sliver using Bumblebee (COLDTRAIN) as initial-access loader; “Motivated threat actors can generate a Sliver shellcode and embed it in custom loaders like Bumblebee”; implants heavily obfuscate/encrypt configs (garble/gobfuscate); extract configs from memory when decrypted for use; process injection is core. Hunting should focus on TTPs resilient to tool churn. — [Microsoft Looking for the Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- **HarfangLab (Jun 2024):** “Supposed Grasshopper” Nim downloader → Donut stage (~15 MB) embedding Sliver; Donut self-decodes, API-hashes, patches AMSI/WLDP, maps/executes Sliver. Campaign used realistic WordPress lure sites and dedicated infra—illustrates open-source encrypt/load stack in targeted ops. — [HarfangLab](https://harfanglab.io/insidethelab/supposed-grasshopper-operators-impersonate-israeli-gov-private-companies-deploy-open-source-malware/)
- **Hunter’s Ledger (Mar 2026):** Full open-directory recovery of ScareCrow+Donut+Sliver build pipeline; ScareCrow polymorphic loader with encrypted shellcode chunks; Donut AES-128-CTR over Sliver PE; sleep masking / ETW / AMSI / HalosGate; recommends behavioral and certificate IOCs over hashes because rebuilds are polymorphic (~8 minutes). — [Hunter’s Ledger](https://the-hunters-ledger.com/reports/sliver-open-directory/)
- **Fortbridge (Apr 2025):** Red-team research modifying Sliver protobuf/strings and replacing Donut AMSI-bypass defaults with custom memory-mapping loaders to evade Windows Defender and Elastic EDR static/behavioral detections; final delivery via small DLL loader. — [Fortbridge Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr)
- **Packer detection guidance (general, 2026 industry):** Packing/encryption defeats static appearance; durable detection is post-unpack behavior (W→X transitions, unexpected child processes, C2, credential access)—aligned with SpecterOps-style “detect the operation not the tool” tradecraft messaging. — [ManageEngine packers guide](https://www.manageengine.com/malware-protection/articles/malware-packers.html); [SpecterOps Reactive Progress / Tradecraft Analysis framing](https://medium.com/specter-ops-posts/reactive-progress-and-tradecraft-innovation-b616f85b6c0a)

### Inferences
- “Bumblebee-style” in Microsoft’s sense = dedicated loader family that decrypts/runs Sliver shellcode; the 2024–2026 analogue in open reporting is often Donut+ScareCrow (or custom AES) rather than Bumblebee itself.
- Defenders and authorized operators converge on the same conclusion: static encrypt-at-rest is table stakes; detection and OPSEC both move to behavior, memory, and loader uniqueness.

### Gaps
- Elastic Security’s own long-form public blog specifically titled around encrypted Sliver loaders was not found in this pass; Fortbridge’s Elastic EDR lab results are the main Elastic-adjacent citation here.
- Immersive Labs materials (suggested) were not publicly fetchable in this research pass.

---

## Quick reference — MITRE mapping

| Pattern | Technique |
| --- | --- |
| Encrypt/encode implant on disk | T1027 / T1027.013 Encrypted/Encoded File; T1027.002 Software Packing |
| Decrypt then run in current process memory | T1140 + T1620 Reflective Code Loading |
| Inject decrypted shellcode into another process | T1055 Process Injection |
| Hostname/domain-derived decrypt key | T1480.001 Environmental Keying |

## Source date cheat sheet (primary)

| Source | Date |
| --- | --- |
| Microsoft Sliver lining | 2022-08-24 |
| Donut README (ongoing primary) | current / v1.1 lineage |
| ScareCrow Optiv archive | 2023-08-18 |
| HarfangLab Supposed Grasshopper | 2024-06-28 |
| BallisKit ShellcodePack + Sliver | 2025-05-06 |
| Fortbridge Reforging Sliver | 2025-04-01 |
| Hunter’s Ledger ScareCrow+Sliver | 2026-03-01 |
| MITRE T1027.013 | created 2024-03-29 |
| MITRE T1620 | 2021+ (reflective loading + encrypt-until-exec language) |
