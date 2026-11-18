# Why Windows Defender can kill a Sliver session that already called back (especially Beacon → interactive)

Authorized lab / adversary-emulation analysis. Scope is **post-execution**: the implant already decrypted, ran, and registered with the teamserver. The operator report is “Beacon orqali ochilgan sessiya defender tomonidan yopilmoqda” (a session opened via a Beacon is being closed by Defender). Loader-stage tricks (XOR, unique hashes, RW→RWX, no CreateThread, hide-console) are treated as **already spent** once the Go implant is live in process memory.

Two products must be distinguished throughout:

- **Microsoft Defender Antivirus (inbox / MDAV)** — `WinDefend` / `MsMpEng.exe`. Real-time protection, cloud-delivered protection, client behavioral blocking, scheduled scans, Protection History, Operational log 1006/1015/1116/1117. Present on Windows 10/11 even with **no** E5 license. — [Microsoft Learn: MDAV in Windows](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows)
- **Microsoft Defender for Endpoint (MDE / E5 or P1/P2)** — `Sense` / `MsSense.exe`. EDR telemetry, advanced hunting, behavioral blocking + containment, EDR in block mode, Sense Operational log. — [Microsoft Learn: Sense events](https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes); [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)

Inbox Defender **alone** can still terminate a live implant via signature, heuristic, behavior, or cloud classification. MDE adds process-tree / injection / C2 hunting that Microsoft published specifically against Sliver.

---

## Once the Sliver implant is decrypted and running, what artifacts exist in memory?

### Takeaway
A live Sliver implant is a **full statically linked Go binary unpacked in process memory** (typically ~16–30 MB). Independent of how it arrived (XOR loader, unique hash, RW→RX, no CreateThread), memory contains protobuf schema strings, often `sliverpb` / `github.com/bishopfox/`, Go runtime/`Go buildinf`, session keys, and (for HTTP) default C2 path/encoder artifacts. Public YARA is written to scan **memory as well as files**.

### Cited Findings
- Immersive Labs: “Memory detection is easier as the entire Go binary must be unpacked into memory regardless of any packing of the binary or staged delivery.” Average implant size ~16 MB. — [Immersive Labs: Detecting and decrypting Sliver C2](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide) (2023-04-24)
- Immersive **file** YARA `sliver_binary_native` matches PE/ELF/Mach-O magic plus strings `sliverpb`, `github.com/bishopfox/`, and `chacha20poly1305`. Separate **memory** rule `sliver_memory` matches only `sliverpb` (file rule uses header offsets that fail in dumps). — [Immersive-Labs-Sec/SliverC2-Forensics `sliver.yar`](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.yar)
- Elastic `Multi_Trojan_Sliver` rules set `scan_context = "file, memory"` and key on protobuf strings `).RequestResend`, `).GetPrivInfo`, `InvokeSpawnDllReq`, `NetstatReq`, `HTTPSessionInit`, `ScreenshotReq`, `RegistryReadReq`, package path `B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb`, plus x86/x64 bytecode for session start/register. — [elastic/protections-artifacts `Multi_Trojan_Sliver.yar`](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar)
- BishopFox maintainers: garble **does not obfuscate protobuf methods**; running Elastic’s YARA against a live beacon finds those strings **in the binary and in memory**. Issue still open; custom AST obfuscation for protobuf is “slow going,” some work in v1.6, no comprehensive ETA. A later comment notes “several Defender AV signatures detecting these strings.” — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760) (opened 2024-08-16; moloch comment 2025-01-06)
- The DFIR Report: in-the-wild Sliver sample used garble; analysts still versioned it via protobuf definition strings because protobuf “aren’t as easily obfuscated.” VT hash in the post shows multi-AV hits on disk. — [The DFIR Report, 2024-08-12](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/)
- Fortbridge (2025 lab vs Elastic + Defender): stock implants hit many YARA rules; culprits included protobuf names (`ScreenshotReq`) and Defender-oriented extracted ASCII strings `DllUnregisterServer`, `DllRegisterServer`, `DllInstall`, `GetJitter`, `VoidFunc`, `GetKill`, `AddTunnel`, `GetIsIOC`, and ` Go buildinf:`. Those strings exist in the **running** implant, not only on disk. — [Fortbridge: Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/) (2025-04-01)
- Microsoft (MDE hunting): Sliver decrypts/de-obfuscates configuration **in memory**; hunters extract config from process memory after load. Stagers exist to shrink the **on-disk** first stage; the full implant still lands in RAM. — [Microsoft Security Blog: Looking for the ‘Sliver’ lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/) (2022-08-24)
- Immersive: **session keys are always present in memory** of an active implant (pattern `00 00 [32-byte key] ?? ?? ?? 00 C0 00 00`). Canary domains (if enabled) are **cleartext** in the binary; real C2 is encrypted until runtime. — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)
- Dominic Breuker (stager + inject into Edge): Process Hacker finds a large RX region **not backed by a DLL** containing readable Sliver implant content. — [Learning Sliver C2 (07) – Stagers: Process Injection](https://dominicbreuker.com/post/learning_sliver_c2_06_stagers_process_injection/) (2022-10-09)
- Solar 4RAYS (Russian IR write-up): memory dumps of session implants can yield C2 URI prefixes `wg://`, `mtls://`, `http://`, `https://`, `dns://`, `tcppivot://`, `namedpipe://`; mTLS dumps can also yield certificates. Garble only obfuscates strings **longer than 7 characters**, leaving short protocol tokens. — [RT-Solar: implants under the microscope](https://rt-solar.ru/solar-4rays/blog/3843/)
- Named-pipe pivots are **not** created by default on a beacon→session upgrade. They appear only if the operator starts `pivots named-pipe` (session-only) and generate `--named-pipe`. Default pipe path is operator-chosen (`\\.\pipe\<name>`). — [Sliver Docs: Pivots](https://sliver.sh/docs/?name=Pivots)
- Certificates: mTLS implants embed a client cert against the Sliver CA. Hunt & Hackett: default **operator** mTLS listener can show issuer `CN=operators` / subject `CN=multiplayer` (this is the **operator gRPC** listener, not necessarily the implant C2 cert). FoxIO (2026): Sliver mTLS X509 structure has a **JA4X** fingerprint of the cert *generator*, independent of CN/SAN values. — [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver) (2024-04-25); [FoxIO: JA4Scan / Sliver](https://foxio.io/blog/introducing-ja4scan-active-server-fingerprinting-for-tls-and-quic) (2026-09-30)
- HTTP C2 default extensions (if the profile was not customized) are compiled into the implant: `.woff` stager, `.html` key exchange, `.js` long-poll, `.php` session, `.png` close; nonce query param selects encoder. This UI already flags that fingerprint: “This still looks like default Sliver to public detectors.” — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); local [`httpc2_fingerprint.go`](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/httpc2_fingerprint.go); [`en.ts` `httpc2.defaultCopy`](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)

### Inferences
- After callback, the **on-disk loader hash is no longer the object under scan**. The object is the process’s private/mapped executable memory plus the Go image (or the host process if injected).
- `sliverpb`, protobuf RPC names, and `Go buildinf` are **family signatures**, not loader signatures. XOR/unique-hash/RWX tricks never touch them once plaintext is mapped.
- Named pipes and extra certs are **optional post-ex artifacts**. They are not required for a session kill; protobuf + Go runtime + unbacked RX + C2 traffic are enough.

### Gaps
- Microsoft does **not** publish the live MDAV YARA/ML feature set. Fortbridge inferred Defender strings from [roadwy/DefenderYara](https://github.com/roadwy/DefenderYara), which can lag cloud signatures.
- No public 2025–2026 dump of exact `Win32/` threat names Defender assigns to live Sliver memory (e.g. `Trojan:Win64/Sliver` vs generic `Behavior:Win32/…`) was found in this pass.

---

## Do Microsoft or researchers document Sliver in-memory signatures and behavioral rules (inject, migrate, getsystem, execute-assembly, spawn)?

### Takeaway
Yes. Microsoft’s 2022 MDE hunting blog is still the canonical **behavioral** map for stock Sliver post-ex (CRT inject, GetSystem→`spoolsv.exe`, default `notepad.exe` sacrificial process, PsExec service named “Sliver”). Elastic, Immersive, Hunt & Hackett, Fortbridge, and The DFIR Report document **in-memory YARA** plus the same injection API chain. Inbox Defender’s **client behavioral blocking** can also stop a process that already started (`Behavior:Win32/…!ml`), including Command-and-Control and Defense-Evasion tactics, without needing an MDE license.

### Cited Findings
- Microsoft MDE (2022, still cited 2023–2026): default `migrate` / `Sideload` / `SpawnDll` / `Execute-Assembly` follow `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`. Example alert: “A process was injected with potentially malicious code.” GetSystem hunt: `SeDebug` then remote thread into `spoolsv.exe` within 30 seconds. Default execute-assembly / inject sacrificial process is `notepad.exe`. Default PsExec: `DisplayName`=`Sliver`, `Description`=`Sliver implant`, `ImagePath` matching `%WINDIR%\Temp\<10 alnum>.exe`. Config extraction from **memory**. JARM / HTTP header hunting for listeners. — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Hunt & Hackett (2024): `execute-shellcode` defaults to spawning `C:\windows\system32\notepad.exe`, `VirtualAllocEx` RW, `WriteProcessMemory`, `VirtualProtectEx` RX, `CreateRemoteThread`. Sysmon: Event 1 (implant + child), Event 10 (process access), Event 8 (CreateRemoteThread). “The memory of a system was proven to be the most important data source for most of the attack methods of Sliver.” Modern EDR uses ETW for those traces. — [Hunting for a Sliver in a haystack](https://www.huntandhackett.com/blog/hunting-for-a-sliver)
- Elastic: `Multi_Trojan_Sliver` file+memory YARA (above). Kernel ETW call-stack rules label `unbacked_rwx`, `allocate_shellcode`, `hollow_unbacked`, `shellcode`; execute-assembly loading `clr.dll` from an unbacked stack. — [Elastic: Upping the Ante](https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks) (2023-05-31); [Doubling Down ETW call stacks](https://www.elastic.co/security-labs/threat-command/doubling-down-etw-callstacks) (2024-01-09)
- Fortbridge vs Elastic (2025): after static string scrubbing, HTTP beacon init via Go `LazyDLL` → `LoadLibraryExW` from **unbacked memory** still fired **“Network Library Loaded from Unbacked Memory.”** Module stomping failed because of implant size. “Many commands built into the Sliver implant will still trigger Elastic behavioral alerts during runtime.” — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [CybersecurityNews summary](https://cybersecuritynews.com/sliver-framework-customized/) (2025-04-02)
- Microsoft Learn (MDAV, not only MDE): “Microsoft Defender Antivirus can also stop threats based on their behaviors and process trees **even when the threat has started execution**. A common example … is fileless malware.” Client behavioral blocking sends process trees to cloud ML and **blocks the running artifact**. Behavior detections use MITRE names such as `Behavior:Win32/CommandAndControl.*!ml`, `Behavior:Win32/DefenseEvasion.*!ml`, `Behavior:Win32/PrivilegeEscalation.*!ml`. — [MDAV overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows); [Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking); [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment) (updated 2026-05-06)
- Microsoft lists techniques behavioral blocking has stopped, including **cross-process injection**, **process hollowing**, **credential dumping from LSASS**, **C2 download of payloads**, **AV tampering**. — [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)
- Event ID **1015** `MALWAREPROTECTION_BEHAVIOR_DETECTED` is the engine-side “suspicious behavior” event (distinct from file-hash 1006/1116). — [Microsoft Learn: Defender event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- Corelight released a Sliver network-detection package covering all four primary listeners (HTTP, DNS, mTLS, WireGuard), framed as detecting **post-compromise C2 after a loader already ran**. — [Corelight: New Sliver C2 Detection](https://corelight.com/blog/new-sliver-c2-detection-released-redteam-detected) (2023-05-04)
- Red Canary **2025 and 2026 Threat Detection Reports** do **not** list Sliver among top-10 threats (identity, infostealers, RMM, SocGholish dominate). Absence is not a claim that Sliver is undetected; it is not a high-volume commodity family in their customer telemetry. — [Red Canary 2026 TDR](https://redcanary.com/blog/threat-detection/2026-threat-detection-report/); [Red Canary 2025 TDR](https://redcanary.com/blog/threat-detection/2025-threat-detection-report/)

### Inferences
- Stock Sliver **post-ex** is documented as textbook T1055. Opening an interactive session and then running `execute-assembly`, `migrate`, `getsystem`, `execute-shellcode`, or `spawndll` is a much louder event than the original beacon check-in.
- Inbox Defender can kill **without** MDE if cloud ML or a behavior signature fires (`Behavior:Win32/…` or a Sliver-family signature). MDE adds named alerts Microsoft already published against this framework.

### Gaps
- Microsoft has not published a 2025–2026 successor to the 2022 Sliver-lining blog with updated alert names. Researchers still treat that post as current hunting guidance.
- Exact mapping from a given Sliver command to a specific `Behavior:Win32/…` or `Win32/` threat name is not public.

---

## Beacon vs session: does `interactive` / “open session” look like process injection / CreateRemoteThread / fork&run?

### Takeaway
**No — not by itself.** Sliver `interactive` / RPC `OpenSession` starts a **session connection loop as a goroutine inside the same beacon process**. It does not generate a new implant on the teamserver, does not CreateRemoteThread into a child, and is not Cobalt Strike–style fork&run. Defender killing “the session” is almost always killing **that same process** (or a later post-ex inject the operator ran *from* the session). The session **is** louder on the network (long-poll / persistent TCP vs sleep+jitter).

### Cited Findings
- Official Sliver tutorial: “Session can be spun up in our beacon process using the `interactive` command. **Under the hood this will spawn a goroutine running session connection loop in the same beacon process.**” Sessions use long-polling / a constantly maintained TCP connection; beacons check in and sleep. Typical engagement: deploy beacon, switch to session for active enumeration. SOCKS5 and high-bandwidth commands are session-only. — [Sliver Tutorials: 2 – Beacons vs Sessions](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions)
- BishopFox wiki (Getting Started): beacons may be tasked to open interactive sessions over **any C2 protocol they were compiled with**; `close` closes the session (beacon remains). You cannot open HTTP session from an implant compiled without HTTP. — [BishopFox wiki: Getting Started (archived)](https://github.com/BishopFox/sliver/wiki/Getting-Started/c05dac02c4045704731b64d7055b98b7236e8fe8)
- Operator guides: `interactive` leaves the original beacon intact (dual-mode); `close` returns to beacon without killing the remote process. Session-mode implants cannot become beacons. — [Hackers Arise](https://hackers-arise.com/sliver-building-command-and-controlc2-during-a-cyb/) (2025-07-17); [stinger.io Windows Beacon](https://stinger.io/sliver/windows/windows-beacon-implant) (2025-10-31); [Radiant Sec](https://radiantsec.io/docs/tools/sliver/) (2026-08-01)
- This UI’s `OpenSessionFromBeacon` sends `C2S: []`, `Delay: 0` — same as native `interactive` with defaults. Comment in code: “instructs a beacon to open a new interactive session on its next check-in.” `CloseSession` “closes an interactive session without killing the remote process.” — [`backend/internal/sliver/beacon_ops.go`](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/beacon_ops.go)
- Radiant Sec OPSEC table: Session = “More visible (long-lived connection)”; Beacon = “Low-churn, blends with scheduled traffic.” Long-lived mTLS to port 8888 is called out as anomalous; prefer HTTPS 443. — [Radiant Sec](https://radiantsec.io/docs/tools/sliver/)
- **ASR does not generally block CreateRemoteThread.** The ASR rule “Block Office applications from injecting code into other processes” (GUID `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84`) applies to Word/Excel/OneNote/PowerPoint only. InfinitumIT (2026): MDE records `CreateRemoteThreadApiCall` / `NtAllocateVirtualMemoryRemoteApiCall` and even `RemoteCreateThreadProcessHollowing`, but there is **no default-on ASR covering PowerShell/cmd/wscript/generic processes**. — [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference); [InfinitumIT: MDE and T1055](https://www.infinitumit.com.tr/blog/microsoft-defender-for-endpoint-process-injection-t1055-tespit?lang=en) (2026-08-04)
- Commands that **do** look like fork&run / CRT inject, and which operators often run *after* opening a session: `execute-shellcode` (default notepad + CRT), `execute-assembly` (sacrificial process, default notepad), `migrate`, `getsystem` (inject `spoolsv.exe`), `spawndll` / `sideload`. Those are documented above (Microsoft, Hunt & Hackett).
- SOCKS, `portfwd`, interactive `shell`, and some Armory tools **require a session**. Operators who open a session to “do work” immediately increase both network dwell and the chance of running a high-signal command. — [Sliver Tutorials: Beacons vs Sessions](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions)

### Inferences
- The assignment hypothesis “the child process is a fresh Sliver implant from the teamserver” is **incorrect for stock `interactive` / this UI’s Open Session**. No new PE is generated. The same decrypted Go image keeps running; it just adds a long-lived C2 loop.
- If the original beacon lived in a custom loader process, the session lives there too. Killing the session **kills the beacon**.
- If the operator *then* `migrate`s or `execute-shellcode`s into another process, **that** child is a new memory-resident implant and is the classic Defender/MDE injection target — even if the beacon parent survives.
- Why a session dies “after callback” more often than a quiet beacon: (1) long-lived connection + more HTTP long-poll / TLS; (2) more Go threads/heap activity while “awake”; (3) operators immediately run noisy post-ex; (4) memory scanners have a larger, hotter working set to match. None of that is the loader’s XOR stub.

### Gaps
- Implant source for `OpenSession` handler was not re-read line-by-line in this pass; the tutorial/wiki wording is treated as authoritative.
- No public telemetry proving Defender specifically keys on “HTTP long-poll vs beacon interval” as a distinct signature; the visibility difference is documented as OPSEC, not as a named MDAV rule.

---

## Memory scanners: can MsMpEng scan process memory after the file on disk looked unique?

### Takeaway
Yes. Unique on-disk hashes only beat **exact-hash IOCs of that file**. MDAV real-time protection, cloud protection, scheduled scans, and (on MDE) EDR memory models inspect **running processes**, fileless/in-memory code, and behavior **after** execution. Public Sliver YARA is explicitly dual `file, memory`. Fortbridge’s 2025 finding that “lack of sleep mask” leaves idle implants easy to YARA-scan is the mechanism that matches “callback succeeded, then later the session died.”

### Cited Findings
- Microsoft: MDAV “can stop threats based on their behaviors and process trees even when the threat has started execution”; fileless malware is the example. Client behavioral blocking monitors the device, sends process trees to cloud ML, and **blocks the running artifact**. Cloud-delivered protection feeds the Intelligent Security Graph. — [MDAV overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows); [Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking)
- Microsoft: real-time protection “continuously scans your computer”; files are scanned before access/execution; scheduled quick scan + always-on RTP + cloud is the default recommended combo. Unsigned binaries trigger RTP or scheduled scans at launch. — [MDAV scan best practices](https://learn.microsoft.com/en-us/defender-endpoint/mdav-scan-best-practices); [Troubleshoot performance issues](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-performance-issues)
- Event 1006 Detection Source includes Real-time, AMSI, NIS (network inspection), IOAV. Event 1015 is explicit **behavior** detection. — [Defender event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- Independent reverse-engineering of MDAV (Chinese write-up, 2025-era engine): module-load via `WdFilter.sys` → untrusted module added to MOAC → `TriggerEmsScan` submits a **memory scan** job to the engine thread pool. Treat as **researcher reconstruction**, not Microsoft documentation. — [Weixin: Defender memory-scan trigger](https://mp.weixin.qq.com/s/C6CePu9albvGTj3_9aUxeg)
- Elastic Multi_Trojan_Sliver and Immersive `sliver_memory` are designed to hit **unpacked** implants. Fortbridge: “large binary size and lack of sleep mask leave memory-resident implants easy to YARA-scan while idle.” — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Sleep-obfuscation literature (general, not Sliver-default): EDRs with periodic memory scanning (pe-sieve class, Elastic Defend, SentinelOne) hunt private executable regions and known implant byte patterns **during sleep**. — [Red Team Leaders: Sleep Obfuscation](https://docs.redteamleaders.com/offensive-security/defense-evasion/sleep-obfuscation-encrypting-beacons-during-rest) (2026-05-02)
- BishopFox: `--obfuscate` / garble does not hide protobuf in memory (#1760). Sleep obfuscation is **not** a shipped generate flag; moloch: “Obfuscated sleep is complicated because of the go runtime”; PR #1805 (Ekko) remains unmerged with deadlock issues as of late 2026 comments. — [Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171); [PR #1805](https://github.com/BishopFox/sliver/pull/1805)

### Inferences
- A unique loader SHA-256 is irrelevant once `MsMpEng` (or MDE) looks at **process memory**. The implant’s protobuf/Go strings are stable across unique loaders.
- Time delay (beacon lives minutes, session dies later) is consistent with **scheduled/quick scan**, **cloud classification after more telemetry**, or **behavior after interactive work** — not with “the loader was FUD then suddenly wasn’t.”

### Gaps
- Microsoft does not document a public “scan all process memory every N minutes” interval. RTP + scheduled quick scan + cloud is the documented model; EMS/MOAC internals are unofficial.
- No public A/B test “same Sliver beacon, unique loader, Defender RTP only, time-to-kill” was found.

---

## Network: default Sliver HTTPS JA3/JARM, URI patterns, certificates, and this UI’s HTTP C2 warning

### Takeaway
Default HTTP(S) C2 is **fingerprintable** (extensions, nonce, cookies, empty UA). This UI already warns: “This still looks like default Sliver to public detectors.” TLS: **client** JA3 of a stock Go implant is a Go crypto/tls fingerprint (wininet driver is the documented way to look like Windows). **Server** HTTPS JARM is randomized by default but not operator-specified; mTLS JARM/JA4X and default port 8888 remain hunting features. Network detection does not require the on-disk loader to be known.

### Cited Findings
- Immersive default HTTP map: `.woff` stager, `.html` key exchange, `.js` long-poll, `.php` session, `.png` close; random path from a **fixed default set**; nonce query parameter selects encoder (modified Base32/58/64, English-words list of 1,420 words, gzip). Snort + Sigma published. Operators **can** reconfigure all of this. — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)
- Local fingerprint helper treats profile name `default`, nonce length 1, extensions `.woff`/`.php`/`.png` or `.js`/`.php`, empty User-Agent, cookies `JSESSIONID`+`rememberMe` as default-looking. UI copy: “This still looks like default Sliver to public detectors.” — [`httpc2_fingerprint.go`](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/httpc2_fingerprint.go); [`en.ts`](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts)
- Radiant Sec: “Cleartext C2 profiles: default HTTP(S) profile URLs/filenames are documented and fingerprintable. Customize per engagement.” Prefer 443/80 over long-lived mTLS 8888. — [Radiant Sec](https://radiantsec.io/docs/tools/sliver/)
- BishopFox (moloch, issue #1809, 2024-11-04): “The **server-side HTTPS signatures are randomized by default but cannot be specified**. mTLS’ are **fixed Golang fingerprints** and we don’t recommend using this C2 protocol in contexts which require stealth. We don’t have any feature to modify the **client** fingerprints other than on Windows you can specify **wininet** which should give you the default Windows fingerprint.” — [BishopFox/sliver#1809](https://github.com/BishopFox/sliver/issues/1809)
- Community JA3 lists include Sliver hashes such as `b386946a5a44d1ddcc843bc75336dfce` and `9740f1e2c6dc332d1a2bbf8b67e79dc5` (treat as **OSINT lists**, not Microsoft-published). — [ebpf-guard `tls-fingerprints.yaml`](https://raw.githubusercontent.com/zugolO/ebpf-guard/main/rules/tls-fingerprints.yaml)
- Historical JARM: tofile.dev (2021) measured Sliver mTLS JARM `28d28d28d00028d00043d28d28d43d47390d982d099a542ccbc90628951062` from hardcoded cipher `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`; HTTPS JARM depended on Go version. cedowens C2-JARM listed Sliver (Go 1.15.2) `2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811adc883`. **These hashes are version-dated**; BishopFox later added HTTPS randomization. — [tofile.dev Hunting Sliver](https://blog.tofile.dev/2021/09/04/sliver.html); [cedowens/C2-JARM](https://github.com/cedowens/C2-JARM); [port:9 fingerprinting](https://blog.port9.org/posts/fingerprinting-tls-servers/)
- FoxIO JA4Scan (2026): Sliver HTTPS listener randomization still leaves a recognizable JA4Scan class; mTLS TLS1.3 + `RequireAndVerifyClientCert` plus default port **8888** narrows internet-wide hits; **JA4X** fingerprints the X509 *structure* of Sliver-generated mTLS certs even when CN changes. — [FoxIO JA4Scan](https://foxio.io/blog/introducing-ja4scan-active-server-fingerprinting-for-tls-and-quic)
- Hunt & Hackett: hunt TLS on 31337 with issuer `CN=operators` / subject `CN=multiplayer` (default **operator** C2, not implant); JARM for malicious TLS servers; WireGuard where WireGuard is unused. — [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver)
- Corelight: detection package for all four listener types, including encrypted/VPN-obscured. — [Corelight](https://corelight.com/blog/new-sliver-c2-detection-released-redteam-detected)
- Microsoft 2022 blog includes JARM/HTTP-header hunting for Sliver **listeners** (infra side). Inbox Defender’s NIS (`WdNisSvc` / Event 1006 source NIS) can inspect some network threats but is **not** documented as a Sliver-HTTP YARA engine.

### Inferences
- A successful callback with **default HTTP C2** is already a network IOC. Switching beacon→session increases connection lifetime (long-poll / persistent), which helps network sensors and may contribute to host “C2 behavior” classifiers (`Behavior:Win32/CommandAndControl.*!ml`).
- Customizing HTTP C2 **before generate** is the only way to change what the **already-running** implant will send. Loader XOR cannot rewrite compiled paths.

### Gaps
- No Microsoft-published JA3/JA4 values for Sliver implants were found.
- Whether inbox Defender NIS currently signatures default `.php`/`.woff` Sliver URIs is not documented; public detections are Snort/Sigma/Zeek/Corelight.

---

## If the operator generated a beacon then used “open session,” is the on-disk loader irrelevant because a fresh implant is spawned?

### Takeaway
**The loader is irrelevant for a different reason:** `OpenSession` does **not** spawn a fresh teamserver-built implant. The session is a goroutine in the **existing** process. The bytes Defender scans are the **already-decrypted Sliver image** in that process (or in a process the operator later migrated into). Unique loader hashes, XOR, hide-console, and “no CreateThread in the stub” do not apply to that image.

### Cited Findings
- Same-process goroutine: [Sliver Tutorials: Beacons vs Sessions](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions)
- UI OpenSession empty C2S / Delay 0: [`beacon_ops.go`](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/beacon_ops.go)
- A **new** implant appears only if the operator separately `generate`s a session payload and delivers it (`execute`, `sideload`, `execute-shellcode`, `migrate`, PsExec, etc.). Those paths **are** injection/spawn and **are** the Microsoft/Hunt & Hackett detections. — [Microsoft Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/); [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver)
- Immersive: full Go binary must unpack into memory regardless of staging. — [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)

### Inferences
- Mental model to discard: “loader was unique → session is a new file from C2 → Defender hashes the new file.” Correct model: “loader ran once → plaintext Sliver lives in RAM → `interactive` only changes C2 mode → Defender/MDE inspect RAM + behavior + network.”
- If the lab used a **shellcode loader** that injected into a host process, the session is still that host process. Protection History `Path` may show the host EXE (e.g. a spoofed OneDrive name) or a memory address, not the original encrypted blob.

### Gaps
- Whether any Sliver UI/build in this fork ever auto-generates a *second* implant on Open Session: the wrapped RPC does not; native `interactive` does not.

---

## Tamper / remediation: does Defender “threat detected / action taken: remove” kill the process (1116) vs quarantine the file?

### Takeaway
Event **1116** is detection only (`MALWAREPROTECTION_STATE_MALWARE_DETECTED`). Event **1117** is the action (`Clean` / `Quarantine` / `Remove` / `Block` / `Allow` / `No action`). Quarantine/Remove/Clean of a **running** image typically **terminates the process** as part of remediating the resource; Block prevents execution. 1116 alone does not prove the session was killed — 1117 Action + Action Status do. Failed remediation is **1118** (noncritical) or **1119** (critical; endpoint may be unprotected). Behavior-only hits may appear as **1015** before or instead of a family name.

### Cited Findings
- 1006 = engine-side malware detected (`MALWAREPROTECTION_MALWARE_DETECTED`); 1116 = platform-side state detection. On modern Windows both often fire for one incident; they are not duplicates. — [Microsoft Learn: event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus); [Forenza on 1006 vs 1116](https://forenza.io/windows-defender-event-1006-threat-detected/) (2026-05-31)
- 1117 actions include Clean, Quarantine, Remove, Allow, User defined, No action, **Block** (“The resource was blocked from executing”). User action text: “Microsoft Defender Antivirus removed or quarantined a threat.” Non-remediating actions (Allow / No action / None) **do not** stop the process. — [Microsoft Learn: 1117](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- 1116 user-action text: “Microsoft Defender Antivirus can **suspend and take routine action** on this threat.” — same Learn page
- 1015 = suspicious **behavior** detected (`MALWAREPROTECTION_BEHAVIOR_DETECTED`), includes Process Name, Target File Name, Signature ID. — same
- Protection History in Windows Security is the user-visible 1116/1117 pair (typically two-week UI retention; Event Viewer keeps longer). — [Techdows: Protection History](https://techdows.com/view-protection-history-of-microsoft-defender-antivirus-in-windows-10.html)
- Client behavioral blocking: once cloud ML classifies the artifact malicious, it is **blocked on the device**; running attacks can be stopped. — [Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking)
- ASR blocks are **1121** (block) / **1122** (audit), not 1116. Network protection block is **1126**. Do not confuse ASR 1121 with malware 1116. — [ASR events](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)
- Tamper protection (on by default in modern Windows) keeps RTP on and blocks disabling Defender; it is **not** the mechanism that kills Sliver. Event **5013** = tamper protection blocked a change. — [NHIMG MDAV guide](https://nhimg.org/microsoft-defender-antivirus-guide) (2026-11-08)

### Inferences
- Operator-visible “Defender closed the session” ≈ process terminated because 1117 Action was Quarantine/Remove/Clean/Block against the process image or a memory resource, **or** MDE EDR-in-block-mode killed it without a local 1117 (Sense-side).
- If Protection History shows only a **file** quarantine of an old loader on disk, but the process was already running from memory, that 1117 might **not** explain the session drop — look for a second detection whose Path is the running process or “memory.”

### Gaps
- Microsoft’s public event schema does not always spell “process terminated” as a separate field; investigators infer it from Action + Process Name + the process disappearing. No official table mapping Action IDs to NtTerminateProcess was found.

---

## What telemetry to collect (inbox Defender vs MDE)

### Takeaway
On a **box-only** Windows 10/11 lab: Protection History threat **name**, Operational log **1006, 1015, 1116, 1117, 1118, 1119**, plus 1121/1122 if ASR is on, 1125/1126 if network protection is on, 5007/5013 for tamper/config. Record Detection Source, Detection Type, Path, Process Name, Action, signature/engine versions. On **MDE-onboarded** hosts, also collect Sense Operational, Defender portal alert/incident, and Advanced Hunting (`DeviceEvents` injection APIs, `DeviceNetworkEvents`). `Get-MpComputerStatus` (`AMRunningMode`, `OnboardingState`) tells you which stack actually acted.

### Cited Findings
- Event Viewer path: **Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational**. Filter 1116,1117. — [Microsoft Learn: how to view events](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- Recommended forward set for SIEM: 1006/1116 (detect), 1007/1117 (action), 1008/1118/1119 (fail), 1121 (ASR block), 1150/1151 (health), 2001 (sig update fail), 5001/5010/5012 (RTP/AV disabled), 5007 (config change), 5013 (tamper block). — [NHIMG MDAV guide](https://nhimg.org/microsoft-defender-antivirus-guide)
- 1006/1116 fields that matter for this incident: **Name** (threat family vs `Behavior:Win32/…`), **Path**, **Detection Type** (Heuristics / Generic / Concrete / Dynamic signature), **Detection Source** (Real-time / System / User / AMSI / NIS / IOAV), **Process Name**, Signature Version, Engine Version. — [Microsoft Learn event 1006/1116](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- MDE Sense log: **Applications and Services Logs → Microsoft → Windows → SENSE → Operational**. “SENSE is the internal name used to refer to the behavioral sensor that powers Microsoft Defender for Endpoint.” — [Review events using Event Viewer](https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes)
- Distinguish stacks: Defender AV = `WinDefend` / `MsMpEng.exe`; MDE = `Sense` / `MsSense.exe`. `Get-MpComputerStatus`: `AMRunningMode` Normal | Passive Mode | EDR Block Mode | SxS Passive Mode; `OnboardingState` 1 = onboarded. Inbox AV can be Active without MDE. — [Microsoft Q&A: AV vs EDR](https://learn.microsoft.com/en-in/answers/questions/5977297/clarification-on-whether-microsoft-defender-is-ope); [Get-MpComputerStatus / compatibility](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)
- MDE hunting examples Microsoft published for Sliver: GetSystem (SeDebug + remote thread into spoolsv), default PsExec registry values, injection into notepad. Those queries run in the **Microsoft 365 Defender portal**, not Event Viewer. — [Microsoft Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- MDE `DeviceEvents` ActionTypes observed in injection research: `CreateRemoteThreadApiCall`, `NtAllocateVirtualMemoryRemoteApiCall`, `NtProtectVirtualMemoryApiCall`, `RemoteCreateThreadProcessHollowing`. — [InfinitumIT](https://www.infinitumit.com.tr/blog/microsoft-defender-for-endpoint-process-injection-t1055-tespit?lang=en)
- EDR in block mode (MDE, **off by default**) can remediate even when MDAV is not primary AV. — [Behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)
- Correlate 4688 (process create) / Sysmon 1, 3 (network), 8 (CreateRemoteThread), 10 (process access) around the 1116 timestamp. Hunt & Hackett mapped those Sysmon IDs to Sliver `execute-shellcode`. — [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver)

### Inferences
- If the lab box is **not** onboarded (`OnboardingState=0`, no `MsSense.exe`), blame **inbox MDAV** (RTP + cloud + behavior). Loader folklore about “EDR only” is then false.
- If onboarded, collect **both** Windows Defender Operational **and** Sense + portal. A session can die from MDAV 1117 *or* from MDE containment with a portal alert and a thin local 1116.
- Threat **name** is the highest-value single field: family signature (`Trojan:Win64/…`, `VirTool:…`) vs `Behavior:Win32/CommandAndControl.*!ml` vs ASR 1121 tells you whether this was **in-memory family YARA**, **behavior**, or **ASR**.

### Gaps
- No public dictionary of current Defender threat names for Sliver 1.5–1.7 was found. Lab must record the exact Name string from 1116.

---

## Can sleep obfuscation / encrypt-at-rest / unique loader hash help AFTER the implant is live?

### Takeaway
**Unique loader hash: no.** It never applied to RAM. **Encrypt-at-rest: no after decrypt** — plaintext is what scanners and behavior engines see; Fortbridge found encrypt-in-loader **ineffective** against Elastic+Defender without source-level implant edits. **Sleep obfuscation: theoretically delays memory-YARA during beacon sleep only**; stock Sliver **does not ship Ekko-style sleep mask** (Go runtime makes it hard; PR #1805 unmerged). An **interactive session is awake** (long-poll loop), so sleep encryption would not cover the window when the operator is actually using the session — which is exactly when the report says Defender closes it.

### Cited Findings
- Unique hash vs exact-hash lookup only; VirusTotal still sandboxes a new hash. This project’s README already states that. Go loader still contains `VirtualAlloc` / `CreateThread` / `kernel32.dll` if those APIs are used. — [repo README](file:///home/cup/Documents/personal/sliv/README.md)
- Encrypt-at-rest research in this tree: ciphertext defeats inner-payload hashes and many string YARA **on disk**; it does not defeat stub signatures, entropy heuristics, sandbox detonation of decrypt→alloc→exec, or **periodic memory scanners that see plaintext while the implant is awake**. Fortbridge: encrypted implant in a loader vs Elastic+Defender **ineffective** without deeper customization. — [local `detection_reality.md`](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20encrypt%20at%20rest%20loaders/detection_reality.md); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- moloch (2023): “typically these [direct syscalls] will be most effective to implement **in your loader**. Obfuscated sleep is complicated because of the go runtime.” — [BishopFox discussion #1171](https://github.com/BishopFox/sliver/discussions/1171)
- PR #1805 adds `--sleep-obfuscation` / `-B` for Windows beacons (Ekko / later APC trampoline); reviewers reported hang/deadlock with Go runtime Suspend/Resume; **not merged** as of comments dated through 2026-11. — [PR #1805](https://github.com/BishopFox/sliver/pull/1805); [Issue #1806](https://github.com/BishopFox/sliver/issues/1806)
- Fortbridge explicitly calls out **lack of sleep mask** as a reason memory-resident Sliver is easy to YARA while idle. Even after they renamed protobuf and cleared static YARA **on disk and in memory scans**, **built-in commands still triggered Elastic behavioral alerts**. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Sleep-mask theory (Ekko): encrypt image during sleep so YARA/PE-structure scans miss it; **while awake** (callback, tasking, interactive loop) memory is plaintext RX again. — [dtsec Ekko intro](https://dtsec.us/2023-04-24-Sleep/) (2023-04-24); [DEV: Sleep Mask part 1](https://dev.to/aliangbo/sleep-mask-in-red-team-vs-blue-team-engagements-part-1-a-deep-dive-into-ekkos-timer-based-382e) (2026-09-19)
- BishopFox anti-virus docs (project stance): AV bypass is **out of Sliver’s scope**; use packers/crypters/stagers. Loader tricks are a **delivery** layer. — cited throughout [Sliver UI AV OPSEC practices.md](file:///home/cup/Documents/personal/sliv/reports/Sliver%20UI%20AV%20OPSEC%20practices.md) from [sliver.sh Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion)

### Inferences
- For the reported failure mode (**callback succeeded, then session closed**), loader-stage OPSEC has **already succeeded** at its job (initial execution). It cannot protect a live, decrypted, protobuf-rich Go implant, especially one that just switched to a long-lived session and may be running post-ex.
- The only in-process mitigations that even *aim* at this phase are: (1) **source-level** protobuf/export/Go-string scrub (fork; breaks stock client/server compatibility), (2) **sleep encryption while beaconing** (not in upstream, and unused during interactive), (3) **don’t open interactive / don’t run CRT post-ex** on a host with Defender RTP+cloud, (4) **custom HTTP C2 + wininet** to reduce network fingerprint — none of which are XOR/unique-hash/hide-console.

### Gaps
- No public 2026 measurement of Defender time-to-kill for stock vs protobuf-renamed vs sleep-obfuscated Sliver beacons.
- Whether Microsoft’s cloud ML uses JA3 of the *implant process* as a feature is unpublished.

---

## Synthesis for the report writer

**What happened (most likely, authorized-lab reading of “beacon opened a session, then Defender closed it”):**

1. Custom loader beat **on-disk hash / some static YARA**. Implant decrypted, beacon checked in. That only proves the **stub** was not blocked at launch.
2. Operator used `interactive` / UI Open Session. **Same PID**, new long-lived C2 goroutine. No new file from the teamserver.
3. Minutes later MDAV and/or MDE matched **in-memory family strings** (protobuf / `sliverpb` / exports / `Go buildinf`), **unbacked executable + network DLL load** behavior, **C2 behavior** (`Behavior:Win32/CommandAndControl`), and/or a **post-ex inject** the operator ran from the session (`execute-assembly`/`migrate`/`getsystem`).
4. 1117 Quarantine/Remove/Block (or MDE containment) **terminated the process** → both session and beacon drop.

**Loader tricks cannot prevent step 3.** They are spent at step 1.

**ASR CreateRemoteThread is a red herring** for stock `interactive` (same process, and ASR inject rule is Office-only). It becomes relevant only if the operator later injects.

**Collect:** Protection History Name + 1116/1117 Path/Process/Action + `Get-MpComputerStatus` OnboardingState/AMRunningMode + (if onboarded) Sense/portal alert. That single Name field tells you signature vs behavior vs ASR.
