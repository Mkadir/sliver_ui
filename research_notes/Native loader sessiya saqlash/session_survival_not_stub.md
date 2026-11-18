# Post-callback survival of stock BishopFox Sliver (v1.7.x) vs stage-0 stub language (Go → C/C++/C#)

Authorized-lab synthesis. Scope is **after** the loader has executed and a callback exists. The product question is whether rewriting the wrap stub from Go to C/C++/C# changes **Defender/Elastic killing a live session**, or only the **stub PE** that launches Donut PIC.

**Short answer:** a native C/C++/C# stub that still `VirtualAlloc` + CALL Donut PIC of a **stock** `sliverpb` image addresses **stage-0 PE / unique-hash / Go-runtime IAT of the wrap**. It does **not** own the decrypted 16–30 MB Go implant, protobuf RPC names, HTTP C2 profile, sleep, or post-ex CRT. Fortbridge’s Elastic+Defender success path was **implant source surgery + disk `LoadLibrary` of a DLL** (MEM_IMAGE), not a smaller language of unbacked shellcode loader. A C stub that still maps Donut PIC into private executable memory is the class Fortbridge already found **ineffective**.

---

## Does switching the wrap stub from Go to C/C++/C# address Defender killing the session, or only the stub PE?

### Takeaway
Language of the wrap changes **delivery-time** detections of the unsigned host PE (Go ML families, stub IAT, entropy of an embedded blob). Once Donut has mapped the implant, Defender/Elastic inspect the **plaintext Go implant in unbacked (or image-backed) process memory**, its `LoadLibraryExW` call stack, default HTTP fingerprints, and later post-ex. A C stub that still CALL Donut PIC does not change those objects.

### Cited Findings
- BishopFox’s official stance: anti-virus evasion is **out of Sliver’s scope**; operators should use packers, crypters, and stagers. Listed externals are PEzor and Veil. — [Sliver Docs: Anti-virus Evasion](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Anti-virus%20Evasion.md); [sliver.sh Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion)
- Fortbridge (Apr 2025, Elastic **and** Windows Defender): “embedding an encrypted implant in a loader, which extracts, decrypts, and loads it at runtime via self-injection or process hollowing” plus staged download — **“I tested all of these techniques against Elastic EDR and Windows Defender… they proved ineffective.”** Success required protobuf/export/`bishopfox` string edits **and** a tiny C program that `LoadLibrary`s the implant **DLL from the same folder**, finds the export, and runs it in a new thread. — [Fortbridge: Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Fortbridge implant size: “large binary sizes (**up to 30 MB!**) and the lack of a sleep mask.” After static YARA was cleaned, HTTP beacon init via Go `LazyDLL` → `LoadLibraryExW` still produced Elastic **“Network Library Loaded from Unbacked Memory.”** Hardware-breakpoint hooking of `LoadLibraryExW` did **not** bypass it. Module stomping was abandoned because no candidate module fit the implant. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Elastic’s published rule **“Network Module Loaded from Suspicious Unbacked Memory”** (v1.0.64, min endpoint 8.8.0) matches `ws2_32.dll` / `wininet.dll` / `winhttp.dll` when `process.thread.Ext.call_stack_contains_unbacked == true` and the call-stack summary is one of a short list of `ntdll.dll|kernelbase.dll|Unbacked` (and WOW64 variants). Description: “creating thread’s stack contains frames pointing **outside any known executable image**. This may indicate evasion via process injection.” — [elastic/protections-artifacts `defense_evasion_network_module_loaded_from_suspicious_unbacked_memory.toml`](https://raw.githubusercontent.com/elastic/protections-artifacts/main/behavior/rules/windows/defense_evasion_network_module_loaded_from_suspicious_unbacked_memory.toml)
- Elastic 8.8 “Upping the Ante”: behavior protection includes **“Library loading from unbacked region”** and **“Process created from unbacked region.”** Example given is Sliver `execute-assembly` loading `clr.dll` from a call stack containing `Unbacked`. — [Elastic: Upping the Ante](https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks)
- Elastic 8.11 “Doubling Down”: API events enriched with `unbacked_rwx`, `execute_shellcode`, `sensitive_api`, `hollow_unbacked`, `hidden_code` (PAGE_NOACCESS), `execute_fluctuation`. Kernel ETW-Ti covers `VirtualAlloc` / `VirtualProtect` / `MapViewOfFile` (and Ex variants). — [Elastic: Doubling Down on ETW call stacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- Almond Offensive (2025): “A strong indicator for general malicious behaviour is a sensitive operation initiated from **unbacked** memory, that is, a piece of code not coming from an executable file stored on the filesystem, but instead having been loaded at runtime in dynamically allocated virtual memory. This is the typical behaviour of **shellcode**.” Elastic’s network-module rule is the C2-implant example. — [Almond: Evading Elastic EDR’s call stack signatures](https://offsec.almond.consulting/evading-elastic-callstack-signatures.html)
- Microsoft MDAV: **Memory scanning engine** “scans the memory space used by a running process to expose malicious behavior that could be hiding through code obfuscation.” Cloud column for memory scanning is **N/A** (client-only). Behavior monitoring and behavior-based ML run **post-execution**. — [Microsoft Learn: Advanced technologies of MDAV](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav) (updated 2026-05-22)
- Microsoft: client behavioral blocking / behavioral blocking and containment can **stop a threat that has already started**, including **contacting C2 to download payloads**, **cross-process injection**, **process hollowing**. Inbox MDAV participates; EDR-in-block-mode is MDE and **off by default**. — [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment) (updated 2026-05-22)
- Microsoft 2017 (still the public explanation of *why* reflective load is hunted): reflective DLL loading procures **executable memory** (`VirtualAlloc`/`VirtualProtect`); “a library that is loaded this way may not be readily visible”; memory forensics shows **RWX sections without a corresponding DLL**. Detection model keys on abnormal executable allocations. — [Microsoft: Detecting reflective DLL loading with Windows Defender ATP](https://www.microsoft.com/en-us/security/blog/2017/11/13/detecting-reflective-dll-loading-with-windows-defender-atp/)
- `MEM_IMAGE` vs `MEM_PRIVATE`: a PE mapped by the kernel loader (EXE or `LoadLibrary` of a DLL on disk) is `MEM_IMAGE`. User-mode `VirtualAlloc` of shellcode is `MEM_PRIVATE` / unbacked. “There’s no way around it — if we want to mimic the loader, we need to figure out a way to make a `MEM_IMAGE`.” — [Amethyst Systems: Mimicking the Windows Executable Loader’s Memory Allocation](https://amethyst.systems/blog/posts/mimicking-the-windows-executable-loaders-memory-allocation/) (2025-01-08)
- Elastic `Multi_Trojan_Sliver` YARA (still live in protections-artifacts as fetched 2026-11) sets `scan_context = "file, memory"` and matches protobuf method names `).RequestResend`, `).GetPrivInfo`, `InvokeSpawnDllReq`, `NetstatReq`, `HTTPSessionInit`, `ScreenshotReq`, `RegistryReadReq`, package path `github.com/bishopfox/sliver/protobuf/sliverpbb`, plus x86/x64 session-start/register bytecode (`Multi_Trojan_Sliver_3d6b7cd3`). — [elastic/protections-artifacts `Multi_Trojan_Sliver.yar`](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar)
- Garble does **not** rename protobuf methods; maintainers: “easy signatures.” A later comment: **“several Defender AV signatures detecting these strings.”** Custom AST obfuscation “some of it is merged into v1.6… no ETA on a comprehensive fix.” Issue closed as completed 2026-01-30 — **do not read that as “1.7.x implants are clean”**; Elastic YARA still contains those strings in 2026-11. — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760)
- BallisKit (May 2025, **Sliver 1.7.3**): “For evasion purpose it is generally a good practice to load the C2 generated DLL or EXE with ShellcodePack and **not rely on the C2 own loader**.” Vanilla generate with `--skip-symbols`. Stagers “bypassed some EDRs but were **caught by others when the second stage was loaded in memory** (stageless implant is stealthier, but the tradeoff is the huge implant size).” — [BallisKit: Sliver + MacroPack/ShellcodePack](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)
- bytebl33d (Jan 2025): custom **C++ FilelessPELoader** and **C# DInvoke** stagers + ThreatCheck on the **stub**, Donut **`-b 1 -e 3`** (no AMSI patch, entropy 3) of a **stock** Sliver EXE, plus HTTP C2 json edits. Goal stated: get a beacon **without alerting Defender at execution**. That is **stage-0 + Donut flags + HTTP profile**, not an implant fork. — [bytebl33d: Anti-Virus Evasion with Sliver C2](https://bytebl33d.github.io/blog/sliver-evasion/)
- BishopFox (moloch, 2023): “typically these [direct syscalls] will be most effective to implement **in your loader**. Obfuscated sleep is complicated because of the go runtime.” — [BishopFox/sliver discussion #1171](https://github.com/BishopFox/sliver/discussions/1171)

### Inferences
- **C/C++/C# wrap vs Go wrap** can change: unsigned-PE ML on the host (`Wacatac`-class Go hits), size of the stub, IAT of the **stub**, entropy of the container, whether the stub itself is a known Go runtime. Those are **pre-callback / on-disk stub** issues.
- **C/C++/C# wrap does not change**, if the payload is still Donut PIC of stock Sliver: (1) decrypted `sliverpb` / protobuf RPC names / `Go buildinf` / `bishopfox` in RAM; (2) `MEM_PRIVATE` executable region (Donut’s in-memory PE map); (3) Go `NewLazyDLL` → `LoadLibraryExW` of `wininet`/`ws2_32` **from unbacked**; (4) compiled HTTP extensions / nonce encoder; (5) absence of sleep mask; (6) later `execute-assembly`/`migrate` CRT. Those are **post-callback session-kill** objects.
- Fortbridge’s working loader was **not** “write the stub in C then CALL shellcode.” It was **C as a `LoadLibrary` host of a string-cleaned DLL on disk**. A product that switches Go wrap → C wrap but keeps `VirtualAlloc`+Donut is repeating the **failed** Fortbridge branch.
- bytebl33d’s Defender-off-alert screenshot is **callback obtained**. It is not a published long-haul Elastic unbacked-memory or MDAV memory-scan survival test of stock `sliverpb`. Do not treat “got a beacon” as “session stayed alive against memory YARA + unbacked network-load.”

### Gaps
- No public 2025–2026 A/B of **identical stock 1.7.x implant** launched by (a) Go wrap RWX CALL, (b) C VirtualAlloc+CALL Donut, (c) C disk `LoadLibrary` of SHARED_LIB, with time-to-kill under inbox MDAV vs Elastic. Fortbridge is the closest controlled write-up and it already separates (b) fail vs (c) succeed **after implant string clean**.
- Exact Microsoft threat **Name** string for live Sliver memory (`Trojan:Win64/Sliver.*` vs `Behavior:Win32/CommandAndControl.*!ml` vs generic) is not in a public catalog; operators must copy Protection History. Citable named hit: `Behavior:Win32/AMSI_PATCH_T.B12` on Donut AMSI — [BishopFox/sliver#2200](https://github.com/BishopFox/sliver/issues/2200).

---

## Fortbridge: after string scrub, Elastic still flagged `LoadLibraryExW` from unbacked memory. What does that mean for a C loader that still VirtualAlloc+CALL Donut PIC?

### Takeaway
Fortbridge’s remaining Elastic hit was **not** “the C packer is signed.” It was **the implant thread’s call stack**: Go `LazyDLL` loads a network DLL from a region **not backed by an image**. Donut PIC is definitionally that region. A C trampoline that CALLs Donut does not move the implant into `MEM_IMAGE`; it **is** the unbacked caller Elastic’s rule is written for.

### Cited Findings
- Sequence in Fortbridge: (1) protobuf `ScreenshotReq` etc. renamed in `.proto` + regen; (2) `Multi_Trojan_Sliver_3d6b7cd3` bypassed by inlining `maxConnectionErrors` instead of `transports.GetMaxConnectionErrors()`; (3) Donut bypass hardcoded **3 → 1** in `server/generate/donut.go` because default AMSI bypass is “heavy signature detection”; (4) even then, HTTP beacon `NewLazyDLL()` → `LoadLibraryExW` → Elastic **Network Library Loaded from Unbacked Memory**; (5) pre-loading libraries did not help (`NewLazyDLL()` still calls `LoadLibraryExW`); (6) HWBP hook to `GetModuleHandle` **did not bypass**; (7) module stomping abandoned (**~30 MB**); (8) **back to disk DLL + LoadLibrary**. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Defender-oriented strings Fortbridge pulled from [roadwy/DefenderYara](https://github.com/roadwy/DefenderYara) and found as ASCII in the **running** implant: `DllUnregisterServer`, `DllRegisterServer`, `DllInstall`, `GetJitter`, `VoidFunc`, `GetKill`, `AddTunnel`, `GetIsIOC`, ` Go buildinf:`. Three are `regsvr32` exports; `VoidFunc` is PowerSploit reflective PE. They removed unused exports and renamed `StartW`. Remaining protobuf getters (`GetJitter`) required `.proto` member rename + `make pb` + call-site updates. Final runtime YARA needed a project-wide `bishopfox` replace. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Fortbridge conclusion: “Obviously **many commands built into the sliver implant will still trigger Elastic behavioral alerts**, but that’s for another day. This post has demonstrated that basic source code modification can, at least, allow heavily signatured open source projects to **execute on disk**.” Similar projects: **better-sliver**, **slivercloak**. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Elastic rule name in artifacts is **“Network Module Loaded from Suspicious Unbacked Memory”** (not the exact Fortbridge UI string; Fortbridge quoted the product alert). Logic is unbacked call stack + load of `ws2_32`/`wininet`/`winhttp`. — [protections-artifacts toml](https://raw.githubusercontent.com/elastic/protections-artifacts/main/behavior/rules/windows/defense_evasion_network_module_loaded_from_suspicious_unbacked_memory.toml)
- Donut’s job is in-memory PE map of EXE/DLL into allocated memory, then execute. Default AMSI/WLDP bypass **continue-on-fail (3)** was hardcoded in Sliver; operators used external `donut -b 1`. Flags later exposed on generate; issue closed 2026-02-02. — [BishopFox/sliver#1759](https://github.com/BishopFox/sliver/issues/1759); [Fortbridge donut.go 3→1](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Elastic also publishes **“Rundll32 or Regsvr32 Loaded a DLL from Unbacked Memory”** — a *different* rule (LOLBin proxy). Fortbridge’s hit was the generic network-module-from-unbacked rule, which fires on **any** process whose thread stack is unbacked when `wininet`/`ws2_32` loads — including a custom C EXE that CALLs shellcode. — [rundll32/regsvr32 unbacked rule](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_rundll32_or_regsvr32_loaded_a_dll_from_unbacked_memory.toml)

### Inferences
- **C loader + Donut PIC of stock or even string-cleaned implant** ≈ Fortbridge steps 3–6, which **failed** against Elastic. The C language of the trampoline is irrelevant; the **call stack frame is `Unbacked`**.
- **C loader + disk `LoadLibrary` of a string-cleaned SHARED_LIB** ≈ Fortbridge step 8, which **got a callback on Elastic**. That is a **different architecture** than sliver-ui’s current XOR+`VirtualAlloc` RWX+assembly CALL of PIC.
- **C loader + disk `LoadLibrary` of a stock (un-cleaned) Sliver DLL** still dies on **disk/memory YARA** (`ScreenshotReq`, exports, `Go buildinf`, `bishopfox`). Fortbridge had to clean the implant **before** disk load worked. A native stub cannot do that.
- Module stomping of 16–30 MB Go is **contra-indicated** by the only 2025 lab that tried it against Elastic. Do not spend product time on it without a size-reduction story (upstream discussed shrinking via moving code out of the main implant in Go 1.21 — discussion #1171 — not a shipped 1.7.x sleep-mask-sized implant).

### Gaps
- Fortbridge did not publish the Elastic rule UUID; mapping to `aa265fbd-…` / name “Network Module Loaded from Suspicious Unbacked Memory” is by matching the quoted alert semantics and the public toml, not by a screenshot of the UUID.
- Fortbridge’s C loader uses `CreateThread` on the export. That is a **disk-backed DLL thread**, not unbacked PIC. Whether MDAV still 1117s that unsigned DLL on a 2026 cloud signature set was not re-tested in this pass.

---

## Does hosting Sliver as a DLL sideloaded into a signed EXE (disk-backed MEM_IMAGE) change Defender memory scanner vs unbacked RWX CALL?

### Takeaway
**Only if the Sliver implant itself is the disk DLL that the signed EXE `LoadLibrary`s** (Fortbridge path, MEM_IMAGE). If the signed EXE sideloads a **tiny stub DLL** that then VirtualAlloc+CALL Donut PIC, the implant is still unbacked private executable memory — ScareCrow-class docs already say binary/inject mode does **not** get sideload benefits. Sideload also does **not** hide protobuf in the DLL’s mapped image; unsigned Sliver DLL on disk was Fortbridge’s DefenderYara problem until strings were cleaned.

### Cited Findings
- Kernel maps EXE/DLL as `MEM_IMAGE`; `VirtualAlloc` of PIC is `MEM_PRIVATE`. Reflective loaders exist specifically to avoid `LoadLibrary`. — [Amethyst Systems](https://amethyst.systems/blog/posts/mimicking-the-windows-executable-loaders-memory-allocation/); [Microsoft 2017 reflective DLL](https://www.microsoft.com/en-us/security/blog/2017/11/13/detecting-reflective-dll-loading-with-windows-defender-atp/)
- Fortbridge success loader: “a simple program that just loads the implant dynamic library **from the same folder**, finds the entry point export and runs it in a new thread.” That is **Windows loader, disk path, MEM_IMAGE**. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Final Frontier Security (2026-07): “In a default Windows setup, Defender will watch a **signed executable load an unsigned DLL from its own folder and do nothing**” about SmartScreen/MoTW on the DLL. SmartScreen “doesn’t intercept DLL loads via `LoadLibraryA`/`LoadLibraryExA`.” **Detection** they recommend: signed EXE loading unsigned DLL from user-writable path (Downloads/Desktop/AppData) — Sysmon Event 7. — [Final Frontier: Building a Sideload DLL](https://finalfrontiersecurity.com/blog/building-a-sideload-dll-and-how-to-spot-one/)
- Print3M (2025-09): DLL sideloading is substituting a DLL next to a copied signed host that uses relative `LoadLibrary`. Delivery/reputation layer, not memory-YARA of the payload bytes. — [Print3M: DLL Sideloading for Initial Access](https://print3m.github.io/blog/dll-sideloading-for-initial-access)
- Microsoft MDAV memory scanning still “scans the memory space used by a running process.” An image-backed DLL is still scanned; Fortbridge’s DefenderYara hits were **ASCII in the mapped implant**, not only unbacked heuristics. Disk load without string-clean **failed**. — [MDAV advanced tech](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Elastic unbacked rules are **call-stack** rules (who called `LoadLibrary` of `wininet`). If the implant is a real `MEM_IMAGE` DLL, `LoadLibraryExW` of `wininet` originates from that image — the `Unbacked` frame goes away. If the implant is PIC inside the sideload host, the frame stays `Unbacked`. — [Elastic unbacked network-module rule](https://raw.githubusercontent.com/elastic/protections-artifacts/main/behavior/rules/windows/defense_evasion_network_module_loaded_from_suspicious_unbacked_memory.toml)
- ATT&CK T1620 detection guidance (2026-11): EDR memory scanning “alerting on **unbacked executable regions** and thread start addresses outside loaded modules.” — [NHIMG: T1620 Reflective Code Loading](https://nhimg.org/mitre-attandck-t1620-reflective-code-loading-guide)
- BallisKit also publishes a **DLL sideloading with ShellcodePack** tutorial (linked from the Sliver post) as a **packer** feature, not as “stock Sliver becomes FUD.” — [BallisKit Sliver tutorial, related link](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)

### Inferences
- **Honest split for sliver-ui:**
  - **Signed-host + bland DLL that *is* the Sliver SHARED_LIB (string-cleaned)** — changes Elastic **unbacked** network-load; does **not** by itself beat memory YARA on `ScreenshotReq` / `sliverpb` unless the implant is forked. Matches Fortbridge. Native C host can do `LoadLibrary`; it still needs the **implant** cleaned.
  - **Signed-host + stub DLL that VirtualAlloc+Donut** — reputation/sideload for **stage-0 only**. Implant remains unbacked. This is what a “C stub rewrite” of the current wrap actually is, even if you emit a DLL.
  - **Unsigned wrap EXE (Go or C) + RWX CALL** — current architecture; Fortbridge classed it ineffective vs Elastic+Defender after decrypt.
- Microsoft inbox Defender is **not documented** as “we never scan MEM_IMAGE.” Memory scanner + YARA-on-memory still apply. The **behavioral** win of sideload/disk LoadLibrary is **call-stack / unbacked / reflective-load models**, plus SmartScreen not re-checking the DLL.

### Gaps
- No Microsoft Learn page that says “MEM_IMAGE is excluded from MDAV memory scan.” The 2017 ATP blog hunts **reflective** (no corresponding DLL) specifically; it does not promise that a malicious-but-image-backed DLL is ignored.
- ScareCrow’s exact sentence “binary loader does not benefit from any sideloading” was not re-fetched this pass (local prior note). Treat sideload-vs-inject as operator-docs consensus, not as a Microsoft citation.

---

## HTTP C2 default fingerprint (.woff / .php / .js) vs custom profile — network behavior after callback

### Takeaway
Default HTTP C2 extensions are **compiled into the implant** from `http-c2.json` **before generate**. A native loader cannot rewrite them. After callback, sessions use **`.php` session + `.js` long-poll**; beacons sleep then poll. Customizing the profile is a **generate-time implant** change and is one of the few post-callback levers that does **not** require forking protobuf. It does not hide in-memory strings or unbacked call stacks.

### Cited Findings
- BishopFox HTTPS C2 docs (still current in 2026-11): implant_config defaults `stager_file_ext` **`.woff`**, `poll_file_ext` **`.js`**, `start_session_file_ext` **`.html`**, `session_file_ext` **`.php`**, `close_file_ext` **`.png`**. “Everything in the path except for the extension is ignored by the server.” Warning: changing `http-c2.json` **may break existing implants**; change **prior to generating**. Each implant embeds a **random subset** of the server profile. — [Sliver HTTPS C2.md](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/HTTPS%20C2.md); [sliver.sh HTTPS C2](https://sliver.sh/docs/?name=HTTPS+C2)
- Under the hood, default configuration maps: `.woff` stagers, `.js` long poll, `.html` key exchange, `.php` session, `.png` close. Encoder chosen per request (custom Base64, hex, gzip, English, PNG, combinations); nonce = `random * EncoderModulus + encoderID`. — [HTTPS C2.md “Under the Hood”](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/HTTPS%20C2.md)
- Dominic Breuker published a default `http-c2.json` dump matching those extensions and stock `poll_files` (`jquery.min`, `bootstrap`, …) / `session_files` (`login`, `api`, …) / cookies (`PHPSESSID`, …). — [Learning Sliver C2 (04) HTTP/HTTPS](https://dominicbreuker.com/post/learning_sliver_c2_04_transports_in_detail_http_and_https/)
- moloch (#1809, 2024-11-04): “The **server-side HTTPS signatures are randomized by default but cannot be specified**. **mTLS’ are fixed Golang fingerprints** and we don’t recommend using this C2 protocol in contexts which require stealth. We don’t have any feature to modify the **client** fingerprints other than on Windows you can specify **wininet** which should give you the default Windows fingerprint.” — [BishopFox/sliver#1809](https://github.com/BishopFox/sliver/issues/1809)
- wininet is an implant generate URL option (`?driver=wininet`), **not** a loader flag. Docs: wininet is “generally more susceptible to introspection by security products as these functions are well-known and easy to hook.” — [Sliver C2 Advanced Options](https://sliver.sh/docs/?name=C2+Advanced+Options); [HTTPS C2.md Proxies](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/HTTPS%20C2.md)
- bytebl33d: first OPSEC step was **editing `~/.sliver/configs/http-c2.json`**, then generate. That is implant-side. — [bytebl33d](https://bytebl33d.github.io/blog/sliver-evasion/)
- BishopFox 2025-12 talk (Tim): “I haven’t had a lot of issues with EDR detection rates when it comes to **purely network traffic** based detections. It’s really more on the **behavioral** side… `execute-assembly` with default parameters, it’ll open up notepad and inject into it… EDR is going to be more around having a **custom stager** that can load it in memory and then kind of how you run your commands. We tend to use a **socks proxy** a lot… to avoid host-based detections.” — [YouTube: Sliver Building Better Encoders (transcript via search)](https://www.youtube.com/watch?v=6unwFhurm-E)
- Microsoft behavioral blocking lists **“Contacting Command and Control (C&C) to download payloads”** as a stopped technique — host behavior, not JA3. — [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)
- Sessions vs beacons (official tutorial): session = long-poll / constantly maintained connection **in the same process**; beacon = check-in and sleep. `interactive` “will spawn a goroutine running session connection loop **in the same beacon process**.” — [Sliver Tutorials: Beacons vs Sessions](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions)

### Inferences
- **Custom HTTP C2 profile ≠ default** is a real post-callback change (URI/ext/cookie/UA). It is **generate-time**. Rank it as network-IOC reduction, not memory-YARA reduction. sliver-ui already warns “This still looks like default Sliver to public detectors” — keep that; default generate must not silently stay `default` if the product claims OPSEC.
- **Loader XOR / C stub cannot** rewrite compiled paths. If the operator wrapped an implant built with `default`, the live session will keep fetching `.php`/`.js`.
- Opening **interactive** increases `.php` session + `.js` long-poll dwell versus a sleeping beacon. That is **implant C2 mode**, not stub language. BishopFox’s own talk treats host **behavior** (notepad inject, command choice) as the usual EDR catch, not HTTP extensions — still, public Snort/Sigma/Immersive rules key on those extensions; do not ship `default` as the quiet profile.
- `wininet` changes **client TLS/HTTP library fingerprint** (implant), at the cost of easier user-mode hooks. Unrelated to stub language.

### Gaps
- Whether **inbox MDAV NIS** currently signatures default `.woff/.php` Sliver URIs is not documented; public network detections are Snort/Sigma/Zeek/Corelight. Do not claim Defender “kills the session because of `.php`” without a Protection History Name.
- No Microsoft-published JA3/JA4 for Sliver implants.

---

## Sleep mask / Ekko: does a C loader encrypt the implant during sleep?

### Takeaway
**No.** Stock Sliver ships **no** sleep obfuscation. PR #1805 (Ekko, `--sleep-obfuscation` / `-B`, Windows beacons only) was still **unmerged** as of a 2026-07-09 force-push, with hang/deadlock and RWX-during-wake issues. moloch: Go runtime makes obfuscated sleep hard. A C stub that CALLs Donut **does not own** the beacon sleep loop; encrypting the stub’s allocation would brick the Go runtime unless the stub suspends every goroutine — which is an **implant** feature (the PR), not a wrap feature. Interactive sessions are **awake** (long-poll); sleep-encrypt would not cover the window the operator is actually using.

### Cited Findings
- moloch (2023-03-29): “Obfuscated sleep is complicated because of the go runtime, but we’re open to ideas.” Syscalls “typically… most effective to implement **in your loader**.” — [Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171)
- Same thread: encrypting one Go function while other goroutines run panics; **pausing the Go runtime** is required (GoSleepyCrypt, goEkko). goEkko: “When the sleep obfuscation happens the go routines pause.” — [Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171)
- PR #1805 (opened 2024-10-31): Ekko for Windows **beacons**; pauses Go runtime; encrypts beacon memory. Maintainer rkervella: flags belong in `coreBeaconFlags` because it is **only relevant for beacons**. Testing: process **hangs**, stops calling back; memory stuck RWX. Reviewer asked why RW→**RWX** (Havoc uses RW→RX). Author force-pushed **2026-07-09**; PR not described as merged. — [PR #1805](https://github.com/BishopFox/sliver/pull/1805)
- better-sliver README: “Added some sleepmasking to the beacons (**had to remove this due to big bugs**).” — [gsmith257-cyber/better-sliver-package](https://github.com/gsmith257-cyber/better-sliver-package)
- Fortbridge lists **lack of sleep mask** plus large size as why idle implants are easy to YARA in memory. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Official beacons-vs-sessions: interactive session is a **goroutine in the same process**, long-poll / maintained TCP — i.e. **not sleeping**. — [Sliver Tutorials](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions)
- Elastic `execute_fluctuation` / `write_fluctuation` / `unbacked_rwx` explicitly hunt sleep-mask style protect flips. A naive wrap-level XOR of the PIC region during a stub `Sleep()` would also hit those behaviors if the implant is still mapped there — and would race the Go scheduler. — [Elastic Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)

### Inferences
- **Do not claim** “native C stub adds sleep encryption of the implant.” The stub does not own beacon sleep. Implementing outer sleep-encrypt without suspending the Go runtime is the panic/deadlock class #1171 / #1805 already hit **inside** Sliver.
- Sleep mask, **if** it ever ships, helps **idle beacon memory YARA**, not an **interactive session** (plaintext RX while the operator works — the reported “Defender closed my session” window).
- Syscalls in the **loader** (moloch) help **stage-0** API telemetry. They do not encrypt `sliverpb` after map.

### Gaps
- Whether any 1.7.x point release silently merged a subset of #1805 was not verified by reading `implant/sliver/ekko/` on a tag; GitHub UI still shows the PR as the implementation vehicle and comments through 2026 treat it as not landed. Treat stock 1.7.x as **no sleep mask**.

---

## BishopFox: AV evasion out of tree; Garble does not obfuscate protobuf

### Takeaway
Upstream will not make stock implants “FUD.” Garble misses protobuf method names that Elastic and Defender YARA on **file and memory**. Closing #1760 in Jan 2026 does not delete `ScreenshotReq` from public Elastic rules fetched in Nov 2026. A native stub cannot garble or rename protobuf; that is an **implant/server/client fork** (`make pb` + matching client).

### Cited Findings
- “The Sliver authors do not consider anti-virus evasion to be within the scope of the Sliver project… designed to be interoperable with… packers, crypters, and stagers.” Externals: PEzor, Veil. — [Anti-virus Evasion.md](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Anti-virus%20Evasion.md)
- #1760 (2024-08-16): “Garble is not picking up the protobuf methods, which makes for easy signatures.” Community: dirty find/replace. Cyb3r-Monk-class comment: **several Defender AV signatures**. moloch (2025-01-06): custom AST obfuscation, some in v1.6, **no ETA**. Closed completed 2026-01-30. — [Issue #1760](https://github.com/BishopFox/sliver/issues/1760)
- Elastic YARA still matches `ScreenshotReq`, `HTTPSessionInit`, `InvokeSpawnDllReq`, `github.com/bishopfox/sliver/protobuf/sliverpbb` with `scan_context = "file, memory"` (creation dates 2021–2022, last_modified up to 2023-09-20; **still in main** 2026-11). — [Multi_Trojan_Sliver.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar)
- Fortbridge: changing `message ScreenshotReq` in `sliver.proto`, regenerating, and grepping the **entire** client/server/implant tree is required; automation was `sed` on the BishopFox install script. That is a **fork**, and the **operator client must match**. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- DFIR Report (2024-08-12): in-the-wild garble’d Sliver still versioned via protobuf definition strings “aren’t as easily obfuscated.” — [The DFIR Report](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/)
- `--evasion` / `-e` is userland unhooking and **does not** control Donut AMSI (`#1759`). `--skip-symbols` **disables** garble (BallisKit recommends this when an **external** packer will re-protect). — [#1759](https://github.com/BishopFox/sliver/issues/1759); [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)

### Inferences
- sliver-ui talking to **stock BishopFox 1.7.x** cannot promise protobuf-clean memory. Document **external implant fork** (slivercloak / better-sliver / Fortbridge-style `sed`) as the YARA path.
- Generate flags that **are** in-tree and honest: HTTP profile ≠ default; Donut Bypass=1; `--skip-symbols` when wrapping externally; `format=shared` if pursuing disk LoadLibrary. None of these are “C stub.”

### Gaps
- What exactly landed when #1760 was closed “completed” (partial AST obfuscation vs docs-only) was not diffed against 1.7.x tags this pass. Elastic’s public rule still keys on the old names — sufficient to treat stock implants as **still signatured** until proven otherwise in lab.

---

## Microsoft 2022 “Sliver lining”: post-ex CRT inject vs stock `interactive` same-process

### Takeaway
Stock `interactive` / UI Open Session is **not** fork&run and **not** `CreateRemoteThread`. It is a **goroutine in the same PID**. Microsoft’s published MDE hunts (still the public baseline) target **`migrate` / `sideload` / `spawndll` / `execute-assembly`**: `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`, default sacrificial **`notepad.exe`**, GetSystem → **`spoolsv.exe`**. Defender “killing the session” after callback is usually **that same PID** dying (memory/behavior/C2), or a **later** CRT command the operator ran from the session — not a fresh teamserver implant spawned by Open Session.

### Cited Findings
- Official tutorial: “Session can be spun up in our beacon process using the `interactive` command. **Under the hood this will spawn a goroutine running session connection loop in the same beacon process.**” — [Beacons vs Sessions](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions)
- Hunt & Hackett (2024): `execute-shellcode` defaults to spawning `C:\windows\system32\notepad.exe`, `VirtualAllocEx` RW, `WriteProcessMemory`, `VirtualProtectEx` RX, `CreateRemoteThread`. “The memory of a system was proven to be the most important data source for most of the attack methods of Sliver.” Sysmon 1/8/10. — [Hunt & Hackett: Hunting for a Sliver](https://www.huntandhackett.com/blog/hunting-for-a-sliver)
- Microsoft Security Blog 2022-08-24 “Looking for the ‘Sliver’ lining” is the canonical MDE hunting post (GetSystem / notepad / PsExec DisplayName=`Sliver` / in-memory config / JARM). Independent researchers still treat it as current through 2026; this pass’s HTML fetch of the article body returned chrome-only, so **injection-chain specifics below are cited from Hunt & Hackett + Elastic’s execute-assembly example**, not re-quoted from the Microsoft HTML. — [Microsoft: Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Elastic “Upping the Ante”: **Sliver execute-assembly** loading `clr.dll` from `*mscoreei.dll|Unbacked*`. — [Elastic](https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks)
- BishopFox 2025-12 talk: default execute-assembly “open up notepad and inject” **gets caught by default**; use SOCKS to avoid host-based detections; custom stager + **how you run commands**. — [YouTube transcript](https://www.youtube.com/watch?v=6unwFhurm-E)
- Microsoft behavioral blocking: stopped techniques include **cross-process injection** and **process hollowing**. — [Behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)
- ASR “Block Office applications from injecting code into other processes” is **Office-only**, not a generic CRT ban. — [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)

### Inferences
- Product copy must not imply Open Session “spawns a new implant file.” Unique loader hash is already spent; `interactive` does not mint a new PE.
- Post-ex CRT is **implant command behavior**. A C stub cannot wrap `execute-assembly`. Mitigations are operator tradecraft (SOCKS, don’t default-notepad, don’t migrate) or implant forks — **out of wrap**.
- If Protection History Path is `notepad.exe` / `spoolsv.exe`, the kill is **post-ex inject**, not the wrap. If Path is the wrap PID / “memory,” it is **in-process implant** (YARA / unbacked / C2 behavior).

### Gaps
- Microsoft 2022 article body was not recoverable from microsoft.com HTML in this pass (page chrome only). Hunt & Hackett + Elastic independently document the same CRT chain against Sliver; use those as the verified injection citations.

---

## bytebl33d / BallisKit / slivercloak / better-sliver: implant fork vs loader

### Takeaway
Public 2025–2026 “got a callback with Defender/EDR on” write-ups split cleanly: **(A) unique stage-0 / commercial packer of a stock implant** (bytebl33d, BallisKit) vs **(B) search-replace / fork of Sliver source** (Fortbridge, slivercloak, better-sliver). Only (B) changes **post-callback memory YARA**. (A) can get **initial** callback and still lose the session to unbacked/YARA/behavior. sliver-ui is a GUI over stock gRPC; (B) is **out of tree**.

### Cited Findings

**bytebl33d (2025-01-04) — loader + Donut flags + HTTP json; stock implant**
- Custom C++ FilelessPELoader (AES fetch, ThreatCheck loop on **the loader**) and C# DInvoke + InvisibilityCloak (GUID/string reverse, Windows Application subsystem).
- Sliver generate: `generate beacon … -e -f shellcode` **or** EXE then **external** `donut -b 1 -e 3` (“AMSI/WDLP/ETW : none”).
- HTTP C2 json “minor modifications.”
- Claim: loader “connected to our server **without alerting Windows Defender**.” Follow-on: they used the session for hash dump (post-ex). No Elastic unbacked discussion. — [bytebl33d](https://bytebl33d.github.io/blog/sliver-evasion/)

**BallisKit (2025-05-06) — commercial packer of stock 1.7.3**
- “Do not rely on the C2’s own loader”; pack EXE/DLL with ShellcodePack (`--indirect-syscalls`, `--spoof-callstack`, profile-dependent ETW patch/unhook).
- Generate: `--skip-symbols`, HTTPS. Size 19 MB → 12 MB compressed.
- Stager listener: `--shellcode-bypass 1` (disable Donut evasion that triggers EDRs); previously `--donut-bypass`.
- Stagers: small (90–250 KB); **caught by some EDRs when second stage loaded in memory**. Stageless stealthier, huge. “I tested the EXE payload on several EDRs and could run the EXE and launch several commands without being detected” — **unnamed EDRs**, commercial claim. — [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)

**slivercloak (thelikes, modules dated in README example 2025-01-11) — implant/server SOURCE**
- Docker clone of Sliver + Go modules, then compile client/server. **Not a stub.**
- `donotamsi`: `server/generate/donut.go` `Bypass: 3` → `1` (and `config.Bypass = 3` → `1`). — [mod-donut.go](https://raw.githubusercontent.com/thelikes/slivercloak/main/builder/mod-donut.go)
- `Elastic`: search-replace protobuf/YARA names across the tree, e.g. `ScreenshotReq`→`Smith`, `InvokeSpawnDllReq`→`Derek`, `HTTPSessionInit`/`httpSessionInit`→`Robert`, `RequestResend`→`Frankie`, `GetPrivInfo`→`Wallace`, plus `-NoExit` casing. — [mod-elastic.go](https://raw.githubusercontent.com/thelikes/slivercloak/main/builder/mod-elastic.go)
- `branding`: `sliver`→`gunner`, `beacon`→`lazer`, `bishopfox`→`knightbruce` (breaks stock client compatibility if used carelessly). — [mod-branding.go](https://raw.githubusercontent.com/thelikes/slivercloak/main/builder/mod-branding.go)
- Fortbridge cites slivercloak as the Docker/source-mod analogue of their `sed` script. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)

**better-sliver (gsmith257-cyber) — implant fork**
- Goals: “less detectable by adding more features, changing default fingerprints, and adding more obfuscation options.”
- Claimed: broke static shellcode signatures (Donut signature remains); changed default mTLS CAs; changed `shell` command (YARA); JARM randomization (later in Sliver v1.6); sleepmask **added then removed for bugs**. — [better-sliver-package README](https://github.com/gsmith257-cyber/better-sliver-package)

**In-the-wild modified Sliver (Radicl, 2026-07) — still YARA’d**
- Rust downloader + AES-CFB second stage; payloads still `github.com/bishopfox/sliver` + `sliverpb.*` plus extra `FlyFireReq` messages. Hunters wrote YARA on **stock strings AND custom protobuf**. Forking without removing `bishopfox`/`sliverpb` does not hide family. — [Radicl: Cross-Platform Rust Loader Delivers Modified Sliver](https://radicl.com/resources/cross-platform-rust-loader-delivers-modified-sliver-implant-via-cloud-storage-abuse)

### Inferences
| Project | Layer changed | Post-callback stock `sliverpb` survival? |
|---|---|---|
| bytebl33d C++/C# | Stage-0 stub + Donut `-b 1 -e 3` + HTTP json | **Not shown.** Gets callback; implant still stock Go in RAM. |
| BallisKit ShellcodePack | Stage-0 packer (syscalls, callstack spoof, compress) | **Partial / vendor-claimed** for unnamed EDRs; they admit **in-memory stage-2** still caught. Implant still stock unless separately forked. |
| Fortbridge C `LoadLibrary` | Stage-0 **architecture** (MEM_IMAGE) **plus** implant string clean | **Yes vs Elastic static + unbacked-network**, in that lab. Built-in commands still behavior-alert. |
| slivercloak | Implant/server source (protobuf, branding, Donut bypass) | **Aims at memory YARA.** Loader not included. |
| better-sliver | Implant fork (CA/JARM/shell/signatures) | **Aims at fingerprints + YARA.** Sleepmask failed. |
| sliver-ui C stub rewrite | Stage-0 PE language | **No**, if PIC path kept. |

### Gaps
- BallisKit does not name the EDRs; treat “several commands without being detected” as a **vendor tutorial**, not a Microsoft/Elastic primary source.
- slivercloak Elastic module does **not** rename every Fortbridge DefenderYara string (`GetJitter`, `VoidFunc`, `Go buildinf:`). It is a **partial** YARA dodge, not a complete Fortbridge clone.

---

## Ranked techniques: post-callback survival of stock 1.7.x vs stage-0-only

### Takeaway
Rank by **whether the live implant image / call stack / C2 / post-ex changes**. Anything that only changes the wrap PE is **stage-0**. Stock 1.7.x **cannot** gain sleep mask, protobuf rename, or MEM_IMAGE implant mapping from a C trampoline that still CALLs Donut.

### Cited Findings
Ranking table is an inference over the sources in previous sections; each row cites the controlling source.

### Inferences

**A. Changes post-callback survival of stock BishopFox 1.7.x (implant must change, or architecture of how the implant is mapped)**

| Rank | Technique | What it changes after callback | Stock 1.7.x GUI can do? | Native C stub enough? |
|---|---|---|---|---|
| A1 | Fork implant: protobuf / export / `bishopfox` / `Go buildinf` string clean (Fortbridge, slivercloak Elastic+branding) | Memory+disk YARA (`Multi_Trojan_Sliver`, DefenderYara ASCII) | **No** — fork; client/server must match | **No** |
| A2 | Map implant as **disk DLL `LoadLibrary`** (MEM_IMAGE), not Donut PIC | Elastic unbacked `wininet`/`ws2_32` call stack | Only if UI emits `format=shared` + LoadLibrary host **and** implant is clean | **C host yes; PIC path no** |
| A3 | HTTP C2 profile ≠ default **at generate** | Network URI/ext/cookie/UA IOCs | **Yes** (already in sliver-ui) | **No** — compiled in |
| A4 | Donut **Bypass=1** (no AMSI/WLDP patch) | `Behavior:Win32/AMSI_PATCH_*` / Elastic AMSI patch rules during map | **Yes** as generate flag (#1759 closed 2026-02; BallisKit `--shellcode-bypass 1`; slivercloak donotamsi) | Only if stub **doesn’t** add its own AMSI patch |
| A5 | Prefer **beacon** vs interactive; avoid default `execute-assembly`/`migrate`/`getsystem` | Less long-poll; avoid CRT/notepad/spoolsv hunts | **Yes** as operator/docs; Open Session is same PID | **No** |
| A6 | `?driver=wininet` (Windows) | Client TLS fingerprint (Go crypto/tls → Windows) | Generate URL option | **No** |
| A7 | Sleep obfuscation | Idle memory YARA only; not interactive | **Not in 1.7.x** (#1805 unmerged; better-sliver removed it) | **No** — must pause Go runtime |
| A8 | Module stomping | Would back implant with a legitimate image | Fortbridge **failed** at ~30 MB | **No** |

**B. Stage-0 / stub-only (spent once callback exists)**

| Rank | Technique | What it changes | Native C stub? |
|---|---|---|---|
| B1 | Unique SHA-256 / XOR embed / `-buildid` | Exact-hash IOC of **wrap file** | Irrelevant after decrypt |
| B2 | Go wrap → C/C++/C# wrap, same VirtualAlloc+CALL Donut | Stub PE ML / Go runtime IAT of **host** | **This is the proposed rewrite** — does not save stock `sliverpb` |
| B3 | PAGE_NOACCESS → RW → RWX, no CreateThread in stub | Some CRT/start-address heuristics; Elastic still sees unbacked + `VirtualProtect` | Hygiene; Fortbridge-class still fails |
| B4 | Signed-EXE sideload of a **PIC stub DLL** | SmartScreen/reputation of host | Stage-0; implant still unbacked |
| B5 | ThreatCheck loop on the **stub** (bytebl33d) | Static signatures of loader source | Stage-0 |
| B6 | Commercial packer (ShellcodePack/PEzor) of stock EXE | Stage-0 syscalls/callstack/compress; BallisKit: stage-2 in memory still caught | External; not in-tree |
| B7 | 1.8s sleep + RAM check | Toy emulators, not MDAV cloud detonation / live memory scan | Stage-0 |
| B8 | Hide-console / `windowsgui` | User window | Not EDR |

**C. Do not claim / do not implement in sliver-ui**

- C stub “saves a live session against Defender.”
- Sleep-mask in the wrap.
- Module stomping of 16–30 MB Go.
- In-tree ScareCrow / Donut CLI / AMSI patch (the patch **is** `AMSI_PATCH_T.B12`).
- Unique hash as memory-scanner bypass.

### Gaps
- No public MDAV vs Elastic head-to-head with Fortbridge’s **exact** disk-DLL + cleaned implant on 2026 signature revisions. Treat Fortbridge as the best 2025 primary, not as a forever guarantee.

---

## Honest product ranking for sliver-ui (as assigned)

### Takeaway
Keep wrap as **lab packaging**. Do not market a C rewrite as session survival. Rank: (1) optional native C (or even Go) **RX/image-backed DLL LoadLibrary path** for `format=shared`, labeled honestly; (2) generate-time HTTP C2 ≠ `default` + Donut Bypass=1; (3) document external implant forks; (4) **do not claim** a C stub saves a stock `sliverpb` image.

### Cited Findings
- Fortbridge: disk LoadLibrary + string-clean **worked**; encrypted loader / hollowing / unbacked shellcode **did not**; built-in commands still Elastic-behavior. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- BishopFox: AV out of scope; use external packers/stagers. — [Anti-virus Evasion.md](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Anti-virus%20Evasion.md)
- #1759 / BallisKit / slivercloak: Donut bypass **1** is the supported way to drop AMSI-patch signatures; generate flags exist as of 2026-02. — [#1759](https://github.com/BishopFox/sliver/issues/1759); [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19); [slivercloak mod-donut.go](https://raw.githubusercontent.com/thelikes/slivercloak/main/builder/mod-donut.go)
- HTTPS C2 must be changed **before generate**. — [HTTPS C2.md](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/HTTPS%20C2.md)
- slivercloak / better-sliver / Fortbridge `sed`: **source forks**, not GUIs. — [slivercloak](https://github.com/thelikes/slivercloak); [better-sliver-package](https://github.com/gsmith257-cyber/better-sliver-package)
- Elastic unbacked network-module rule + Multi_Trojan_Sliver memory YARA: the live implant, not the stub language. — [unbacked toml](https://raw.githubusercontent.com/elastic/protections-artifacts/main/behavior/rules/windows/defense_evasion_network_module_loaded_from_suspicious_unbacked_memory.toml); [Multi_Trojan_Sliver.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar)

### Inferences

| Priority | sliver-ui action | Symptom it actually addresses | Honesty constraint |
|---|---|---|---|
| **1** | Optional **native C (or tiny) stub that `LoadLibrary`s a Sliver `format=shared` DLL from disk** (export in a new thread). Prefer RX image sections the Windows loader created — **not** VirtualAlloc+CALL Donut PIC. | Elastic **unbacked** `LoadLibraryExW` of `wininet`/`ws2_32` **if** the implant is the DLL. Does **not** remove protobuf YARA unless implant is forked. | Label: “disk DLL; still unsigned; still needs string-clean implant; not a C PIC trampoline.” Fortbridge sample was tiny C, not a Go runtime host. |
| **2** | Generate-time **HTTP C2 ≠ `default`** + **Donut Bypass=1** (and ExitOpt=block if wrap still CALLs PIC). | Network default-fingerprint; `AMSI_PATCH_*` during map. | Native Sliver flags. Copy must not say this hides `sliverpb` in RAM. |
| **3** | Document **external implant fork** (Fortbridge method, slivercloak, better-sliver) in the existing external-loader guide. | Memory+disk family YARA. | Out of this GUI. Stock BishopFox client will not speak a renamed protobuf schema. |
| **4** | **Do not claim** C/C++/C# stub saves a **stock sliverpb** image. Do not reopen in-tree ScareCrow/Donut CLI/FUD. | Prevents lying about symptom-2 (callback then kill). | Switching Go wrap → C wrap with the **same** VirtualAlloc+Donut PIC is **B2 stage-0 only**. |

**Direct answer to the product question:** rewriting the wrap from Go to C/C++/C# **only addresses the stub PE** (and, if and only if the C program is a disk `LoadLibrary` host of a SHARED_LIB, the **unbacked call-stack** class). It does **not** keep a stock 1.7.x interactive session alive against MDAV memory scan, Elastic `Multi_Trojan_Sliver`, or Elastic unbacked-network-load **unless** the implant is also string-cleaned **and** mapped as an image. A C loader that still VirtualAlloc+CALL Donut PIC is the Fortbridge **failure** path.

### Gaps
- Design spike still required: Go `syscall.LoadDLL` of a dropped SHARED_LIB vs a tiny C host (Go host runtime remains noisy). Not implemented; Fortbridge’s working sample was **tiny C**.
- This pass did not detonate sliver-ui wrap on Windows 11 + live Defender; rankings are from 2024–2026 **public** labs (Fortbridge, bytebl33d, BallisKit, Elastic artifacts, Microsoft Learn), not a new engagement-specific cloud sample.
