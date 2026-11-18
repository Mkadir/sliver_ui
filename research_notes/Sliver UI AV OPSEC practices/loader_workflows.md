# Loader / Shellcode / DLL Delivery Workflows (Sliver UI mapping)

Scope: real multi-stage delivery chains operators use when raw C2 EXE/DLL implants are AV/EDR-detected (2023–2026). Framed for Sliver UI product features. No “guaranteed FUD” claims — EDRs detect behavior (injection, unbacked RX, call stacks), not only static bytes.

Sliver UI codebase context (this repo): `POST /api/shellcode/rdi` and session `exec-shellcode` / `sideload` / `spawn-dll` already exist; `ShellcodeEncoder` / `SGNEnabled` are Sliver RPCs not yet wrapped in the UI (`docs/LOADER_AV_OPSEC_PLAN.md`).

---

## What is the typical Windows chain when EXE beacon is burned?

### Takeaway
When a raw Sliver EXE/service PE is signatured, operators stop dropping that PE on disk and instead: generate a `shared` DLL or PE → convert to PIC shellcode (Donut or sRDI) → optionally encode (SGN/XOR) → encrypt-at-rest inside a custom/sideload loader → stage or inject in-memory. Prefer DLL sideloading of a signed host over noisy remote process injection when possible.

### Cited Findings
- sRDI converts arbitrary DLLs into position-independent shellcode (bootstrap + RDI loader + packed DLL); payload arrives without a classic PE header on disk/in transit, and can be injected with standard shellcode techniques — [NetSPI sRDI blog](https://www.netspi.com/blog/technical-blog/adversary-simulation/srdi-shellcode-reflective-dll-injection/); [monoxgas/sRDI](https://github.com/monoxgas/sRDI).
- Blob layout is `[Bootstrap][RDI shellcode][DLL bytes][+ optional user data]`; bootstrap locates itself, hands control to RDI, which remaps sections, calls DllMain, optionally hashed export — [NetSPI](https://www.netspi.com/blog/technical-blog/adversary-simulation/srdi-shellcode-reflective-dll-injection/); [RBT Security sRDI overview](https://www.rbtsec.com/blog/shellcode-reflective-dll-injection-srdi-converting-dlls-into-position-independent-shellcode/).
- Donut generates x86/x64/dual PIC that loads .NET assemblies, native EXE/DLL, VBS/JS from memory; modules can be embedded or HTTP-staged; optional Chaskey encryption, PE header overwrite, AMSI/WLDP/ETW patching — [TheWover/donut](https://github.com/TheWover/donut).
- Sliver’s own `format shellcode` path uses Donut on Windows (`SliverShellcode`: “Windows: Donut, macOS: beignet, Linux: malasada”) and embeds sRDI helpers (`ShellcodeRDI` / `ShellcodeRDIFromBytes`) — [pkg.go.dev generate@v1.7.6](https://pkg.go.dev/github.com/bishopfox/sliver@v1.7.6/server/generate).
- Practical Sliver operator pattern when stock EXE is noisy: generate EXE/DLL with protections *disabled* (faster, smaller), then wrap with an external PE/.NET loader (e..g. ShellcodePack) rather than relying on Sliver’s built-in loader; staged shellcode via `profiles new --format shellcode` + `stage-listener` — [BallisKit Sliver + MacroPack/ShellcodePack tutorial](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19); [Sliver staged implants walkthrough](https://www.thezentester.com/sliver-c2-staged-implants/).
- Alternate path: generate Sliver EXE → convert with external Donut (`-e` entropy/encryption, optional AMSI bypass level) → custom runner — [bytebl33d Anti-Virus Evasion with Sliver](https://bytebl33d.github.io/blog/sliver-evasion/).
- DLL sideloading (and .NET AppDomainManager injection) is preferred over dropping a standalone malicious EXE because execution inherits the signed host’s reputation; SpecterOps BlackAlps talk covers AppDomainManager + traditional sideload — [BlackAlps 2023: Sideloading Serenade](https://www.youtube.com/watch?v=YiOjiroFOv8).
- Scarecrow-style tooling and DEF CON adversary village material emphasize sideload loaders over binary-based loaders as lower-signal initial execution — [DEF CON 29 Adversary Village transcript (Matthew Eidelberg)](https://media.defcon.org/DEF%20CON%2029/DEF%20CON%2029%20villages/DEF%20CON%2029%20villages%20captions/DEF%20CON%2029%20-%20Adversary%20Village%20-%20Matthew%20Eidelberg%20-%20Operation%20Bypass%20Catch%20My%20Payload%20If%20You%20Can.eng.txt).
- Outflank OST markets payload generators, stego loaders, and sideload-oriented packaging as the commercial red-team answer to burned PE drops — [Outflank Security Tooling](https://www.cobaltstrike.com/product/outflank-security-tooling).
- Sliver post-exploitation `spawndll`/`sideload` convert DLLs via sRDI then inject with a fixed `OpenProcess → VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → CreateRemoteThread` path; `execute-assembly` uses Donut then the same inject pattern — [tishina.in Sliver OPSEC notes](https://tishina.in/opsec/sliver-opsec-notes).
- Elastic Defend (8.11+) added kernel ETW call-stack rules for shellcode, unbacked memory calling sensitive APIs, direct/indirect syscalls, AMSI/ETW patching — behavior still catches “encoded” loaders — [Elastic: Doubling Down ETW Call Stacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- Elastic also hunts unsigned/recently-dropped DLLs loaded by trusted binaries (classic sideload shape) and suspicious library loads — [Elastic: Hunting Suspicious Windows Libraries](https://www.elastic.co/security-labs/Hunting-for-Suspicious-Windows-Libraries-for-Execution-and-Evasion); [Unsigned DLL Side-Loading rule](https://elastic.github.io/detection-rules-explorer/rules/ca98c7cf-a56e-4057-a4e8-39603f7f0389).

### Inferences
- **Typical burned-EXE recovery chain (Windows):**  
  1) Sliver generate `shared` (DLL) or PE → 2) Donut *or* sRDI → PIC → 3) optional SGN/XOR encode → 4) encrypt blob into custom/Nim/Rust/Go/.NET loader *or* package as sideload DLL next to a signed host → 5) optional HTTP stage-0 downloader → 6) in-memory map/execute (local preferred; remote CRT inject as last resort) → 7) beacon + jitter, not interactive session for first call-home.
- Stock Sliver `shellcode` format already runs Donut server-side; operators still wrap that blob in an *external* loader because the *runner* (not the C2 PIC) is what AV sees on disk.
- Sideloading reduces “unknown EXE” reputation hits but shifts detection to library-load telemetry (path, age, signature) — UI checklists must warn about that, not claim sideload = invisible.

### Gaps
- No single public “canonical” Outflank/MDSec step-by-step for Sliver specifically in 2025–2026 open blogs; commercial OST details are paywalled — mapping relies on NetSPI/Donut/Sliver source + operator writeups.
- Exact current Defender/CrowdStrike hit rates for Sliver+Donut vs Sliver+custom loader are engagement-specific and not publishable as fixed stats.

---

## What about Linux? (SO, memfd, LD_PRELOAD, etc.)

### Takeaway
Linux tradecraft centers on shared objects (`.so`) and fileless execution via `memfd_create` + `fexecve`/`execveat`, plus `LD_PRELOAD` for process-local hooks — not Windows-style sRDI. Sliver can emit Linux shared libraries and (in newer trees) shellcode via “malasada,” but mature delivery still uses external droppers/memfd stubs; remote ptrace injection is often blocked by Yama.

### Cited Findings
- `memfd_create` creates an anonymous RAM-backed FD; write ELF bytes then `fexecve`/`execveat` so the payload never hits a filesystem path — common cryptominer/botnet and red-team pattern — [Purpleshift: Ghost in the RAM](https://purpleshift.io/purple/2026-06-29-onsd/); [reverseengineering.app memfd technique](https://www.reverseengineering.app/en/techniques/memfd-fileless-execution); [THC: bypassing noexec](https://iq.thc.org/bypassing-noexec-and-executing-arbitrary-binaries).
- Forensic shape: process executable shows as `/memfd:…` or `/proc/self/fd/N (deleted)` — detectable with process/exe path analytics — [reverseengineering.app](https://www.reverseengineering.app/en/techniques/memfd-fileless-execution).
- Unprivileged Linux injection often uses `/proc/PID/mem` or shell → memfd staging; ptrace/`ptrace_scope` and missing tools constrain reliability — [joev.dev unprivileged process injection](https://archive.vn/2024.01.01-111549/https://joev.dev/posts/unprivileged-process-injection-techniques-in-linux).
- `LD_PRELOAD` / shared-object injection remains a standard execution and privesc pattern (hook `_init` / libc symbols) — [Hacking Articles LD_PRELOAD](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/); [Stealth-ELF SO injection PoC](https://github.com/NickP3lle/Stealth-ELF).
- Public memfd ELF loader shellcode (remote read → memfd → exec) exists as reusable stubs (~170 bytes class) — [Exploit-DB 51693](https://www.exploit-db.com/shellcodes/51693).
- Sliver `SliverShellcode` documents Linux path as “malasada” (alongside Windows Donut / macOS beignet) — [pkg.go.dev generate](https://pkg.go.dev/github.com/bishopfox/sliver@v1.7.6/server/generate). Historically maintainers noted shellcode format was Windows-first; Linux shellcode support matured later and operators should verify per server version — [Sliver Discussion #824](https://github.com/BishopFox/sliver/discussions/824).
- SpecterOps maintains a `tradecraft-linux` skill pack covering Linux process injection, execution, and persistence validation workflows (operator checklists, not a Sliver RPC) — [SpecterOps/skills](https://github.com/SpecterOps/skills).

### Inferences
- **Typical Linux chain:** generate Sliver `shared` `.so` or ELF → optional pack/encrypt → stage-0 script/binary downloads into memfd → `fexecve` **or** drop `.so` and run via `LD_PRELOAD` / compromised service config → beacon. Avoid noisy `ptrace` inject on hardened hosts.
- UI should treat Linux loaders as **checklist + artifact download** (SO + memfd stub links), not pretend Windows RDI/SGN maps 1:1.

### Gaps
- Detailed public 2024–2026 “Sliver Linux malasada internals” docs are thin compared to Donut/sRDI; exact encoder behavior for Linux shellcode needs verification against the operator’s Sliver server version.
- Distro-specific detections (e.g. Falco rules for memfd+fexecve) vary widely — no universal bypass narrative.

---

## Role of Donut, sRDI, custom loaders, Nim/Rust/Go loaders relative to Sliver outputs?

### Takeaway
Donut and sRDI are **format converters** already partially inside Sliver (generate shellcode / ShellcodeRDI / execute-assembly / spawndll). Custom Nim/Rust/Go/.NET loaders are **disk-facing stage-0** that own encryption, keying, and execution — they sit *outside* Sliver RPC and wrap Sliver outputs. Stock SGN/symbol obfuscation is not a substitute for a unique loader.

### Cited Findings
- Donut: PIC generator for .NET/PE/script; embed or HTTP stage; encryption; optional AMSI/ETW/WLDP patches; library API for C2 integration — [Donut README](https://github.com/TheWover/donut). Authors explicitly suggest integrating Donut into RATs/C2 and adding environmental keying / polymorphism as operator exercises — same source.
- Sliver calls Donut for Windows shellcode generation and for `execute-assembly` (`DonutFromAssembly` → inject) — [pkg.go.dev](https://pkg.go.dev/github.com/bishopfox/sliver@v1.7.6/server/generate); [tishina.in](https://tishina.in/opsec/sliver-opsec-notes).
- sRDI: DLL→PIC without embedding ReflectiveLoader inside the DLL; Sliver exposes `ShellcodeRDI` RPC and uses sRDI for `spawndll` — [monoxgas/sRDI](https://github.com/monoxgas/sRDI); [Sliver generate ShellcodeRDI*](https://pkg.go.dev/github.com/bishopfox/sliver@v1.7.6/server/generate); this UI already wraps RDI at `POST /api/shellcode/rdi`.
- Sliver shellcode encoders include Shikata Ga Nai (SGN), XOR, XOR_DYNAMIC via `ShellcodeEncoder` / generate-time SGN — [sgn package docs](https://pkg.go.dev/github.com/bishopfox/sliver/server/encoders/shellcode/sgn); [LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md). SGN needs RWX for self-modifying decode — [Sliver Discussion #824](https://github.com/BishopFox/sliver/discussions/824).
- Operator consensus in public writeups: prefer **custom** loader over C2-native loader for initial access; disable Sliver’s built-in SGN/symbols when the external packer will re-protect, to shrink size and avoid double-noise — [BallisKit tutorial](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).
- Rust sRDI ports (e.g. venom-rs / srdi-rs) and Go ports (Doge-sRDI, citing Sliver’s ShellcodeRDI.go) show the ecosystem re-implements the converter in “cleaner” languages for custom toolchains — [memN0ps srdi-rs](https://github.com/memN0ps/srdi-rs); [timwhitez/Doge-sRDI](https://github.com/timwhitez/Doge-sRDI).
- OPSEC forks of Donut add custom CLR hosting / ETW tricks because **vanilla Donut stubs are themselves signatured** over time — [Zuigetzu/Donut-CustomHost](https://github.com/Zuigetzu/Donut-CustomHost); public X note on evasive Donut forks (Nov 2026) — [r1cksec on Homer fork](https://x.com/r1cksec/status/2119732782540927373).
- Sliver implants use GetProcAddress (not direct syscalls) for WinAPI — important if writing an external builder expecting syscall-only implants — [tishina.in](https://tishina.in/opsec/sliver-opsec-notes).
- Loader detection model (2024–2025): file scan + memory YARA + behavioral telemetry; encrypting the implant only defeats the first; sleep/masking and call-stack hygiene address the others imperfectly — [blog.deeb.ch Anti-EDR Compendium (via AwesomeMalDevLinks mirror)](https://github.com/dobin/AwesomeMalDevLinks/blob/main/data/out/maldev/blog.deeb.ch_posts_how-edr-works.md).

### Inferences
| Tool | Relation to Sliver output | UI implication |
|---|---|---|
| Donut (built-in) | Converts PE/assembly → shellcode at generate / execute-assembly | Already partly automated; expose shellcode format + options |
| sRDI (built-in) | Converts `shared` DLL → PIC | Automate via existing RDI API + Loaders page |
| SGN/XOR | Mutate shellcode bytes post-generate | Wire `ShellcodeEncoder` RPC; honesty about RWX/behavior |
| External Donut / Homer / etc. | Re-pack PE when operators want different entropy/bypass knobs | External checklist only |
| Nim/Rust/Go/.NET custom loaders | Stage-0: decrypt, key, inject/sideload | Templates/checklist; do not ship “FUD crypter” in UI |
| Commercial (OST, ShellcodePack, MacroPack) | Phishing + loader packaging | Links + “run outside UI” |

### Gaps
- No authoritative public matrix of which Nim/Rust loader frameworks “work best” with Sliver 1.7 in 2026 — landscape churns monthly as signatures update.
- Whether Sliver UI should shell out to a local `donut` binary is a product/security decision (RCE surface on the UI host), not settled by research.

---

## Which steps are realistic to embed in Sliver UI (RPC) vs must remain external?

### Takeaway
Embed anything Sliver already exposes over gRPC (generate formats, RDI, encoders, stage listeners, session sideload/spawn-dll/exec-shellcode, HTTP C2 profiles). Keep custom packers, sideload host pairing, environmental keying, memfd stubs, and phishing macros as **external tools + in-UI checklists**. Never claim the UI “bypasses AV.”

### Cited Findings
- Sliver RPCs / generate APIs relevant to loaders: `Generate` (exe/shared/shellcode/service), `ShellcodeRDI`, `ShellcodeEncoder` / `ShellcodeEncoderMap`, SGN at generate, Donut helpers, `SpoofMetadata`, stage save/listeners — [pkg.go.dev generate](https://pkg.go.dev/github.com/bishopfox/sliver@v1.7.6/server/generate); [sgn package](https://pkg.go.dev/github.com/bishopfox/sliver/server/encoders/shellcode/sgn).
- This UI already implements: implant generate (incl. shellcode/shared), `POST /api/shellcode/rdi`, session `sideload`, `spawn-dll`, `exec-shellcode`, HTTP C2 profiles / traffic encoders — [LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md); routes in `backend/internal/api/server.go`.
- Not yet wrapped in UI: `ShellcodeEncoder`, `ShellcodeEncoderMap`, `ImplantConfig.SGNEnabled` — same plan doc.
- Stock Sliver remote injection is a well-known CRT pattern and “should be picked up by most advanced EDRs”; prefer BOFs / alternatives in mature environments — [tishina.in](https://tishina.in/opsec/sliver-opsec-notes).
- Elastic call-stack and sideload rules show why byte-only transforms fail against modern EDR — [Elastic ETW call stacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks); [Elastic sideload hunting](https://www.elastic.co/security-labs/Hunting-for-Suspicious-Windows-Libraries-for-Execution-and-Evasion).
- TrustedSec payload design: host keying → network keying → external kill switch → (optional) defensive impairment → payload retrieval → load/execute → cleanup; green blocks mandatory — [TrustedSec Execution Guardrails (2024)](https://trustedsec.com/blog/execution-guardrails-no-one-likes-unintentional-exposure).

### Inferences — stage map for Sliver UI

| Stage | Automate via Sliver RPC / UI? | Notes |
|---|---|---|
| Generate `shared` / `shellcode` / `service` / beacon+jitter | **Yes — RPC** | Already in Implants UI |
| HTTP C2 profile / traffic encoders / domain camouflage | **Yes — RPC** | Already in `/http-c2` |
| DLL → sRDI PIC | **Yes — RPC** | `ShellcodeRDI`; promote on Loaders page |
| Post-encode SGN / XOR / XOR_DYNAMIC | **Yes — RPC (wire)** | Encoder map + encode endpoints planned |
| Generate-time `SGNEnabled` | **Yes — RPC (expose)** | Checkbox on shellcode generate |
| PE metadata spoof (`SpoofMetadata`) | **Maybe — RPC** | Exists in Sliver 1.7.2+; UI not present — candidate |
| Stage listener + MSF-style stager blob | **Yes — RPC** | Prefer checklist warning: use custom staging when possible |
| Session `execute-shellcode` / `sideload` / `spawn-dll` | **Yes — RPC** | Already Advanced tab; link from Loaders |
| Encrypt-at-rest blob packing (AES/Chaskey in custom stub) | **External / checklist** | Donut can encrypt module; custom loaders own this |
| Pair signed sideload host + malicious DLL naming | **Checklist only** | Needs target reconnaissance; Elastic detects bad paths |
| Custom Nim/Rust/Go/.NET loader compile | **External** | Optional downloadable *lab stub* templates later |
| Environmental keying / DNS kill switch | **External** | TrustedSec pattern; not a Sliver RPC |
| Linux memfd / LD_PRELOAD packaging | **Checklist + download SO** | No Sliver “memfd packer” RPC |
| Phishing macros / LNK / ISO / ClickOnce | **External** | MacroPack / OST / etc. |
| Sleep masking / call-stack spoof / indirect syscalls | **External / implant fork** | Beyond stock Sliver UI scope |
| “Scan with Defender and iterate” lab loop | **Checklist** | Operator workstation process |

**Product framing (honest):** Loaders page = transform pipeline (RDI → encode → download) + operator checklist linking HTTP C2 OPSEC and session execution tools. External appendix documents Donut CLI, custom loaders, sideload, memfd — “run outside UI.”

### Gaps
- Stage-listener / `generate stager` HTTP surface in *this* UI fork was not fully inventoried in this pass — confirm before promising “stage-0 from UI.”
- SpoofMetadata RPC wiring effort vs value needs a short spike.

---

## What checklists do mature red teams follow before first implant drop?

### Takeaway
Mature teams treat first drop as a gated release: infra OPSEC, unique payload, environmental guardrails, staged retrieval, beacon hygiene, and a kill switch — validated in a lab mirror of the target EDR — not “generate EXE and email it.”

### Cited Findings
- TrustedSec mandatory/situational payload flow: right-host checks → environment keying → external keying/kill switch → optional telemetry tamper → retrieve payload → load/execute → cleanup; sleep between steps to avoid neat telemetry alignment; “if someone wants to reverse your payload, they will” — [TrustedSec Execution Guardrails](https://trustedsec.com/blog/execution-guardrails-no-one-likes-unintentional-exposure) (MITRE T1480.001 referenced therein).
- Infra OPSEC: separate domains/IPs for phishing vs stage-0 vs long-haul C2; no default C2 profiles/JA3; redirectors; never browse infra from personal IP — [C2 Infrastructure OPSEC](https://cybersecpentesting.com/blog/c2-infrastructure-opsec.html); [kindatechnical infrastructure checklist](https://kindatechnical.com/penetration-testing/red-team-infrastructure-redirectors-c2-and-opsec.html).
- Payload OPSEC: unique payloads per target; strip metadata; avoid signature reuse across clients — [RedGuard-Suite operational_security.md](https://github.com/RichardHam-co-uk/RedGuard-Suite/blob/main/docs/playbooks/operational_security.md).
- Sliver-specific: customize `http-c2.json` (URIs, headers); prefer beacon over session for initial; avoid interactive `shell`; treat stock CRT inject as high-signal; prefer BOFs; use custom staging/encoding over default MSF stager/SGN when facing EDR — [tishina.in](https://tishina.in/opsec/sliver-opsec-notes).
- BallisKit: for evasion, load C2-generated DLL/EXE with an external loader, not the C2’s own loader; generate a lighter “vanilla” implant then protect externally — [BallisKit tutorial](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19).
- Detection reality check: Elastic rules for unbacked/shellcode call stacks, sideload from suspicious folders, recently dropped unsigned DLLs — operators must assume these exist — [Elastic ETW](https://www.elastic.co/security-labs/doubling-down-etw-callstacks); [Elastic libraries hunting](https://www.elastic.co/security-labs/Hunting-for-Suspicious-Windows-Libraries-for-Execution-and-Evasion).

### Inferences — checklist suitable for Sliver UI “before first drop”

**Infrastructure**
- [ ] Written RoE / scope; deconfliction with white cell
- [ ] Separate redirector vs teamserver; engagement-only domains/certs
- [ ] HTTP(S) C2 profile customized (not default URIs/UAs); link `/http-c2`
- [ ] Canaries / kill switch (DNS TXT or stage URL disable) planned

**Artifact**
- [ ] Prefer `shared`/shellcode over raw EXE on disk
- [ ] Run RDI/encode pipeline or external loader wrap
- [ ] Unique build name/hash per target; strip/spoof metadata
- [ ] Encrypt-at-rest in stage-0; no plaintext implant in phishing attachment
- [ ] Lab detonation against target-like AV/EDR *before* live send

**Execution design**
- [ ] Host + domain environmental keying (TrustedSec)
- [ ] Beacon + jitter for first call-home; delay interactive upgrade
- [ ] Prefer sideload / userland execution over remote CRT inject on mature EDR
- [ ] Linux: memfd or SO preload plan; check `ptrace_scope` / noexec
- [ ] Sleep/jitter between keying → download → execute

**Operational**
- [ ] Monitor for unexpected callbacks (wrong host = burn + rotate)
- [ ] Document rollback: disable stage URL, rotate listeners, regenerate

### Gaps
- Public checklists rarely publish exact “hours aged domain” or “which EDR lab image” standards — those are firm-specific.
- Outflank/SpecterOps course materials that would deepen this section are largely behind training paywalls ([SpecterOps Tradecraft Analysis](https://specterops.io/training/tradecraft-analysis/), OST).

---

## Cross-cutting: detection limits (honesty for product copy)

### Takeaway
Encoders and RDI change **static** appearance; modern EDR focuses on **behavior and call stacks**. UI copy must say layered OPSEC reduces risk; nothing in Sliver UI can promise bypass.

### Cited Findings
- Elastic 8.11+ behavior protection: shellcode / unbacked memory / direct syscall / AMSI-ETW patch rules via kernel ETW call stacks — [Elastic](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- Call-stack signatures (e.g. `ntdll|kernelbase|Unbacked`) are actively researched and bypassed in labs, then re-tuned — arms race, not a solved evasion — [GBHackers on Elastic call gadgets](https://gbhackers.com/researchers-bypass-elastic-edr/).
- Donut/default AMSI patches and public loader stubs accumulate signatures; forks exist specifically because upstream became noisy — [Donut README](https://github.com/TheWover/donut); [Donut-CustomHost](https://github.com/Zuigetzu/Donut-CustomHost).
- Sliver stock inject path is textbook remote thread injection — [tishina.in](https://tishina.in/opsec/sliver-opsec-notes).

### Inferences
- Feature success metric for Sliver UI Loaders: **operator completes a correct multi-stage package with fewer mistakes** (wrong format, missing encode, dropping raw PE), not “undetected on VirusTotal.”

### Gaps
- Vendor-specific false-negative longevity after a public technique post is unpredictable; do not cite stale “0/26 VT” screenshots as evidence.

---

## Sources index (primary)

- https://github.com/monoxgas/sRDI  
- https://www.netspi.com/blog/technical-blog/adversary-simulation/srdi-shellcode-reflective-dll-injection/  
- https://github.com/TheWover/donut  
- https://pkg.go.dev/github.com/bishopfox/sliver@v1.7.6/server/generate  
- https://pkg.go.dev/github.com/bishopfox/sliver/server/encoders/shellcode/sgn  
- https://tishina.in/opsec/sliver-opsec-notes  
- https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19  
- https://www.thezentester.com/sliver-c2-staged-implants/  
- https://bytebl33d.github.io/blog/sliver-evasion/  
- https://trustedsec.com/blog/execution-guardrails-no-one-likes-unintentional-exposure  
- https://www.elastic.co/security-labs/doubling-down-etw-callstacks  
- https://www.elastic.co/security-labs/Hunting-for-Suspicious-Windows-Libraries-for-Execution-and-Evasion  
- https://purpleshift.io/purple/2026-06-29-onsd/  
- https://iq.thc.org/bypassing-noexec-and-executing-arbitrary-binaries  
- https://www.cobaltstrike.com/product/outflank-security-tooling  
- https://github.com/SpecterOps/skills  
- Local: `/home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md`
