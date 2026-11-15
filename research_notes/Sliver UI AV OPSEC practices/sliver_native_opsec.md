# Sliver-Native OPSEC and Implant Generation Practices

Scope: Sliver-native features and community-recommended workflows for Windows/Linux beacons and sessions (formats, HTTP C2 profiles, traffic encoders, SGN, limits, naming, staging). Authorized testing context only. Prefer 2023–2026 primary sources; distinguish Sliver-native vs external tooling.

## What does official Sliver documentation recommend for implant generation OPSEC (formats: exe/shared/shellcode/service, beacons vs sessions, SGNEnabled, obfuscate, evasion)?

### Takeaway
Official Sliver docs explicitly place AV/EDR bypass **out of project scope** and point operators to packers/crypters/stagers; native generation OPSEC is about choosing format/mode (beacon vs session), enabling symbol obfuscation, optional `--evasion`, execution limits, and avoiding default fingerprintable artifacts—not claiming invisibility.

### Cited Findings
- Official stance: “The Sliver authors do not consider anti-virus evasion to be within the scope of the Sliver project… Sliver is designed to be interoperable with common techniques for bypassing anti-virus software such as packers, crypters, and stagers.” External examples linked include PEzor and Veil. — [Sliver Docs: Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion)
- Output formats: `exe` (executable), `shared` (DLL/.so/dylib), `service` (Windows service EXE; see `psexec`), `shellcode`. Service is Windows-only. Shellcode first-class for `windows/{386,amd64}`, `linux/{amd64,arm64}`, `darwin/arm64`; not for `linux/386` or `darwin/amd64`. — [Payload Compatibility](https://sliver.sh/docs?name=Payload+Compatibility); generate help examples in [xz.aliyun analysis of generate flags](https://xz.aliyun.com/t/15460)
- Sessions vs beacons: sessions = persistent interactive channel; beacons = async check-in with `--seconds` / `--jitter`. Community/operator guides consistently rate beacons as better OPSEC for long-haul presence; sessions for active work/pivots. — [Radiant Sec Sliver guide](https://radiantsec.io/docs/tools/sliver/); [Gravanon operator guide](https://gravanon.com/); [tishina sliver-opsec-notes](https://tishina.in/opsec/sliver-opsec-notes)
- Symbol obfuscation: enabled by default via garble-style symbol obfuscation; `--skip-symbols` / `-l` disables it (faster builds, “slightly noisier”). — [Radiant Sec](https://radiantsec.io/docs/tools/sliver/); client `generate.go` prints “Symbol obfuscation is enabled” when `ObfuscateSymbols` is true — [generate.go](https://github.com/BishopFox/sliver/blob/master/client/command/generate/generate.go)
- `--evasion` / `-e`: “enable evasion features (e.g. overwrite user space hooks)” — documented as userland unhooking (ntdll remapping) on Windows when dumping/injecting. — [generate flag help](https://xz.aliyun.com/t/15460); [tishina](https://tishina.in/opsec/sliver-opsec-notes)
- `SGNEnabled` / `--disable-sgn` (`-G`): Shikata Ga Nai shellcode encoder applies when format is shellcode; default is enabled for shellcode builds; `-G` disables. SGN is **shellcode-format only**, not a general EXE packer. — [generate.go](https://raw.githubusercontent.com/BishopFox/sliver/master/client/command/generate/generate.go); [Issue #2099](https://github.com/BishopFox/sliver/issues/2099); [BallisKit tutorial](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)
- Execution limits (native): `--limit-datetime`, `--limit-domainjoined`, `--limit-fileexists`, `--limit-hostname`, `--limit-locale`, `--limit-username`; also `--max-errors` (default 1000), reconnect/poll timeouts. Used to constrain where/when an implant runs (sandbox/canary hygiene). — [generate help](https://xz.aliyun.com/t/15460)
- Naming: `-N` / `--name` sets implant/agent name shown in sessions/beacons; default random adjective_noun style names appear in docs/examples. Profiles (`profiles new` / `profiles generate`) reuse full generate configs including format and C2. — [Radiant Sec](https://radiantsec.io/docs/tools/sliver/); [HTTPS C2 docs](https://sliver.sh/docs/?name=HTTPS+C2)
- Staging (native): Meterpreter-compatible staging over TCP/HTTP(S); profile with `--format shellcode` + `stage-listener`; MSF `generate stager` removed—use msfvenom `custom` payloads or custom stagers. Default stage URL extension `.woff` (configurable in HTTP C2 config). Optional AES-CBC stage encryption + zlib/gzip/deflate. — [Stagers docs](https://sliver.sh/docs/?name=Stagers)
- Windows shellcode uses Donut with tunable `--shellcode-*` flags (entropy, compress, exitopt, bypass, headers, etc.); Linux/macOS shellcode currently mainly support `--shellcode-compress`. — [Stagers docs](https://sliver.sh/docs/?name=Stagers)

### Inferences
- Operators should treat Sliver generation as producing a unique Go implant with procedural C2 and optional light native evasion—not a finished AV-resistant dropper. Production OPSEC typically pairs native options (beacon + obfuscation + custom HTTP profile + limits) with an **external** loader/crypter.
- Prefer `generate beacon` for persistence; promote to interactive only when needed (`interactive` from beacon). Prefer `shared`/`shellcode` + custom loader over raw `exe` on disk when AV is present.
- `--skip-symbols` trades OPSEC for build speed; docs and guides still default to obfuscation on for operational builds.

### Gaps
- No single official “recommended generate command line for OPSEC” checklist on sliver.sh beyond AV-out-of-scope + stagers interoperability; community guides fill that gap with varying quality.
- Exact semantics of `--obfuscate` vs default `ObfuscateSymbols` naming differ across secondary guides (some list `--obfuscate` as a flag; client source centers on `ObfuscateSymbols` / `--skip-symbols`)—operators should verify against their installed client `help generate`.

## How are HTTP(S) C2 profiles / traffic encoders used in practice to blend traffic?

### Takeaway
Native HTTP OPSEC is driven by editing `~/.sliver/configs/http-c2.json` (or named HTTPC2 profiles in newer versions) **before** generating implants, plus optional Wasm traffic encoders; defaults are documented and fingerprintable, so customization of paths, extensions, headers, cookies, and UA is the primary blending lever.

### Cited Findings
- HTTP C2 config path default: `~/.sliver/configs/http-c2.json`. Warning: changes can break existing implants—customize before generation. — [HTTPS C2 docs](https://sliver.sh/docs/?name=HTTPS+C2)
- Implant-side knobs: `user_agent` (blank = random platform UA), `chrome_base_version`, probabilistic `url_parameters` / `headers`, min/max files and path segments, separate file lists/extensions for stager / poll / session / start_session / close. Defaults include `.woff` stagers, `.js` poll, `.html` key exchange, `.php` session, `.png` close. — [HTTPS C2 docs](https://sliver.sh/docs/?name=HTTPS+C2)
- Server-side: `random_version_headers`, response `headers`, cookie name lists. — [HTTPS C2 docs](https://sliver.sh/docs/?name=HTTPS+C2)
- Procedural C2: each request randomizes URLs/query args; each implant embeds a **random subset** of the server profile so implants from the same server need not look alike. Encoders (obfuscation, not crypto) include Base64 (custom alphabet), Hex, Gzip, English, PNG, Gzip+English, Base64+Gzip. Encoder ID embedded in cache-busting nonce query param `_`. Invalid nonce ⇒ request ignored as C2 (may still serve website content). — [HTTPS C2 docs](https://sliver.sh/docs/?name=HTTPS+C2); [Immersive Labs detection writeup](https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide/)
- Operator practice (tishina): rotate extensions/filenames; copy legitimate browser request/response headers (e.g. from Burp); consider domain fronting / configurable Host header. — [tishina sliver-opsec-notes](https://tishina.in/opsec/sliver-opsec-notes)
- Radiant Sec: prefer HTTP(S) on 443/80 over long-lived mTLS on 8888; “Cleartext C2 profiles: default HTTP(S) profile URLs/filenames are documented and fingerprintable. Customize per engagement.” — [Radiant Sec](https://radiantsec.io/docs/tools/sliver/)
- Listener camouflage: `websites` static content + `--website` on `http`/`https`; Let’s Encrypt `--lets-encrypt` or custom cert/key instead of default self-signed. — [HTTPS C2 docs](https://sliver.sh/docs/?name=HTTPS+C2)
- Advanced HTTP options (URL query on generate C2 string): `driver=wininet` (Windows NTLM/Kerberos proxy auth; more hookable), `proxy`, timeouts, `force-http`, disable Accept/Upgrade headers. — [C2 Advanced Options](https://sliver.sh/docs/?name=C2+Advanced+Options)
- Traffic Encoders (v1.6+): user-defined Wasm encode/decode modules for HTTP(S) payloads; Rust recommended over TinyGo for performance; messages &gt;2 MB skip custom encoders by default (configurable at generate time). — [Traffic Encoders docs](https://sliver.sh/docs?name=Traffic+Encoders); [Bishop Fox Workshop Part 3](https://bishopfox.com/resources/sliver-workshop-part-3-building-better-encoders)
- Community NDR-oriented example profiles customize UA, path/file vocabularies, cookie names to look like SaaS/CDN traffic. — [0xFFF-cmd Obfuscate-Sliver-Network-http-c2.json](https://github.com/0xFFF-cmd/Sliver/blob/main/Obfuscate-Sliver-Network-http-c2.json)
- Detection side confirms defaults are signatured (Corelight package, Immersive Labs Snort-style HTTP rules on default paths/encoders). — [Corelight Sliver detection](https://corelight.com/blog/new-sliver-c2-detection-released-redteam-detected); [Immersive Labs](https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide/)

### Inferences
- Blending is mostly **profile hygiene + infra** (real domain, valid cert, CDN/redirector, website decoy), not encoder crypto. Built-in encoders rotate to reduce static network signatures but remain reverse-engineerable.
- Named HTTPC2 profiles (Get/SaveHTTPC2Profiles in recent Sliver) allow per-engagement profiles without editing a single global JSON—aligned with UI OPSEC work in this repo’s memory notes.
- `wininet` driver helps corporate proxy environments but increases EDR visibility relative to Go’s HTTP stack.

### Gaps
- Sparse public “battle-tested” Wasm traffic encoder repos with measured NDR evasion results (workshop demos exist; few published engagement writeups with metrics).
- Exact UI/RPC workflow for binding `http_c2_profile` name at generate time is version-dependent; confirm against local Sliver version.

## What is the recommended use of shellcode + RDI + ShellcodeEncoder (Shikata Ga Nai / XOR) in Sliver?

### Takeaway
Native path: build `--format shellcode` (Donut on Windows) optionally through SGN (`SGNEnabled`, disable with `-G`), stage via `stage-listener`, or inject via sideload/spawndll (sRDI) and execute-shellcode; SGN is a light polymorphic XOR-style encoder—operators and vendors treat it as insufficient alone against modern AV, so custom/external loaders are the common recommendation.

### Cited Findings
- Windows shellcode generation uses Donut; shellcode tuning flags documented under Stagers (`--shellcode-encoder`, `--shellcode-compress`, entropy, exitopt, bypass, headers, thread, unicode, oep). Linux/macOS shellcode: mainly compression. — [Stagers docs](https://sliver.sh/docs/?name=Stagers)
- Client applies SGN after build when `IsShellcode` and `SGNEnabled`: RPC `ShellcodeEncoder` with `ShellcodeEncoder_SHIKATA_GA_NAI`, default 1 iteration. `--disable-sgn` flips `SGNEnabled` off. — [generate.go](https://raw.githubusercontent.com/BishopFox/sliver/master/client/command/generate/generate.go)
- Server SGN package wraps `github.com/moloch--/sgn` with Architecture, Iterations, MaxObfuscation, PlainDecoder, Safe, BadChars, Asci. — [sgn package docs](https://pkg.go.dev/github.com/bishopfox/sliver/server/sgn)
- `execute-shellcode` can also apply `--shikata-ga-nai` (requires RWX pages; arch 386/amd64; iterations). — [execute-shellcode.go](https://github.com/BishopFox/sliver/blob/master/client/command/exec/execute-shellcode.go)
- `sideload` on Windows: DLL → shellcode via sRDI/Donut, inject into sacrificial process. `spawndll`: reflective DLL case of sideload. Linux sideload: `memfd_create` + `LD_PRELOAD`. — [Third Party Tools docs](https://sliver.sh/docs/?name=Third%20Party%20Tools); [Dominic Breuker Learning Sliver C2 (10)](https://dominicbreuker.com/post/learning_sliver_c2_10_sideload/)
- tishina: “recently, sliver started supporting shikata-ga-nai. I'd still go with a custom staging/encoding solution over it though.” Staging protocol is simple length-prefix + shellcode; prefer custom stagers. — [tishina](https://tishina.in/opsec/sliver-opsec-notes)
- BallisKit (2025): often **disable** Sliver SGN/symbols/evasion (`--disable-sgn --skip-symbols`) to get a smaller “vanilla” implant, then wrap with external ShellcodePack/MacroPack for EDR bypass—i.e. external tooling preferred over native SGN for real evasion. — [BallisKit tutorial](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)
- Reliability caveats: Issues #2099 / #2138 document SGN encoder failures (empty files, hang/fallback) in 1.6.x; workaround `--disable-sgn`; fixes landed on `fix/sgn` branch. — [Issue #2099](https://github.com/BishopFox/sliver/issues/2099); [Issue #2138](https://github.com/BishopFox/sliver/issues/2138)
- Official AV page points to external packers (PEzor, Veil) rather than claiming SGN sufficiency. — [Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion)

### Inferences
- Recommended native workflow for constrained delivery: `profiles new --format shellcode` → `stage-listener` → small custom/msf stager fetching `.woff` (or customized ext) → in-memory Donut shellcode (± SGN).
- For OPSEC-sensitive Windows execution of tools: prefer BOFs/extensions or `execute-assembly --in-process` over remote CRT injection; when injection is required, change sacrificial `--process` away from `notepad.exe`.
- SGN ≈ polymorphic XOR encoder heritage from Metasploit; useful as a mild static-signature disruptor, not a primary EDR strategy.

### Gaps
- Limited public guidance on `--shellcode-encoder` values beyond SGN/`none` in newer clients (encoder map command exists: `shellcode-encoders`).
- No official endorsement ranking SGN iterations vs detection rates.

## Linux-specific vs Windows-specific OPSEC differences for Sliver implants?

### Takeaway
Windows carries most of Sliver’s evasion surface (Donut/SGN shellcode, service format, userland unhooking, CLR/BOF, named-pipe pivots, sacrificial process injection); Linux focuses on ELF/`shared` (.so), optional shellcode on amd64/arm64, memfd+LD_PRELOAD sideload, and network/process hygiene—with fewer native “evasion” toggles and different telemetry (e.g. defunct children, unsigned Go ELF).

### Cited Findings
- Format matrix: Service = Windows-only; shellcode unsupported on `linux/386`; supported on `linux/amd64` and `linux/arm64`. Shared libraries supported on both major Linux arches. — [Payload Compatibility](https://sliver.sh/docs?name=Payload+Compatibility)
- Shellcode options: full Donut tuning Windows-only; Linux shellcode “currently only support `--shellcode-compress`”. — [Stagers docs](https://sliver.sh/docs/?name=Stagers)
- `--evasion` userland hook overwrite / ntdll remapping described in Windows-centric OPSEC notes; tishina series states focus is “only focused on Windows evasion at the moment.” — [tishina](https://tishina.in/opsec/sliver-opsec-notes)
- Linux sideload: write .so to memfd via `memfd_create`, preload with `LD_PRELOAD` into a chosen process (e.g. bash)—no Windows-style CRT injection path. — [Third Party Tools](https://sliver.sh/docs/?name=Third%20Party%20Tools)
- tishina Linux note: “For some reason, sliver on Linux creates loads of defunct child processes… blame `execute -o`.” Interactive `shell` still warned as bad OPSEC on all platforms. — [tishina](https://tishina.in/opsec/sliver-opsec-notes)
- Transport OPSEC similar: HTTP(S) blending via same http-c2.json; mTLS/WG “look pretty standard” when egress allows; DNS “optimized for speed, not evasion.” — [tishina](https://tishina.in/opsec/sliver-opsec-notes); [HTTPS C2](https://sliver.sh/docs/?name=HTTPS+C2)
- Cross-compile: Linux hosts can build Windows shared/shellcode with embedded Zig; macOS shared/shellcode may need osxcross/external builders. — [Cross-compiling Implants](https://sliver.sh/docs/?name=Cross-compiling+Implants)
- Beacon examples for Linux with long sleep/jitter appear in community cheatsheets as “OPSEC ready” patterns (e.g. 1800s sleep). — [Hacknetics sliver.md](https://github.com/jtaubs1/OSCP-Prep/blob/main/c2-frameworks/sliver.md)
- Sleep obfuscation (Ekko-style) PRs/discussions are Windows-oriented; Go runtime complicates portable sleep masks. — [Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171); [PR #1805](https://github.com/BishopFox/sliver/pull/1805)

### Inferences
- On Linux, OPSEC gains more from: non-default binary names/paths, beacon timing, HTTP profile customization, avoiding noisy `shell`/`execute`, and memfd-based loading—than from `--evasion`/SGN.
- On Windows, treat unsigned large Go EXE on disk as high-signal; plan staged shellcode or sideload + external crypter; avoid default notepad sacrificial process and default HTTP profile.

### Gaps
- Few dedicated Linux Sliver AV/EDR case studies (most public detection content is Windows + network C2).
- Hardened Linux (SELinux/AppArmor, noexec /tmp, memfd restrictions) interaction with Sliver sideload not well documented in official docs.

## Common operator mistakes that cause immediate AV hits with Sliver?

### Takeaway
Immediate hits usually come from **default artifacts**: stock HTTP C2 URLs/extensions, unsigned on-disk Go EXE, default notepad.exe execute-assembly, enabling interactive `shell`, raw mTLS:8888, and relying on native SGN/garble alone against updated YARA—rather than from a single missing flag.

### Cited Findings
- Official: AV evasion out of scope; expect to use external packers/stagers. — [Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion)
- Default HTTP profile paths/filenames are documented and fingerprintable (Immersive Labs, Radiant Sec, Corelight detections). — [Immersive Labs](https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide/); [Radiant Sec](https://radiantsec.io/docs/tools/sliver/); [Corelight](https://corelight.com/blog/new-sliver-c2-detection-released-redteam-detected)
- Unsigned Go implant binary / AppLocker-WDAC: “Implant binary is an unsigned Go executable not in any software inventory.” Large size (often multi-MB to ~16–30MB cited) aids static YARA. — [Radiant Sec](https://radiantsec.io/docs/tools/sliver/); [Immersive Labs](https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide/); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Fortbridge (2025): out-of-the-box implants now detected much faster as vendors signatured standard configs; protobuf/export strings (e.g. ScreenshotReq, DllUnregisterServer, GetJitter, VoidFunc) and init patterns feed YARA; lack of sleep mask called out as pain point. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Sacrificial `notepad.exe` loading .NET CLR via default `execute-assembly` is a strong EDR signal; change `--process`. — [Radiant Sec](https://radiantsec.io/docs/tools/sliver/)
- Interactive `shell` explicitly prompts: “This action is bad OPSEC, are you an adult?” Spawns child cmd/shell with no PPID spoofing/arg rewriting. — [tishina](https://tishina.in/opsec/sliver-opsec-notes)
- Standard remote injection path (VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → CreateRemoteThread) is EDR-classic; tishina recommends BOFs/alternatives in mature environments. — [tishina](https://tishina.in/opsec/sliver-opsec-notes)
- Long-lived mTLS to non-standard port 8888 anomalous vs HTTPS/443. Self-signed HTTPS certs vs Let’s Encrypt/real domain. — [Radiant Sec](https://radiantsec.io/docs/tools/sliver/); [HTTPS C2](https://sliver.sh/docs/?name=HTTPS+C2)
- LSASS access via procdump without extra evasion; prefer armory nanodump/BOFs and expect alerts. — [tishina](https://tishina.in/opsec/sliver-opsec-notes); [Radiant Sec](https://radiantsec.io/docs/tools/sliver/)
- Canary domains stored cleartext in binary (detection/intel aid)—misuse or unexpected canary DNS can burn ops. — [Immersive Labs](https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide/)
- Watchtower: operators can monitor VT/X-Force for implant hash submissions—implies dropped samples get uploaded quickly when AV hits. — [Corelight](https://corelight.com/blog/new-sliver-c2-detection-released-redteam-detected)
- Hunt.io / threat-intel threads catalog real-world Sliver OPSEC failures (default-ish configs, open dirs, predictable naming). — [Ctrl-Alt-Intel X thread](https://x.com/ctrlaltintel/status/2082677566633316681); [Hunter’s Ledger ScareCrow+Sliver open dir](https://the-hunters-ledger.com/reports/sliver-open-directory/)

### Inferences
- Highest-ROI mistake fixes (native): customize http-c2 before generate; use beacons with realistic sleep/jitter; don’t drop raw EXE; never use default notepad; don’t type `shell`; prefer HTTPS+valid cert+website decoy; rotate stage URLs.
- Highest-ROI external: custom loader/crypter (or source-level string/protobuf mutation per Fortbridge) because native garble+SGN no longer reliably beats commodity AV.

### Gaps
- No authoritative public matrix of “flag X ⇒ VT detection rate Y” for current Sliver releases (detections churn monthly).
- Reddit/r/redteamsec discussions are sparse and often loader-specific; weighted lightly per assignment guidance.
