# AV detection of BishopFox Sliver Windows implants on disk (static / file scan)

Authorized lab / detection-engineering inventory. Scope is **on-disk static scan** of stock Sliver `generate` output for Windows **v1.5–v1.7.x**: EXE, SHARED_LIB DLL, and Donut/sRDI `.bin` shellcode. Runtime/memory/network detections are cited only when they reuse the same file bytes (Elastic `scan_context = "file, memory"`). No exploit PoCs.

**Vendor layers (do not collapse):**

| Layer | What it is | Typical on-disk names |
| --- | --- | --- |
| **MDAV inbox** | Local `mpengine` VDM/YARA + PE ML + emulator on the file | `Trojan:Win64/Sliver.D`, `VirTool:Win64/Splinter.A`, `Win32/AMSI_Patch_T.B13`, `Trojan:Win32/Wacatac.B!ml` |
| **MDE** | EDR hunting + post-exec behavior; 2022 blog is mostly **not** file YARA | “A process was injected…”, GetSystem/PsExec KQL; `ALF:Trojan:Win32/Sliver.A` (cloud/ALF) |
| **Elastic** | Public YARA `Multi.Trojan.Sliver` + behavior rules | `Multi.Trojan.Sliver` / `Multi_Trojan_Sliver_*` |
| **Generic ML** | Statistical PE classifiers, often unsigned Go | `Wacatac.B!ml`, `ML.Attribute.HighConfidence`, Trapmine |

**Format split (stock generate):**

| Format | On-disk object | Dominant static hits |
| --- | --- | --- |
| **EXE** (`-f exe`) | Large unsigned Go PE (~16–30 MB) | Protobuf/RPC ASCII, `github.com/bishopfox/…`, `sliverpb`, ` Go buildinf:`, Go PE-shape ML |
| **SHARED DLL** (`-f shared`) | Same Go image as c-shared + extra **export names** | Everything EXE has, plus `StartW` / `VoidFunc` / `DllInstall` / `DllRegisterServer` / `DllUnregisterServer` in the export table **and** as ASCII |
| **`.bin` shellcode** (`-f shellcode`) | Donut PIC wrapping the implant (Windows); optional sRDI of a DLL via `StartW` | Donut **AMSI-bypass stub** (`AMSI_Patch_T.B13`) if Bypass≠1; encrypted module (entropy=3) can **hide** plaintext `sliverpb` until decrypt; sRDI of an uncleaned DLL still carries PE/export strings |

BishopFox policy: AV evasion is **out of scope**; operators are pointed at packers/crypters/stagers (PEzor, Veil). — [Sliver Anti-virus Evasion.md](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Anti-virus%20Evasion.md); [sliver.sh Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion)

---

## What does Elastic `Multi_Trojan_Sliver` match on file context?

### Takeaway
The public Elastic rule file is three rules, all `scan_context = "file, memory"`, `os = "multi"`, `arch_context = "x86"`. On disk they fire on **unobfuscated protobuf getter/RPC names**, the **Go protobuf package path**, and (rule 3) **session-start/register bytecode** — not on PE magic alone and not on `StartW`.

### Cited Findings
- File lives at [elastic/protections-artifacts `yara/rules/Multi_Trojan_Sliver.yar`](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar) (fetched 2026-11; three rules, 89 lines). All three set `scan_context = "file, memory"` and `threat_name = "Multi.Trojan.Sliver"`.

**Rule `Multi_Trojan_Sliver_42298c4a`** (created 2021-10-20, last_modified 2022-01-14, sample `3b45aae401ac64c055982b5f3782a3c4c892bdb9f9a5531657d50c27497c8007`). Exact strings:

```
$a1 = ").RequestResend"
$a2 = ").GetPrivInfo"
$a3 = ").GetReconnectIntervalSeconds"
$a4 = ").GetPivotID"
$a5 = "name=PrivInfo"
$a6 = "name=ReconnectIntervalSeconds"
$a7 = "name=PivotID"
```

Condition: `2 of them`. These are protobuf-generated **method/field name** fragments (Go getters + `name=` tags), not C2 URLs.

**Rule `Multi_Trojan_Sliver_3bde542d`** (created 2022-08-31, last_modified 2022-09-29, sample `05461e1c2a2e581a7c30e14d04bd3d09670e281f9f7c60f4169e9614d22ce1b3`). Exact strings:

```
$a1 = "B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb" ascii fullword
$b1 = "InvokeSpawnDllReq" ascii fullword
$b2 = "NetstatReq" ascii fullword
$b3 = "HTTPSessionInit" ascii fullword
$b4 = "ScreenshotReq" ascii fullword
$b5 = "RegistryReadReq" ascii fullword
```

Condition: `1 of ($a*) or all of ($b*)`. `$a1` is the **Go module/protobuf package path** as it appears in the compiled binary (the `B/Z-` prefix is part of the Go string table encoding Elastic matched). The five `$b*` names are **sliverpb RPC/message type identifiers**.

**Rule `Multi_Trojan_Sliver_3d6b7cd3`** (created 2022-12-01, last_modified 2023-09-20, sample `9846124cfd124eed466465d187eeacb4d405c558dd84ba8e575d8a7b3290403e`). No ASCII strings. It matches **x86/x64 bytecode** families `$session_start_*` and `$register_*` (3 x86 + 3 x64 session-start; 5 x86 + 8 x64 register). Condition: `1 of ($session_start_*) and 1 of ($register_*)`. Fortbridge later identified this as hitting the **`transports.GetMaxConnectionErrors()`** call site (inlining the constant bypasses it). — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)

- BishopFox issue #1760 reproduced **exactly** the string rule hits on a stock Windows EXE beacon (`generate --http {ip} --os windows`) with Elastic’s public YARA: `").RequestResend"`, `").GetPrivInfo"`, `"B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb"`, `InvokeSpawnDllReq`, `NetstatReq`, `HTTPSessionInit`, `ScreenshotReq`, `RegistryReadReq`. — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760)
- MalwareBazaar still indexes `Multi_Trojan_Sliver_3d6b7cd3` against live EXE/ELF samples through 2026-09 (84 sightings). — [MalwareBazaar rule page](https://bazaar.abuse.ch/browse/yara/Multi_Trojan_Sliver_3d6b7cd3/)
- Elastic does **not** list `StartW`, `VoidFunc`, `DllRegisterServer`, `GetJitter`, or ` Go buildinf:` in this file. Those are **DefenderYara / Fortbridge** ASCII, not Elastic’s published Sliver YARA.

### Inferences
- On **file** scan, Elastic’s first two rules are **plaintext protobuf/package strings**. They apply equally to **EXE and SHARED DLL** (same Go image). They apply to **Donut `.bin`** only if Donut entropy left those strings in the clear (default entropy=3 encrypts the module; the Donut **loader stub** is a different signature class).
- Rule 3 is **compiler-output bytecode**, so it survives string garble but is sensitive to inlining/`GetMaxConnectionErrors` (Fortbridge).
- `$a1` package path is the most specific single-string IOC in the public Elastic set; the `$b*` set of five RPC names is the family-wide protobuf fingerprint.

### Gaps
- Elastic does not publish which of the three rules ships in which Elastic Agent version, or whether Endpoint uses a superset of this GitHub file.
- No public Elastic YARA in this file is **DLL-export-specific** (`pe.exports("StartW")` is absent).

---

## What did Fortbridge map as Defender / DefenderYara ASCII on Sliver?

### Takeaway
Fortbridge (Samuel Birkinshaw, Apr 2025) scanned stock implants with extracted Windows Defender YARA from [roadwy/DefenderYara](https://github.com/roadwy/DefenderYara) and attributed **on-disk and in-memory** hits to nine **ASCII strings in byte form**. Three are unused **regsvr32 COM exports**; `VoidFunc` is the PowerSploit reflective-PE export; four are protobuf/runtime getters; one is the Go buildinfo marker. `StartW` was **renamed separately** as the shared-lib entry, not listed among the nine DefenderYara `$a_01_*` hits.

### Cited Findings
- Fortbridge hypothesized Defender’s **internal YARA** (not open source) caused immediate on-disk detection; they used extracted rules from `https://github.com/roadwy/DefenderYara`, filtered `.yar` related to Sliver or Go malware, and scanned implants **on disk and in memory**. — [Fortbridge: Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Exact culprits they published (offsets from their disassembly of a matching implant; `$a_01_N` is DefenderYara’s extracted string index):

| Offset (their sample) | DefenderYara id | ASCII |
| --- | --- | --- |
| `0x16d8889` | `$a_01_0` | `DllUnregisterServer` |
| `0x16d8877` | `$a_01_1` | `DllRegisterServer` |
| `0x16d886c` | `$a_01_2` | `DllInstall` |
| `0x5975f7` | `$a_01_3` | `GetJitter` |
| `0x16d88a4` | `$a_01_4` | `VoidFunc` |
| `0x594873` | `$a_01_5` | `GetKill` |
| `0x5974ef` | `$a_01_6` | `AddTunnel` |
| `0x595db5` | `$a_01_7` | `GetIsIOC` |
| `0xb66a02` | `$a_01_8` | ` Go buildinf:` (leading space) |

— [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/) (same list mirrored by [Cyber Security News recap](https://cybersecuritynews.com/sliver-framework-customized/))

- Fortbridge’s interpretation: three strings are **exported functions that execute a Sliver DLL via `regsvr32.exe`**. `VoidFunc` is the export used with PowerSploit `Invoke-ReflectivePEInjection.ps1`. They **removed unused exports** from source and **renamed `StartW`** in `sliver.go` and `sliver.c`. Remaining getters (`GetJitter`) required renaming the protobuf **member** (`Jitter` in `BeaconRegister`) and `make pb`. Final runtime YARA still needed a project-wide `bishopfox` replace. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Stock shared-lib export set (CLI default, still documented in this repo’s generator patches): `StartW,VoidFunc,DllInstall,DllRegisterServer,DllUnregisterServer`. — [BishopFox generate help / local `patches/sliver-v1.7.3/README.md`](https://github.com/BishopFox/sliver/discussions/755); source comments in older `sliver.go` (`//export VoidFunc` “PowerSploit Invoke-ReflectivePEInjection”; `DllInstall`/`DllRegisterServer`/`DllUnregisterServer` for `regsvr32`). — [v1.2.1 sliver.go](https://github.com/bishopfox/sliver/blob/v1.2.1/sliver/sliver.go)
- `GetJitter()` is a generated getter on `BeaconRegister.Jitter` in `sliver.pb.go` / `sliver.proto`. `AddTunnel` is a `Connection` method in the transports package. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [pkg.go.dev transports](https://pkg.go.dev/github.com/B0lg0r0v/sliver_modified/implant/sliver/transports)
- ` Go buildinf:` is the **Go 1.18+ buildinfo** prefix (`runtime/debug` / `debug/buildinfo`), present in essentially every Go PE unless stripped in a way that still often leaves the marker. Fortbridge treated it as a Defender YARA needle, not just a compiler artifact.
- Fortbridge also renamed protobuf **message** names (example `ScreenshotReq` → `ScShotReq`) because Elastic/community YARA keys those identifiers. They hardcoded Donut bypass **3 → 1** in `server/generate/donut.go` because default AMSI bypass is “heavy signature detection.” — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- [roadwy/DefenderYara](https://github.com/roadwy/DefenderYara) is extracted `mpavbase.vdm` / `mpasbase` HSTR (`SIGNATURE_TYPE_PEHSTR_EXT`, etc.). README warns “some strings or condition maybe wrong.” Fortbridge did **not** publish the **Defender family name** of the rule that contained those nine strings (only the `$a_01_*` indices). GitHub code search of that repo requires login; this pass could not open the exact `.yar` filename.

### Inferences
- **EXE:** `GetJitter` / `GetKill` / `AddTunnel` / `GetIsIOC` / ` Go buildinf:` fire without any export table. COM export **names as ASCII** still appear in stock shared-lib **and** often in EXE Go string tables because the `//export` blocks are compiled into shared builds; on a pure EXE they may be absent if the shared-lib template is not compiled in.
- **DLL:** all nine strings plus **PE export directory** names. `regsvr32`/`rundll32` analytics then have a name to hang on (`DllRegisterServer`, `StartW`).
- **`.bin`:** plaintext ASCII of those strings depends on Donut entropy. The **export names** are not a PE export table in raw PIC; they can still exist as ASCII inside the embedded PE if Donut did not encrypt, or after emulator unpack.

### Gaps
- The exact Defender **threat name** (`Trojan:Win64/Sliver.*` vs a generic HSTR) for the nine-string rule was not published by Fortbridge and was not recovered from DefenderYara without authenticated GitHub code search.
- Whether ` Go buildinf:` is in a **Sliver-specific** Defender rule or a **generic Go** rule is not proven from the extracted dump; Fortbridge found it in “sliver or go based malware” rules they selected.

---

## Immersive Labs / Huntress / Microsoft 2022 “Sliver lining” file indicators

### Takeaway
**Immersive (2023)** published the simplest **unmodified-file** YARA: PE/ELF/Mach-O magic **and** `sliverpb` **and** `github.com/bishopfox/` **and** `chacha20poly1305`. **Microsoft (2022)** named inbox families (`Trojan:Win64/Sliver.D`, Splinter/ALF) and hunted **behavior + default PsExec strings**, not public file YARA. **Huntress** has **no** dedicated Windows static YARA for Sliver implants in the sources reviewed; they published **Linux** Sliver **hashes** in a 2025 campaign. UK **NCSC** (SVR advisory) YARA is the other first-party file rule set: `/sliver/`, `sliverpb.`, and eight RPC names.

### Cited Findings

#### Immersive Labs (24 Apr 2023)
- Unmodified implants are statically compiled Go, **average ~16 MB**. Canary domains (if used) are **plaintext** in the file; real C2 is encrypted. — [Immersive: Detecting and decrypting Sliver C2](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)
- File rule `sliver_binary_native` (Kev Breen), [Immersive-Labs-Sec/SliverC2-Forensics `Rules/sliver.yar`](https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/blob/main/Rules/sliver.yar):

```
$sliverpb = "sliverpb"
$bishop_git = "github.com/bishopfox/"
$encryption = "chacha20poly1305"
```

Condition: Go-capable headers (`uint16(0)==0x5a4d` PE, ELF `0x464c457f`, Mach-O magics) **and all three strings**. The blog states this is for **unmodified** Windows/Linux/macOS implants. A **separate** `sliver_memory` rule matches **only** `sliverpb` because the file rule’s header offsets fail on dumps.

#### Microsoft “Looking for the ‘Sliver’ lining” (24 Aug 2022) — Defender Experts for Hunting
- Default generate formats: **Shellcode, Executable, Shared library/DLL, Service**. Stagers exist to shrink the on-disk first stage; “file-based detection more challenging.” Motivated actors embed Sliver **shellcode** in custom loaders (Bumblebee). — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/); [Wayback 2022-10-22 full text](https://web.archive.org/web/20221022171703/https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Obfuscation: **garble** (current) / **gobfuscate** (earlier). Config extraction is described as **memory** work because strings are obfuscated on disk — i.e. Microsoft did **not** publish a protobuf-string YARA in this blog.
- Inbox / WDSI **file** families listed in that post and the matching encyclopedia entry:

  - `Trojan:Linux/Sliver.A`
  - `Trojan:Win64/Sliver.D` — WDSI page published **2021-11-26**, updated **2022-08-29**; “Detected by Microsoft Defender Antivirus”; points back at the same blog. Additional names on that page: `ALF:Trojan:Win32/Sliver.A`, `ALF:Trojan:Win32/SliverServer.A`, `VirTool:Win64/Splinter.A`. — [WDSI Trojan:Win64/Sliver.D](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Sliver.D)
  - `TrojanDownloader:PowerShell/Splinter.A`
  - `Behavior:Win32/Splinter.A`
  - `VirTool:Win32/SPLINTER.A`

  Microsoft does **not** publish the YARA bytes behind `Trojan:Win64/Sliver.D`. Treat it as an **inbox family label**, not a quoted string list.
- **File-adjacent default strings they *did* quote** are **service metadata**, not implant protobuf: PsExec remote service `DisplayName == 'Sliver'`, `Description == 'Sliver implant'`, `ImagePath` regex `^[a-zA-Z]:\\windows\\temp\\[a-zA-Z0-9]{10}\.exe`. — [Microsoft blog KQL](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Default interactive **shell** command line (process-creation, not PE scan): `powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8`. Sigma `proc_creation_win_hktl_sliver_c2_execution_pattern.yml` copies this (Nextron, 2022-08-25). — [SigmaHQ](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_sliver_c2_execution_pattern.yml)
- MDE alerts in the blog are **behavioral** (injection API sequence, PsExec service install), not static YARA.

#### Huntress
- Huntress **did not** publish a Windows Sliver implant file YARA in sources reviewed for this pass. Their 2025-12 PeerBlight write-up lists a **Linux** Sliver payload **SHA-256** `2cd41569e8698403340412936b653200005c59f2ff3d39d203f433adb2687e7f` and drop paths (`/usr/bin/sshd-agent`, `~/.config/.system-monitor/.sys-mon`) — hash/path IOCs, not string YARA. — [Huntress: PeerBlight](https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell)
- Closest similarly named public hunt that **does** discuss Windows Sliver host artifacts is **Hunt & Hackett** (“Hunting for a Sliver in a haystack”), which is **behavior** (`execute-shellcode` → notepad + VirtualAllocEx/WPM/CRT), not file YARA. Do not conflate Huntress with Hunt & Hackett.

#### NCSC UK (SVR advisory YARA; often cited alongside Microsoft 2022)
Extracted from [NCSC PDF](https://www.ncsc.gov.uk/files/Advisory%20Further%20TTPs%20associated%20with%20SVR%20cyber%20actors.pdf) by [gist ecapuano](https://gist.github.com/ecapuano/2c59ff1ea354f1aae905d6e12dc8e25b):

`sliver_github_file_paths_function_names`:
- Paths: `"/sliver/"`, `"sliverpb."`
- RPC names: `RevToSelfReq`, `ScreenshotReq`, `IfconfigReq`, `SideloadReq`, `InvokeMigrateReq`, `KillSessionReq`, `ImpersonateReq`, `NamedPipesReq`
- Condition: ELF or PE **and** (`all of ($p*)` **or** `3 of ($fn*)`)

Two additional NCSC rules are **bytecode** (`sliver_proxy_isNotFound_retn_cmp_uniq`, `sliver_nextCCServer_calcs`) with a false-positive warning.

#### Other public file YARA that still fire on stock PE/DLL
- **Wazuh** `sliver_client`: `$s1="sliverpb"`, `$s2="/sliver/"`, `$s3="github.com/bishopfox/sliver/"` plus protocol CMP bytes (`wg`, `http`+`s`, `dns`+`s`, `mtls`); `filesize < 50MB`. — [Wazuh blog](https://wazuh.com/blog/detecting-sliver-c2-framework-with-wazuh/)
- **ditekSHen / Malpedia `win_sliver_w0` / `INDICATOR_TOOL_Sliver`**: `$x1 = "github.com/bishopfox/sliver/protobuf/sliverpbb."` plus `.commonpb.ResponseR`, `.PortfwdProtocol`, `.WGTCPForwarder`, `.WGSocksServerR`, `.PivotEntryR`, `.BackdoorReq`, `.ProcessDumpReq`, `.InvokeSpawnDllReq`, `.SpawnDll`, `.TCPPivotReq`. Condition: PE/ELF/Mach-O and (`1 of ($x*)` or `5 of ($s*)`). — [ditekshen detection](https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_tools.yar); [Malpedia win.sliver](https://malpedia.caad.fkie.fraunhofer.de/details/win.sliver)
- **Google Chronicle GCTI** (gssincla@google.com, 2022-11-18): `Sliver_Implant_32bit` / `Sliver_Implant_64bit` match **C2 URL-scheme switch/case immediates** (`tcppivot`, `wg`, `dns`, `http`, `https`, `mtls`, `namedpipe`) as CMP immediates, **not** protobuf names. 32-bit condition: `4 of ($s*) and not "cloudfoundry"`. Still matching MalwareBazaar EXE samples in 2026. — [chronicle/GCTI Sliver__Implant_32bit.yara](https://raw.githubusercontent.com/chronicle/GCTI/main/YARA/Sliver/Sliver__Implant_32bit.yara); [64-bit](https://github.com/chronicle/GCTI/blob/main/YARA/Sliver/Sliver__Implant_64bit.yara)

### Inferences
- **File-scan consensus across Immersive / NCSC / Wazuh / ditekSHen / Elastic:** `sliverpb` + `github.com/bishopfox/sliver` + protobuf `*Req` names. Microsoft’s public 2022 work is the outlier: they **named a family** and hunted **TTPs**, and did not dump those strings.
- Canary domains are a **compile-time plaintext** file IOC if the operator enabled them (Immersive).
- Huntress should be cited for **campaign hashes**, not for a Windows static signature catalog.

### Gaps
- Microsoft has not published the **string list** inside `Trojan:Win64/Sliver.D`. Cyb3r-Monk on #1760 said “several Defender AV signatures detecting these strings” (the Elastic protobuf set) — that is an operator comment, not a WDSI page.
- Huntress Windows Sliver file YARA: **not found**.

---

## Do unsigned Go PEs trip generic ML (`Trojan:Win32/Wacatac.B!ml`, gopclntab) even without Sliver strings?

### Takeaway
**Yes.** `Wacatac.B!ml` is Microsoft’s **machine-learning** PE classifier (`!ml`), not a Sliver YARA. Formidable (May 2026) tripped it on a **benign** unsigned Wails/Go GUI with **zero** Sliver strings and **zero** sandbox detections. Praetorian (May 2026) measured the same family on Go tooling and showed **`gopclntab` bulk** moves the score; stripping symbols **increased** detections. This is **EXE-shaped Go**, independent of `sliverpb`.

### Cited Findings
- Formidable (`Formidable.exe`, Wails 3 + Go 1.25, May 2026): VT consistently `Trojan:Win32/Wacatac.B!ml`. NSIS installer 2/71 (Microsoft + Trapmine); bare EXE 1/71 (Trapmine). Four VT sandboxes (CAPA, CAPE, Jujubox, Zenbox) **0 dynamic** detections. VersionInfo, Win10/11 manifest, dropping `-w -s`, `-buildid=`, NSIS polish, FP submission: **no score change**. Author’s diagnosis: classifier weights **Go PE shape** — large `.text`, `gopclntab`, `runtime.morestack_noctxt` / `runtime.gcWriteBarrier`, statically linked, no CRT — because Go malware volume (BlackCat, **Sliver**, stealers) trained “Go-shaped unsigned EXE” as malicious. Same product as Electron had never been flagged. — [Formidable: Defender, Wacatac.B!ml, and the Go-binary problem](https://formidable.tools/posts/defender-wacatac-go-binary/)
- `!ml` = Microsoft ML, **not** a signature definition. Features: PE structure, sections, imports, entropy, strings, metadata. — [Formidable](https://formidable.tools/posts/defender-wacatac-go-binary/)
- Praetorian (28 May 2026), using VirusTotal as an oracle on **Go** binaries (goffloader, then Sliver-obfuscation pipeline):
  - YARA-style (`Trojan/Win.Sliver.R774471`, `Multi.Trojan.Goffloader`) ≠ ML (`ML.Attribute.HighConfidence`, `Wacatac.B!ml`).
  - `-trimpath -ldflags "-s -w"` **increased** detections and **did not** remove Go package paths (reflection keeps them).
  - Public **garble** / gobfuscate **increased** VT hits (CrowdStrike Falcon on garbled goffloader).
  - ML **over-indexes on `gopclntab`**: a small runtime-only table looks like minified malware; diluting with a large “ghost profile” of real-project symbols dropped **Microsoft Wacatac from ~95% to ~20%** on otherwise-identical payloads.
  - Microsoft **cloud** ML is “substantially more aggressive” than local `MpCmdRun.exe`; a 100% Wacatac VT hit can be clean locally. Models retrain on a **daily** cadence.
  - Fake MSVC Rich header / patched linker version made detections **worse** (“Don’t fight the toolchain”).
  - AhnLab `Trojan/Win.Sliver.R774471` in their Sliver pipeline was **not** protobuf: it was four **osslsigncode** certificate strings on **signed** builds (`" TLS CA"`, `-n "Application Service"`, `-i "https://support.microsoft.com"`). Unsigned variants were AhnLab-clean but lit CrowdStrike/Elastic/Symantec ML. — [Praetorian: Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/)
- Elastic’s public Sliver YARA does **not** mention `gopclntab`. Wacatac and Elastic `Multi.Trojan.Sliver` are **different detectors**.

### Inferences
- **EXE:** unsigned stock Sliver is a **stack**: (1) family YARA (`sliverpb`/protobuf) **and** (2) generic Go ML. Cleaning protobuf without changing Go PE shape leaves **Wacatac-class** risk. A tiny C host wrapping PIC can drop (2) for the **stub** and does nothing to (1) inside the blob.
- **DLL:** Formidable explicitly speculated a **launcher EXE + Go c-shared DLL** because “DLLs are scored differently from EXEs.” That is an author hypothesis, not a measured A/B.
- **`.bin`:** not a PE; Wacatac PE-ML does not apply to raw shellcode the same way. Donut/sRDI blobs are scored as **generic shellcode / DonutLoader / AMSI-patch** instead.
- Praetorian’s AhnLab `Trojan/Win.Sliver.R774471` is a **signing-template** rule, not evidence that AhnLab YARA’s on `GetJitter`.

### Gaps
- No public Microsoft feature list that says “gopclntab weight = X.” Praetorian/Formidable are the best 2026 measurements.
- No published A/B of **identical Sliver implant** as EXE vs SHARED DLL vs `.bin` under inbox MDAV PE-ML with protobuf strings stripped.

---

## Donut default AMSI patch (`Win32/AMSI_Patch_T.B13`) — is it shellcode-format specific?

### Takeaway
**Yes, it is Donut-loader-stub specific, which on stock Sliver means Windows `format=shellcode` (and any other path that embeds Donut PIC).** It is **not** a `sliverpb` string. Default Donut AMSI/WLDP bypass (**Continue = 3**) compiles a well-known `AmsiScanBuffer` patch into the PIC; MDAV names that family `Win32/AMSI_Patch_T.B13` (and `.B12` on execute-shellcode). Stock **EXE/SHARED DLL** do not include Donut. **sRDI** of a DLL (`StartW`) is a different blob and does not carry Donut’s AMSI stub.

### Cited Findings
- Donut `-b` / `bypass`: `1=None`, `2=Abort on fail`, `3=Continue on fail` **(default)**. Loader can patch AMSI, WLDP, ETW. — [TheWover/donut README](https://github.com/thewover/donut); [donut docs/devnotes.md](https://github.com/TheWover/donut/blob/master/docs/devnotes.md)
- Fortbridge: default AMSI bypass inside Sliver shellcode generation is **itself signatured**; they changed Donut bypass **3 → 1** in `server/generate/donut.go`. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- BishopFox/sliver **#1814** (opened 2024-11-10): title **`Win32/AMSI_Patch_T.B13 defender detect sliver`**. Reporter: no generate-time switch to disable the AMSI patch. Author later: “get the shellcode and patch those bytes where the check is done.” — [sliver#1814](https://github.com/BishopFox/sliver/issues/1814)
- BishopFox/sliver **#2200**: `execute-shellcode` of **Donut**-generated shellcode from a **benign C#** payload (`donut.exe -a 2 -b 1 -x 1 -e 1 -z 1`) flagged `Behavior:Win32/AMSI_PATCH_T.B12`. Same command on C++ Donut output did **not**. moloch: “upstream issue with Donut.” Note: this report used **`-b 1` (none)** and still got **B12** — so B12 is not exclusively “bypass=3.” — [sliver#2200](https://github.com/BishopFox/sliver/issues/2200)
- TheWover/donut **#165** (Dec 2024): even a **MessageBox** Donut stub started failing MDAV on inject; VT 15/61 on the stub. Maintainer attribution: **“It’s due to the AMSI bypass that is used by donut.”** Encoder (`-e`) changes did not help. — [donut#165](https://github.com/TheWover/donut/issues/165)
- Classic on-disk/AMSI **byte signature** for the x64 patch (widely documented, not Sliver-specific): `B8 57 00 07 80 C3` (`mov eax, 0x80070057; ret`). Researchers describe Defender `AMSI_Patch_T.B12` as looking at **modified `AmsiScanBuffer` prologues** (runtime) **and** the patch bytes in files/scripts. — [COFFSec: How to Identify Which Part of Your Payload Triggers Defender](https://coffsec.medium.com/how-to-identify-which-part-of-your-payload-triggers-defender-detection-25bdd95186b4); [Qalique on AMSI_Patch_T.B12](https://medium.com/@q3alique/lethe-amsi-veh-bypassing-amsi-without-patching-amsi-dll-part-3-7a208ea0708d)
- `Behavior:Win32/AMSI_Patch_T.B13` is a Defender **behavior/family** name; a consumer encyclopedia page exists but has **no byte dump**. — [HackerDose B13 page](https://hackerdose.com/malware/what-is-behaviorwin32-amsi_patch_t-b13/)
- Sliver Windows **SHELLCODE** generate uses **Donut**. SHARED_LIB → in-memory shellcode in `rpc-tasks.go` uses **`ShellcodeRDIFromBytes(..., "StartW", "")`** (sRDI), not Donut. — [BishopFox `rpc-tasks.go`](https://github.com/BishopFox/sliver/blob/master/server/rpc/rpc-tasks.go); [generate.SliverShellcode docs](https://pkg.go.dev/github.com/bishopfox/sliver@v1.7.6/server/generate)
- Donut **entropy=3** (random names + encryption, Chaskey) is the usual OPSEC setting; it encrypts the **module** so plaintext `sliverpb` may be absent from the `.bin` **file** until runtime. The **AMSI stub is in the loader**, outside that encrypted module. — [Donut README](https://github.com/thewover/donut); [bytebl33d Sliver evasion](https://bytebl33d.github.io/blog/sliver-evasion/)

### Inferences
- **EXE / DLL on disk:** `AMSI_Patch_T.B13` should **not** fire from Donut, because Donut is not in those artifacts. They still hit protobuf/export/`Go buildinf`/Wacatac.
- **`.bin` (Donut):** two independent static classes: (1) Donut **loader/AMSI stub** (B13/B12, vendor DonutLoader YARA); (2) **embedded implant** if entropy left strings in the clear or the emulator unpacks them.
- **`.bin` (sRDI of SHARED_LIB):** no Donut AMSI stub; **StartW** and PE/protobuf strings from the DLL can still be in the blob.
- B12 vs B13: both are AMSI-patch families; B13 is the name operators attached to **Sliver generate shellcode** (#1814); B12 appeared on **execute-shellcode of Donut C#** (#2200). Do not treat the suffix as a documented Microsoft mapping to a single byte pattern without a VDM extract.

### Gaps
- Microsoft has not published the B13 signature body. Fortbridge/Donut#165/sliver#1814 are the primary attributions.
- Whether inbox MDAV scans **raw `.bin`** as thoroughly as PE (some engines require a PE header) is engine-specific; Elastic/Immersive file rules often require MZ/ELF.

---

## Shared-lib exports: `StartW`, `VoidFunc`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer` — which rules cite them?

### Takeaway
**DefenderYara / Fortbridge** cite **`DllUnregisterServer`, `DllRegisterServer`, `DllInstall`, `VoidFunc`** as ASCII HSTR needles (with `GetJitter` etc.). **`StartW` is not in that nine-string list**; Fortbridge still renamed it as the **LoadLibrary/rundll32 entry**. Elastic `Multi_Trojan_Sliver` does **not** cite any of these five. Splunk’s `StartW` analytic is a **rundll32 command-line** rule aimed at Cobalt Strike, which will also see Sliver `rundll32 implant.dll,StartW`.

### Cited Findings
- Stock CLI default exports string: `"StartW,VoidFunc,DllInstall,DllRegisterServer,DllUnregisterServer"`. — [sliver generate `-v/--exports`](https://github.com/BishopFox/sliver) as quoted in this tree’s [`patches/sliver-v1.7.3/README.md`](../../patches/sliver-v1.7.3/README.md); [`backend/internal/sliverfork/generator.go`](../../backend/internal/sliverfork/generator.go)
- Source comments (Merlin-derived): `VoidFunc` for PowerSploit `Invoke-ReflectivePEInjection.ps1`; `DllInstall` for `regsvr32 /s /n /i`; `DllRegisterServer` for `regsvr32 /s`; `DllUnregisterServer` for `regsvr32 /s /u`. `StartW` is the Go-exported entry; `DllMain`/`Start` thread into it (`--run-at-load`). — [sliver#1563](https://github.com/BishopFox/sliver/issues/1563); [v1.2.1 sliver.go exports](https://github.com/bishopfox/sliver/blob/v1.2.1/sliver/sliver.go)
- Fortbridge DefenderYara ASCII: `DllUnregisterServer`, `DllRegisterServer`, `DllInstall`, `VoidFunc` (plus protobuf getters and ` Go buildinf:`). They **removed unused exports** and **renamed `StartW`**. — [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)
- Elastic public YARA: **none** of the five export names. — [Multi_Trojan_Sliver.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Sliver.yar)
- Splunk ESCU **“Suspicious Rundll32 StartW”** (`9319dda5-73f2-4d43-a85a-67ce961bddb7`): `rundll32` process with `*startw*`. Written for **Cobalt Strike**, still matches Sliver shared-lib rundll32. This is **process-creation**, not PE YARA. — [Splunk Security Content](https://research.splunk.com/endpoint/9319dda5-73f2-4d43-a85a-67ce961bddb7/)
- sRDI conversion of a Sliver DLL hardcodes export **`StartW`**. — [rpc-tasks.go `ShellcodeRDIFromBytes(fileData, "StartW", "")`](https://github.com/BishopFox/sliver/blob/master/server/rpc/rpc-tasks.go)
- Community loaders (e.g. SliverMirage README) advertise the same export set: `DllRegisterServer`, `DllUnregisterServer`, `StartW`, `VoidFunc`. — [SliverMirage README](https://github.com/daniomass/SliverMirage/blob/main/README.md)

### Inferences
- **DLL file scan:** COM export **names as ASCII + export table** are a Defender-oriented family IOC even if protobuf is garbled. `StartW` is a **generic** reflective/rundll32 name (CS overlap); it is weaker alone, stronger combined with Go PE + `sliverpb`.
- **EXE:** `//export` COM names should be absent if the shared-lib template is not compiled; Fortbridge still saw some of these on the implants they scanned (their sample offsets put COM strings near `0x16d88xx`, getters near `0x594xxx`). Treat COM names as **SHARED_LIB-primary**, getters as **all formats**.
- **`.bin`:** sRDI path **embeds `StartW` as the resolved export**. Donut of an EXE has no export table.

### Gaps
- No public YARA in Elastic/Immersive/NCSC/GCTI uses `pe.exports("StartW")` as a Sliver condition. Fortbridge is the primary citation that Defender HSTR used the COM/`VoidFunc` **strings**.

---

## Does garble (`ObfuscateSymbols`) remove protobuf strings? BishopFox #1760

### Takeaway
**No.** Garble does **not** rename protobuf-generated method/type names (`ScreenshotReq`, `).RequestResend`, `InvokeSpawnDllReq`, …). Maintainers called this a **known issue** (garble and/or the protobuf library). Custom AST obfuscation was “some of it merged into v1.6” with **no ETA** for a comprehensive fix. Issue #1760 was closed 2026-01-30; **Elastic’s public YARA still contains those strings in 2026-11** — do not read the close as “1.7.x is clean.”

### Cited Findings
- #1760 (CodeXTF2, 2024-08-16): stock `generate --http` Windows EXE beacon; Elastic public YARA matched `").RequestResend"`, `").GetPrivInfo"`, `"B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb"`, `InvokeSpawnDllReq`, `NetstatReq`, `HTTPSessionInit`, `ScreenshotReq`, `RegistryReadReq`. — [BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760)
- rkervella (member, 2024-08-16): “This is a **known issue**. Still not sure if it's a regression in Garble or if something changed in the protobuf library, or a bit of both. Either way, **Garble is not picking up the protobuf methods, which makes for easy signatures**.”
- moloch (2024-08-21): “At least the DNS ones are gone, not sure why these are showing up.”
- dalemazza (2024-12-26): “These are on **most of the Yara rules on GitHub** for sliver.”
- Cyb3r-Monk (2024-12-31): “**several Defender AV signatures detecting these strings.**”
- moloch (2025-01-06): “We've been toying with **custom AST obfuscation for the protobuf** some of it is merged into **v1.6** but it's slow going … **no ETA** on a comprehensive fix.” Issue **closed as completed 2026-01-30**.
- Earlier #833 (2022-09, v1.5.24): Defender static signature despite “dynamic code generation & compile-time obfuscation.” moloch: obfuscation is **incomplete**, intended to complicate **automated analysis**, not manual signature writing. rkervella: “garble is **missing out a bunch of stuff on the protobuf generated files**.” Later: “these are not annotations … **types and function names**, so we can't really replace them after code generation.” — [BishopFox/sliver#833](https://github.com/BishopFox/sliver/issues/833)
- Dated #481 (2021): DefenderCheck isolated **`sliverpb`** as the hit. — cited in local notes from [sliver#481](https://github.com/BishopFox/sliver/issues/481)
- Microsoft 2022: current implementations use **garble**; earlier **gobfuscate**; de-obfuscation of configs is still “fairly manual.” — [Microsoft Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Praetorian 2026: public garble **itself** can add EDR hits (CrowdStrike on garbled Go). Garble is not a free lunch even when it does rename. — [Praetorian](https://www.praetorian.com/blog/llm-edr-signature-reduction/)

### Inferences
- Stock **v1.5–v1.7.x** with default or even `--obfuscate` still ships **plaintext protobuf RPC identifiers** that Elastic, NCSC, ditekSHen, Wazuh, and (per #1760 comments) Defender key on.
- Garble **can** scramble some Go package path *segments* and literals; Elastic’s `B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb` and Immersive’s `github.com/bishopfox/` show the **module path still leaks** on the samples those rules were built from (and on #1760’s 2024 generate).
- Renaming protobuf is a **`.proto` + `make pb` + lockstep teamserver** change (Fortbridge), not an `ObfuscateSymbols` flag.

### Gaps
- What subset of protobuf AST obfuscation actually landed in v1.6/v1.7.x is not itemized in #1760. Empirical fact: Elastic strings still matched a 2024 generate, and the public YARA file is unchanged as of this fetch.

---

## Inventory: exact identifiers by format (stock v1.5–v1.7.x)

### Takeaway
Almost every public **file** detector is a **string or CMP-immediate** on the Go implant image. EXE and DLL share the protobuf/package/Go-runtime set; DLL adds COM/`VoidFunc`/`StartW`; Donut `.bin` adds the **AMSI stub** and can **subtract** plaintext protobuf if entropy=3 holds (until unpack). Generic Go ML is **EXE-primary**.

### Cited Findings — identifier table

| Identifier | Kind | Cited by | EXE | SHARED DLL | Donut `.bin` | sRDI `.bin` |
| --- | --- | --- | --- | --- | --- | --- |
| `github.com/bishopfox/sliver/protobuf/sliverpbb` / `…sliverpbb.` / `B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb` | Go package path | Elastic `$a1`; ditekSHen `$x1`; #1760 | Y | Y | if plaintext | if plaintext |
| `github.com/bishopfox/` / `github.com/bishopfox/sliver/` | module path | Immersive; Wazuh `$s3` | Y | Y | if plaintext | if plaintext |
| `/sliver/` | path | NCSC `$p1`; Wazuh `$s2` | Y | Y | if plaintext | if plaintext |
| `sliverpb` / `sliverpb.` | protobuf package | Immersive; NCSC `$p2`; Wazuh `$s1` | Y | Y | if plaintext | if plaintext |
| `).RequestResend` `).GetPrivInfo` `).GetReconnectIntervalSeconds` `).GetPivotID` | protobuf getters | Elastic 42298c4a | Y | Y | if plaintext | if plaintext |
| `name=PrivInfo` `name=ReconnectIntervalSeconds` `name=PivotID` | protobuf `name=` tags | Elastic 42298c4a | Y | Y | if plaintext | if plaintext |
| `InvokeSpawnDllReq` `NetstatReq` `HTTPSessionInit` `ScreenshotReq` `RegistryReadReq` | RPC messages | Elastic 3bde542d; #1760 | Y | Y | if plaintext | if plaintext |
| `RevToSelfReq` `IfconfigReq` `SideloadReq` `InvokeMigrateReq` `KillSessionReq` `ImpersonateReq` `NamedPipesReq` | RPC messages | NCSC `$fn*` | Y | Y | if plaintext | if plaintext |
| `.BackdoorReq` `.ProcessDumpReq` `.InvokeSpawnDllReq` `.SpawnDll` `.TCPPivotReq` `.WGTCPForwarder` `.WGSocksServerR` `.PivotEntryR` `.PortfwdProtocol` `.commonpb.ResponseR` | protobuf types | ditekSHen / Malpedia | Y | Y | if plaintext | if plaintext |
| `GetJitter` `GetKill` `AddTunnel` `GetIsIOC` | getters / methods | Fortbridge DefenderYara | Y | Y | if plaintext | if plaintext |
| `DllUnregisterServer` `DllRegisterServer` `DllInstall` `VoidFunc` | `//export` ASCII | Fortbridge DefenderYara | maybe | **Y (exports)** | rare | **StartW path** |
| `StartW` | export | Fortbridge rename; sRDI; Splunk rundll32 | no | **Y** | no | **Y** |
| ` Go buildinf:` | Go runtime | Fortbridge DefenderYara | Y | Y | if plaintext | if plaintext |
| `chacha20poly1305` | crypto lib | Immersive | Y | Y | if plaintext | if plaintext |
| `gopclntab` / Go PE shape | ML feature | Formidable; Praetorian | **Y (Wacatac)** | maybe | N/A (not PE) | N/A |
| CMP `http`/`https`/`dns`/`wg`/`mtls`/`tcppivot`/`namedpipe` | scheme switch | GCTI; Wazuh `$p*` | Y | Y | if code present | if code present |
| Elastic session-start/register bytecode | compiler pattern | Elastic 3d6b7cd3 | Y | Y | if unpacked | if unpacked |
| Donut AMSI stub / `B8 57 00 07 80 C3` class | Donut loader | #1814 B13; donut#165; Fortbridge 3→1 | no | no | **Y (default -b 3)** | no |
| Canary FQDN | plaintext domain | Immersive | if enabled | if enabled | if plaintext | if plaintext |

### Inferences
- **Stock EXE** is a 16–30 MB unsigned Go PE: family YARA **and** Wacatac-class ML. That is the default `generate` output.
- **Stock DLL** is the same image plus **export-table IOCs** that DefenderYara and rundll32/regsvr32 analytics use. Disk `LoadLibrary` of this file is still a **file scan** of those strings (Fortbridge had to rename them before disk load worked).
- **Stock Donut `.bin`** trades protobuf-on-disk for **Donut-stub-on-disk** unless bypass=1 **and** entropy hides the module **and** the scanner does not emulate. It is not “clean”; it is a **different signature surface**.
- **sRDI `.bin`** is closer to a **flattened DLL**: `StartW` + PE/protobuf strings, no Donut AMSI stub.

### Gaps
- No public 2025–2026 MDAV detection-rate table for the three formats of the **same** 1.7.x implant.
- Exact current VDM contents for `Trojan:Win64/Sliver.D` remain closed-source; Fortbridge’s nine ASCII strings are the best open mapping.

---

## Cross-cutting PE / ML / vendor names (not string YARA)

### Takeaway
Inbox MDAV has a **named Sliver family** (`Trojan:Win64/Sliver.D`, Splinter/ALF) **and** generic Go ML (`Wacatac.B!ml`) **and** a Donut AMSI family (`AMSI_Patch_T.B13`). Elastic’s public name is `Multi.Trojan.Sliver`. Kaspersky uses `Trojan.Win64.Sliver.*`. AhnLab `Trojan/Win.Sliver.R774471` in Praetorian’s work was a **cert template**, not implant protobuf.

### Cited Findings
- Microsoft WDSI: `Trojan:Win64/Sliver.D` (2021-11-26 / 2022-08-29), plus `ALF:Trojan:Win32/Sliver.A`, `ALF:Trojan:Win32/SliverServer.A`, `VirTool:Win64/Splinter.A`. — [WDSI](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Sliver.D)
- Microsoft blog appendix also: `Trojan:Linux/Sliver.A`, `TrojanDownloader:PowerShell/Splinter.A`, `Behavior:Win32/Splinter.A`, `VirTool:Win32/SPLINTER.A`. — [Microsoft 2022](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Kaspersky catalog families `Trojan.Win64.Sliver.rr` / `.ht` / `.io` (generic family page, no public YARA). — [Kaspersky Trojan.Win64.Sliver.rr](https://threats.kaspersky.com/en/threat/Trojan.Win64.Sliver.rr/)
- Typical size: ~16 MB (Immersive) to ~30 MB (Fortbridge) — a static visibility feature (hard to hide, easy to notice in downloads).
- BishopFox: AV evasion out of tree. — [Anti-virus Evasion.md](https://github.com/BishopFox/sliver/blob/master/docs/sliver-docs/pages/docs/md/Anti-virus%20Evasion.md)

### Inferences
- A stock Windows EXE can be labeled **family** (Sliver/Splinter), **generic ML** (Wacatac), or **both**. VT vendor names are not a substitute for which **engine** fired (inbox vs cloud vs MDE).
- Signing can **add** signatures (Praetorian AhnLab) while helping SmartScreen — a file-scan tradeoff, not a protobuf fix.

### Gaps
- Live 2026 `mpengine` may have additional unpublished HSTR beyond Fortbridge’s 2025 extract. Extracted DefenderYara **lags the cloud**.
