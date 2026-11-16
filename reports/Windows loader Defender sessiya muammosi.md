# Unique hash sessiyani saqlamaydi

**Windows wrap EXE “yaxshi ishlamayapti” degan shikoyat ikki alohida sinfni aralashtiradi: (A) Defender o‘chiq laboratoriyada ham sessiya umuman ochilmaydi — format, C2, GUI+1.8s, beacon sahifasi yoki `CALL` dan keyin Go `main` chiqishi; (B) beacon orqali callback bo‘lgach Defender jonli implantni yopadi — XOR, unique SHA-256, RW→RWX, CreateThread yo‘q, hide-console va sandbox sleep allaqachon sarflangan qatlam.** Unique SHA-256 **aniq-hash IOC** ni uradi, Defender bypass emas: cloud ML, emulator, Block at First Sight va xotira skaneri hashni verdict sifatida emas, **kesh** sifatida ishlatadi ([Microsoft Learn: Advanced technologies of MDAV](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)). Ildiz sabab (A) da host trampoline PIC qaytsa jarayonni o‘ldiradi va wrap C2/formatni tekshirmaydi; (B) da decrypt qilingan **16–30 MB Go implant** `sliverpb`, protobuf RPC nomlari va `Go buildinf` bilan xotirada ochiq yotadi, `interactive` esa yangi fayl emas — **shu PID ichidagi goroutine** ([Fortbridge: Reforging Sliver](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [Sliver Tutorials: Beacons vs Sessions](https://sliver.sh/tutorials/?name=2+-+Beacons+vs+Sessions)). VeryLazyTech qo‘llanmasi static → emulator → behavior **qatlam ro‘yxati**, FUD retsepti emas ([VeryLazyTech: Antivirus bypass](https://www.verylazytech.com/windows/antivirus-av-bypass)). Mahsulotda FUD da’vosiz ish: hostni `jump` dan keyin tirik tutish, lab diagnostika, `format=shellcode` + `StartW`, mos listener; in-tree Donut/ScareCrow va “0/70” checkbox qayta ochilmaydi. BishopFox AV evasion ni Sliver doirasidan tashqariga qo‘yadi ([Sliver Docs: Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion)).

## (A) Sessiya ochilmasligi ko‘pincha trampoline va C2, Defender emas

Defender o‘chiq VM da “run qildim, sessiya yo‘q” degan natija avvalo **to‘g‘rilik va operator paketi** sinfidir. Wrap `POST /api/loaders/build` PIC baytlarini kutadi: Windows `format=shellcode` Donut PIC (`48 83 E4 F0` stack-check, `MZ` emas); `format=shared` esa DLL, default export `StartW`. Wrap tab `rdi` / `function_name` yubormaydi; backend `MZ` ko‘rsa `ShellcodeRDI` ni **bo‘sh** `FunctionName` bilan chaqiradi. sRDI `DllMain` ni ishlatadi, keyin hash `0x10` (bo‘sh nom) bo‘yicha export qidiradi; Sliver `DllMain` `RunAtLoad=false` da `CreateThread(Start)` qilmaydi, `StartW` topilmaydi, stub `RET` qiladi — jarayon ~2 soniyada o‘ladi, callback yo‘q ([BishopFox srdi.go](https://github.com/BishopFox/sliver/blob/v1.7.3/server/generate/srdi.go); [monoxgas/sRDI](https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c); [implant main.c](https://github.com/BishopFox/sliver/blob/v1.7.3/implant/sliver/main.c)). `format=exe` ni wrap qilish sRDI ni EXE ustida ishlatadi; to‘g‘ri konverter Donut (`format=shellcode`). Intended yo‘l: Implants da `os=windows`, `format=shellcode`, jonli listener C2 → Loaders → Build EXE.

Ikkinchi tuzoq **C2 generate da pishiriladi**, wrap da emas. UI default `https://127.0.0.1:443`; bo‘sh C2 ro‘yxati backend da `mtls://127.0.0.1:8888` ga tushadi. Windows mehmonida `127.0.0.1` teamserver emas. `https://host:443` `mtls :8888` jobiga mos kelmaydi; Loaders `matchC2Job` chaqirmaydi. Compile muvaffaqiyati callback emas. Uchinchi tuzoq: `is_beacon=true` callback ni `/beacons` ga yozadi, `/sessions` ga emas; default interval 60s + 20% jitter — faqat Sessions ni tomosha qilish “sessiya ochilmayapti” ni yasaydi. To‘rtinchi: hide-console default **on** (`-H windowsgui`); Windows da bu daemon emas, faqat oyna yo‘q. Stub `Sleep(1800)` + `GetTickCount` delta `< 1400` bo‘lsa `os.Exit(0)` (emulator skip); 1 GiB dan kam RAM ham `os.Exit(0)`. Operator 1 soniyada “ishlamadi” deydi. Persistence `run()` ni to‘xtata olmaydi — bu sinfni tashlab yuboring.

Beshinchi, mahsulot bug‘i: `jump_windows_amd64.s` `CALL AX` qiladi, PIC qaytsa Go stackni tiklaydi va `RET` — `run()` → `main` → `ExitProcess`, barcha in-process threadlar o‘ladi. Linux trampoline `exit_group` qiladi; Windows qilmaydi. UI Donut `Thread` ni qo‘ymaydi (protobuf nol → in-line entry); `runner.Main()` loop ishlasa `CALL` qaytmaydi. PIC qaytadigan holatlar — bo‘sh-export RDI, EXE-via-RDI, Donut `EXIT_THREAD` qisqa payload — **Defender o‘chiq** da ham sessiya yo‘q. BishopFox: jarayon tugasa loader kodingizda bug bo‘lishi mumkin ([sliver#1410](https://github.com/BishopFox/sliver/issues/1410)). Donut `-x 3` (block indefinitely) generator tomoni; stub `jump` dan keyin qaytmasligi kerak ([TheWover/donut](https://github.com/TheWover/donut)). Wine testi `xor eax,eax; ret` + `SLIV_BG=1` — trampoline ABI, Windows sessiya testi emas.

Oltinchi shox **Defender 1116/1117**: jarayon <1s da yo‘qoladi, fayl karantinda, Protection History da threat nomi. 1116 aniqlash, 1117 harakat (Quarantine/Remove/Block jarayonni o‘ldiradi); 1015 behavior; ASR 1121/1122 — 1116 emas ([Microsoft Learn: Defender event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)). 1116 yo‘q, jarayon ~2.0s da o‘lsa — bu (A), Defender emas.

**Qaror daraxti (bir o‘zgaruvchini o‘zgartiring).** Avval implant qatori: OS / Arch / Format / C2 URL / IsBeacon / limits. Format `SHELLCODE` bo‘lishi kerak; `SHARED` uchun Tools da `StartW` bilan RDI, keyin wrap (ikkinchi RDI yo‘q); `EXECUTABLE` ni wrap qilmang. Jobs da protocol+port mosligi. C2 host Windows qutisidan yetarli (`127.0.0.1` faqat teamserver o‘sha OS da). Beacon bo‘lsa `/beacons`, interval×(1+jitter) kutish. Hide-console labda o‘chiq qiling. Task Manager + Wireshark `host <c2> and port <c2>` + Event Viewer `Microsoft-Windows-Windows Defender/Operational`.

```
t = 0..3s, jarayon yo'q, fayl yo'qolgan, 1116+1117
  → Defender on-access/BAFS (simptom 1, lekin (A) to'g'rilik emas).
  → Trampoline ABI misteriyasi emas; Protection History Name ni yozing.

t = 0..0.5s, jarayon yo'q, 1116 YO'Q, fayl diskda
  → enoughRAM (<1 GiB) yoki noto'g'ri arch / ishga tushmadi.
  → SLIV_BG=1 (lab) RAM+sleep ni o'tkazadi.

t ≈ 2.0s, jarayon yo'q, 1116 YO'Q, fayl diskda
  → pause() tugadi; PIC qaytdi yoki VirtualAlloc fail.
  → Eng ehtimol: SHARED bo'sh-export RDI yoki EXE-via-RDI.
  → Tuzatish: format=shellcode, yoki RDI function_name=StartW.

t > 5s, jarayon TIRIK, 1116 yo'q
  → Stub qaytmadi. Wireshark:
       paket yo'q → limits.ExecLimits, Donut/Go osilishi, yoki 127.0.0.1 guest.
       to'g'ri host:port, UI yo'q → protocol/profile/cert, yoki /beacons, yoki noto'g'ri server.
       TLS 443, job mtls 8888 → C2 sinfi.

t > 5s, jarayon tirik, paketlar OK, UI bo'sh
  → Beacon sahifasi / interval; Events.
```

| # | Bitta o‘zgaruvchi | Kutiladigan natija |
|---|---|---|
| A | windows/amd64 **shellcode**, C2 = jonli https host (na `127.0.0.1`), is_beacon **off**, wrap, run | `/sessions` da qator **agar** Defender ruxsat bersa; jarayon qoladi |
| B | Xuddi shu, is_beacon **on** | `/beacons` intervaldan keyin, Sessions emas |
| C | **shared** wrap, Tools RDI export yo‘q | ~2s o‘lim, callback yo‘q |
| D | Tools RDI `StartW`, keyin wrap | Jarayon qoladi (Defender ruxsat bersa) |
| E | C2 https:443, faqat mtls:8888 | Jarayon qolishi mumkin; sessiya yo‘q; Wireshark 443 |
| F | C2 `127.0.0.1` guest VM dan | Loopback paketlar; teamserver yo‘q |
| G | VM RAM 512 MB | Darhol chiqish; 1116 yo‘q |
| H | Jonli Defender, default siyosat | 1116/1117; <1s; fayl karantin |
| I | Hide-console off | Shu umr; Go panic ko‘rinadi |

Bu daraxt shu tadqiqotda Windows 11 da end-to-end detonatsiya qilinmagan; sRDI bo‘sh export **manba** dan chiqarilgan, Procmon izi yo‘q. Agar (A) Defender-off da yiqilsa, AV haqida gapirmang — loader/C2 bug.

## (B) Callback dan keyin o‘ldirish: loader hiylasi allaqachon sarflangan

Beacon check-in bo‘lsa, wrap o‘z ishini qilgan: stub ishga tushdi, blob decrypt bo‘ldi, PIC yugurdi. Keyin Defender nima o‘qiydi? **Diskdagi unique hash emas** — jarayon xotirasidagi to‘liq Go implant. Immersive: packing qanday bo‘lmasin, butun Go binary xotiraga ochiladi; o‘rtacha ~16 MB, Fortbridge da 30 MB gacha ([Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)). Elastic `Multi_Trojan_Sliver` `scan_context = "file, memory"`: `ScreenshotReq`, `HTTPSessionInit`, `RequestResend`, `GetPrivInfo`, `github.com/bishopfox/sliver/protobuf` ([Multi_Trojan_Sliver.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Sliver.yar)). Immersive xotira qoidasi faqat `sliverpb`. Fortbridge DefenderYara: `DllUnregisterServer`, `GetJitter`, `VoidFunc`, `AddTunnel`, `GetIsIOC`, `Go buildinf:`. Garble protobuf metodlarini o‘zgartirmaydi; maintainer “several Defender AV signatures detecting these strings” ([BishopFox/sliver#1760](https://github.com/BishopFox/sliver/issues/1760); [The DFIR Report](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/)).

`interactive` / UI Open Session **yangi implant generate qilmaydi**. Rasmiy tutorial: session loop **shu beacon jarayonida goroutine**. UI `OpenSessionFromBeacon` `C2S: []`, `Delay: 0`. Yangi PE faqat alohida `generate` + `execute` / `sideload` / `execute-shellcode` / `migrate` da paydo bo‘ladi — bu Microsoft 2022 dan beri hujjatlagan `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread` zanjiri, MDE “A process was injected with potentially malicious code”, default qurbon `notepad.exe`, GetSystem → `spoolsv.exe` ([Microsoft: Sliver lining](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/); [Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver)). Stock `interactive` fork&run emas; ASR “Office injecting” qoidasi Word/Excel uchun, generic CRT ni default o‘chirmaydi ([ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)). Session o‘lsa, odatda **shu PID** o‘ladi — beacon ham ketadi.

Inbox MDAV (`MsMpEng`) MDE litsenziyasisiz ham ishga tushgan tahdidni to‘xtatadi: client behavioral blocking process tree ni cloud ML ga yuboradi va **running artifact** ni block qiladi. Nomlar MITRE taktika: `Behavior:Win32/CommandAndControl.*!ml`, `DefenseEvasion`, `PrivilegeEscalation`. Event **1015** behavior, 1116/1117 oila/hash. MDE (`MsSense`) qo‘shilsa portal alert va EDR-in-block-mode (default off) mahalliy 1117 siz ham o‘ldirishi mumkin ([Client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking); [Behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)). `Get-MpComputerStatus` `OnboardingState` / `AMRunningMode` qaysi stack ishlaganini aytadi.

Xotira skaneri client funksiya: “no cloud counterpart for the memory-scanning engine” ([adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav)). Unique loader SHA-256 RTP, scheduled scan, Intel AMS va YARA `file, memory` ni chetlab o‘tmaydi. Fortbridge “lack of sleep mask” ni idle implantni oson YARA qilish sababi deb yozadi. Stock Sliver Ekko ship qilmaydi; moloch Go runtime tufayli qiyin; PR #1805 merge bo‘lmagan ([Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171); [PR #1805](https://github.com/BishopFox/sliver/pull/1805)). Interactive session **uyg‘oq** (long-poll) — sleep-encrypt operator ishlayotgan oynani yopmaydi, ya’ni shikoyatdagi oyna.

Tarmoq: default HTTP `.woff` stager, `.html` key exchange, `.js` long-poll, `.php` session, `.png` close, nonce encoder. Bu UI allaqachon yozadi: “This still looks like default Sliver to public detectors” ([Sliver HTTPS C2](https://sliver.sh/docs/?name=HTTPS+C2); [Immersive Labs](https://www.immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)). moloch: HTTPS server JARM random, lekin operator tanlamaydi; mTLS Go fingerprint; Windows da `wininet` client fingerprint ([sliver#1809](https://github.com/BishopFox/sliver/issues/1809)). Loader XOR kompilyatsiya qilingan pathlarni qayta yozmaydi. Beacon→session ulanish umrini oshiradi — `Behavior:Win32/CommandAndControl` klassifikatoriga qo‘shimcha signal.

Encrypt-in-loader Fortbridge da Elastic+Defender ga **samarasiz** edi; ishlagan yo‘l protobuf/export/string tozalash + **diskdan LoadLibrary**, VirtualAlloc unbacked shellcode emas. Keyin ham built-in buyruqlar Elastic behavior ni tetikladi. Module stomping 30 MB Go uchun tashlandi. 2025–2026 omma yozuvlari “unique Go wrap SHA-256” ni yetarli deb yozmaydi; custom stub, Donut AMSI patch **off**, skip-symbols + tashqi packer, HTTP profile, yoki Sliver fork ([bytebl33d](https://bytebl33d.github.io/blog/sliver-evasion/); [BallisKit](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19)).

**Telemetriya (lab, FUD emas):** Protection History **Name**, Operational **1006, 1015, 1116, 1117, 1118, 1119**, ASR bo‘lsa 1121/1122, Detection Source/Type/Path/Process/Action, `Get-MpComputerStatus`. MDE bo‘lsa Sense Operational + portal. Nom maydoni aytadi: oila YARA vs `Behavior:Win32/…` vs ASR. Aniq `Trojan:Win64/Sliver.*` katalogi ommaviy emas; citable hitlar Elastic `Multi.Trojan.Sliver`, `Behavior:Win32/AMSI_PATCH_T.B12` / `Win32/AMSI_Patch_T.B13` ([sliver#2200](https://github.com/BishopFox/sliver/issues/2200); [sliver#1814](https://github.com/BishopFox/sliver/issues/1814)). Folklore nomlar `Exploit:Win32/ShellCode`, `Behavior:Win32/AllocatedAndExecute`, `VirTool:Win32/OffensiveGo` shu pass da Microsoft Learn da topilmadi — Protection History dagi **aynan shu qator** ni yozing.

## XOR, unique hash, RWX, CreateThread yo‘q — hash qatlami, xotira emas

Windows stub `windowsSource()` / `Build()`: `GOOS/GOARCH CGO_ENABLED=0`, `-s -w`, ixtiyoriy `-H windowsgui`, unique `-buildid`. `main`: `hideWindow` → `enoughRAM` (1 GiB) → `pause` (1.8s) → `persist` → `run`. `run`: `VirtualAlloc` `PAGE_NOACCESS` keyin RW commit, `cfg.dat` chunk copy, XOR (`combinedXORKey` + 16-byte nonce), `VirtualProtect` **RWX `1<<6`** (qoladi), `FlushInstructionCache`, 8 MiB RW stack, `LockOSThread`, `SetGCPercent(-1)`, `jump`. API nomlari `\xHH` + `ds()`; Go runtime IAT da `kernel32.dll` / `VirtualAlloc` / `CreateThread` qoladi. `mintUniqueness`: nonce, 4–24 KiB `n.bin`, random `NameKey`, `-buildid` — SHA-256 har build o‘zgaradi. Bu **hash-IOC**. Cloud ML yangi unsigned Go PE + yuqori-entropy embed ko‘radi.

Microsoft arxitekturasi polymorphic / first-seen PEni **feature, emulation, detonation, behavior** bilan sinflaydi; hash verdictni keshlaydi ([adv-tech-of-mdav](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav); [Cloud protection](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission)). BAFS Internet-zona EXE ni default **10s** (60s gacha) lock + sample detonation ([Block at first sight](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus)). `.exe` “safe sample”; metadata `SubmitSamplesConsent=2` da ham ketadi. Stimpson logida bir dasturchi PCdan ~3 oyda **217** sample, shundan **201** bir xil unpublished Go test — Event 2050 ([Privacy Affairs](https://www.privacyaffairs.com/microsoft-defender-sample-submission/)). SmartScreen unsigned hashni noldan boshlaydi, “unknown ≠ trusted”; EV cert endi instant reputation bermaydi ([SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)). Praetorian 2026: Go hitlar `Wacatac.B!ml` / `ML.Attribute.HighConfidence`; `-s -w` **oshirdi**; `gopclntab` ML og‘irligi; fake Rich header yomonlashtirdi ([Adversarial Oracles](https://www.praetorian.com/blog/llm-edr-signature-reduction/)). Formidable: **benign** Wails+Go GUI `Trojan:Win32/Wacatac.B!ml`, to‘rt sandbox 0 dynamic ([Formidable](https://formidable.tools/posts/defender-wacatac-go-binary/)). XOR entropy ni tushirmaydi; qisqa kalit oshirishi ham mumkin.

ETW-Ti `ALLOCVM` / `PROTECTVM` ni `CreateThread` siz ham yozadi ([EtwTiViewer](https://github.com/adanto/EtwTiViewer); [Elastic: Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)). Elastic `unbacked_rwx`, `execute_shellcode`, `sensitive_api` — call-stack, thread-create emas. gatari 2024: XOR diskni o‘tdi, **RWX + to‘g‘ridan-to‘g‘ri CALL** runtime da o‘ldirildi; VT upload butun hashni known-bad qildi ([A Trip Down Memory Lane](https://gatari.dev/posts/memory-lane/)). CreateThread skip Sysmon 8 va tarixiy CRT scan trigger ni kamaytiradi; 2025–2026 kernel+memory+behavior ni emas. RWX Donut/SGN self-mod uchun testlar talab qiladi (`1<<6`) va **oshiradi** unbacked-exec signalini. PEzor `-rx` SGN bilan nomuvofiq ([PEzor README](https://github.com/phra/PEzor)). PAGE_NOACCESS-first BorderGate 2022 CRT race (eski); Elastic `hidden_code`. 24H2 “AMSI heap scanning” Microsoft Learn da yo‘q; AMSI hostlari PowerShell/.NET/Office — **native Go EXE yo‘li emas** ([AMSI on MDAV](https://learn.microsoft.com/en-us/defender-endpoint/amsi-on-mdav)). Native loaderga AMSI patch qo‘yish IOC; r-tec 2025: `AmsiScanBuffer` patch Defender jarayonni o‘ldiradi ([r-tec](https://www.r-tec.net/r-tec-blog-bypass-amsi-in-2025.html)). Default Donut AMSI/WLDP continue-on-fail o‘zi signature: `Win32/AMSI_Patch_T.B13`, Elastic AMSI/WLDP patching, `Behavior:Win32/AMSI_PATCH_T.B12` ([Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [donut#165](https://github.com/TheWover/donut/issues/165); [sliver#1759](https://github.com/BishopFox/sliver/issues/1759)). 1.8s Sleep mpengine emulator byudjetiga qarshi 2018 o‘yin; cloud detonation real OS, PEzor misoli **120s**. Hide-console EDR ni yashirmaydi.

| Hiyla (ship) | Qaysi detection sinfiga tegishi mumkin | Nima ga tegmaydi |
|---|---|---|
| XOR embed + nonce | Ichki blob aniq-hash, diskdagi ba’zi string YARA | Decrypt dan keyin xotira; PE ML; behavior |
| Unique `-buildid` / `n.bin` | Aniq fayl hash | Sandbox, ML, xotira YARA, BAFS detonation |
| `ds()` API nom XOR | Stub manbasida `VirtualProtect`/`schtasks` plaintext | Go runtime IAT; ETW-Ti; WdFilter |
| `PAGE_NOACCESS` → RW → decrypt | Ba’zi heap/emulator commit qilmasa | `VirtualProtect` RWX ETW-Ti; `hidden_code` |
| CreateThread yo‘q, private stack `CALL` | User-mode CRT start-address; Sysmon 8 | Unbacked executable; ETW-Ti ALLOC/PROTECT; implant stringlar |
| Sleep 1.8s + tick | Sleep ni skip qiladigan qisqa emulator | Cloud sandbox; jonli Defender; 60–120s detonation |
| RAM ≥ 1 GiB | Kichik emulator VM | 8+ GiB lab PC; Defender content process |
| Hide-console / `windowsgui` | Foydalanuvchi oynasi | EDR, xotira, C2 |
| Persistence (default off) | Reboot umri | Defender; T1547/T1053 artefact **qo‘shadi** |
| RWX (`1<<6`) | Donut/SGN yozishi shart | Behavioral RWX / unbacked-exec signalini **oshiradi** |

**Qolgan halollik:** Wine `ret` Windows sessiya emas. Compile ≠ callback. Unique hash ≠ VirusTotal 0/70. Persistence/hide-console jonli implantni Defenderdan saqlamaydi. README Go runtime da `VirtualAlloc`/`CreateThread`/`kernel32.dll` qolishini tan oladi.

## VeryLazyTech qatlamlari: bor, arzon, tashqarida

[VeryLazyTech AV bypass](https://www.verylazytech.com/windows/antivirus-av-bypass) lab metodologiya, “shu bilan Defender FUD” va’dasi emas. U bizning mavjud halol copy bilan bir xil qatlamlarni sanaydi: payloadni yashirish, string, unique tool, sleep, RAM, sandbox nom, DLL form factor, sideload, syscall/Freeze, AMSI/ETW, SmartScreen. Qo‘llanma **decrypt qilingan 16–30 MB Go image**, `Behavior:Win32/CommandAndControl`, yoki Donut/RDI `CALL` ga `RET` qilganda process exit ni tuzatmaydi.

| Qo‘llanma bandi | Bu Windows loaderda | Ikki simptomga mosligi |
|---|---|---|
| Encrypt payload, runtime decrypt | Ha — XOR `cfg.dat` | Ichki blob **static hash**. Decrypt dan keyin RWX da plaintext. Jonli sessiyani saqlamaydi. |
| Obfuscate strings | Qisman — API `\xHH`; Go runtime stringlar qoladi | Go/`sliverpb` xotira YARA ga zaif |
| Custom tool (public signature yo‘q) | Qisman — har build unique hash | First-seen baribir cloud-sandbox ([BAFS](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus)) |
| Sleep before exec | Ha — 1.8s + GetTickCount | Qo‘llanma misoli **60s**. 1.8s faqat emulator. Cloud detonation uchun qisqa |
| Low-RAM exit | Ha — 1 GiB | Qo‘llanma 2 GiB. Oshirish arzon |
| Sandbox nom `HAL9TH` | **Yo‘q** | Arzon T1497.001; Saint Bot `HAL9TH` ([MITRE T1497.001](https://attack.mitre.org/versions/v19/techniques/T1497/001)). Jonli Defender bypass emas. `MP_FORCE_USE_SANDBOX` boshqa narsa ([Learn](https://learn.microsoft.com/en-us/defender-endpoint/sandbox-mdav)) |
| ThreatCheck (bad bytes) | **Yo‘q (operator lab)** | Disk flag bo‘lsa keyingi diagnostika ([rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/threatcheck)). UI dan shell out qilmang |
| DLL ni EXE dan afzal | Faqat **EXE** chiqaramiz | Havoc VT 7/26 vs 4/26 shu hostdagi Defender emas. Sideload kuchliroq form factor |
| DLL sideload + SharpDllProxy | **Yo‘q** (in-tree ScareCrow-class rad) | Disk OPSEC uchun tashqi yo‘l |
| Freeze (suspended + direct syscalls) | **Yo‘q** | Public Go syscall stublar tez eskiradi. In-tree Donut/ScareCrow bilan bir sinf — **tashqarida** |
| defendnot / Set-MpPreference | **Yo‘q, tashqarida qolsin** | AV ni o‘chiradi, admin, Tamper Protection. Loader feature emas |
| AMSI patch / amsiInitFailed | **Native Go EXE uchun N/A** | AMSI PowerShell/.NET/Office. Native Go o‘tadi. **Donut stub** default bypass=3 signature ([Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)) |
| ETW `EtwEventWrite` RET | Stub da yo‘q; Donut qilishi mumkin | User-mode. Kernel ETW / WdFilter qoladi |
| SmartScreen / MoTW / ISO | Yetkazib berish, compile emas | EXE allaqachon yugursa ahamiyatsiz |
| Fork&run vs inline .NET | **Simptom 2 ni tushuntiradi** | `execute-assembly` notepad CRT — Microsoft ovlaydi. Stock `interactive` **inline same process** |

**Allaqachon bor:** XOR-at-rest, unique hash (hash-IOC copy bilan), qisqa sleep+tick, 1 GiB RAM, hide-console, RWX `CALL`, HTTP C2 sahifa + default-fingerprint ogohlantirish, beacon checkbox, Obfuscate/Evasion (compile-time, bypass emas).

**Arzon / scope ichida:** `HAL9TH` (va o‘xshash) sandbox nom — emulator, jonli Defender emas; tick anti-skip saqlab operator kutishini uzaytirish (cloud “o‘tadi” deb yozilmasin); ThreatCheck ni operator lab appendix; `format=shellcode` + hostni `jump` dan keyin tirik tutish; auto-RDI ga `StartW`; Loaders da `matchC2Job` + IsBeacon; lab console preset; Implants port auto-fill (`8888`-only, default `443` — product bug); Donut **Bypass=1** va wrap uchun **ExitOpt=3** ni native flag sifatida ulash (patch yozish emas — signatured patch ni **o‘chirish**).

**Tashqarida / qayta ochilmaydi:** defendnot, in-tree Freeze, native Go EXE da AMSI patch, in-tree Donut CLI, ScareCrow, VT widget, Implants “FUD encrypt”, silent watchdog “AV heal”, UnDefend/BYOVD, module stomping (Fortbridge 30 MB da yiqildi), wrap ichida sleep-mask.

## Mahsulot: hostni tirik tuting, yashirin chiqishni oching, FUD ni yopiq qoldiring

Muvaffaqiyat metriksi allaqachon tanlangan: **kamroq noto‘g‘ri paket**, VT ball emas. Wrap — lab qulayligi, crypter do‘koni emas. Havoc jumlasi: agent evasive deb yozilmagan, tashqi loader kutiladi ([Havoc Agent](https://havocframework.com/docs/agent)).

**A — Defender-off da sessiyani ko‘rsatish (birinchi; simptom 1).** Lab log: `enoughRAM`, sleep delta, `VirtualAlloc` addr, `VirtualProtect`, “calling shellcode”, “shellcode returned — host will exit”. Bugun `pause` / `enoughRAM` / `run` yutib yuboradi. Hide-console on da `os.Exit(0)` breadcrumb siz bo‘lmasin (lab: `%TEMP%\sliv-loader.log`). Loaders `matchC2Job` hard-warn + C2 URL. Tanlangan build `IsBeacon` + interval; toast “Watch **Beacons**, not Sessions”. Auto-RDI `function_name=StartW`; EXE-as-PIC ni rad etish; truncated-PE 400 qolsin. “Lab verify” preset: hide-console **off**. Port auto-fill ni `8888`-only dan tuzatish. Checklist: debug implant, mos listener, 2× beacon interval. “Continue in Loaders” da shellcode tomon prompt (EXE defaultni jim o‘zgartirmang). **Trampoline:** PIC qaytsa ham host o‘lmasin (block / `Wait` / `exit_group` analogi); Linux allaqachon `CALL` dan keyin chiqadi, Windows `RET` qiladi — shu farq (A) ni yasaydi. A yiqilsa, bu **loader/C2 bug**, AV teshigi emas.

**B — threat nomlari (simptom 2 va Defender-on 1).** UI runbook, VT widget emas: Protection History, `Get-MpThreat`, 1116/1015, `MpCmdRun -Scan`. Xarita: `AMSI_PATCH_*` → Donut Bypass=1; protobuf / `Multi.Trojan.Sliver` → Sliver fork (tashqi); generic injection/behavior → RWX/unbacked/CRT. ThreatCheck tashqi appendix; UI hostdan shell out yo‘q.

**C — ixtiyoriy, dalil bilan.** C1: generate da Donut Bypass=1 + wrap ExitOpt=3 — native, halol yorliq. C2: `format=shared` uchun disk `LoadLibrary` stub (Fortbridge muvaffaqiyat yo‘li), yorliq “disk DLL; still unsigned; still needs string-clean implant”; spike kerak — Fortbridge namunasi kichik C, Go runtime host baribir shovqinli. C3: operator kutishi 0 (lab) yoki 10–120s, copy “cloud MDAV kutadi”. C4: encoder NONE da RX — tadqiqot, SGN bilan hech qachon. C5–C7: stomping / sleep-mask / wrap AMSI-ETW patch — **qilmang**. C8: sideload shablon+docs, in-tree ScareCrow emas.

**D — FUD hech qachon.** In-tree Donut CLI, ScareCrow, VT 0/70, encrypt-FUD checkbox, unique-hash ni sandbox/ML bypass deb yozish, “skips emulators” ni evasion deb yozish, UnDefend.

Copy tuzatish (en+zh birga, `i18n.test.ts`): 1.8s “skips some AV emulators” → toy emulator Sleep skip da **chiqadi**, Microsoft cloud sandbox ni kechiktirmaydi, unique SHA-256 hash-IOC. “no CreateThread” maqtovi → stub lokal `CALL` + RWX; Donut/SGN yozish oynasi; Go runtime odatiy API; EDR bypass emas. Sideload satri wrap `*_loader.exe` ScareCrow emas, signed-host+DLL **tashqarida**. Generate default `format=exe` + HTTP `default` Loaders guide dagi `format=shellcode` + mos listener ga zid.

Tashqi yo‘l (simptom 2 ni 2025–2026 qog‘ozlarida yechgan narsa): custom stage-0, Donut `-b 1 -e 3` tashqi, ThreatCheck tsikli, packer oldidan `--disable-sgn --skip-symbols`, signed-host sideload yoki disk DLL, HTTP profile, ba’zan `slivercloak` / `better-sliver` fork. UI `loaders.guide.external` da qolsin. Commodity “FUD + UnDefend” stacklar (masalan omma `pantha704/sliver-c2`) ko‘chirilmaydi.

**Reyting**

| Daraja | Ish | Simptom | Murakkablik | Halollik |
|---|---|---|---|---|
| 1 | A1–A7 diagnostika + lab log + C2/beacon ogohlantirish | 1 | Past | Yuqori |
| 2 | A4 `StartW` + EXE-as-PIC rad + **host `jump` dan keyin tirik** | 1 | Past | Yuqori |
| 3 | C1 Donut Bypass/ExitOpt plumbing | 2 (`AMSI_PATCH_*`) + 1 umr | Past | Yuqori — native flag |
| 4 | HTTP C2 ≠ `default` + beacon generate/checklist | 2 tarmoq | Allaqachon bor | Yuqori |
| 5 | B Protection History runbook | 1+2 nom | Copy | Yuqori |
| 6 | C2 ixtiyoriy disk-DLL stub | 2 unbacked | O‘rta spike | Halol yorliq shart |
| 7 | Tashqi loader / Sliver fork | 2 YARA+behavior | Operator | UI emas |
| 8 | **Qilmang:** ko‘proq XOR, uniqueness, ScareCrow, RWX marketing, stomping, sleep-mask, VT | — | — | FUD |

## Conclusion

Operator ikki voqeani bitta “loader yomon” hikoyasiga yig‘gan. Birinchisi wrapning o‘z `RET`i, bo‘sh RDI va `127.0.0.1`/beacon sahifasi — buni XOR chuqurlashtirish emas, **ko‘rinadigan muvaffaqiyatsizlik va jarayon umri** yechadi. Ikkinchisi wrap muvaffaqiyatining dalili: plaintext Sliver allaqachon RAM da, `interactive` yangi hash bermaydi, inbox Defender xotira+behavior+C2 bilan o‘ldiradi. VeryLazyTech shu tashxisni tasdiqlaydi, yangi FUD qatlami bermaydi. Keyingi chorak crypter emas: Windows `jump` qaytmasin, Loaders C2/format/beacon ni yolg‘on toast qilmasin, Protection History nomini yozing, Donut/ScareCrow eshigini yopiq qoldiring. Unique hash sessiyani saqlamaydi — u faqat kechagi faylning barmoq izini almashtiradi.
