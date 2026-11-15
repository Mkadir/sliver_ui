# UI Feature Mapping: AV-aware Payload Workflows Across C2 Platforms

Competitive/product research for Sliver UI (Mkadir fork). Public sources only. Local context: existing plan at `docs/LOADER_AV_OPSEC_PLAN.md`; Implants already generate win/linux formats exe/service/shared/shellcode with Obfuscate/Evasion and HTTP C2 profiles; Shellcode RDI API exists without a Loaders page; ShellcodeEncoder/SGN not yet wrapped.

---

## What UI sections do mature C2 platforms provide for payload packaging beyond "generate implant"?

### Takeaway
Mature platforms treat packaging as a multi-surface workflow: generate agent → transform/wrap into delivery artifacts → optionally key/stage/stego → apply malleable traffic/profile settings — often split across dedicated payload generators, kits/scripts, wrappers, and offline loader tools rather than a single “Generate” button.

### Cited Findings
- Cobalt Strike separates delivery packaging into **kits** loaded via Script Manager: Artifact Kit (EXE/DLL generation from shellcode), Resource Kit (HTA/PowerShell/Python/VBA/VBS templates), Applet Kit, Elevate Kit; operators download Arsenal via **Help → Arsenal**, build templates, then load `artifact.cna` / `resources.cna` so Attacks → Packages use custom artifacts — [HelpSystems: Kits, Profiles, and Scripts](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/blog_kits-profiles-scripts.htm); [HelpSystems: The Artifact Kit](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm); [Cobalt Strike: Resource Kit](https://cobaltstrike.com/help-resource-kit).
- Cobalt Strike payload packaging UI paths include **Attacks → Packages → Windows Executable** (staged) and **Windows Executable (S)** (stageless) with outputs EXE, Service EXE, DLL, PowerShell, Raw PIC; Artifact Kit techniques are selected by loading a built kit’s Aggressor script, not by a checkbox alone — [aldeid: Windows Executable](https://www.aldeid.com/wiki/Cobalt-Strike/Attacks/Packages/Windows-Executable); [Internal All The Things: Cobalt Strike Kits](https://swisskyrepo.github.io/InternalAllTheThings/command-control/cobalt-strike-kits/).
- Mythic’s UI uses a multi-step **Create Payload** wizard: OS filter → payload type + build parameters → command selection → C2 profile parameters → name/description; separate **Payload Types and C2 Profiles** management (headphones icon) and **Payloads** list with build-step progress, download, export/import of payload configs — [Mythic Quick Usage](https://docs.mythic-c2.net/quick-usage); [Mythic Building Payloads](https://docs.mythic-c2.net/message-flow/building-payloads); [Mythic Operator Video: UI](https://www.youtube.com/watch?v=0UT5C9BFGT0).
- Mythic supports **wrapper payload types** (e.g. msbuild/macros pattern): wrappers take a prior build as input, have no C2 profiles of their own, and re-package for delivery; Apollo-style agents expose Donut-related build params (shellcode format, AMSI/WLDP/ETW bypass choices) grouped/hidden by output type — [Mythic Payload Type Configuration](https://docs.mythic-c2.net/version-2.3/payload-types/configuration); [Mythic Dynamic Build Parameters](https://docs.mythic-c2.net/customizing/payload-type-development/payload-type-info/dynamic-build-parameters); [Mythic Payload Type Definition (wrappers)](https://docs.mythic-c2.net/customizing/payload-type-development/payload-type-info/payload-type-definition).
- Havoc’s packaging UI is primarily **Attack → Payload** for Demon: listener, arch, format (Windows EXE/DLL/Shellcode/Service EXE), sleep technique (Foliage/Ekko/Wait), indirect syscalls, injection alloc/execute/spawn targets; teamserver **Yaotl profiles** preconfigure listeners/URIs/headers and Demon binary string replace — not a separate “artifact kit” product surface — [Havoc Agent docs](https://havocframework.com/docs/agent); [Medium: Havoc Client UI](https://medium.com/@r1ckyr3c0n/havoc-c2-framework-part-2-client-user-interface-2024-c029322527f1); [Havoc Profiles](https://havocframework.com/docs/profiles).
- Nighthawk (public marketing) advertises a **payload generator** for OpSec PE artifacts (DLL, EXE, Service EXE, XLL, CPL), **steganography stager**, and separate offline tools **NHLoader** (PE generator/infector with infection, encoding in BMP/PNG/WAV/XML, persistence modes) and Stego Loader GUIs; later releases integrate OpSec-driven loaders into the UI/API payload generator and a **Stager Kit** (stages 0–2) — [Nighthawk About](https://nighthawkc2.io/about/); [Nighthawk 0.2.6 Three Wise Monkeys](https://nighthawkc2.io/three-wise-monkeys/); [Nighthawk 0.3 Automate](https://nighthawkc2.io/automate-all-the-things/); [Nighthawk 0.4 Janus](https://nighthawkc2.io/janus/); [Nighthawk 1.0 Apex](https://nighthawkc2.io/apex/).
- Brute Ratel (high-level public): Community Kit hosts scripts/configs and **deprecated payload loaders**; public vendor/reseller materials describe listener/profile creation, Badger generation, then **custom C loaders** or **DLL sideloading** as the delivery step outside a single generate dialog; cheat-sheet style public notes list generate formats exe/dll/service — [BRc4 Community Kit](https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit); [Anchor Technologies BRc4 product page](https://anchor-u.com/product/brute-ratel-c4/); [1337skills BRc4 cheat sheet](https://1337skills.com/cheatsheets/brute-ratel-c4/).
- Upstream Sliver UI (`9Insomnie/sliver_ui`) documents Implants generation (OS/arch/format/C2/evasion/obfuscate) under Payloads but **no dedicated Loaders / artifact-kit section** in the published feature table — [GitHub 9Insomnie/sliver_ui](https://github.com/9Insomnie/sliver_ui).

### Inferences
- “Beyond generate” consistently means: (1) post-build transforms (encode/RDI/Donut/wrap), (2) template/kit override of PE/script carriers, (3) staging/keying/stego as separate generators, (4) traffic/profile config as a sibling surface — Sliver UI already has (4) via HTTP C2; the gap is (1)–(3).
- Commercial leaders (Nighthawk, BRc4 marketing) emphasize **loader/artifact workstations** as first-class products; open frameworks (Havoc, Mythic) either bake evasion into generate dialogs or use agent/wrapper plugins.

### Gaps
- No public screenshots/docs of the full Brute Ratel Commander “payload packaging” UI beyond high-level workflow descriptions and unofficial cheat sheets (commercial, non-public UI).
- Cobalt Strike official product Features page was behind a challenge page during fetch; kit behavior is documented in HelpSystems manuals and historical blog posts instead.
- Exact Mythic UI labels for every wrapper agent vary by installed agent; Donut options are agent-defined, not a global Mythic “Loaders” page.

---

## How do malleable C2 profiles + artifact kits appear in operator workflows?

### Takeaway
Profiles shape **network and in-memory/post-ex behavior at teamserver/agent config time**; artifact kits/wrappers shape **on-disk/script delivery carriers at package time**. Operators typically configure profile first (or once per engagement), then generate/package payloads that inherit that profile — kits are loaded once per client session and silently rewire package menus.

### Cited Findings
- Cobalt Strike Malleable C2 is specified when starting the teamserver (`./teamserver [IP] [password] [/path/to/profile]`); one profile per instance; profiles control HTTP indicators, SSL/code-signing certs, and memory/process-inject/post-ex options — not edited inside the Attacks → Packages dialog — [HelpSystems: Kits, Profiles, and Scripts](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/blog_kits-profiles-scripts.htm); [ThreatExpress malleable-c2 guide](https://github.com/threatexpress/malleable-c2); [Unit 42: Malleable C2 Profile tutorial](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/).
- Artifact Kit contract: Cobalt Strike passes shellcode + meta to an Aggressor hook (`EXECUTABLE_ARTIFACT_GENERATOR`); the kit returns EXE/DLL; workflow is download Arsenal → edit/build technique → Script Manager load `artifact.cna` → generate via Packages — [HelpSystems: Artifact Kit](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm); [rastamouse: Custom Beacon Artifacts](https://rastamouse.me/custom-beacon-artifacts/); [Cobalt Strike blog: proxy DLL with Artifact Kit](https://www.cobaltstrike.com/blog/create-a-proxy-dll-with-artifact-kit).
- Official Artifact Kit docs explicitly warn kits **fail** when vendors signature the technique or when cloud reputation treats unknown PE as bad; recommend treating that like application whitelisting (use known-good hosts such as PowerShell) — [HelpSystems: Artifact Kit — Where Artifact Kit Fails](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm).
- Mythic splits **C2 Profiles** (dockerized servers + per-payload C2 parameters in the wizard) from **Payload Type build parameters** / wrappers; operators edit profile `config.json` from the C2 Profiles page and pick profile params during Create Payload — [Mythic C2 Profiles Overview](https://docs.mythic-c2.net/version-2.3/c2-profiles); [Mythic Quick Usage](https://docs.mythic-c2.net/quick-usage).
- Havoc Yaotl profile configures listener Hosts/URIs/Headers/UserAgent and Demon defaults (sleep, spawnto, binary string replace) at teamserver start; payload generation UI then selects a live listener and Demon options (sleep technique, syscalls) — [Havoc Profiles](https://havocframework.com/docs/profiles); [Havoc Agent](https://havocframework.com/docs/agent).
- Nighthawk marketing presents malleable agents + **point-and-click OpSec artifact generators** and staging as parallel toolchain pieces (UI payload generator + offline NHLoader/Stego), including keying before reflective load — [Nighthawk About](https://nighthawkc2.io/about/); [Nighthawk 0.2 Catch Us If You Can](https://nighthawkc2.io/catch-us-if-you-can/).
- Sliver UI fork already maps the “profile” half to an **HTTP C2 Profiles** page + implant generate field `http_c2_profile` / traffic encoders / listener camouflage; LOADER plan states traffic OPSEC and host/loader OPSEC are separate layers — local `docs/LOADER_AV_OPSEC_PLAN.md`; workspace memory on Sliver UI OPSEC.

### Inferences
- For Sliver UI, keep HTTP C2 Profiles as the malleable-traffic sibling; add Loaders as the Artifact-Kit/wrapper sibling — do not merge both into Implants alone.
- Operator mental model to copy: **Profile once → Generate implant (shared/shellcode preferred) → Transform/package → Deliver via inject/sideload/service**.

### Gaps
- Public Nighthawk materials do not fully document how “malleable egress” config is laid out in the main UI versus config files.
- Sliver’s native HTTP C2 profile model differs from CS Malleable DSL (JSON RPC profiles vs `.profile` language); feature parity is conceptual, not syntactic.

---

## What should Sliver UI's Loaders / OPSEC section include as MVP vs advanced?

### Takeaway
MVP should wire existing Sliver RPCs (RDI + ShellcodeEncoder + SGNEnabled) into a `/loaders` Source → Transform → Output wizard with honest checklists and Implants deep-links; advanced work should stay guidance/export-oriented (sideload templates, external Donut/packers, optional artifact workstation) rather than shipping a commercial-grade crypter inside the UI.

### Cited Findings
- Local plan already specifies MVP: sidebar **Loaders** under Payloads; steps Source (build picker / upload) → Transform (RDI for shared, Encoder SGN/XOR/XOR_DYNAMIC, iterations, bad chars) → Output (download + SHA256 + OPSEC checklist); Phase 1 APIs `GET /api/shellcode/encoders`, `POST /api/shellcode/encode`, expose `SGNEnabled`; RDI already at `POST /api/shellcode/rdi` — local `docs/LOADER_AV_OPSEC_PLAN.md`.
- Cobalt Strike’s closest analogue to MVP is **Artifact Kit + Raw/shellcode packages**, with the honesty that kits only beat limited AV sandboxes and get signed over time — [HelpSystems: Artifact Kit](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm).
- Mythic MVP analogue is **build parameters + wrapper chain + build-step visibility** (e.g. “passing Apollo through Donut”) rather than a separate Loaders nav item — [Mythic Building Payloads](https://docs.mythic-c2.net/message-flow/building-payloads); [Mythic Operator Video: UI](https://www.youtube.com/watch?v=0UT5C9BFGT0).
- Havoc documents that Demon was **not designed to be evasive**; operators are expected to use external loaders/packers/crypters/stagers — UI exposes sleep obfuscation and syscall/injection knobs, not a full artifact factory — [Havoc Agent — About Evasion](https://havocframework.com/docs/agent).
- Nighthawk advanced bar (marketing): dedicated NHLoader GUI, PE infection, stego staging, multi-key keying, Stager Kit stages 0–2, CET-compatible masking modes — far beyond Sliver RPC surface — [Nighthawk 0.2.6](https://nighthawkc2.io/three-wise-monkeys/); [Nighthawk 0.4](https://nighthawkc2.io/janus/); [Nighthawk 1.0](https://nighthawkc2.io/apex/).
- BishopFox maintainers have publicly stated sleep obfuscation/direct syscalls are often **most effective in the loader**, and Go-runtime sleep obfuscation is hard in-implant — [Sliver Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171).

### Inferences — Prioritized Sliver UI feature set

| Priority | Feature | Rationale vs competitors |
|---|---|---|
| P0 MVP | `/loaders` page: pick shared/shellcode build → optional RDI → encode → download | Closes gap vs CS Artifact/Raw and Mythic Donut step; APIs mostly exist |
| P0 MVP | Wrap `ShellcodeEncoder` + `ShellcodeEncoderMap`; expose `SGNEnabled` on generate for shellcode | Matches plan; SGN is Sliver-native post-process |
| P0 MVP | Implants success banner + row actions “Send to Loaders” / “RDI” / “Encode” | Matches Mythic “continue pipeline” and CS package flow |
| P0 MVP | Persistent disclaimer + layered OPSEC checklist linking `/http-c2`, inject/sideload | Matches CS “Artifact Kit Fails” honesty and Havoc “use external loaders” stance |
| P1 | Operator checklists: local-inject, rdi-dll, sideload naming, service hygiene | BRc4/Nighthawk workflows emphasize sideload/custom loader after generate |
| P1 | Presets: encoder light/noisy; show before/after size+hash | Nighthawk/Mythic show build feedback; reduces operator error |
| P2 Advanced | Markdown/export stub “loader project” (lab examples only) | Analog to Arsenal kit source without claiming FUD |
| P2 Advanced | Document external tools appendix (Donut, custom packers) as out-of-band | Mythic wrappers / Havoc guidance pattern |
| P3 Optional | Named artifact store / job history for transformed blobs | Nighthawk/CS team server artifact storage territory; needs product decision |
| Non-goal | Shipping commercial crypter, PE infection GUI, stego stager, CET stack masking | Nighthawk-class; not in Sliver RPC; high review bar |

### Gaps
- Whether Sliver server builds in this deployment actually enable all encoder/arch pairs must be verified at runtime (`ShellcodeEncoderMap`) — not confirmed in this research pass.
- No public UX study of operator preference for “Loaders page” vs “extra Implants wizard step”; recommendation follows existing local plan + CS/Mythic split surfaces.

---

## How should Windows vs Linux beacon generation differ in the UI wizard?

### Takeaway
Windows generation should emphasize service/DLL/shellcode delivery paths, RDI, sideload/service naming, and stronger evasion disclaimers; Linux generation should emphasize shared/`.so` + shellcode, fewer AV-centric encoder claims, and sideload-into-process guidance — the wizard must filter formats and loader transforms by OS rather than showing a flat Windows-centric form.

### Cited Findings
- Current Sliver UI Implants form already filters formats: Windows `exe|service|shellcode|shared`; Linux `exe|shared|shellcode` (no service); Darwin same as Linux set — local `frontend/src/pages/ImplantsPage.tsx`.
- Cobalt Strike packaging docs for Artifact Kit / Windows Executable are **Windows PE-centric** (EXE, Service EXE, DLL, rundll32 Start export); Linux/SSH beacon packaging is a different path — [aldeid: Windows Executable](https://www.aldeid.com/wiki/Cobalt-Strike/Attacks/Packages/Windows-Executable); [HelpSystems: Artifact Kit](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm).
- Havoc Demon payload formats in public UI writeups are Windows EXE/DLL/Shellcode/Service EXE; custom agents declare `SupportedOS` and format lists per agent — [Medium: Havoc UI](https://medium.com/@r1ckyr3c0n/havoc-c2-framework-part-2-client-user-interface-2024-c029322527f1); [Havoc custom agents](https://www.mintlify.com/HavocFramework/Havoc/extensibility/custom-agents).
- Mythic wizard **starts with OS selection** specifically to filter payload types and build parameters (`supported_os` / hide_conditions on parameters) — [Mythic Quick Usage](https://docs.mythic-c2.net/quick-usage); [Mythic Dynamic Build Parameters](https://docs.mythic-c2.net/customizing/payload-type-development/payload-type-info/dynamic-build-parameters).
- Sliver sideload docs differ by OS: Windows needs DLL entrypoint; Linux uses `-p` process + `.so`; MacOS drops temp file — [Sliver Third Party Tools](https://sliver.sh/docs/?name=Third%20Party%20Tools).
- Nighthawk public payload generator marketing focuses on Windows PE formats (DLL/EXE/Service/XLL/CPL) and Windows OpSec plugins — [Nighthawk About](https://nighthawkc2.io/about/).

### Inferences — Concrete wizard differences for Sliver UI

**Shared wizard spine (both OS):** OS → arch → format → C2 (+ HTTP profile when http/https) → beacon/session cadence → limits → generate → optional “Continue in Loaders”.

**Windows-specific affordances:**
- Formats: show **service** with ServiceName/Description hygiene hints (already partial).
- Prefer recommending **shared** or **shellcode** for Loaders path; warn that raw **exe** on disk is highest signature risk.
- Loaders: enable **RDI** (DLL→PIC), SGN/XOR encoders, link to `execute-shellcode` / sideload / spawndll / service install.
- Show evasion/obfuscate toggles with Windows-oriented disclaimer (EDR behavioral detections).

**Linux-specific affordances:**
- Hide **service** format; hide or disable Windows-only loader steps (RDI-as-Windows-DLL, rundll32, XLL/CPL-style tips).
- Emphasize **shared (.so)** + **shellcode**; checklist points to Linux `sideload -p` and in-memory execute-shellcode.
- Encoder section: only show arch/encoder pairs returned by `ShellcodeEncoderMap`; avoid copying Windows “AMSI/ETW bypass” language.
- Obfuscate remains relevant (Go symbols); “Evasion” copy should not imply Windows EDR feature parity.

### Gaps
- Public detail on Sliver `ShellcodeRDI` Linux `.so` support vs Windows DLL-only was not fully verified in this pass; UI should gate RDI on OS/format based on API errors or server capability probes.
- Darwin/FreeBSD nuances beyond format lists were not deeply researched here (secondary to Win/Linux question).

---

## What warnings/disclaimers should the UI show so operators do not trust Obfuscate/Evasion alone?

### Takeaway
Disclaimers should state that Obfuscate/Evasion and encoders are **compile-time or byte-mutation aids**, not AV/EDR bypass guarantees; cite layered OPSEC (traffic profile + staged in-memory delivery + bland host artifacts); mirror Cobalt Strike’s “Artifact Kit fails / reputation” and Havoc’s “use external loaders; Demon isn’t FUD” messaging.

### Cited Findings
- Local plan required page copy: Obfuscate/Evasion ≠ bypass chain; SGN/XOR mutate bytes but EDRs detect behavior; layered OPSEC; **impossible to promise** guaranteed evasion; authorized/lab use only — `docs/LOADER_AV_OPSEC_PLAN.md` §7.
- Cobalt Strike Artifact Kit official docs: sandboxes evolve; vendors signature kit techniques; **cloud reputation / unknown-file** defenses are not defeated by obfuscation — treat like application whitelisting — [HelpSystems: Artifact Kit](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm).
- Havoc official Agent docs: Demon **most likely does not** bypass AV/EDR; evasion was out of scope; designed to work **with** loaders/packers/crypters/stagers; note on GitHub: “Please do not open any issues regarding detection” — [Havoc Agent](https://havocframework.com/docs/agent); [Havoc GitHub README](https://github.com/HavocFramework/Havoc).
- BishopFox on Sliver: loader is often the right place for syscalls/sleep obfuscation; implant-side Go sleep encryption is non-trivial — [Sliver Discussion #1171](https://github.com/BishopFox/sliver/discussions/1171).
- Nighthawk marketing stresses OpSec tooling but also publishes responsible-distribution messaging (licensed use, attribution/watermarking) — useful tone for “powerful ≠ unsupervised” — [Nighthawk: With Great Power…](https://nighthawkc2.io/with-great-power-comes-great-responsibility/); [Nighthawk EULA](https://nighthawkc2.io/eula/).

### Inferences — Recommended UI warning surfaces

1. **Implants generate form** (near Obfuscate/Evasion checkboxes): short inline note — “Symbol renaming / limited evasion flags do not make a PE ‘FUD’. Prefer shared/shellcode + Loaders + HTTP C2 profile.”
2. **Loaders page banner** (always visible): multi-bullet disclaimer from plan §7; link to `/http-c2` and session inject tools.
3. **Post-generate toast/banner**: “Build ready. For host OPSEC continue in Loaders; for traffic OPSEC review HTTP C2 profile.”
4. **Encoder success panel**: “Encoder changed byte pattern (hash/size shown). Behavioral EDR, sandbox detonation, and reputation checks may still flag execution.”
5. **Footer legal/ops**: authorized red-team / lab / adversary-simulation only (already plan Phase 0).

Suggested concise disclaimer string (en):

> Obfuscate and Evasion are compile-time implant options. They are not an antivirus or EDR bypass. Shellcode encoders (SGN/XOR) only transform bytes. Expect detection unless you also layer HTTP C2 camouflage, in-memory delivery, and environment-appropriate host artifacts. No UI option can guarantee evasion.

### Gaps
- No public Sliver UI upstream i18n strings for such disclaimers yet; zh.ts parity will be required per project AGENTS.md when implemented.
- Product/legal review may want stronger/weaker wording than the draft above; this research only recommends based on peer-tool honesty patterns.

---

## Cross-platform UI affordance summary (quick reference)

| Affordance | Cobalt Strike | Mythic | Havoc | Nighthawk (public) | BRc4 (public high-level) | Sliver UI today | Sliver UI proposed |
|---|---|---|---|---|---|---|---|
| Generate agent | Packages / listeners | Create Payload wizard | Attack → Payload | Payload generator | Badger generate | Implants | Keep + deep-link |
| Malleable traffic | Teamserver `.profile` | C2 Profiles page + wizard params | Yaotl listeners/Demon | Malleable egress (mktg) | Profiles / DoH etc. | HTTP C2 page | Keep |
| Artifact/loader kit | Arsenal Artifact/Resource Kit | Wrappers + Donut build params | External loaders (documented) | NHLoader / Stego / Stager Kit | Custom loader / sideload | RDI API only | **Loaders MVP** |
| Sleep/syscall knobs | Malleable + kits | Agent-specific | In payload dialog | Beacon OpSec config | Indirect syscalls etc. | Limited (Evasion) | Document; loader-first |
| Honesty about AV | Artifact Kit “fails” section | Agent notes / docs | Explicit non-evasive stance | OpSec marketing + EULA | EDR-focus marketing | Weak | **Required banners** |
