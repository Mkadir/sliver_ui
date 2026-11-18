# Sliver UI encrypt-at-rest + in-memory decrypt — product/design options

Scope: authorized lab/red-team product framing for Mkadir/sliver_ui (and 9Insomnie-style forks). Rank what to ship in-UI vs checklist vs external tool, with effort and OPSEC honesty. Prefer features backed by Sliver gRPC first.

---

## How do Cobalt Strike Artifact Kit, Mythic payload wrappers, Havoc, and Nighthawk NHLoader present “encrypted loader” to operators?

### Takeaway
Peers treat encrypt-at-rest as a **packaging layer outside the implant core**: Cobalt Strike patches XOR-obfuscated Beacon into operator-built Artifact Kit templates; Mythic uses **wrapper payload types** (ScareCrow/service/dll) and Donut build knobs in the UI; Havoc documents Demon as **not designed to be evasive** and expects external loaders/crypters; Nighthawk markets NHLoader/keying as a first-class payload-generator product (environmental + remote key stacking). None promise “FUD.”

### Cited Findings
- Cobalt Strike Artifact Kit is a source framework of EXE/DLL templates that recover shellcode via sandbox-resistant behaviors (e.g. named-pipe self-serve in `bypass-pipe.c`); operators download Arsenal via Help → Arsenal, rebuild templates, and load `artifact.cna` so Attacks → Packages use the new artifacts — [HelpSystems Artifact Kit](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm); [Cobalt Strike Arsenal Kit feature page](https://www.cobaltstrike.com/product/features/arsenal-kit).
- Official CS docs explicitly state Artifact Kit techniques get signatured over time; operators must modify kits; reputation/cloud AV is a different problem than string obfuscation — [HelpSystems Artifact Kit](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm).
- Default CS artifacts use **XOR keys** to obfuscate Beacon shellcode on disk; custom artifacts can replace XOR with any reversible transform and patch keys into a `Phear`-style struct — [Rasta Mouse: Custom Beacon Artifacts](https://rastamouse.me/custom-beacon-artifacts/).
- Mythic **wrapper** payload types take a prior build’s bytes and emit a new on-disk form without their own C2 (e.g. `service_wrapper`, ScareCrow wrapper); Apollo declares `wrapped_payloads = ["scarecrow_wrapper", "service_wrapper"]` and exposes Donut shellcode format/bypass build parameters in the web UI — [Mythic Payload Type Definition](https://docs.mythic-c2.net/customizing/payload-type-development/payload-type-info/); [Mythic Building Payloads](https://docs.mythic-c2.net/message-flow/building-payloads).
- Community Mythic wrappers (e.g. Erebus) present encrypt as a build-time **Shellcrypt** chain (compress → RC4/XOR/AES → encode) with per-build keys; VBA stagers fetch RC4-encrypted shellcode from Mythic file store — [Whispergate/Erebus](https://github.com/Whispergate/Erebus).
- ScareCrow (used as Mythic/CS wrapper target) encrypts shellcode (AES-256 / ELZMA / RC4), embeds ciphertext + key/IV into a compiled sideload/binary loader, and exposes `-encryptionmode` / `-Loader` to operators as CLI (or CNA) options—not as implant compile flags — [optiv/ScareCrow](https://github.com/optiv/ScareCrow); [Optiv ScareCrow overview](https://www.optiv.com/insights/source-zero/tools/scarecrow-payload-creation-framework).
- Havoc official docs: Demon “wasn't designed to be evasive”; it is “designed to be interoperable with … loaders, packers, crypters, and stagers”; UI payload window exposes sleep/syscall/injection knobs, not a crypter — [Havoc Agent docs](https://havocframework.com/docs/agent).
- Public Havoc tradecraft: generate shellcode in UI → wrap with external XOR/sideload loaders (LatLoader) or Crystal Palace-linked custom loaders; community modules advertise “simple shellcode loader” as AV bypass, separate from Demon generation — [icyguider/LatLoader](https://github.com/icyguider/LatLoader); [calv004/Crystal-Havoc](https://github.com/calv004/Crystal-Havoc).
- Nighthawk 0.2 marketed **payload keying** in the payload generator: decrypt keys from DNS TXT/CNAME, HTTPS, or local env (username, machine name, disk serial, etc.); generator also exports C#/C decryption stubs for custom loaders — [MDSec: Nighthawk 0.2 – Catch Us If You Can](https://www.mdsec.co.uk/2022/05/nighthawk-0-2-catch-us-if-you-can/) (primary marketing post; `nighthawkc2.io` DNS unresolved during this research pass).
- Nighthawk 0.4 “Stager Kit” / NHLoader: OpSec loader integrated into backend API and UI payload generator; plugin architecture converts PE→PIC; keying can be **stacked** (e.g. username → machine name → env var → HTTPS-fetched key) — search-indexed summary of [Nighthawk 0.4 – Janus](https://nighthawkc2.io/janus/) (site DNS failed at fetch time; treat as marketing claim corroborated by prior MDSec posts).
- Third-party analysis of NHLoader PE: encrypted implant in `.text`, config AES/gzip, keying used so sandboxes without correct environment never decrypt cleartext — [Proofpoint Nighthawk analysis (2022)](https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice) (URL content shifted when fetched Nov 2026; rely on indexed excerpts + MDSec primary posts).

### Inferences
- **Presentation pattern for Sliver UI to copy:** (1) native generate → (2) optional encode/stage encrypt via C2 RPCs → (3) **external or template wrapper** that owns disk-facing decrypt+exec → (4) honest disclaimer that kits/wrappers get burned.
- Cobalt Strike = operator-compiled template kit + Aggressor patch-in; Mythic = first-class wrapper build pipeline in UI; Havoc = document external; Nighthawk = commercial in-product keying/loader. Sliver UI sits closest to **Havoc honesty + Mythic-lite wrappers via templates**, not full NHLoader productization.
- “Encrypted loader” in mature UIs is never “checkbox makes implant FUD”; it is **artifact packaging** with keys shown once / patched into stubs.

### Gaps
- Live fetch of `nighthawkc2.io` failed (DNS); NHLoader UI screenshots/exact form fields for 2025–2026 releases were not re-verified beyond MDSec 0.2 and indexed 0.4 summaries.
- Licensed Cobalt Strike Artifact Kit source (exact current XOR vs AES defaults per technique) is not public; public descriptions + Rasta Mouse custom-artifact writeup used instead.
- Mythic `scarecrow_wrapper` container internals were not cloned; behavior inferred from Mythic wrapper model + ScareCrow CLI.

---

## For Sliver UI specifically: Option A (GenerateStage/AES stage only) vs B (post-process encrypt into stub template) vs C (Donut CLI) vs D (document-only)

### Takeaway
**Ranked for this repo:** ship **A first** (native stage-listener AES + GenerateStage / custom stage-0 templates) because it is already Sliver gRPC/CLI and matches LOADER plan Phase 6; add **B as Phase 4/7 lab stubs** (AES blob + downloadable decrypt stub, keys filled once); keep **C external checklist** (Donut already inside Sliver `format shellcode`; shelling out adds host RCE surface); never stop at **D alone** for encrypt-at-rest—document-only is the honesty layer *on top of* A/B, not a substitute for staging AES that Sliver already has.

### Cited Findings
- Sliver stage-listener supports `--aes-encrypt-key` / `--aes-encrypt-iv` (AES-CBC-128 “for obfuscation”), optional compress (zlib/gzip/deflate), RC4; prints AES KEY/IV after start; docs include C# decrypt+exec example fetching `.woff` — [Sliver Stagers docs](https://sliver.sh/docs/?name=Stagers); [BishopFox stage.go (aesEncryptKey length % 16, default IV `0000000000000000`, PreludeEncrypt)](https://github.com/BishopFox/sliver/blob/f4a0431f/client/command/jobs/stage.go); [Sliver Discussion #1081](https://github.com/BishopFox/sliver/discussions/1081).
- `profiles stage` similarly exposes AES/RC4/compress for staged implant bytes — [Sliver HTTP Payload staging tutorial](https://sliver.sh/tutorials?name=4+-+HTTP+Payload+staging).
- This repo’s plan already defines Path 2 Stage-0: stage-listener UI with optional AES (show once, never store in UI DB), GenerateStage download, custom stubs that GET `*.woff` + AES decrypt + VirtualAlloc/exec — [local LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md).
- Dead path today: `MsfStage` returns explicit error (“MSF stager generation is not supported…”) while route `POST /api/msf/stage` remains — [backend/internal/sliver/msf.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/msf.go); [server.go routes](file:///home/cup/Documents/personal/sliv/backend/internal/api/server.go).
- RDI API already wired (`POST /api/shellcode/rdi` → `Client.ShellcodeRDI`) but no Loaders page — [handlers_implants.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_implants.go); [implants_exec.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants_exec.go).
- Donut (used by Sliver Windows shellcode generate) optionally encrypts modules with **Chaskey** + 128-bit random key; entropy level 3 = random names + symmetric encryption; also supports HTTP-staged modules — [TheWover/donut README](https://github.com/TheWover/donut).
- Operator consensus: prefer **external** packer/loader over C2-native disk loader; generate lighter implant then wrap — [BallisKit Sliver + MacroPack/ShellcodePack](https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19); prior local research maps encrypt-at-rest packing as **External / checklist** — [loader_workflows.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20UI%20AV%20OPSEC%20practices/loader_workflows.md).
- Plan Phase 4 explicitly allows later “Export loader project.zip” minimal stub that reads encrypted blob (key from UI) as advanced Phase 5 with higher review bar; Phase 0–3 prioritize encoders/RDI UI before crypter-like stubs — [LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md).
- Integrating Donut CLI into UI host is called out as unsettled product/security decision (RCE surface) in prior research — [loader_workflows.md Gaps](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20UI%20AV%20OPSEC%20practices/loader_workflows.md).

### Inferences — ranked options

| Rank | Option | What operator gets | Effort (relative) | OPSEC honesty | Ship? |
|---|---|---|---|---|---|
| **1** | **A — GenerateStage / stage-listener AES** | Encrypted stage-2 on wire/at rest on staging URL; custom/GenerateStage stage-0 decrypts in memory | Medium (wrap existing RPCs + UI; retire msf stub) | AES-CBC-128 is **obfuscation**, not strong crypto; stock MSF stagers signatured; prefer custom stubs | **Yes — Phase 6 (plan)** |
| **2** | **B — Post-process encrypt → stub template** | Download `.bin.enc` + C/C#/Go stub with key/IV patched or sidecar; local decrypt+exec without stage server | Medium–High (template pack + browser/server AES; no Sliver RPC for “pack PE”) | Same as ScareCrow-lite; stub itself will be YARA’d; lab examples only | **Yes — Phase 4/7 optional stubs** |
| **3** | **D — Document-only** | Checklists: encrypt-at-rest required before phishing drop; links to Donut `-e 3`, ScareCrow, ShellcodePack | Low | Correct framing; alone does not close Artifact-Kit gap | **Always as copy layer; not sole deliverable** |
| **4** | **C — Integrate Donut CLI** | UI shells to local `donut` for entropy/AMSI knobs beyond Sliver embed | High + security review | Vanilla Donut stubs get signatured; forks exist because upstream burns — [Donut](https://github.com/TheWover/donut); duplicates Sliver’s already-embedded Donut path | **No in-UI; checklist + “run outside UI”** |

- **Option A** aligns with peer “stage encrypted blob, small loader decrypts” (Sliver native, BallisKit HTTPS_STAGER, Mythic HTTP module stage) and reuses keys operators already type into CLI.
- **Option B** is the Artifact-Kit / ScareCrow analogue without shipping a commercial crypter: templates, not a polymorphic PE engine.
- Combining A+B: stage-listener AES for remote stage-2; stub-template AES for first-drop when no staging host—both belong under `/loaders`, not Implants checkboxes.
- Success metric remains **fewer wrong packages** (raw PE email, plaintext shellcode in attachment), not VT score — [SLIVER_UI_AV_OPSEC_RESEARCH.md](file:///home/cup/Documents/personal/sliv/docs/SLIVER_UI_AV_OPSEC_RESEARCH.md).

### Gaps
- Exact gRPC surface for HTTP stage-listener vs TCP-only on newest Sliver master is in flux (issue notes HTTPS staging regressions on master) — [BishopFox/sliver#2009](https://github.com/BishopFox/sliver/issues/2009); UI must probe/version-gate.
- No spike yet measuring LOC to wrap `StartTCPStagerListener` + HTTP job helpers vs documenting CLI-only for v1.

---

## Key management: where does the AES key live (UI form once, embedded in stub, environmental keying from DNS)?

### Takeaway
For Sliver UI v1: **generate or accept key/IV in the stage-listener / stub form, display once, patch into downloadable stub or show for operator copy—do not persist in UI DB**. Embedded-in-stub keys match ScareCrow/CS XOR defaults and Sliver’s own stage examples. **Environmental / DNS keying is checklist + advanced template only** (TrustedSec / Nighthawk pattern)—high value OPSEC, not a Sliver RPC, easy to get wrong in product copy.

### Cited Findings
- Sliver stage-listener: operator supplies `--aes-encrypt-key` / `--aes-encrypt-iv`; server prints them after job start; example C# stager hardcodes `AESKey` / `AESIV` strings matching the listener — [Sliver Stagers](https://sliver.sh/docs/?name=Stagers); [stage.go](https://github.com/BishopFox/sliver/blob/f4a0431f/client/command/jobs/stage.go).
- Local plan non-goal: “Storing AES stage keys or payloads in Spiver UI’s own DB (remain stateless; blobs stay in browser download / Sliver server builds)”; stage form: “optional AES key/IV (show once, never store in UI DB)” — [LOADER_AV_OPSEC_PLAN.md](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md).
- ScareCrow build: encrypt shellcode → base64 ciphertext + key + IV → compile into loader binary (key material lives **in the stub**) — [ScareCrow.go EncryptShellcode → CompileFile](https://github.com/optiv/ScareCrow/blob/main/ScareCrow.go).
- Cobalt Strike default artifacts: XOR key in artifact/`Phear` structure patched at generate time — [Rasta Mouse](https://rastamouse.me/custom-beacon-artifacts/).
- Donut: 128-bit random key for Chaskey when entropy=3; key material travels with loader/module design (embedded or staged) — [Donut README](https://github.com/TheWover/donut).
- TrustedSec execution guardrails: local host keying → network keying → **external DNS TXT kill switch / key** → retrieve payload → load/execute; warns single hostname key + embedded payload was reversed by blue team; “if someone wants to reverse your payload, they will” — [TrustedSec Execution Guardrails (2024)](https://trustedsec.com/blog/execution-guardrails-no-one-likes-unintentional-exposure).
- Nighthawk keying: remote DNS TXT/CNAME or HTTPS; local username/machine/env/disk serial; 0.4 claims **stackable** keys; generator exports decrypt stubs — [MDSec Nighthawk 0.2](https://www.mdsec.co.uk/2022/05/nighthawk-0-2-catch-us-if-you-can/); indexed [Nighthawk 0.4 Janus](https://nighthawkc2.io/janus/).
- MITRE T1480.001 (Execution Guardrails: Environmental Keying) referenced by TrustedSec as the control family — [TrustedSec](https://trustedsec.com/blog/execution-guardrails-no-one-likes-unintentional-exposure).

### Inferences — key placement matrix for Sliver UI

| Pattern | Where key lives | Fits Sliver UI? | OPSEC note |
|---|---|---|---|
| **UI form once → show/copy** | Operator clipboard / engagement notes | **Default for stage-listener** | Matches Sliver CLI; no UI DB |
| **Embedded in stub** | Strings/bytes inside downloaded template | **Default for Option B stubs** | Sandbox can extract; still beats plaintext implant |
| **Fetched with stage-2** | Key only on staging server; stub has URL | Overlaps stage-listener AES (ciphertext at URL; key in stub or prepended IV behavior) | Sliver may prepend IV to blob—stub must match server semantics ([Discussion #771](https://github.com/BishopFox/sliver/discussions/771)) |
| **Environmental keying** | Derived from hostname/domain/user | Checklist + optional advanced `#ifdef` stub | Prevents wrong-host detonation; golden images weaken it |
| **DNS/HTTPS remote key** | TXT/CNAME or HTTP body | Checklist / Phase 7+ template | Kill switch + anti-sandbox; DNS telemetry; not Sliver RPC |

- Product copy must say Sliver AES stage is **obfuscation-grade** (CBC-128, fixed/default IV footguns) — wrong key length already panics/errors in the wild ([#1848](https://github.com/BishopFox/sliver/issues/1848)).
- UI validation: enforce key length rules Sliver uses (`len % 16 == 0` for AES key string); warn on default IV.

### Gaps
- Whether current Sliver server prepends IV to AES stage blob on all protocols needs version-specific verification before stub templates hardcode decrypt framing.
- No public Sliver-native “environmental keying” RPC—any UI claiming DNS keying would be **template-only**, not teamserver-backed.

---

## What already exists in this repo (plan phases, RDI API, dead msf/stage stub)?

### Takeaway
The fork already owns **network OPSEC** (`/http-c2`) and a **working RDI backend** without a Loaders page; encoder RPCs and stage-listener/GenerateStage are planned but unwired; `POST /api/msf/stage` is a deliberate dead stub. Encrypt-at-rest for delivery is specified in plan Phase 6 (stage AES) and Phase 4/7 (stub templates), not as a separate crypter product.

### Cited Findings
- Capability table: shellcode/shared generate yes; RDI API yes / UI page no; ShellcodeEncoder / SGNEnabled not wrapped; stage-listener no; GenerateStage stub-only via msf path — [LOADER_AV_OPSEC_PLAN.md §3](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md).
- Phased build order: Phase 1 encoders → Phase 2 LoadersPage → Phase 3 Implants deep-links → Phase 4 checklists/templates → **Phase 6 stage-0** → Phase 7 persistence/background on stubs — [LOADER_AV_OPSEC_PLAN.md §10](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md).
- Research synthesis: prioritize Loaders MVP (RDI+encode) then guidance; stage listeners P1; exportable lab stub P2; commercial crypter **non-goal** — [SLIVER_UI_AV_OPSEC_RESEARCH.md](file:///home/cup/Documents/personal/sliv/docs/SLIVER_UI_AV_OPSEC_RESEARCH.md).
- Code: `ShellcodeRDI` client + `handleShellcodeRDI`; `MsfStage` always errors; routes registered for both — [implants_exec.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants_exec.go); [msf.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/msf.go); [server.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/server.go).
- Prior loader workflow research already marked “Encrypt-at-rest blob packing (AES/Chaskey in custom stub)” as External/checklist while stage AES is native — [loader_workflows.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20UI%20AV%20OPSEC%20practices/loader_workflows.md).

### Inferences
- Encrypt-at-rest work should **extend existing plan phases**, not invent a parallel “Crypter” nav item.
- Rewire `/api/msf/stage` → stage generate/listener APIs when Phase 6 lands (plan already says this).
- 9Insomnie/upstream Sliver UI pattern (implants download only, no Loaders) is the gap this fork’s docs already target — [SLIVER_UI_AV_OPSEC_RESEARCH.md](file:///home/cup/Documents/personal/sliv/docs/SLIVER_UI_AV_OPSEC_RESEARCH.md).

### Gaps
- Full inventory of frontend references to `/api/msf/stage` UX copy was not re-grepped in this pass; assume Partial UI still calls the stub.

---

## Recommend a phased product decision for the plan doc

### Takeaway
**Decision:** Treat encrypt-at-rest as a **first-class Loaders concern** delivered in three honesty-bounded layers—(1) native Sliver stage AES + custom stage-0 templates, (2) optional downloadable AES stub project for offline first-drop, (3) external-tool checklist (Donut CLI, ScareCrow, environmental/DNS keying)—never as an Implants “FUD” toggle. Amend `LOADER_AV_OPSEC_PLAN.md` with an explicit **§ Encrypt-at-rest product decision** that ranks Option A → B → D, rejects in-UI Donut CLI (C), and locks key handling to show-once / stub-embed / no UI DB.

### Cited Findings
- Plan already separates transform path (RDI/SGN) from stage-0 path and forbids commercial crypter / FUD claims — [LOADER_AV_OPSEC_PLAN.md §4.7, §7](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md).
- Peer precedent: Mythic wrappers + Havoc external-loader stance + CS Artifact Kit modification requirement — [Mythic Payload Type Info](https://docs.mythic-c2.net/customizing/payload-type-development/payload-type-info/); [Havoc Agent](https://havocframework.com/docs/agent); [HelpSystems Artifact Kit](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm).
- TrustedSec + Elastic reality: encrypt defeats static; behavior/call stacks remain; guardrails are mandatory process not a checkbox — [TrustedSec](https://trustedsec.com/blog/execution-guardrails-no-one-likes-unintentional-exposure); [Elastic ETW call stacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks).
- Sliver AES stage is documented as obfuscation-oriented CBC-128 — [Sliver Stagers](https://sliver.sh/docs/?name=Stagers).

### Inferences — recommended plan-doc amendment (for report writer / maintainers)

**Product decision (proposed text for LOADER plan):**

1. **P0–P1 (unchanged):** Loaders MVP = RDI + ShellcodeEncoder + SGNEnabled + checklists. Encrypt-at-rest is **not** blocked on MVP, but MVP copy must already say “prefer encrypted stage / external loader; do not email plaintext shellcode.”
2. **P1 / Phase 6 (Option A — ship):** Stage Listeners + AES/RC4/compress fields; show key/IV once; custom stage-0 template pack with decrypt matching Sliver framing; GenerateStage with MSF-signature warning; retire dead `MsfStage` error into real stage API or clear deprecation.
3. **P2 / Phase 4–7 (Option B — ship carefully):** “Export encrypted shellcode + stub” lab templates (C/C#/Go): UI AES-encrypts blob in browser or ephemeral backend memory; patches key into stub source zip; marked **authorized lab example**, not evasion guarantee.
4. **Always (Option D):** External appendix — Donut `-e 3`, ScareCrow/ShellcodePack, TrustedSec keying diagram, Nighthawk-style DNS keying as operator exercise; link BallisKit.
5. **Non-goal (Option C):** Do not shell out to Donut CLI from the UI binary; Sliver server already embeds Donut for `format shellcode`.
6. **Keys:** generate/validate in form → display once → optional stub embed → never write to SQLite/UI config; environmental/DNS keying = advanced template + checklist only.
7. **OPSEC banner (required):** Encrypt-at-rest hides bytes from disk scanners and casual staging sniffing; it does not stop EDR behavioral detection; Sliver stage AES is obfuscation-grade; unique stubs beat shared UI templates over time (same failure mode as stock Artifact Kit).

**Effort snapshot:**

| Deliverable | Effort | Depends on |
|---|---|---|
| Stage-listener + AES UI (A) | M | Sliver RPC wrap, version gate HTTP vs TCP |
| Custom decrypt stubs for stage AES | S–M | Correct IV/framing tests |
| Offline AES stub export (B) | M | Template pack + crypto in Go or WebCrypto |
| Donut CLI integration (C) | H + sec review | Reject for v1 |
| Docs/checklist only (D) | S | Already largely written in research docs |

### Gaps
- Formal sign-off on whether stub AES runs in **browser (WebCrypto)** vs **backend ephemeral** (avoids key in browser memory but expands server attack surface) needs a short security design note before Phase B coding.
- HTTPS stage-listener support must be confirmed against the operator’s Sliver server version before promising it in UI copy ([#2009](https://github.com/BishopFox/sliver/issues/2009)).

---

## Sources index

- https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_artifact-kit-main.htm  
- https://www.cobaltstrike.com/product/features/arsenal-kit  
- https://rastamouse.me/custom-beacon-artifacts/  
- https://docs.mythic-c2.net/message-flow/building-payloads  
- https://docs.mythic-c2.net/customizing/payload-type-development/payload-type-info/  
- https://github.com/Whispergate/Erebus  
- https://github.com/optiv/ScareCrow  
- https://www.optiv.com/insights/source-zero/tools/scarecrow-payload-creation-framework  
- https://havocframework.com/docs/agent  
- https://github.com/icyguider/LatLoader  
- https://www.mdsec.co.uk/2022/05/nighthawk-0-2-catch-us-if-you-can/  
- https://nighthawkc2.io/janus/ (DNS unresolved during research; use MDSec + indexes)  
- https://sliver.sh/docs/?name=Stagers  
- https://sliver.sh/tutorials?name=4+-+HTTP+Payload+staging  
- https://github.com/BishopFox/sliver/blob/f4a0431f/client/command/jobs/stage.go  
- https://github.com/TheWover/donut  
- https://trustedsec.com/blog/execution-guardrails-no-one-likes-unintentional-exposure  
- https://blog.balliskit.com/tutorial-sliver-c2-with-balliskit-macropack-and-shellcodepack-452e94c24b19  
- https://www.elastic.co/security-labs/doubling-down-etw-callstacks  
- Local: `/home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md`  
- Local: `/home/cup/Documents/personal/sliv/docs/SLIVER_UI_AV_OPSEC_RESEARCH.md`  
- Local: `/home/cup/Documents/personal/sliv/research_notes/Sliver UI AV OPSEC practices/loader_workflows.md`  
- Local: `/home/cup/Documents/personal/sliv/backend/internal/sliver/msf.go`  
- Local: `/home/cup/Documents/personal/sliv/backend/internal/sliver/implants_exec.go`  
