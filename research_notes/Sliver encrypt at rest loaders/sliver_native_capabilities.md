# Sliver native encrypt/encode capabilities (v1.5–1.7, focus 1.7.3)

Scope: what Sliver natively does at **generate** vs **stage** time for “encrypted on disk / decrypt in memory,” for shellcode, shared library, and executable formats. Sources: Sliver docs (module-embedded), BishopFox/sliver@v1.7.3 tree under `/home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/`, and related GitHub issues (2023–2026).

## Does `generate` encrypt the PE/DLL/shellcode blob at rest, or only obfuscate symbols (garble) / SGN-encode shellcode?

### Takeaway
`generate` does **not** encrypt EXE/DLL/service blobs at rest. It can garble symbols (`ObfuscateSymbols`), apply limited `Evasion`, and—for **shellcode format only**—optionally Donut-encrypt the embedded PE (Windows `entropy=3`) and/or post-process with a polymorphic shellcode encoder (SGN/XOR/XOR_DYNAMIC) that prepends a self-decoder. Raw PE/DLL downloads remain plaintext binaries.

### Cited Findings
- Official stance: AV evasion is **out of project scope**; Sliver is meant to interoperate with external packers/crypters/stagers — [Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion); local copy `/home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/docs/sliver-docs/pages/docs/md/Anti-virus Evasion.md`.
- `ImplantConfig` generate knobs include `Evasion`, `ObfuscateSymbols`, legacy `SGNEnabled`, `ShellcodeEncoder`, and `ShellcodeConfig` (Donut/beignet/malasada options)—**no** AES/RC4 encrypt fields on the implant config itself — [`protobuf/clientpb/client.proto`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/protobuf/clientpb/client.proto) (`ImplantConfig` / `ShellcodeConfig`).
- CLI: `--skip-symbols` disables symbol obfuscation; `--evasion` enables limited evasion; `--shellcode-encoder` and `--shellcode-*` only apply when `--format shellcode` — [`client/command/generate/commands.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/client/command/generate/commands.go).
- Symbol obfuscation is **garble** at compile time (`Obfuscation: config.ObfuscateSymbols` / `GOGARBLE`) for executable, shared lib, and shellcode build paths — [`server/generate/binaries.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/generate/binaries.go); garble binary is a bundled server asset — [`server/assets/assets-helpers.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/assets/assets-helpers.go).
- Windows shellcode path: compile PE → `DonutShellcodeFromFile(...)` with `ShellcodeConfig`; default Donut entropy is **none** (`DonutEntropyNone`) unless config sets 1–3 — [`server/generate/donut.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/generate/donut.go), [`binaries.go` `windowsShellcode`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/generate/binaries.go).
- Docs: `--shellcode-entropy`: `1=none, 2=random names, 3=random+encrypt` (**Windows only**); macOS/Linux shellcode currently only support `--shellcode-compress` among shellcode-* options — [Stagers docs](https://sliver.sh/docs?name=Stagers); local `docs/.../Stagers.md`.
- After RPC `Generate`, the **client** optionally runs `ShellcodeEncoder` on the returned shellcode bytes (SGN / XOR / XOR_DYNAMIC) before saving — [`client/command/generate/generate.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/client/command/generate/generate.go) (~L1728+) and [`helpers.go` `GetSliverBinary`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/client/command/generate/helpers.go).
- Shared library / executable formats: no Donut wrap and no shellcode encoder path; encoder flag is ignored with a warning when format ≠ shellcode — `parseShellcodeEncoderFlag` in `generate.go`.
- Payload format matrix (shellcode supported on windows/{386,amd64}, linux/{amd64,arm64}, darwin/arm64 only) — [Payload Compatibility](https://sliver.sh/docs?name=Payload+Compatibility).

### Inferences
- “Obfuscate” in Sliver UI/CLI ≈ compile-time symbol renaming (garble), **not** ciphertext-on-disk for the PE/DLL.
- True encrypt-at-rest of a downloadable EXE/DLL is **not** a native generate feature; operators must use external crypters/loaders (PEzor, custom stubs, etc., as docs point out).
- For shellcode, “encrypt at rest” is partial and format-specific: Donut entropy=3 encrypts the **module inside** the Donut loader (Windows); SGN/XOR produce **self-decoding** blobs (decoder stub + encoded payload), not a separate key the operator must store.

### Gaps
- Exact Donut AES/key layout for `entropy=3` is defined in `github.com/sliverarmory/wasm-donut` (v0.0.3 per `go.mod`); the module tree was not fully inspected beyond Sliver’s wrapper and proto comments—behavior is “symmetric encryption of module + random names” per Sliver docs/proto, not independently re-verified against Donut upstream here.
- Degree to which `Evasion` alone changes static PE signatures was not measured; authors explicitly de-scope AV bypass.

## Stage-listener AES/RC4 encryption of stage-2 — how it works, what the stager must do

### Takeaway
Stage encryption is applied **after** building the stage-2 implant (often shellcode): optional compress → AES-CBC (PreludeEncrypt, IV prepended) **or** RC4. The stager must download bytes, strip the 16-byte IV (AES), decrypt with the operator-supplied key/IV, optionally decompress, then allocate/execute. In v1.7.3, `stage-listener` client code effectively supports **TCP** staging; HTTP(S) stage-listener was reduced/removed on master (issue #2009)—HTTP serving of staged builds uses a different path (`profiles stage` / `implants stage` + HTTP C2 `stagerHandler`).

### Cited Findings
- Docs: compression `zlib` / `gzip` / `deflate` (level 9); encryption **AES-CBC-128** “primarily for obfuscation”; default IV `0000000000000000` if unset; example C# stager skips first 16 bytes then decrypts — [Stagers – Encrypted Stage Example](https://sliver.sh/docs?name=Stagers).
- `stage-listener` client (`jobs/stage.go`): generate via `GetSliverBinary` → compress → `util.PreludeEncrypt` or `RC4EncryptUnsafe` → for `tcp://` prepend 4-byte LE size and `StartTCPStagerListener`; non-tcp schemes print **Unsupported staging protocol** — [`client/command/jobs/stage.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/client/command/jobs/stage.go).
- BishopFox member TimBF (Oct 2025): on master, “stage-listener is really only used for tcp stage” after HTTP/HTTPS stage-listener broke — [GitHub issue #2009](https://github.com/BishopFox/sliver/issues/2009).
- `PreludeEncrypt`: PKCS7-pad, AES-CBC, output = `IV || ciphertext` (copies provided IV into first block); `PreludeDecrypt` reads IV from first 16 bytes — [`util/cryptography.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/util/cryptography.go). Comments: “vanilla AES… interoperability with Prelude”; “more advanced cipher modes are often difficult to implement in a stager.”
- `RC4EncryptUnsafe` explicitly marked cryptographically insecure; “Added for stage-listener shellcode obfuscation” — same file.
- Mutual exclusion: cannot set both AES and RC4 — `stage.go` and `GenerateStage` `Encrypt()`.
- AES key length must be multiple of 16; RC4 key 1–256 bytes — `stage.go` / `rpc-generate.go`.
- Parallel path **`profiles stage`** → RPC `GenerateStage`: build from profile → optional prepend size → compress → encrypt → `SaveStage` (stores encrypted bytes with a resource ID for later HTTP serve) — [`profiles-stage.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/client/command/generate/profiles-stage.go), [`server/rpc/rpc-generate.go` `GenerateStage`/`Encrypt`/`Compress`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/rpc/rpc-generate.go), [`SaveStage`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/generate/implants.go).
- Quirk: `GenerateStage` RPC response `File.Data` returns **pre-encrypt `fileData`**, while `SaveStage` persists **encrypted `stage2`** — `rpc-generate.go` L1142–1184 (UI/API consumers must not assume response bytes == staged-on-disk bytes).
- HTTP C2 `stagerHandler` serves builds marked `Stage=true` (from `StageImplantBuild` / `implants stage`) by resource-ID nonce in URL—writes payload bytes as stored (so encrypted if produced via `profiles stage`) — [`server/c2/http.go` `stagerHandler`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/c2/http.go); tutorial [4 - HTTP Payload staging](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/docs/sliver-docs/pages/tutorials/md/4%20-%20HTTP%20Payload%20staging.md).
- Docs still describe HTTP stage-listener + `.woff` default `stager_file_ext` and custom stager fetching `http://…/whatever.woff` — [Stagers](https://sliver.sh/docs?name=Stagers); HTTPS C2 docs list `.woff` = Stagers — [HTTPS C2](https://sliver.sh/docs?name=HTTPS+C2). This matches older 1.5.x behavior and the `profiles stage` + HTTP listener model more than current `stage-listener` TCP-only client code.
- Stager obligations (from docs + code): (1) fetch stage bytes; (2) if TCP/MSF, honor size prefix; (3) if AES, drop leading IV / decrypt CBC; (4) if compressed, decompress; (5) RWX alloc + execute. Stock MSF custom stagers do **not** decrypt AES—custom stager required when encryption is enabled.

### Inferences
- Stage AES/RC4 is the main **native** “encrypt blob at rest / on the wire, decrypt in stager memory” feature—and it applies to **stage-2 content** (any profile format built into the stage), not to a separate PE crypter for interactive `generate` downloads.
- For Sliver UI targeting 1.7: expose TCP `stage-listener` encryption clearly; for HTTP encrypted stages prefer **`profiles stage` + `implants stage` + HTTP(S) C2**, and do not assume `stage-listener --url http://…` still works on 1.7.3.

### Gaps
- Whether any 1.7.x patch re-adds HTTP to `stage-listener` after #2009 was not confirmed beyond 1.7.3 module contents (TCP-only switch).
- Exact nonce/URL shapes for `stagerHandler` vs tutorial `?x=implantID` examples differ slightly between docs eras; operators should verify against live HTTP C2 config (`stager_file_ext`, resource IDs).

## Donut options inside Sliver shellcode generation (encryption, AMSI) — what flags exist

### Takeaway
Windows shellcode generation uses **wasm-donut**. Tunables are exposed as `--shellcode-*` (deprecated hidden `--donut-*` aliases). Encryption-related: `--shellcode-entropy 3` = random names + symmetric encrypt of the module. AMSI/ETW-style bypass is Donut’s `--shellcode-bypass` (1=none, 2=abort on failure, 3=continue)—default **3**. Non-Windows shellcode (beignet/malasada) only meaningfully uses compression among these flags.

### Cited Findings
- Proto `ShellcodeConfig` maps Donut options; comments: Entropy `1=none, 2=random names, 3=random names + symmetric encryption (Windows/Donut only)`; Bypass `1=none, 2=abort on failure, 3=continue on failure (Windows/Donut only)`; also Compress, ExitOpt, Headers, Thread, Unicode, OEP — [`client.proto` ShellcodeConfig](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/protobuf/clientpb/client.proto).
- CLI flags (commands.go): `--shellcode-entropy` (default 1), `--shellcode-compress`, `--shellcode-exitopt` (default 1), `--shellcode-bypass` (default 3), `--shellcode-headers` (default 1), `--shellcode-thread`, `--shellcode-unicode`, `--shellcode-oep`; deprecated `--donut-*` hidden — [`commands.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/client/command/generate/commands.go).
- `normalizeDonutConfig` clamps Entropy/Compress/ExitOpt/Bypass/Headers into Donut ranges; defaults: entropy none, compress none, exit thread, bypass continue, headers overwrite — [`donut.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/generate/donut.go).
- Stagers doc lists the same shellcode options and notes Windows vs macOS/Linux support split — [Stagers](https://sliver.sh/docs?name=Stagers).
- Separate from Donut: in-session `ExecuteAssembly` / in-proc assembly RPCs have `AmsiBypass` / `EtwBypass` bools on **implant tasking**, not on generate — [`sliver.proto`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/protobuf/sliverpb/sliver.proto).

### Inferences
- Donut `bypass` is **loader-time** AMSI/WLDP/ETW handling inside the Donut stub when the shellcode runs—not a generate-time encrypt-at-rest control.
- `entropy=3` is the closest native “encrypt payload material inside shellcode” switch for Windows shellcode; the Donut stub holds/uses the key—no separate operator decrypt step when injecting the resulting `.bin`.

### Gaps
- Full Donut bypass flag semantics (which APIs patched) deferred to TheWover/Donut / wasm-donut docs; Sliver only passes through the integer enum.
- Whether `entropy=3` alone materially reduces AV detections was not evaluated (authors say AV is out of scope).

## ShellcodeEncoder (SGN, XOR, XOR_DYNAMIC) — encrypt-at-rest or polymorphic encode?

### Takeaway
These are **polymorphic encoders with embedded decoder stubs**: output is still runnable shellcode that decodes itself in memory. They are **not** keyed encrypt-at-rest requiring an external loader decrypt step. Available via RPC `ShellcodeEncoder` / `ShellcodeEncoderMap` and CLI `shellcode-encoders` / `--shellcode-encoder` on generate (shellcode format) and migrate.

### Cited Findings
- Enum: `NONE`, `SHIKATA_GA_NAI`, `XOR`, `XOR_DYNAMIC` — [`client.proto`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/protobuf/clientpb/client.proto).
- Arch map in 1.7.3: amd64 → xor, xor_dynamic, shikata_ga_nai; arm64 → xor, xor_dynamic; 386 → shikata_ga_nai only — [`server/encoders/shellcode/shellcode.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/encoders/shellcode/shellcode.go).
- SGN wraps `github.com/moloch--/sgn` with iterations, bad chars, max obfuscation, safe mode — [`server/encoders/shellcode/sgn/sgn.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/encoders/shellcode/sgn/sgn.go).
- XOR/XOR_DYNAMIC (amd64) based on Metasploit-style encoders: generate key, XOR payload, emit decoder + encoded payload (Keystone-assembled stubs) — [`server/encoders/shellcode/amd64/xor.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/encoders/shellcode/amd64/xor.go) (copyright header notes Metasploit lineage).
- RPC applies encoder with iterations (default 1) and bad chars; does not take an operator-supplied long-term key — [`server/rpc/rpc-shellcode.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/server/rpc/rpc-shellcode.go).
- Legacy `SGNEnabled` maps to `SHIKATA_GA_NAI` when `ShellcodeEncoder` is NONE — client generate/helpers paths.
- Also usable on migrate (`MigrateReq.Encoder`) — `client.proto` `MigrateReq`.

### Inferences
- For UI wording: label as **“Encode shellcode (polymorphic)”**, not “Encrypt payload.” Encoded shellcode is still a single injectable blob.
- Encoding is **shellcode-only**; cannot SGN-encode a raw EXE/DLL without first converting to shellcode (Donut/RDI/external).

### Gaps
- Empirical AV bypass efficacy of SGN/XOR in 2025–2026 not researched here.
- Whether server-side generate ever auto-encodes without client post-process: encoding is applied in the **client** after `Generate` returns; a raw RPC `Generate` consumer that skips client logic would get unencoded Donut/malasada/beignet output even if `ShellcodeEncoder` is set on the config (config field is advisory for client post-process / profile storage).

## GenerateStage / profiles — any encrypt fields?

### Takeaway
Yes—on **`GenerateStageReq` / `profiles stage`**, not on normal `GenerateReq`. Fields: `AESEncryptKey`, `AESEncryptIv`, `RC4EncryptKey`, `PrependSize`, `Compress`. Implant profiles themselves store shellcode encoder / Donut config / obfuscate flags, but **not** AES/RC4 stage keys.

### Cited Findings
- `GenerateStageReq` fields as above — [`client.proto`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/protobuf/clientpb/client.proto).
- CLI `profiles stage`: `--aes-encrypt-key`, `--aes-encrypt-iv`, `--rc4-encrypt-key`, `--prepend-size`, `--compress` — [`commands.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/client/command/generate/commands.go), [`profiles-stage.go`](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/client/command/generate/profiles-stage.go).
- Processing order: build (exe/shared/shellcode per profile) → optional size prepend → compress → encrypt → save staged build — `GenerateStage` in `rpc-generate.go`.
- Tutorial: “encoding or encrypting our payloads before exposing them externally using the `profile stage` command” — [HTTP Payload staging tutorial](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/docs/sliver-docs/pages/tutorials/md/4%20-%20HTTP%20Payload%20staging.md).
- `stage-listener` duplicates compress/encrypt client-side before TCP listen (does not call `GenerateStage` RPC); uses `GetSliverBinary` which **does** apply shellcode encoder from profile — `jobs/stage.go` + `helpers.go`.

### Inferences
- Profile = blueprint for **how to build** the implant; stage encrypt keys are **per stage operation**, not persisted as profile crypto fields (operators must remember/show keys when starting staging).
- UI should treat stage encryption keys as ephemeral secrets shown once (aligned with local plan doc).

### Gaps
- Whether compressed+encrypted stage order interacts badly with some community stagers (compress-then-encrypt is what Sliver does; stagers must decrypt-then-decompress) is documented by community posts but not exhaustively matrix-tested here.

## Clear statement: can Sliver UI expose a single “encrypt payload” checkbox on generate for exe/shared/shellcode?

### Takeaway
**No.** A single generate-time “encrypt payload” checkbox would be misleading. Native encrypt-at-rest exists for **staging** (AES/RC4) and partially inside **Windows Donut shellcode** (`entropy=3`). EXE/shared require an **external loader/crypter** (or stage-0 stub) for true encrypt-on-disk / decrypt-in-memory. Shellcode “encoders” are polymorphic self-decoders, not keyed encryption.

### Cited Findings
- Authors: AV evasion out of scope; use packers, crypters, stagers — [Anti-virus Evasion](https://sliver.sh/docs?name=Anti-virus+Evasion).
- Generate path has obfuscation + shellcode-only Donut/encoder knobs; stage path has AES/RC4 — proto + `generate`/`profiles stage`/`stage-listener` as cited above.
- Local product plan already separates compile-time Obfuscate/Evasion from loaders/encoders/stage-listener — [`docs/LOADER_AV_OPSEC_PLAN.md`](file:///home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md).
- External tooling explicitly recommended in docs (PEzor, Veil) — Anti-virus Evasion.md.

### Inferences
- **Recommended UI mapping (native only):**
  | Format | Native “at rest” crypto? | Honest UI control |
  |--------|--------------------------|-------------------|
  | Executable / Service | No | Obfuscate symbols; Evasion; link to external crypter/loader docs |
  | Shared library | No (optional later RDI→shellcode then encode) | Same; “Convert via RDI / generate shellcode” CTA |
  | Shellcode | Donut entropy=3 (Win); SGN/XOR self-decode | Separate toggles: “Donut entropy/encrypt module”, “Shellcode encoder” |
  | Stage-2 serve | AES-CBC or RC4 (+ compress) | On stage-listener / profiles-stage flows only; show key/IV; require decrypting stager |
- Implementing one checkbox that silently no-ops on EXE/DLL would violate the plan’s honesty gate.

### Gaps
- Community crypter integration (PEzor, etc.) remains external—out of Sliver RPC; UI can only document or shell out later as a plugin.

## Quick reference — native vs external (2023–2026)

| Capability | Native in Sliver 1.5–1.7? | Where |
|------------|---------------------------|--------|
| Garble symbol obfuscation | Yes | `generate` / profiles (`ObfuscateSymbols`) |
| Evasion hooks overwrite | Yes (limited) | `generate --evasion` |
| Encrypt EXE/DLL file on disk | **No** | External crypter/loader |
| Donut module encryption (`entropy=3`) | Yes (Windows shellcode) | `ShellcodeConfig.Entropy` |
| Donut AMSI bypass mode | Yes (Windows shellcode) | `ShellcodeConfig.Bypass` |
| SGN / XOR / XOR_DYNAMIC | Yes (shellcode blob) | `ShellcodeEncoder` RPC + client post-process |
| Shellcode RDI (DLL→PIC) | Yes | `ShellcodeRDI` RPC |
| Stage AES-CBC / RC4 + compress | Yes | `stage-listener` (TCP in 1.7.3), `profiles stage` / `GenerateStage` |
| HTTP(S) stage-listener | **Broken/removed on 1.7 master**; use TCP listener or `profiles stage` + HTTP C2 | Issue #2009; `jobs/stage.go` |
| Custom decrypting stager | **External** (docs provide C# samples) | Operator-written |
| Packers (PEzor, Veil, LLVM obfuscators) | **External** | Docs links |

## Source index

- https://sliver.sh/docs?name=Stagers
- https://sliver.sh/docs?name=Anti-virus+Evasion
- https://sliver.sh/docs?name=Payload+Compatibility
- https://sliver.sh/docs?name=HTTPS+C2
- https://github.com/BishopFox/sliver/issues/2009
- Module tree: `/home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/` (notably `docs/.../Stagers.md`, `server/generate/{donut,binaries}.go`, `server/rpc/rpc-{generate,shellcode,stager}.go`, `client/command/jobs/stage.go`, `client/command/generate/{generate,helpers,profiles-stage,commands}.go`, `util/cryptography.go`, `server/encoders/shellcode/`, `protobuf/clientpb/client.proto`)
- Local plan: `/home/cup/Documents/personal/sliv/docs/LOADER_AV_OPSEC_PLAN.md`
