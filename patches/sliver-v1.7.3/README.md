# Sliver v1.7.3 generator patches

`third_party/sliver/` is gitignored. **Read these files** — they are the compiler edits.

0001–0003 are one-time IOC cuts. **0004–0006 are the real idea:** every
`Generate` / `GenerateStage` mutates the implant **before** `go build`.

Applied by `go run ./backend/cmd/sliverpatch -root third_party/sliver -generator`
(or `make sliver-server`).

## 0001 `server/generate/donut.go` — Donut AMSI bypass off

Stock default is Donut **Continue** (3). That path is the well-known
`Win32/AMSI_Patch_T.B13` stub. We set the compiler default to **none** (1).

The UI already sends `shellcode_bypass=1` on generate. This patch covers CLI
`generate` and any RPC that leaves Bypass unset.

## 0002 `client/command/generate/commands.go` — exports StartW only

Stock CLI default exports:

`StartW,VoidFunc,DllInstall,DllRegisterServer,DllUnregisterServer`

`VoidFunc` / COM registration names are family IOCs (Fortbridge / Elastic).
Default becomes **StartW** (what disk LoadLibrary calls). The RPC path already
fills `Exports=["StartW"]` when empty (`server/rpc/rpc-generate.go`).

## 0003 `implant/sliver/runner/runner.go` — inline max-errors

Stock implant calls `transports.GetMaxConnectionErrors()`. Elastic rule
`Multi_Trojan_Sliver` matches that call-site bytecode. The three call sites
now use the compile-time template `{{.Config.MaxConnectionErrors}}` instead.

## 0004 `server/rpc/rpc-generate.go` — per-generate polymorph

Instead of hardcoding `Exports=["StartW"]`, `Generate` and `GenerateStage`
call `generate.PolymorphConfig`.

## 0005 `server/generate/binaries.go` — random import disguise

Stock always rewrites `implant/sliver` → `runc/cgroup` (a stable AV fingerprint).
Each compile now uses two random path segments.

## 0006 `server/generate/polymorph.go` — **per implant build**

Each generate (unless Debug):

- `ObfuscateSymbols = true` (garble `-seed=random -literals -tiny`)
- unique `GoPackage` `github.com/<8>/<8>` (not always `github.com/google/gvisor`)
- unique shared-lib export (8-letter ident, not `StartW`)

The UI wrap reads `ImplantConfig.Exports[0]` for disk LoadLibrary.

## Full proto family rename (`proto-idents.json` + `name-map.json`)

166 implant protobuf identifiers (sliverpb/dnspb, length ≥ 8) are rewritten
to **random same-length names** with a shared seed (`seed.hex`). The same map
is applied to sliver-server **and** this UI so sessions still open.

Example (seed `a1b2c3d4e5f60718a1b2c3d4e5f60718`):

| stock | random |
|---|---|
| GetJitter | WgzBgfnsl |
| ScreenshotReq | IaxwcbkpqzZew |
| HTTPSessionInit | ZXTFWukekelUfqv |
| InvokeSpawnDllReq | YnbicuEhswlZdvNkk |

`make sliver-server` applies this every time (stable seed unless you delete
`third_party/sliver/.sliverui-seed`). Per-generate still also randomizes
garble seed, Go package path, DLL export, and import disguise.

## Package path morph (`-proto-pkg`)

Same-length rename of protobuf **package path** identifiers `sliverpb` (8)
and `dnspb` (5), plus the matching directories (`protobuf/sliverpb`,
`protobuf/dnspb`, and copies under `implant/vendor`). Needles are always
the stock names, so re-apply is idempotent.

## What this does **not** change

- Short names (`Ps`, `Cd`, `Rm`) and stdlib collisions (`FileInfo`).
- Garble: already `-seed=random` when Obfuscate is on.
- A running stock `sliver.service` on the machine. Rebuild/install the
  bundled `sliver-server` (`install.sh --with-server`) to generate from
  this compiler.
