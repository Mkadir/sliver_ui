# Native loader architecture (coordinator fill)

The architecture researcher 403'd on a "how to write a native loader" prompt. This note is product architecture from local stub + cited public docs. It is not a PoC.

## Current Go stub (what a naive C port would copy)

`backend/internal/loader/windows.go` + `jump_windows_*.s`:

1. `hideWindow` (ShowWindow/FreeConsole)
2. computer name `HAL9TH` exit
3. RAM ≥ 2 GiB
4. Sleep 1800 ms + GetTickCount skip
5. optional persist
6. `VirtualAlloc` PAGE_NOACCESS reserve → RW commit, chunk copy, XOR decrypt **in the allocation**
7. `VirtualProtect` **RWX (`PAGE_EXECUTE_READWRITE` = `1<<6` / 0x40)**
8. `FlushInstructionCache`
9. 8 MiB RW stack, `CALL` (no `CreateThread`), then `Sleep(INFINITE)` hang

Tests **require** RWX so Donut/SGN can self-modify. Go runtime IAT still has `kernel32.dll` / `VirtualAlloc` / `CreateThread`. Unique SHA-256 is hash-IOC only.

A line-for-line C translation keeps the **same execution shape**: unbacked private memory, protect-flip, in-process CALL of Sliver PIC. Elastic labels that `unbacked_rwx` / `allocate_shellcode`; Fortbridge still flagged `LoadLibraryExW` from unbacked memory after string scrub ([Elastic: Doubling Down](https://www.elastic.co/security-labs/doubling-down-etw-callstacks); [Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/); [Microsoft 2017 reflective DLL](https://www.microsoft.com/en-us/security/blog/2017/11/13/detecting-reflective-dll-loading-with-windows-defender-atp/)).

## Layer map (A stub disk/ML, B emulator, C live session)

| Design choice | A stub PE | B emulator | C live Sliver in RAM |
|---|---|---|---|
| Language Go → MinGW C | **Yes** — drops `gopclntab` / unsigned-Go Wacatac shape ([Formidable](https://formidable.tools/posts/defender-wacatac-go-binary/); [Praetorian](https://www.praetorian.com/blog/llm-edr-signature-reduction/)) | Weak | **No** — implant still Go + `sliverpb` |
| `-mwindows`, no CRT (`-nostdlib`) | Smaller IAT, fewer MinGW strings | Weak | No |
| XOR embed + per-build pad | Hash-IOC | Weak | No after decrypt |
| Sleep+tick, HAL9TH, 2 GiB | No | Toy emulator | No |
| RW → **RX** instead of RWX | Less `unbacked_rwx` | Some | Donut/SGN may break; PEzor `-rx` is incompatible with `-sgn` on self-inject ([PEzor README](https://github.com/phra/PEzor)) |
| Keep RWX | Donut/SGN write window | — | **Raises** unbacked-exec |
| No CreateThread, local CALL | Fewer CRT/Sysmon 8 | — | ETW-Ti ALLOCVM/PROTECTVM still fire |
| Direct/indirect syscalls in-tree | IAT cleaner | — | Elastic `direct_syscall`; public stubs rot; **out of product** (same class as Freeze) |
| Payload in `.text` vs `.data`/overlay | Entropy / section heuristics | Weak | No |
| **Disk `LoadLibrary` of `format=shared` DLL** | Host is a tiny native EXE or signed sideload | Weak | **Only Fortbridge-cited path** that beat unbacked LoadLibraryExW — still needs string-clean implant |
| DLL sideload into signed host | Form factor | Weak | MEM_IMAGE vs MEM_PRIVATE; implant strings remain unless fork |
| Module stomping | — | — | Fortbridge **dropped** at ~30 MB Go |
| Sleep mask in stub | — | — | Stub does not own Sliver sleep; stock has none ([#1171](https://github.com/BishopFox/sliver/discussions/1171), [#1805](https://github.com/BishopFox/sliver/pull/1805)) |

## Recommended product shape if we leave Go wrap

**Primary artifact:** MinGW-w64 C, Linux host `x86_64-w64-mingw32-gcc`, subsystem WINDOWS, optional `-nostdlib` + `kernel32`/`user32` imports only.

**Two operator paths (honest labels):**

1. **PIC path (today's wrap, language swap):** `format=shellcode` XOR blob → RW alloc → decrypt → protect **RX if encoder NONE, RWX if SGN/Donut entropy-write** → same-thread CALL → hang. Helps **A**. Does not claim **C**.
2. **Disk DLL path (Fortbridge-shaped):** generate `format=shared`, do **not** RDI into unbacked PIC. Tiny C EXE (or operator-supplied signed host) calls `LoadLibraryW` on the DLL sitting on disk next to it. Sliver `DllMain` is inert unless `RunAtLoad`; export **StartW** must be `GetProcAddress` + call. Helps **C** only together with implant string/protobuf work **outside** this UI.

**Do not ship as default:** AMSI/ETW byte patches, in-tree syscalls, defendnot, ScareCrow templates, FUD copy.

## Permissions (Microsoft constants)

[Memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants):

- `PAGE_READWRITE` (0x04) — decrypt
- `PAGE_EXECUTE_READ` (0x20) — RX execute
- `PAGE_EXECUTE_READWRITE` (0x40) — RWX; current stub; highest unbacked-exec signal
- `PAGE_NOACCESS` (0x01) — current reserve; some emulator skip; Elastic `hidden_code` class exists

PEzor documents RW alloc then RX as `-rx`; default examples are still RWX self-inject. SGN needs writable code.

## Form factor

| Output | Compile | Operator |
|---|---|---|
| EXE (PIC wrap) | mingw `-mwindows` | drop + run |
| EXE + sibling DLL | mingw EXE `LoadLibrary` | two files; unsigned DLL still scanned |
| DLL only | mingw `-shared` | sideload docs; no in-tree signed-host pack |

## Unique hash without Go `-buildid`

Random 16-byte nonce in XOR key, 4–24 KiB `.bin` pad, timestamp in unused PE field or appended overlay. Same honesty: hash-IOC.

## Compile-on-Linux (see linux_host_compile.md)

Debian packages: `gcc-mingw-w64-x86-64`, `gcc-mingw-w64-i686` ([mingw-w64 downloads](https://www.mingw-w64.org/downloads/)). Windows arm64: llvm-mingw / `zig cc -target aarch64-windows-gnu`. If missing, refuse that arch or keep Go wrap as fallback **with UI copy that Go PE ML remains**.

Wine can smoke-test `xor eax,eax; ret` like today's Go test.

## Product ranking for "sessiya ochilgach Defender o‘ldiradi"

1. Native C stub is justified to stop **Go-PE ML on the wrap** (A).
2. It does **not** replace implant work for (C).
3. The only in-scope loader architecture change that maps to (C) in 2025 papers is **disk-backed DLL load** plus a cleaned Sliver (external fork / protobuf rename) — not a C `VirtualAlloc`+CALL of stock `sliverpb`.
