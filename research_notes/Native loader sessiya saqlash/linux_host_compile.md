# Practical compile-on-Linux-host path for native Windows loaders

Read-only survey of this sliver-ui host plus vendor docs. No packages were installed. Goal: `POST /api/loaders/build` on a Linux UI server still returns a finished PE if the wrap language becomes native C (or C++/C#). Operators must not compile on a Windows box.

## Does this machine already have mingw-w64, zig, clang, wine, csc, dotnet?

### Takeaway
This Kali 2026.1 host already has MinGW-w64 GCC 15 for **Windows x86_64 and i686**, Wine 10 (64-bit only), Go 1.26, Clang 21 (Linux target), and an old .NET 6 SDK. It does **not** have `aarch64-w64-mingw32-gcc`, zig, llvm-mingw, `csc`, or wine32. A C wrap of `windows/amd64` and `windows/386` can compile here today; Windows ARM64 C cannot.

### Cited Findings
- Host identity: `PRETTY_NAME="Kali GNU/Linux Rolling"`, `VERSION_ID="2026.1"`, `ID_LIKE=debian`, kernel `6.18.12+kali-amd64`. — [Kali downloads / rolling](https://www.kali.org/); local `/etc/os-release`.
- `x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc` are on PATH (`/usr/bin/...`). Reported version string: `x86_64-w64-mingw32-gcc (GCC) 15-win32` and the same for i686. — [Debian gcc-mingw-w64 source](https://packages.debian.org/source/unstable/gcc-mingw-w64).
- Installed compiler packages (not the metapackage names): `gcc-mingw-w64-x86-64-win32` and `gcc-mingw-w64-i686-win32` version `15.2.0-12+28.3`, plus matching `*-win32-runtime`, `binutils-mingw-w64-{i686,x86-64}` `2.45.90.20260125-1+13.3`, headers `mingw-w64-{common,i686-dev,x86-64-dev}` `13.0.0-2`. — [gcc-mingw-w64-x86-64 (sid)](https://packages.debian.org/sid/gcc-mingw-w64-x86-64); [gcc-mingw-w64-i686 (sid)](https://packages.debian.org/sid/gcc-mingw-w64-i686).
- The **metapackages** `gcc-mingw-w64-x86-64` / `gcc-mingw-w64-i686` / `gcc-mingw-w64` are **not** installed. Apt candidates on this Kali rolling mirror are `16.2.0-1+29`. Those metapackages depend on both POSIX-thread and Win32-thread compiler flavors. This host only has the **win32** threading flavor. — [gcc-mingw-w64-x86-64 depends posix+win32](https://packages.debian.org/sid/gcc-mingw-w64-x86-64); [source package binary list](https://packages.debian.org/source/unstable/gcc-mingw-w64).
- `aarch64-w64-mingw32-gcc` is missing. `apt-cache search` on this host returned **no** `llvm-mingw` or `gcc-aarch64-w64` package. Debian gcc-mingw-w64 binaries listed on the source page are i686 / x86-64 / ucrt64, not Windows ARM64. — [gcc-mingw-w64 source binaries](https://packages.debian.org/source/unstable/gcc-mingw-w64); [llvm-mingw README: GCC does not support Windows on ARM](https://github.com/mstorsjo/llvm-mingw).
- `zig` is missing. No `zig` package in this host’s apt cache. Official Linux x86_64 tarball is 55 MiB (`zig-x86_64-linux-0.17.1.tar.xz`). — [Zig download](https://ziglang.org/download/).
- `wine` is `/usr/bin/wine`, version `wine-10.0 (Debian 10.0~repack-11+b1)`. Package `wine64` is installed; `wine32` is **not** (`un` / candidate none without i386). First `wine --version` printed `it looks like wine32 is missing, you should install it` and suggested `dpkg --add-architecture i386 && apt-get install wine32:i386`. The 64-bit loader binary lives at `/usr/lib/wine/wine64`; there is no `wine64` on PATH (Wine 10 uses `wine`). — [Wine User Guide](https://dl.winehq.org/wine/docs/en/wineusr-guide.html); [Debian wine](https://packages.debian.org/sid/wine).
- `csc` is missing (no Mono C# compiler on PATH).
- `dotnet` is `/usr/bin/dotnet`, SDK **6.0.400**, runtimes `Microsoft.NETCore.App 6.0.8` and `Microsoft.AspNetCore.App 6.0.8`. RID `linux-x64`. Native AOT is documented as a .NET 7+ publish model. — [Native AOT overview](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/).
- `clang` is Debian clang 21.1.8, `Target: x86_64-pc-linux-gnu`, `InstalledDir: /usr/lib/llvm-21/bin`. `--print-targets` includes `aarch64` and `x86-64` (LLVM backends), not a Windows sysroot. — [Clang](https://clang.llvm.org/).
- `go` is `go1.26.1 linux/amd64` (`/usr/lib/go-1.26`). Current loader builder requires this. — [build.go `lookGo`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go).
- Extra MinGW tools present: `x86_64-w64-mingw32-{windres,objcopy,strip,dlltool,ld}`. **No** `x86_64-w64-mingw32-g++` / `i686-w64-mingw32-g++`. Apt still offers `g++-mingw-w64-x86-64` / `g++-mingw-w64-i686` metapackages (candidate `16.2.0-1+29`). — [source package: g++-mingw-w64-*](https://packages.debian.org/source/unstable/gcc-mingw-w64).

### Inferences
- Product `LookPath` for a C wrap must search the **compiler binary** (`x86_64-w64-mingw32-gcc`), not the Debian metapackage name. This host would pass that check for amd64 and 386 even though `dpkg -l gcc-mingw-w64-x86-64` is empty.
- Clang on a typical Debian/Kali box is not a substitute for MinGW: it can codegen for x86_64/aarch64 but has no Windows headers/import libs unless llvm-mingw or mingw-w64-dev is wired as a sysroot.
- .NET 6 on this host can `dotnet publish -r win-x64 --self-contained` (managed cross-OS publish). It cannot honestly do Native AOT for Windows. `csc` is irrelevant; the SDK is `dotnet`.
- Wine 10 here is a 64-bit PE runner only. 32-bit PE tests will fail until wine32/i386 is added (assignment forbids installing).

### Gaps
- Exact unpacked size of llvm-mingw on disk was not measured (tarball not downloaded; install forbidden).
- `clang --target=x86_64-w64-windows-gnu` link error text was not recaptured after a zsh FLAGS-quoting bug aborted an earlier probe.

## Minimal C program cross-compile: WinMain, -mwindows, embed, size vs Go wrap

### Takeaway
On this host, `x86_64-w64-mingw32-gcc -s -Os -fno-ident -Wl,--gc-sections -mwindows` produces a **13 312-byte** GUI PE for empty `WinMain`. A PIC trampoline that `VirtualAlloc`s `xor eax,eax; ret` is **13 824 bytes**. The current Go wrap of the same 3-byte PIC is **1 559 040 bytes** (~120×). Payload embed via `.incbin` or `objcopy -I binary` adds the blob size with PE alignment (64 KiB payload → 78 848-byte PE). `-nostdlib` entry `WinMainCRTStartup` + `-lkernel32` shrinks to **3 584 bytes** and drops `msvcrt.dll`.

### Cited Findings
- `-mwindows` “specifies that a GUI application is to be generated by instructing the linker to set the PE header subsystem type appropriately.” Default MinGW is `-mconsole`. — [GCC Cygwin and MinGW Options](https://gcc.gnu.org/onlinedocs/gcc/Cygwin-and-MinGW-Options.html).
- `-s` “Remove all symbol table and relocation information from the executable.” — [GCC Link Options](https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html).
- `-fno-ident` “suppresses emission of `.ident` assembler directives and causes the `#ident` preprocessor directive to be ignored.” — [GCC invoke.texi / Code-Gen](https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html#index-fident).
- `objcopy -I binary` creates `_binary_<mangled>_start`, `_binary_<mangled>_end`, `_binary_<mangled>_size`. `--binary-symbol-prefix` can override the mangled name. Output target for this host’s 64-bit probe was `-O pe-x86-64 -B i386:x86-64`. — [GNU objcopy](https://sourceware.org/binutils/docs/binutils/objcopy.html).
- `-nostdlib` “Do not use the standard system startup files or libraries when linking.” Libraries after the object file are still used (`-lkernel32` must come **after** the `.c`). Linker processes left-to-right. — [GCC Link Options](https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html).
- This-host sizes (temp dir `/tmp/sliv-mingw-survey-f2dW`, GCC 15-win32, flags `-s -Os -fno-ident -Wl,--gc-sections -mwindows` unless noted):

  | Artifact | Bytes | `file(1)` |
  |---|---:|---|
  | empty `WinMain` GUI | 13 312 | PE32+ GUI x86-64, stripped, 9 sections |
  | empty `main` console | 13 312 | PE32+ console x86-64 |
  | empty `WinMain` `-static` | 13 312 | still imports `msvcrt.dll` |
  | PIC host (`VirtualAlloc` + `31 C0 C3`) | 13 824 | PE32+ GUI |
  | embed 3-byte array | 13 824 | PE32+ GUI |
  | embed 3-byte `objcopy` (`payload.bin`) | 13 824 | PE32+ GUI |
  | embed 3-byte gas `.incbin` | 13 824 | PE32+ GUI |
  | embed 64 KiB via objcopy (`payload64k.bin`) | 78 848 | 65 536 + 13 312 |
  | `-nostdlib` `WinMainCRTStartup` + `-lkernel32` | 3 584 | PE32+ GUI, 5 sections |
  | empty DLL + `StartW` | 11 264 | PE32+ DLL |
  | i686 empty `WinMain` | 14 848 | PE32 GUI i386 |
  | i686 PIC host | 14 848 | PE32 GUI i386 |
  | i686 nostdlib | 3 584 | PE32 GUI i386 |

- `file(1)` on the GUI binaries: `PE32+ executable for MS Windows 5.02 (GUI), x86-64 (stripped to external PDB), 9 sections`. Subsystem 5.02 is the MinGW default (Windows XP x64 era), not a modern Windows 10 subsystem. — local `file`; [MinGW `-mwindows`](https://gcc.gnu.org/onlinedocs/gcc/Cygwin-and-MinGW-Options.html).
- Default CRT on these Debian **win32** compilers is **`msvcrt.dll`**, not UCRT. `objdump -p empty_winmain.exe` imports `KERNEL32.dll` and `msvcrt.dll`. Strings include `Mingw-w64 runtime failure:` and `VirtualProtect`. `-static` did **not** remove `msvcrt.dll`. `-nostdlib` PE imports only `KERNEL32.dll`. — local objdump; [mingw-w64 UCRT vs MSVCRT](https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-doc/howto-build/ucrt-vs-msvcrt.txt); [GCC `-mcrtdll=`](https://gcc.gnu.org/onlinedocs/gcc/Cygwin-and-MinGW-Options.html).
- Upstream mingw-w64 12+ defaults new toolchains to UCRT unless `--with-default-msvcrt=msvcrt`. This host’s headers are mingw-w64 **13.0.0-2** but the linked CRT is still `msvcrt.dll`. — [ucrt-vs-msvcrt.txt](https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-doc/howto-build/ucrt-vs-msvcrt.txt).
- i686 GUI PE without `-static-libgcc` contains the string `libgcc_s_dw2-1.dll`. `-static-libgcc` still left that string in the 14 848-byte binary on this probe (size did not change). Wine does not ship that DLL. — local `strings`; [GCC `-static-libgcc`](https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html).
- Current Go wrap (`DUMP_PE` from `TestWindowsPEEncryptsPayload`, hide-console GUI, XOR embed + 4–24 KiB `n.bin`): **1 560 576 bytes**, `PE32+ executable for MS Windows 6.01 (GUI), x86-64, 8 sections`. Same 3-byte PIC via `TestPrintWrapSizes`: amd64 **1 559 040**, 386 **1 484 800**, arm64 **1 492 480**. — [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go); [loader_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go).
- Go builder flags today: `go build -trimpath -ldflags "-s -w [-buildid=…] [-H windowsgui]"`, `CGO_ENABLED=0`, `GOTOOLCHAIN=local`. — [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go).
- objcopy symbol pitfall: `payload.bin` → `_binary_payload_bin_start`; `payload64k.bin` → `_binary_payload64k_bin_start`. Linking `embed_incbin.c` (which declared `_binary_payload_bin_*`) against `payload64k.o` failed with undefined references. Gas `.incbin` with explicit `payload_start` / `payload_end` labels avoids the mangled name. — [GNU objcopy binary symbols](https://sourceware.org/binutils/docs/binutils/objcopy.html).
- `--gc-sections` only drops unused sections; without `-ffunction-sections -fdata-sections` it does little on a tiny TU. Empty WinMain and console `main` were the same 13 312 bytes. — [GCC `-s`](https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html).

### Inferences
- A native C wrap returns a PE in the **tens of kilobytes + payload**, not ~1.5 MiB. For a typical Donut/SGN blob of a few hundred KiB, the stub overhead is noise; the Go runtime is the dominant wrap size today.
- Default MinGW CRT is a detection surface: `msvcrt.dll` + `Mingw-w64 runtime failure:` + CRT `VirtualProtect` even when the stub never calls it. A product C template should either `-nostdlib` and import only the APIs it uses, or accept those strings as IOCs (the Go wrap already admits runtime `VirtualAlloc`/`CreateThread`/`kernel32.dll`).
- `-static` on this toolchain does **not** produce a fully static PE; it still links the msvcrt import lib. Do not document “static MinGW” as “no CRT DLL”.
- Hide-console maps to `-mwindows` (PE subsystem GUI), analogous to Go `-H windowsgui`. Console tests (Wine PIC) should keep `-mconsole` / omit `-mwindows`, matching current `HideConsole: false` in `TestExecuteWindowsPICWine`.
- Embed recommendation for generated stubs: gas `.incbin "payload.bin"` with product-chosen symbol names, not `objcopy -I binary` (filename-mangled symbols). Unsigned char array in C is fine for tiny PIC tests; it explodes source size for multi-MB implants (max payload is 64 MiB in `options.go`).
- `-Wl,--gc-sections` should be paired with `-ffunction-sections -fdata-sections` if the stub grows (persist + sandbox).

### Gaps
- Size of a **full** C port of `windows.go` (XOR names, NOACCESS→RW→RWX, 8 MiB stack, persist, HAL9TH, Sleep) was not compiled; only empty/PIC/embed probes.
- Effect of `-ffunction-sections -fdata-sections` on the 13 KiB PE was not measured.
- UCRT via `-mcrtdll=ucrt` / `gcc-mingw-w64-ucrt64` was not tried (ucrt64 compiler not installed).
- Authenticode / VERSIONINFO via `windres` (tool is present) was not probed.

## Windows arm64 from Linux: llvm-mingw, zig, or refuse

### Takeaway
Debian/Kali MinGW **cannot** target `aarch64-w64-mingw32`. The two practical Linux-host options are **llvm-mingw** (one toolchain, four Windows archs, ~80 MiB tarball) or **zig cc -target aarch64-windows-gnu** (~55 MiB). Neither is on this host. Product should keep the existing **Go wrap for `windows/arm64`** (already 1.49 MiB PE, tests pass) or refuse native-C arm64 with an explicit missing-toolchain error — not ask the operator’s Windows box to compile.

### Cited Findings
- llvm-mingw README: “Support for targeting ARM/ARM64 (while GCC obviously does support these architectures, **it doesn't support Windows on ARM**)”; “A single toolchain targeting all four architectures (i686, x86_64, armv7 and arm64)”. Linux cross packages are named `llvm-mingw-<version>-<crt>-ubuntu-<distro>-x86_64.tar.xz`. — [llvm-mingw README](https://github.com/mstorsjo/llvm-mingw).
- Latest llvm-mingw release `20261104` (LLVM 23.1.5) Linux x86_64 UCRT tarball: **84 104 244 bytes** (`llvm-mingw-20261104-ucrt-ubuntu-22.04-x86_64.tar.xz`). Ubuntu aarch64 host tarball: 78 090 360 bytes. Windows-native zip for x86_64 UCRT: 191 037 046 bytes. — [GitHub releases API / 20261104](https://github.com/mstorsjo/llvm-mingw/releases/tag/20261104).
- llvm-mingw defaults to **UCRT**, Windows 7+, PDB via `-gcodeview` + `-Wl,--pdb=`. Address Sanitizer is x86-only. Mixing object files with GNU MinGW CRT/C++ ABI is unsupported. — [llvm-mingw README](https://github.com/mstorsjo/llvm-mingw).
- Zig: “Zig builds for all supported targets independently of the host. There is no separate ‘cross toolchain’.” Example: `zig build-exe hello.zig -target x86_64-windows`. libc list includes `aarch64-windows-gnu`. Official overview shows a Windows hello at **4096 bytes** with `-O ReleaseSmall -fstrip -fsingle-threaded -target x86_64-windows`. — [Zig overview (cross-compiling)](https://ziglang.org/learn/overview); [Zig platform support: aarch64-windows is Tier 2](https://ziglang.org/intro/platform-support/).
- Zig as a C compiler: `zig cc -target x86_64-windows-gnu` / `zig c++ -target x86_64-windows-gnu`; Wails docs wrap `zig cc -target aarch64-windows-gnu` for Windows arm64. Linux x86_64 package is **55 MiB**. — [Zig overview](https://ziglang.org/learn/overview); [Zig 0.17.1 download](https://ziglang.org/download/); [Wails cross-platform build](https://wails.io/guides/build/cross-platform/).
- This host: `aarch64-w64-mingw32-gcc` missing; `zig` missing; no llvm-mingw in apt. Current Go builder **already** emits `windows/arm64` PE (test `TestBuildWindowsOtherArch`, size 1 492 480 for 3-byte PIC). — [loader_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go).
- Native AOT Windows Arm64 is **not** a Linux-host path: Native AOT “does not support cross-OS compilation.” Cross-arch on the **same OS** only (win-x64 host → win-arm64). — [Native AOT cross-compile](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/cross-compile).

### Inferences
- Do **not** block `windows/arm64` wraps if MinGW is missing: Go wrap already works from Linux with zero extra packages.
- If native C is the default for amd64, arm64 should either (1) stay on Go wrap automatically, or (2) require llvm-mingw **or** zig, detected by `LookPath("aarch64-w64-mingw32-gcc")` / `LookPath("zig")`. Mixing GNU MinGW amd64 objects with llvm-mingw arm64 is fine **per binary** (separate compiles); do not mix object files across toolchains in one link.
- Shipping llvm-mingw as a UI dependency (~80 MiB compressed, much more unpacked, four archs) is heavier than zig (~55 MiB) if the only missing target is arm64. Zig also covers amd64/i686 Windows C if MinGW is absent. llvm-mingw is the closer drop-in for existing C flags (`aarch64-w64-mingw32-clang` style triples).
- Product must not tell operators “install Visual Studio on your Windows box for ARM64.” That violates the compile-on-Linux-host constraint.

### Gaps
- No actual `zig cc -target aarch64-windows-gnu` or llvm-mingw compile on this host (tools absent; install forbidden). Wine cannot execute Windows ARM64 PE on this x86_64 box anyway.
- Unpacked llvm-mingw disk footprint not measured.
- Whether Kali/Debian will ever package llvm-mingw: no package in this apt cache as of the survey.

## C# from Linux: `dotnet publish -r win-x64`, hostfxr, Native AOT, AMSI

### Takeaway
C# is a bad default for this product. `dotnet publish -r win-x64 --self-contained` **does** cross-OS from Linux and produced a **71 386 826-byte / 227-file** tree here (hostfxr + `coreclr.dll` + `clrjit.dll` + many `api-ms-win-*.dll`). `PublishAot=true` on SDK 6.0.400 was **ignored** (same tree). Native AOT is a large native PE, needs a **Windows** (or matching-OS) SDK + C++ linker, and **cannot** be produced on Linux for `win-*`. AMSI’s documented Windows hosts are PowerShell/WSH/Office/UAC, not native EXE; CLR `Assembly.Load(byte[])` is an extra AMSI path that Native AOT removes by also removing the CLR.

### Cited Findings
- This host: `dotnet publish -r win-x64 -c Release --self-contained true` of an empty `net6.0` `OutputType=Exe` restored and published. Output dir `out-win`: **227 files, 71 386 826 bytes**. Largest: `System.Private.CoreLib.dll` 10 630 792, `System.Private.Xml.dll` 8 504 456, `coreclr.dll` 5 123 224, `clrjit.dll` 1 436 312. Same layout when `-p:PublishAot=true` was passed (SDK warning NETSDK1179 about `--self-contained`; AOT did not run). — local `/tmp/sliv-dotnet-fxbO`; [dotnet publish](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-publish).
- Native AOT “produces an app that's self-contained and that has been ahead-of-time compiled to native code”; “Native AOT apps don't use a just-in-time (JIT) compiler”; documented starting **.NET 7 and later**. Windows prerequisite is Visual Studio with **Desktop development with C++**. Publish example `dotnet publish -r win-x64 -c Release` on a machine with those prerequisites. Output “contains all the code needed to run in it, including a stripped-down version of the coreclr runtime.” — [Native AOT overview](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/).
- “**Native AOT does not support cross-OS compilation.** Cross-OS compilation with Native AOT requires some form of emulation, like a virtual machine or Windows WSL.” Cross-architecture only (x64↔arm64) on the **same** OS. — [Native AOT cross-compile](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/cross-compile).
- Native AOT limitations include “No dynamic loading, for example, `Assembly.LoadFile`” and “No runtime code generation.” Apps “include required runtime libraries (just like self-contained apps, increasing their size as compared to framework-dependent apps).” Supported Windows archs: x64 and Arm64 (.NET 8); x86 added in .NET 9+. — [Native AOT overview](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/).
- Independent size datapoints (not this host): a 2026 comparison table lists Native AOT publish size **13 MB** vs self-contained ReadyToRun **91 MB** for one sample; another article’s Linux container sample is ~11 MB compressed Native AOT. A large Azure MCP server Native AOT was **~194 MB on win-x64**. These are **not** 13 KiB MinGW stubs. — [Native AOT vs R2R vs JIT](https://startdebugging.net/2026/05/native-aot-vs-readytorun-vs-jit-in-dotnet-11/); [dotnet/runtime#125864](https://github.com/dotnet/runtime/issues/125864).
- Single-file self-contained: “The size of the single file in a self-contained application is large since it includes the runtime and the framework libraries.” “Only managed DLLs are bundled… the native binaries of the core runtime itself are separate files” unless `IncludeNativeLibrariesForSelfExtract=true`, which **extracts to `%TEMP%/.net` on Windows**. — [Single-file deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview).
- AMSI portal: integrated into UAC, **PowerShell**, Windows Script Host, JavaScript/VBScript, Office VBA. It does **not** list native EXE/PE load as an AMSI host. — [AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal).
- Community/.NET-tradecraft sources (not Microsoft product docs) state AMSI scans assemblies loaded via `Assembly.Load(byte[])` from .NET Framework 4.8 / PowerShell. Native AOT has no `Assembly.Load` and no JIT. That removes the **CLR AMSI** hook; it does not remove MDAV PE ML, SmartScreen, or memory scan of the native image. — [BorderGate: Assembly.Load & AMSI](https://www.bordergate.co.uk/assembly-load-amsi/); [S3cur3Th1sSh1t: PowerShell and the .NET AMSI interface](https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/).
- `csc` is the old csc/Mono compiler. This host has neither `csc` nor a modern `dotnet` SDK that implements Native AOT. Framework-dependent publish would require the operator’s Windows box to have a matching runtime — forbidden as a product path.

### Inferences
- Refuse C# as the **host-compile wrap language** unless the UI is willing to ship a ~70 MB directory or a huge single-file bundle, and to document CLR + AMSI + extraction-to-TEMP. That is worse than today’s 1.5 MiB Go PE on size, on file count, and on “one EXE download.”
- Native AOT does **not** solve “compile on the Linux UI host.” It requires a Windows (or matching-OS) C++ toolchain. Using it would **reintroduce** “compile on a Windows box” or a Windows VM — the opposite of the constraint.
- Honest AMSI note for the report writer: switching the wrap from Go/C to **managed** C# *adds* AMSI surface (`Assembly.Load`, PowerShell-style hosts if the stub uses them). Switching to **Native AOT** removes CLR AMSI and also removes Linux-host compile. Native C MinGW PE is outside AMSI’s documented host list (still fully in MDAV PE/memory scope).
- If C# is ever offered, require `dotnet` ≥ 8 on the UI host, refuse Native AOT for `win-*` from Linux, and refuse framework-dependent publish (operator would need a runtime).

### Gaps
- `PublishSingleFile=true` size for this hello was not measured (would still include native runtime files or extract them).
- No .NET 8/9 SDK on this host, so Native AOT failure mode for `win-x64` on Linux was not reproduced (docs already forbid it).
- Microsoft does not publish a first-party “Native AOT is/isn’t AMSI-scanned” statement; AMSI notes for AOT are inferred from “no Assembly.Load” + AMSI host list.

## C++: same MinGW, `-fno-exceptions -fno-rtti`

### Takeaway
C++ is the same cross-compiler family as C, plus `g++-mingw-w64-*` (not installed here). `-fno-exceptions` and `-fno-rtti` are the right size flags; they do not make C++ smaller than C if the stub is WinMain + Win32 APIs. Prefer **C** for the wrap. If C++ is used, require the g++ MinGW packages, pass those two flags, and still `-nostdlib`/`-fno-ident`/`-s`.

### Cited Findings
- This host has **no** `x86_64-w64-mingw32-g++`. Debian/Kali still package `g++-mingw-w64-x86-64` (depends `g++-mingw-w64-x86-64-posix` and `g++-mingw-w64-x86-64-win32`), candidate `16.2.0-1+29`. — [gcc-mingw-w64 source binaries](https://packages.debian.org/source/unstable/gcc-mingw-w64).
- libstdc++ documents `-fno-exceptions` and `-fno-rtti` as the dialect flags that shape the C++ library. — [libstdc++ using](https://gcc.gnu.org/onlinedocs/libstdc++/manual/using.html).
- `-fexceptions` “Enable exception handling. Generates extra code needed to propagate exceptions… GCC enables it by default for languages like C++ … and disables it for languages like C.” Inverse is `-fno-exceptions`. — [GCC Code Gen Options](https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html).
- `-fno-rtti` “Disable generation of information about every class with virtual functions for use by the C++ run-time type identification features (`dynamic_cast` and `typeid`). If you don’t use those parts of the language, you can save some space.” Mixing TUs with and without RTTI can fail to link. — [GCC C++ Dialect Options](https://gcc.gnu.org/onlinedocs/gcc/C_002b_002b-Dialect-Options.html).
- libstdc++ with `-fno-exceptions` rewrites `try`/`catch`/`throw` to `__try`/`__catch` abort-style helpers; user code that still uses `throw` will not compile. — [libstdc++ exceptions](https://gcc.gnu.org/onlinedocs/libstdc++/manual/using_exceptions.html).
- Zig can compile C++ for Windows without Debian g++: `zig c++ -target x86_64-windows-gnu`. — [Zig overview](https://ziglang.org/learn/overview).
- llvm-mingw uses **libc++** not libstdc++, and is “incompatible with object files and static libraries built with other toolchains.” — [llvm-mingw README](https://github.com/mstorsjo/llvm-mingw).

### Inferences
- A loader stub that is Win32 C APIs does not need C++. Adding g++ pulls libstdc++/libgcc exception machinery unless `-fno-exceptions -fno-rtti -static-libstdc++ -static-libgcc` (or `-nostdlib`). That is extra dependency for no product feature.
- If an operator later wants a C++ template, the product still compiles on Linux (g++-mingw or zig c++); it must not require MSVC.
- Do not mix llvm-mingw libc++ objects with GNU libstdc++ objects.

### Gaps
- No C++ PE size on this host (`g++` missing; install forbidden). Empty `WinMain` in C++ with those flags is expected near the 13 KiB C size if no STL is used — unverified here.

## Testing: Wine PIC trampoline, MinGW CRT, no Windows box

### Takeaway
Wine 10 on this host **did** run MinGW x64 GUI/console PEs, including the `xor eax,eax; ret` PIC host and `-nostdlib` PE, all exit 0. That is the same oracle as `TestExecuteWindowsPICWine` for Go. 32-bit PEs **cannot** be tested here (`wine32` missing → `ntdll.dll` `c0000135`). MinGW CRT PEs pull Wine’s `msvcrt` implementation; CRT-less PEs only need `kernel32`. Wine is not a Windows session and not Defender.

### Cited Findings
- Wine User Guide: run with `wine path/to/appname.exe`; Wine is a Windows API implementation (not a VM); supports Win64/Win32. `WINEARCH` selects `win32` (32-bit only) or `win64` (64-bit + WoW64). Debug via `WINEDEBUG`. — [Wine User Guide](https://dl.winehq.org/wine/docs/en/wineusr-guide.html).
- Current Go test: skip if `LookPath("wine")` fails; build 3-byte PIC `31 C0 C3` with `NameKey=0xC3`; `wine` with `SLIV_BG=1 WINEDEBUG=-all`; fail on timeout or non-zero. — [loader_test.go `TestExecuteWindowsPICWine`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go).
- This-host Wine runs (WINEDEBUG=-all, 20s timeout), all **exit 0**: `empty_winmain.exe`, `empty_main_console.exe`, `nostdlib.exe`, `pic_host.exe`, `embed_array.exe`, `embed_objcopy.exe`, `embed_incbin_asm.exe`.
- This-host 32-bit Wine runs **failed**: `wine: failed to load L"\\??\\C:\\windows\\syswow64\\ntdll.dll" error c0000135` / `ShellExecuteEx failed` for every i686 PE, including nostdlib and `-static-libgcc`. Matches missing `wine32`.
- MinGW CRT strings that Wine will load: `msvcrt.dll`, `Mingw-w64 runtime failure:`. Community writeups of MinGW-under-Wine sometimes need `WINEPATH` pointing at `libgcc` DLLs when those were dynamically linked. — [example MinGW+Wine PATH](https://andy6804tw.github.io//2024/08/31/wine-mingw-linux-cpp/).
- Wine is explicitly **not** “Windows session / callback.” Existing project notes already treat Wine `ret` as a trampoline oracle only. — [session_not_opening.md](file:///home/cup/Documents/personal/sliv/research_notes/Windows%20loader%20Defender%20sessiya%20muammosi/session_not_opening.md).

### Inferences
- Keep `TestExecuteWindowsPICWine` as the C-wrap gate: compile MinGW PE of `31 C0 C3` (or the generated C stub with that payload), run under `wine`, require return. Skip when wine missing (CI images may lack it).
- Add a **nostdlib** variant if the product C template drops CRT — CRT init under Wine is a different code path than `WinMainCRTStartup` → `ExitProcess`.
- Skip i686 Wine tests when `syswow64/ntdll` is absent; do **not** treat that skip as “32-bit wrap is broken.” Compile-only tests (`file` = PE32) still apply.
- Do not use Wine to test: persist (HKCU/schtasks), HAL9TH, 2 GiB RAM gate, GUI hide, or Donut implant callback.
- MinGW CRT under Wine is usually fine for x64 because Wine implements `msvcrt.dll`. Dynamic `libgcc_s_dw2-1.dll` is the classic 32-bit footgun — product i686 flags should force `-static-libgcc` (and verify with `objdump` that the DLL is gone; this host’s `-static-libgcc` still left the **string**).

### Gaps
- Whether Debian Wine 10 wow64 can run 32-bit PE *without* wine32 on other distros; this Kali package could not.
- Wine behavior of UCRT (`api-ms-win-crt-*.dll`) MinGW PEs was not tested (this toolchain linked msvcrt).
- No Wine run of the **full** Go wrap was repeated in this survey (`TestExecuteWindowsPICWine` already exists and this host has wine).

## Security of the compile sandbox (temp dir, no user C flags)

### Takeaway
Reuse the Go builder’s sandbox: `MkdirTemp("sliv-loader-*")`, `defer RemoveAll`, mutex, 3-minute `CommandContext`, argv of **fixed** compiler flags, generated source only. Never interpolate operator strings into the compiler command line. Never accept `cflags` / `extra_ldflags` JSON. `LookPath` an allowlisted basename. Do not invoke a shell.

### Cited Findings
- Current `Build`: `os.MkdirTemp("", "sliv-loader-*")`; `defer os.RemoveAll(dir)`; `compileMu` global mutex; `compileTimeout = 3 * time.Minute`; writes `go.mod`, `main.go`, `cfg.dat`/`payload.bin`, `n.bin`, jump asm; `exec.CommandContext(goBin, "build", "-trimpath", "-ldflags", ldflags, "-o", outPath, ".")` with `cmd.Dir = dir`. ldflags are concatenated from constants plus hex `BuildID`. — [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go).
- `lookGo()`: `exec.LookPath("go")` then `runtime.GOROOT()/bin/go`. Error: `Go toolchain not found on this host; install Go to compile loaders`. Handler maps `Build` error to **HTTP 500**. — [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go); [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go).
- User-controlled strings today: `Name`, `PersistName` through `sanitizeIdent` (strips non-identifier runes); `XORKey` via `strconv.Quote` in generated Go. Tests: `TestSanitizeStripsInjection`, `TestWindowsSourceQuotesUserStrings`. JSON body has **no** compiler-flag field. — [options.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/options.go); [loader_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go).
- `buildEnv` copies `os.Environ()` but strips `GOOS`/`GOARCH`/`CGO_ENABLED`/`GOTOOLCHAIN`, then sets those four. Operator/systemd env (`CFLAGS`, `CC`, `LD_PRELOAD`) still inherit. — [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go).
- Payload cap 64 MiB; JSON body cap 96 MiB. — [options.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/options.go); [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go).
- GCC/ld will honor injected flags like `-Wl,-wrap` / `@response-file` / `-fplugin=` if the product ever `sh -c`’s a user string. Fixed argv avoids that. — [GCC Link Options `-Wl`](https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html).

### Inferences
- C builder argv should be a Go `[]string` literal, e.g. `{gcc, "-s", "-Os", "-fno-ident", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections", "-mwindows", "-o", out, "loader.c"}` plus optional `payload.S`. Output path inside the temp dir only.
- Allowlist compiler base names: `x86_64-w64-mingw32-gcc`, `i686-w64-mingw32-gcc`, `aarch64-w64-mingw32-gcc` / `aarch64-w64-mingw32-clang`, `zig`. Reject `$CC` from the environment.
- Strip or ignore `CFLAGS`/`CXXFLAGS`/`LDFLAGS`/`GCC_EXEC_PREFIX`/`CPATH` when spawning gcc (tighter than today’s Go env copy).
- Generated C must quote/hex-escape user persist names the same way `xorQuote` does for Go; do not `sprintf` them into a shell `build.sh`.
- Keep `RemoveAll` even on compile failure so XOR’d payloads do not linger under `/tmp/sliv-loader-*`.
- Do not run `wine` in the production `Build()` path; wine is test-only (executes attacker PIC).

### Gaps
- Whether systemd `sliver-ui.service` `EnvironmentFile` currently sets `CFLAGS`/`CC` was not inspected in this survey.
- Landlock/seccomp for the compiler child is not in the current builder and was not designed here.

## Existing code: Go `build.go` and frontend `exeLoaderStub`

### Takeaway
Host-compile already exists and must stay Linux-side. The frontend C template is **gone**: `exeLoaderStub.ts` is only `xorPayload`. `POST /api/loaders/build` writes a temp Go module and returns a PE/ELF/Mach-O. A native C path should replace (or sit beside) `loader.Build`’s `go build`, not revive a ZIP-for-operator-to-compile flow.

### Cited Findings
- Route: `POST /api/loaders/build` → `handleLoaderBuild` → optional RDI → `loader.Build`. 400 on empty/truncated/EXE-as-PIC; 503 if RDI needs a Sliver client; 500 on compile error. — [server.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/server.go); [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go); [handlers_loaders_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders_test.go).
- Windows stub is generated Go (`windows.go`) plus `jump_windows_*.s`; tests forbid plaintext `CreateThread` / `VirtualProtect` in **source**, and admit Go runtime still contains those strings in the PE. — [windows.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/windows.go); [loader_test.go `assertNoLoaderIOCs`](file:///home/cup/Documents/personal/sliv/backend/internal/loader/loader_test.go).
- `frontend/src/lib/exeLoaderStub.ts` is four lines: XOR helper “Compile lives on the backend.” No `loader.c`, no `build.sh`. `zip.ts` is a generic STORE zip. Tests import `xorPayload` only. — [exeLoaderStub.ts](file:///home/cup/Documents/personal/sliv/frontend/src/lib/exeLoaderStub.ts); [zip.ts](file:///home/cup/Documents/personal/sliv/frontend/src/lib/zip.ts).
- AGENTS.md: backend is the Sliver client; UI work uses `make dev`; compile of loaders is on the UI host. — [AGENTS.md](file:///home/cup/Documents/personal/sliv/AGENTS.md).

### Inferences
- Do not resurrect “download ZIP, compile on Windows.” That contradicts the current product and this research constraint.
- Native C generation belongs in `backend/internal/loader/` next to `windows.go` (e.g. `windows_c.go` emitting `loader.c` + `payload.S`), sharing `Options` / `mintUniqueness` / RDI gating.
- IOC tests that scan the **PE** for `VirtualProtect` will **fail** on default MinGW CRT (this survey’s empty WinMain contains `VirtualProtect`). Either keep `-nostdlib` or relax PE-string tests for C wraps and keep them on generated source.
- Go wrap should remain the fallback when MinGW is missing (especially arm64), same as today’s `lookGo` fallback-to-error — but error instead of ZIP.

### Gaps
- Git history of the removed MinGW `loader.c` frontend template was not dumped in this survey (memory notes it existed as ZIP fallback).

## Debian/Ubuntu package names and dependency size

### Takeaway
Tell operators (and the UI error): `apt install gcc-mingw-w64-x86-64` for amd64, add `gcc-mingw-w64-i686` for 386. That is enough for C. g++ packages only if C++. Wine is **test-only**: `wine` + (for 32-bit) `wine32:i386`. Do not apt-install zig/llvm-mingw from Debian — they are not in this cache; fetch upstream tarballs. MinGW on this host already occupies on the order of **~800 MiB** installed for both arches; x64-only is still **~450 MiB**.

### Cited Findings
- Package names (Debian/Ubuntu/Kali):
  - `gcc-mingw-w64-x86-64` — metapackage, “GNU C compiler for MinGW-w64 targeting Win64”, depends posix **and** win32 flavors. Sid/forky: `16.2.0-1+29`; this host’s installed compiler is the win32 flavor `gcc-mingw-w64-x86-64-win32` `15.2.0-12+28.3`. — [gcc-mingw-w64-x86-64](https://packages.debian.org/sid/gcc-mingw-w64-x86-64).
  - `gcc-mingw-w64-i686` — same for Win32. — [gcc-mingw-w64-i686](https://packages.debian.org/gcc-mingw-w64-i686).
  - `gcc-mingw-w64` — both arches. — [gcc-mingw-w64 source](https://packages.debian.org/source/unstable/gcc-mingw-w64).
  - C++: `g++-mingw-w64-x86-64`, `g++-mingw-w64-i686`.
  - Headers pulled as deps: `mingw-w64-x86-64-dev`, `mingw-w64-i686-dev`, `binutils-mingw-w64-x86-64`.
  - Optional UCRT toolchain name in Debian: `gcc-mingw-w64-ucrt64` (listed on the source page; not installed here).
- This-host `dpkg-query -W Installed-Size` (KiB, ≈1024-byte units):

  | Package | KiB |
  |---|---:|
  | gcc-mingw-w64-x86-64-win32 | 153 491 |
  | gcc-mingw-w64-x86-64-win32-runtime | 63 570 |
  | gcc-mingw-w64-i686-win32 | 151 120 |
  | gcc-mingw-w64-i686-win32-runtime | 53 498 |
  | mingw-w64-x86-64-dev | 143 692 |
  | mingw-w64-i686-dev | 130 818 |
  | mingw-w64-common | 79 012 |
  | binutils-mingw-w64-x86-64 | 26 886 |
  | binutils-mingw-w64-i686 | 23 340 |
  | others (base, libz-mingw-w64) | ~0.9k |

  Sum of those MinGW rows: **826 316 KiB ≈ 807 MiB**. x64-only subset (drop i686 compiler/runtime/dev/binutils): **467 536 KiB ≈ 457 MiB**.
- Wine on this host: `libwine` **606 447 KiB ≈ 592 MiB** plus `wine-common` 11 065 KiB. That is a **test** dependency, not a production compile dependency. — [Debian wine](https://packages.debian.org/sid/wine).
- llvm-mingw Linux tarball **~80 MiB** compressed (see arm64 section). Zig Linux x86_64 **55 MiB**. — [llvm-mingw 20261104](https://github.com/mstorsjo/llvm-mingw/releases/tag/20261104); [Zig download](https://ziglang.org/download/).
- Metapackage `.deb` installed-size is tiny (263 KiB) because it is a dependency wrapper; the cost is the `*-win32` / `*-posix` / `*-dev` packages. — [gcc-mingw-w64-x86-64](https://packages.debian.org/sid/gcc-mingw-w64-x86-64).

### Inferences
- Docs/error string for operators: `install gcc-mingw-w64-x86-64` (Ubuntu/Debian/Kali). Optionally `gcc-mingw-w64-i686`. Do not require `mingw-w64` umbrella if only x64 loaders are sold.
- Do not apt-install Wine on the production UI host just to compile. Wine is CI/dev.
- Go is already required (~this host has 1.26). Native C **adds** ~0.5 GB disk if MinGW is not present. Zig is the small alternative if the host has no MinGW and you want amd64+arm64 Windows from one tarball.
- Prefer documenting the **binary name** in the UI (`x86_64-w64-mingw32-gcc`) so POSIX-vs-win32 alternatives still satisfy `LookPath`.

### Gaps
- Ubuntu LTS installed-size may differ from Kali rolling GCC 15; Debian bookworm is GCC 12. Treat 450–800 MiB as order-of-magnitude, not a promise.
- `posix` vs `win32` threading flavor: this host is win32-only; a full metapackage install would roughly double the compiler packages. Not measured.

## What the product should refuse if mingw is missing

### Takeaway
Refuse **native-C (and C++) Windows compile** with a 503-class error that names the missing binary and the apt package. Do **not** fall back to a ZIP for the operator’s Windows box. Do **not** fail `windows/arm64` if Go wrap still works. Do **not** accept user C flags. Do **not** attempt C# Native AOT for `win-*` from Linux.

### Cited Findings
- Current missing-Go behavior: `lookGo` error string, HTTP **500** from `handleLoaderBuild`. RDI-without-client is already **503**. Empty payload is **400**. — [build.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/build.go); [handlers_loaders.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders.go); [handlers_loaders_test.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/handlers_loaders_test.go).
- Frontend no longer ships a MinGW `loader.c` ZIP. — [exeLoaderStub.ts](file:///home/cup/Documents/personal/sliv/frontend/src/lib/exeLoaderStub.ts).
- Native AOT cannot cross-OS. — [Microsoft Native AOT cross-compile](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/cross-compile).
- Constraint: “Product must not require the operator's Windows box to compile.” — this assignment; current `Build` already compiles on the UI host.

### Inferences
Refuse (hard):
1. **Native C/C++ for `windows/amd64`** if `LookPath("x86_64-w64-mingw32-gcc")` fails (and `zig` is not an enabled fallback). Message: `MinGW-w64 gcc not found (need x86_64-w64-mingw32-gcc); on Debian/Ubuntu: apt install gcc-mingw-w64-x86-64`. HTTP **503** (missing host dependency), not 500.
2. **Native C for `windows/386`** if `i686-w64-mingw32-gcc` missing. Same pattern with `gcc-mingw-w64-i686`.
3. **Native C for `windows/arm64`** if neither `aarch64-w64-mingw32-gcc`/`clang` nor `zig` is present — **unless** the product keeps Go wrap for that arch (recommended). If Go is also missing, refuse the whole build with the existing Go error.
4. **Any `cflags` / `ldflags` / `extra_args` field** on the JSON body. Ignore or 400.
5. **Shelling out to `build.sh` written from user text.**
6. **C# Native AOT `win-*` from Linux.** 400/503 citing Microsoft’s no-cross-OS rule.
7. **Framework-dependent `dotnet publish`** (operator would need a runtime on Windows).
8. **ZIP + “compile this on your Windows box”** as the success path.
9. **Running `wine` inside `POST /api/loaders/build`.**

Allow / fallback:
- Go wrap for all GOOS/GOARCH when MinGW is missing (today’s path), if `go` exists.
- Compile-only success without Wine.
- Linux/Darwin wraps unchanged (they are not MinGW).

Detection at process start (optional): log which Windows C compilers were found so `/api/auth/me` or a loaders capability blob can disable the “native C” checkbox instead of failing at click-time.

### Gaps
- Product UX copy (en/zh i18n keys) for the 503 is not drafted here; i18n must be dual-listed when implemented.
- Whether to auto-fallback Go vs fail-closed when the operator explicitly asked for “native C” is a product choice; this note only forbids the Windows-box path.
