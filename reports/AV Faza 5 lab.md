# AV Faza 5 lab — 2026-11-17

> Authorized Windows lab on host `UALI` against WSL generator `172.25.180.27`.
> Artifact path: `C:\Users\AkalarPC\Downloads\phase5_lab\`

## Environment

| Field | Value |
|---|---|
| OS | Windows (UALI) + WSL2 Ubuntu |
| MDAV | Real-time on; cloud on |
| Listener | HTTPS `0.0.0.0:8443` (job 5); mTLS `*:8888` still up |
| HTTP C2 | `ms-update` saved (was missing; only `default` before) |
| Linux IP | `172.25.180.27` |
| Reachability | `Test-NetConnection 172.25.180.27:8443` → True |

## Code fixes applied this session (WSL)

1. **DiskDLL API wiring** — `handlers_loaders.go`: Windows PE default = disk LoadLibrary (`mingw-c-dll`); `rdi=true` keeps Unbacked PIC.
2. **`IsSharedLib` on generate** — `implants.go`: `format=shared` now sets `IsSharedLib=true` so `//export` + `main.c` DllMain render. Without this, DLL only exported `_cgo_dummy_export`.
3. **Defensive** `SliverSharedLibrary` sets `IsSharedLib=true` in `third_party/sliver` (needs server rebuild to take effect in compiler; UI RPC flag already enough).
4. **Exports in builders JSON** — `ImplantConfigView.Exports` for Loaders export name.
5. **Generate timeout** — 120s → 10m.
6. **Prior MinGW** — `#embed` → `.incbin`, `-std=gnu17` (uncommitted from earlier).

## Artifact

| Item | Value |
|---|---|
| Name | `OneDriveUpdater_lab.dll` + `OneDriveUpdater_lab_loader.exe` |
| SHA-256 (dll) | `55b82a0e1ca6e56646ff8b597dbe8d55e3b4924e248fdc40b962e8ddbe993541` |
| format / engine | shared + **mingw-c-dll** |
| Export | `BaZVGrAF` |
| HTTP C2 | ms-update |
| C2 URL | `https://172.25.180.27:8443` |
| Generate flags | `debug=true`, `obfuscate=false`, `polymorph=false` (garble+c-shared fails: `list runtime/cgo: not a dependency`) |

### String smoke (debug DLL)

| Needle | Count |
|---|---|
| sliverpb | 0 |
| GetJitter | 0 |
| cpmfczjv | 2717 |
| WgzBgfnsl | 1 |
| VoidFunc / DllRegisterServer | 0 |
| bishopfox | 6634 (expected: debug/no branding clean) |
| ScreenshotReq | 1 |
| Go buildinf: | present on earlier EXE; debug shared not rechecked as 0 |

## Runs

### A) DiskDLL loader EXE+DLL

| Field | Value |
|---|---|
| Session | no |
| Process life | ~2–3s |
| Exit | `0xc0000005` Access Violation |
| 1116 Name | none new for `phase5_lab` in this window |
| Note | MinGW host crashes even with `SLIV_BG=1`. No `sliv-loader.log` in lab-fast. |

### B) `rundll32.exe OneDriveUpdater_lab.dll,BaZVGrAF`

| Field | Value |
|---|---|
| Process life | >45s (alive) |
| C2 | HTTPS hits with UA `Microsoft-Delivery-Optimization/10.0` |
| Server log | `Started new session with http session id: 44728b11061538648ed02ef8f1b65896` |
| Then | repeated `Invalid data length` / `Failed to decode body unexpected EOF` |
| API `/api/sessions` | still `[]` |
| 1116 Name | none new for this artifact |

Path gen anomaly: URLs contain dozens of repeated `deliveryoptimization` segments (MaxPathGen/template interaction). Likely related to incomplete session registration.

## Decision tree

- **1116 oila YARA** — not observed on this `phase5_lab` pair in the last run window.
- **Session turadi** — **no** (HTTP transport session id appeared; implant never listed in Sessions).
- **Shift / bugs** — remaining engineering:
  1. MinGW DiskDLL host AV on call into Go export (rundll32 works → implant entry OK).
  2. garble + `-buildmode=c-shared` CGO break (blocks obfuscated shared).
  3. `ms-update` path explosion / `Invalid data length` on register.
  4. debug DLL still has `bishopfox` plaintext (Faza 4 smoke would fail branding).

## Next

1. Fix DiskDLL call/stack (or CreateThread like `main.c` `Start`) so EXE host matches rundll32.
2. Fix ms-update PathSegments / MaxPathGen; retest until `/api/sessions` non-empty.
3. Fix garble c-shared CGO; regenerate obfuscated shared; re-smoke.
4. Rebuild/install patched `sliver-server` so tree-level `IsSharedLib` defensive fix is permanent.

*No FUD claim. Lab incomplete until Sessions lists a live implant.*