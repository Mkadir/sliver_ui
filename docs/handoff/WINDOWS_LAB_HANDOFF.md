# Windows lab handoff — Sliver UI (sliv) AV layers

> Maqsad: shu faylni Windows 10/11 lab mashinasida Grok (yoki boshqa agent) ga berib **Faza 5** ni davom ettirish.
> Yozilgan: 2026-11-16. Repo: `Mkadir/sliver_ui`, branch `feat/ui-auth-opsec-installer`.
> Parollar / private key **yo‘q**. Auth: lab hostdagi `~/.config/sliver-ui/env` (Linux) yoki o‘zingizning lab credential.

---

## 1. Loyiha nima

**Sliver UI (`sliv`):** React+Vite frontend + Go backend (`sliverui`). Backend Sliver C2 gRPC klienti; `make build` bilan UI embed.

- Linux host (generator): UI `:8080`, patched `sliver-server` `:31337`, profile **`sliverui`**
- Windows lab: implantni ishga tushirish + Defender Protection History / Event **1116** Name yozish

Authorized red-team / lab. FUD / VT 0/70 da’vo qilinmaydi.

---

## 2. Chat / session qayerda

| Narsa | Joy |
|---|---|
| Sanitized transcript (user+assistant) | `docs/handoff/CHAT_TRANSCRIPT_SANITIZED.md` |
| To‘liq reja Faza 0–6+ | `docs/AV_LAYERS_CLOSE_PLAN.md` |
| AV detection tadqiqoti | `reports/AV detection of Sliver implants.md` (+ `.uz.md`) |
| Xom compaction (~10MB, 16 segment) | Linux: `~/.grok/sessions/.../01a1dc3e-.../compaction/` |
| Session plan (approved) | session `plan.md` — mazmuni `AV_LAYERS_CLOSE_PLAN.md` da |

Bu handoff **operatsion xulosa**. Har bir tool call ning xom dump i emas.

---

## 3. Nima qilingan (Faza 0–3 ✅)

### Detection thesis (tadqiqot)

AV bitta hash emas — olti qatlam: disk YARA, Go PE-ML, **xotira YARA**, ETW-Ti/Unbacked, behavior/C2 ML, default HTTP fingerprint. Unique hash / XOR / C wrap callback da tugaydi. Format tanlovi: disk `LoadLibrary` → `MEM_IMAGE` vs PIC `VirtualAlloc` → Unbacked.

### Kod

| Faza | Natija |
|---|---|
| 0 | Windows default `format=shared`; HTTP `default` profile generate **400**; PsExec `OneDrive Updator`; Loaders disk DLL = MEM_IMAGE |
| 1 | Proto package morph: `sliverpb`→`cpmfczjv`, `dnspb`→`pnwlb` (substring + pb.go hex rawDesc). Server `strings \| rg sliverpb` → **0** |
| 2 | Yangi install CA CN `workgroup` / mtls `application`. Live `~/.sliver` CA **aylantirilmagan**. GetSystem nil-guard `ms-update` |
| 3 | Advanced placeholder `RuntimeBroker.exe`; CRT warn i18n; CLI notepad→RuntimeBroker generator patch |

### Seed / mapping (lockstep)

```
seed.hex = a1b2c3d4e5f60718a1b2c3d4e5f60718
GetJitter     → WgzBgfnsl
sliverpb      → cpmfczjv
dnspb         → pnwlb
```

Apply: `scripts/build-sliver-server.sh` (`-needles proto-idents.json` + `-proto-pkg`). Ikki marta morph qilmaslik uchun stock needles.

### Jonli Linux (oxirgi holat)

- Unit: `sliver.service` + `sliver-ui.service`, `User=cup`
- Binary: `~/.local/share/sliver-ui/bin/sliver-{server,ui,client}`
- Profile: `sliverui` (`~/.sliver-client/configs/sliverui.cfg`)
- Data: `~/.sliver` (v1.7.3)
- UI: `127.0.0.1:8080` — auth `SLIVER_UI_USER` / `SLIVER_UI_PASS` env faylda
- Proto live: `sliverpb=0`, `cpmfczjv≈3994`, `GetJitter=0`, `WgzBgfnsl=7`

### Muhim teshik (Faza 5 oldidan)

Oxirgi inventarda HTTP C2 profiles = **`['default']` only**. UI generate `default` ni bloklaydi → labdan oldin **`ms-update` ni serverga Save** qilish shart (`HttpC2` page yoki API). Template: `frontend/src/lib/httpC2Templates.ts`.

---

## 4. Operator yo‘li (lab)

```text
1. Linux: HTTPS listener (VM yetadigan IP:port). :443 uchun setcap yoki port ≥1024.
2. Linux: HTTP C2 → save ms-update; generate windows/amd64 shared, polymorph on, profile ms-update.
3. Linux: Loaders → disk LoadLibrary → EXE + sibling DLL.
4. Windows 10 yoki 11: EXE+DLL bir papka, MDAV cloud yoqilgan, run EXE.
5. Yozish: sessiya? · jarayon umri · Event 1015/1116/1117 · Protection History Name
```

Shellcode + C PIC = Unbacked — default lab yo‘li **emas**.

### Generate JSON (namuna)

```json
{
  "name": "OneDriveUpdater_lab",
  "os": "windows",
  "arch": "amd64",
  "format": "shared",
  "polymorph": true,
  "obfuscate": true,
  "c2": [{ "address": "<LINUX_IP>:<PORT>", "protocol": "https" }],
  "http_c2_profile": "ms-update"
}
```

### String smoke (DLL, Defender dan oldin)

| Igna | Kutilgan |
|---|---|
| `sliverpb` | 0 |
| `GetJitter`, `ScreenshotReq`, `HTTPSessionInit` | 0 |
| `bishopfox` | 0 |
| `VoidFunc`, `DllRegisterServer` | 0 |
| `Go buildinf:` | 0 |
| `cpmfczjv` / `WgzBgfnsl` | bo‘lishi mumkin |

---

## 5. Faza 5 — 1116 lab (davom)

**OS:** Windows **10 yoki 11**, oxirgi MDAV + cloud. Event 1116 ikkalasida ham bor. Rejadagi «Win11» lab nishoni; Win10 ham yaroqli. «Muammosiz ishlaydi» **kafolat emas**.

### Qaror

| Natija | Keyingi |
|---|---|
| 1116 yo‘q + sessiya turadi | Ommaviy 1/3/4 labda yopiq; shift qoladi (Go PE-ML, unpublished C2 ML, CRT) |
| Name = oila YARA / `sliverpb` / AMSI_Patch / Wacatac stub | Mos fazaga qaytish |
| Name = `Behavior:Win32/CommandAndControl.*` yoki unpublished | Shift; to‘xtash; FUD yo‘q |

### Lab jadvali (to‘ldirish)

| Maydon | Qiymat |
|---|---|
| OS build | Win10 ___ / Win11 ___ |
| MDAV engine / signature | |
| Artifact SHA-256 | |
| format / engine | shared + mingw-c-dll |
| HTTP C2 | ms-update |
| Listener | |
| Session | ha / yo‘q |
| 1015 | |
| **1116 Name** | |
| 1117 action | |

Natijani `reports/AV Faza 5 lab.md` ga yozish tavsiya.

### Model / agent nima qilmaydi

- Wine natijasini Defender clean deb yozish
- FUD / VT widget
- 1116 o‘tkazish uchun default AMSI patch / BYOVD
- Live CA rotate (siz so‘ramaguncha)
- origin (`9Insomnie`) ga push — faqat Mkadir fork

### Linux hostda nima yetishmaydi

- Windows VM (virsh/VBox) yo‘q edi; wine bor
- Shuning uchun 1116 shu Linuxda bajarilmadi

---

## 6. Faza 4 / 6+ (reja, hali README)

To‘liq: [`docs/AV_LAYERS_CLOSE_PLAN.md`](../AV_LAYERS_CLOSE_PLAN.md)

Qisqa:

- **Faza 4:** generate artifact string smoke (avtomatik)
- **6a:** live `ms-update` kafolati + :443 setcap hujjati
- **6b:** ixtiyoriy `--rotate-ca`
- **6c–6g:** CI smoke, sleep-mask spike, banner, Linux ELF smoke
- **6h:** C implant / ScareCrow / FUD — qilinmaydi

---

## 7. Muhim fayllar (kod)

```
docs/AV_LAYERS_CLOSE_PLAN.md
docs/BUNDLED_SLIVER.md
patches/sliver-v1.7.3/{README.md,seed.hex,proto-idents.json,last-apply.json}
scripts/build-sliver-server.sh
backend/cmd/sliverpatch/main.go
backend/internal/sliverfork/{rewrite.go,generator.go}
backend/internal/sliver/{httpc2_fingerprint.go,psexec.go,implants.go}
backend/internal/loader/{cwin.go,implant_clean.go}
frontend/src/lib/httpC2Templates.ts
frontend/src/pages/{ImplantsPage.tsx,LoadersPage.tsx,HttpC2Page.tsx}
```

`third_party/sliver/` — gitignored BishopFox v1.7.3 + patches. `go.mod`: `replace github.com/bishopfox/sliver => ../third_party/sliver`.

---

## 8. Tezkor buyruqlar (Linux generator)

```bash
# Auth cookie (parolni chatga yozmang)
# source ~/.config/sliver-ui/env

# Profiles — ms-update bo‘lishi shart
curl -sS -b cookie http://127.0.0.1:8080/api/http-c2-profiles

# Proto smoke
strings ~/.local/share/sliver-ui/bin/sliver-server | rg -c 'sliverpb|GetJitter|cpmfczjv|WgzBgfnsl'

# Rebuild after generator change
export GOCACHE=/tmp/go-cache-sliver
bash scripts/build-sliver-server.sh
# then frontend build + go build sliver-ui + cp to ~/.local/share/sliver-ui/bin/ + systemctl restart
```

Windows labda PowerShell (1116):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116} -MaxEvents 20 |
  Select-Object TimeCreated, Id, Message
```

---

## 9. Grokga start prompt

```text
You are continuing authorized red-team work on Sliver UI (sliv).
Read:
  docs/handoff/WINDOWS_LAB_HANDOFF.md
  docs/AV_LAYERS_CLOSE_PLAN.md
  reports/AV detection of Sliver implants.md

Current code already has: shared default, default-HTTP generate blocked, proto package cpmfczjv, disk LoadLibrary wrap, OneDrive PsExec defaults.

Your job: Phase 5 lab on this Windows 10/11 machine with latest MDAV.
1) Confirm ms-update exists on the teamserver (or tell operator to save it from Linux UI).
2) Use artifact: windows/amd64 shared + Loaders disk LoadLibrary EXE+DLL.
3) Run, record 1116 Name / session yes-no.
4) Apply decision tree in the handoff. No FUD. No CA rotate unless asked.
Optional: write results to reports/AV Faza 5 lab.md
```

---

## 10. Git / remote

- Branch: `feat/ui-auth-opsec-installer`
- Push target: **Mkadir** fork only (`git@github.com:Mkadir/sliver_ui.git`), not origin `9Insomnie/sliver_ui`
- Working tree dirty (ko‘p uncommitted AV-layer o‘zgarishlar) — labdan oldin `git status` qiling; kerak bo‘lsa commit Mkadir ga

---

*End of handoff.*
