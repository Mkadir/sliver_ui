# Handoff pack (Windows lab → Grok)

Bu papka Linuxdagi Grok session kontekstini Windows labda davom ettirish uchun.

| Fayl | Mazmun |
|---|---|
| [`WINDOWS_LAB_HANDOFF.md`](./WINDOWS_LAB_HANDOFF.md) | **Asosiy.** Holat, seed/mapping, operator yo‘li, Faza 5 qadamlar, cheklovlar. Grokga shu faylni bering. |
| [`CHAT_TRANSCRIPT_SANITIZED.md`](./CHAT_TRANSCRIPT_SANITIZED.md) | Shu sessiondagi user+assistant turnlar (parol/blob redacted). |
| [`chat_history_user_assistant.sanitized.jsonl`](./chat_history_user_assistant.sanitized.jsonl) | Xuddi shu, JSONL. |
| [`COMPACTION_INDEX.md`](./COMPACTION_INDEX.md) | 16 ta compaction segment indeksi. |
| [`compaction_recent/`](./compaction_recent/) | segment_014–015 (Defender/AV research), password redacted (~1.7MB). |
| [`../AV_LAYERS_CLOSE_PLAN.md`](../AV_LAYERS_CLOSE_PLAN.md) | Faza 0–6+ to‘liq reja. |
| [`../../reports/AV detection of Sliver implants.md`](../../reports/AV%20detection%20of%20Sliver%20implants.md) | AV detection tadqiqoti (en). |
| [`../../reports/AV detection of Sliver implants.uz.md`](../../reports/AV%20detection%20of%20Sliver%20implants.uz.md) | Xuddi shu (uz). |

## To‘liq xom tarix (Linux hostda)

Session ID: `01a1dc3e-0915-7740-a41d-8ce26ea0c307`

`CHAT_TRANSCRIPT_SANITIZED.md` faqat **shu compactiondan keyingi** user/assistant turnlar (~57). Oldingi minglab turnlar `compaction/segment_000`…`013` da (~8MB+) — handoffga kiritilmadi (hajm + secret xavfi). Kerak bo‘lsa Linuxdan nusxa:

```text
~/.grok/sessions/%2Fhome%2Fcup%2FDocuments%2Fpersonal%2Fsliv/01a1dc3e-0915-7740-a41d-8ce26ea0c307/
  chat_history.jsonl
  compaction/segment_000.md … segment_015.md
```

Windows ga ko‘chirishdan oldin: `rg -i 'pass|secret|token' compaction/`.

## Grokga beriladigan prompt (qisqa)

```text
Read docs/handoff/WINDOWS_LAB_HANDOFF.md and docs/AV_LAYERS_CLOSE_PLAN.md.
Continue Phase 5: Windows 10/11 + latest MDAV lab.
Generate path: shared + disk LoadLibrary + ms-update HTTP C2.
Record Event 1116/1117 Name. Do not claim FUD. Do not rotate live CA unless asked.
```
