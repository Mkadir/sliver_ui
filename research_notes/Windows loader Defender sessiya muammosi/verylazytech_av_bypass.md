# VeryLazyTech AV bypass guide mapped onto this loader

Source: [VeryLazyTech — Antivirus (AV) Bypass](https://www.verylazytech.com/windows/antivirus-av-bypass) (fetched 2026-11-16). Operator-supplied. Lab/red-team methodology, not a promise that following it FUD-kills Defender.

## What the guide says vs what we already do

| Guide item | In our Windows loader? | Fit for the two symptoms |
|---|---|---|
| Encrypt payload, decrypt at runtime | Yes — XOR `cfg.dat` | Helps **static hash** of the inner blob. After decrypt, implant is plaintext in RWX. Does not keep a live session alive. |
| Obfuscate strings | Partial — API names XOR `\xHH`; Go runtime strings remain | Weak vs Go/`sliverpb` memory YARA. |
| Custom tool (no public signature) | Partial — unique hash each build | First-seen still cloud-sandboxed ([BAFS](https://demo.wd.microsoft.com/)). |
| Sleep before exec | Yes — 1.8s + GetTickCount anti-skip | Guide example is **60s**. 1.8s is emulator-only. Too short for cloud detonation. |
| Low-RAM exit | Yes — 1 GiB | Guide uses 2 GiB. Cheap to raise. |
| Sandbox computer name `HAL9TH` | **No** | Cheap emulator/sandbox check. ATT&CK T1497.001; Saint Bot compared machine name to HAL9TH ([MITRE](https://attack.mitre.org/versions/v19/techniques/T1497/001)). **Not** a live-Defender bypass: renaming a real PC to HAL9TH is folklore from 2022 tweets; Microsoft’s *MsMpEng sandbox* (`MP_FORCE_USE_SANDBOX`) is a different feature ([Learn](https://learn.microsoft.com/en-us/defender-endpoint/sandbox-mdav)). |
| ThreatCheck (split file, find bad bytes) | **No (operator lab tool)** | Best next diagnostic if disk is flagged. [rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/threatcheck). |
| Prefer DLL over EXE | We only emit **EXE** | Guide’s Havoc VT sample (7/26 EXE vs 4/26 DLL) is not Defender-on-this-host. Sideload is still the stronger form factor. |
| DLL sideload + SharpDllProxy | **No** (rejected in-tree ScareCrow-class) | Highest real-world OPSEC for disk. External. |
| Freeze (suspended process + direct syscalls) | **No** | Guide claims silent Defender in *their* test date. Public Go syscall stubs age fast. Out of product scope (same class as in-tree Donut/ScareCrow). |
| defendnot / no-defender / Set-MpPreference | **No, must stay out** | Disables AV. Needs admin. Tamper Protection. Not a loader feature. |
| AMSI patch / amsiInitFailed | **N/A for native Go EXE** | AMSI hits PowerShell/.NET/Office. Native Go skip AMSI; **Donut stub inside Windows shellcode** still patches AMSI (default bypass=3) and that patch is signatured ([Fortbridge](https://fortbridge.co.uk/research/reforging-sliver-how-simple-code-edits-can-outmaneuver-edr/)). |
| ETW `EtwEventWrite` RET patch | **No in our stub**; Donut may | User-mode only. Kernel ETW / WdFilter remain. |
| SmartScreen / MoTW / ISO | Delivery, not loader compile | Irrelevant once the EXE is already running. |
| Fork&run vs inline .NET | Explains **symptom 2** | Sliver `execute-assembly` fork&run into notepad is exactly the CRT inject Microsoft hunts. Stock `interactive` is **inline same process**, not fork&run. |

## What the guide does **not** fix

- A decrypted 16–30 MB Go Sliver image in memory (`sliverpb`, protobuf RPC names, `Go buildinf`).
- `Behavior:Win32/CommandAndControl` client behavioral blocking after callback.
- Process exit when Donut/RDI **returns** to our `CALL` trampoline.

## Honest takeaways for this product

1. Treat VeryLazyTech as a **layer checklist** (static → emulator → behavior), which matches our existing honesty copy.
2. Do **not** port defendnot, AMSI patches, or Freeze into the UI.
3. Cheap, on-scope items from the guide: HAL9TH (and similar) sandbox name check; longer real wait only if we keep the tick anti-skip; document ThreatCheck as operator lab; prefer `format=shellcode` + keep host process alive after jump.
4. DLL sideload remains the recommended **external** path, already rejected as in-tree work.
