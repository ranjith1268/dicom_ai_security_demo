# Hosted Streamlit — Planned Changes

**Status:** Applied (see git diff for exact lines).

This document describes what was applied to support **hosted Streamlit** users (browser-only, no local setup) while hardening the **local auto-run** path where a Windows handler exists.

## Context

| User flow | What happens today | Limitation |
|-----------|-------------------|------------|
| Download `.dcm` from hosted app, double-click | Opens in default DICOM viewer | No registry handler is installed from the browser |
| Download extracted `.ps1` from Payload Extractor | Browser adds Mark of the Web (MOTW) | Website cannot call `Unblock-File` on the user's PC |
| Embedded `FILE_LAUNCHER` in `.dcm` | Extracts script to `%TEMP%`, runs via PowerShell | Only runs if local handler invokes it |

## Changes to apply

### 1. `Unblock-File` in embedded PowerShell launcher — **done**

**File:** `utils/embed_engine.py` — `FILE_LAUNCHER`

After `[IO.File]::WriteAllText($payloadPath, $script)`, add:

```powershell
Unblock-File -LiteralPath $payloadPath -ErrorAction SilentlyContinue
```

**Why:** Removes `Zone.Identifier` (MOTW) if present on the temp script before `Start-Process`. Harmless when no ADS exists (typical for fresh `WriteAllText`).

**Note:** Existing embedded `.dcm` files keep the old launcher until re-embedded. `threat_pattern_builder.py` imports `FILE_LAUNCHER` from `embed_engine` — no separate edit needed.

### 2. `Unblock-File` in Python double-click handler — **done**

**File:** `scripts/open_embedded_dicom.py` — `_write_temp_ps1()`

After writing a temp `.ps1`, call PowerShell `Unblock-File` on Windows (same effect as launcher).

**Why:** Handler often runs scripts directly (`_run_script_bytes`) without going through the embedded launcher; parity with (1).

### 3. UI — hosted vs local expectations (Threat Embedder) — **done**

**File:** `utils/threat_embedder_ui.py`

- **Double-click section:** Clarify that hosted users see normal DICOM viewer behaviour; auto-run requires a one-time local handler (lab/instructor PCs only).
- **Defender section:** When app runs on Linux (Streamlit Cloud), label scan as requiring a local Windows bridge or instructor setup — not available from browser alone.

### 4. UI — Payload Extractor download note — **done**

**File:** `utils/payload_extractor_ui.py`

For `.ps1` downloads, add caption that Windows may show an “internet file” warning (MOTW) and how to run safely (`Unblock-File` or right-click → Unblock).

## What this does **not** fix

- **Hosted-only double-click auto-run** — still impossible without local registry handler or IT policy.
- **MOTW on browser-downloaded scripts** — `Unblock-File` in launcher does not run until something local executes the launcher.
- **Defender scan from cloud** — still requires `MpCmdRun.exe` on the user's Windows PC (local bridge or instructor script).

## Re-embed required

Users who want the updated launcher with `Unblock-File` must create a **new** embedded `.dcm` after deploy (Threat Embedder → download). Old files retain previous launcher bytes.

## Verification

1. Re-embed Notepad payload with launcher on a lab PC with handler registered → double-click → Notepad opens; check `%TEMP%\dicom_embed_handler.log` on failure.
2. Payload Extractor on hosted app → upload embedded `.dcm` → script + launcher listed → download `.ps1` → confirm UI shows MOTW note.
3. Hosted Threat Embedder post-embed screen → confirm double-click / Defender captions match limitations above.
