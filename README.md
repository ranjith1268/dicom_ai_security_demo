# DICOM AI Security Demo

Educational **Streamlit** application for demonstrating security risks in medical imaging workflows: PHI metadata tampering, simulated hidden AI processing, threat embedding, payload extraction, and DICOM safety validation — for security research and red-team training.

> **Disclaimer:** This project is for **education and authorized security testing only**. Do not use it to hide malware in clinical systems or process real patient data without proper authorization.

---

## Table of contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the app](#running-the-app)
- [Authentication](#authentication)
- [Application modules](#application-modules)
  - [DICOM Threat Embedder](#1-dicom-threat-embedder)
  - [Payload Extractor](#2-payload-extractor)
  - [DICOM Safety Validator](#3-dicom-safety-validator)
- [Security Audit Log](#security-audit-log)
- [Project structure](#project-structure)
- [Configuration reference](#configuration-reference)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)

---

## Overview

The app simulates how DICOM medical images can be misused or abused in AI-assisted workflows:

| Risk area | What the demo shows |
|-----------|---------------------|
| **Metadata tampering** | Patient Name and other tags can be edited with minimal friction |
| **Image manipulation** | Fake fractures/tumors, crops, heatmaps — changes that could mislead readers |
| **Hidden AI processing** | Image augmentations trigger a *simulated* background process that logs credential/PHI access |
| **Steganography** | Scripts and files hidden inside DICOM using private tags or known attack patterns |
| **Auto-run threats** | Launcher scripts appended to DICOMs that execute on double-click via OS file associations |
| **Audit gaps** | Users see "success" in the UI while CRITICAL events accumulate in logs |

Three modules organize the workflow: **DICOM Threat Embedder**, **Payload Extractor**, and **DICOM Safety Validator**.

---

## Requirements

- **Python 3.12** (see `runtime.txt` for Streamlit Cloud)
- Dependencies in `requirements.txt`:
  - `streamlit` — web UI
  - `extra-streamlit-components` — persistent login cookies
  - `pydicom` — DICOM read/write
  - `opencv-python-headless` — image processing
  - `numpy`, `pillow` — array/image handling

**System packages (Linux / Streamlit Cloud):** `packages.txt` lists `libgl1` for OpenCV.

---

## Installation

```bash
git clone <repository-url>
cd dicom_ai_security_demo

pip install -r requirements.txt
```

### Optional: custom login credentials

Copy the secrets template and edit it:

```bash
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
```

```toml
[credentials]
username = "admin"
password = "your-secure-password"

# Optional: secret used to sign session cookies
auth_secret = "random-long-string"
```

`.streamlit/secrets.toml` is gitignored — never commit real passwords.

---

## Running the app

```bash
streamlit run app.py
```

The app opens in your browser (default: `http://localhost:8501`). You must sign in before any feature is available.

---

## Authentication

### Credential sources (priority order)

1. **`.streamlit/secrets.toml`** — `[credentials]` section  
2. **Environment variables** — `DEMO_APP_USERNAME`, `DEMO_APP_PASSWORD`  
3. **Defaults** — `admin` / `demo123` (change for any shared deployment)

### Session persistence

Login state is stored in a **signed browser cookie** (7-day expiry) so a normal page refresh does not sign you out. Use **Logout** in the sidebar to end the session.

Cookie signing uses `auth_secret` from secrets, or `DEMO_AUTH_SECRET` from the environment, or a local-dev default.

### Logged auth events

Successful login, logout, and failed login attempts are written to the Security Audit Log.

---

## Application modules

### 1. DICOM Threat Embedder

7-step wizard to embed known security-research threat patterns into DICOM files.

#### Embedding patterns

| Pattern | What it embeds | Auto-run on double-click |
|---------|---------------|--------------------------|
| **Safe embed (private tag)** | Script or file in a private DICOM tag (`DEMO_EMBED`); pixels and standard metadata unchanged | No |
| **PDF + hidden files** | Encapsulated PDF DICOM with files appended after PDF `%%EOF` | No |
| **EXE / BAT polyglot preamble** | Batch/DOS stub in the 128-byte preamble + script in pixel tail | Yes (with launcher) |
| **Pixel-data append** | PowerShell script hidden in PixelData tail (Chrome launcher or Notepad message) | Yes (with launcher) |

#### Auto-run launcher

For **EXE / BAT polyglot** and **Pixel-data append** patterns an auto-run launcher is appended to the file by default. When the `.dcm` is double-clicked on a machine with the `DicomAutoOpen` file association registered, the launcher script extracts and executes the embedded PowerShell payload automatically.

The wizard generates:
- A downloadable `.dcm` with the full threat embedded
- A JSON log recording embed parameters

#### Payload types (Pixel-data append)

| Payload | Effect when executed |
|---------|---------------------|
| **Chrome script** | Opens Chrome via PowerShell |
| **Notepad script** | Opens Notepad with a custom message |
| **File payload** | Embeds an arbitrary binary file |

---

### 2. Payload Extractor

Upload any `.dcm` and scan for hidden content across all known locations:

| Scan location | Detects |
|---------------|---------|
| Private tag (`DEMO_EMBED`) | Safe-embed scripts and files |
| PixelData tail | Scripts (`<<<DCM_EMBEDDED_SCRIPT>>>`), files (`<<<DCM_EMBEDDED_FILE>>>`) |
| Encapsulated PDF tail | Files appended after `%%EOF` |
| Preamble (bytes 0–127) | MZ/DOS stubs, batch script preambles |
| EOF append | Auto-run launcher (`<<<DCM_FILE_LAUNCHER>>>`), raw binary files |

Extracted items are identified by type (EXE, PDF, MP3, ZIP, PS1, BAT, etc.) and offered as individual downloads with correct file extensions.

---

### 3. DICOM Safety Validator

Defensive companion to the Threat Embedder — scan any `.dcm` and selectively remove identified threats while preserving all legitimate DICOM tags and image data.

#### Detectable threats

| Finding | Severity | Auto-removable |
|---------|----------|----------------|
| MZ/DOS executable header in preamble | CRITICAL | Yes |
| Batch script in preamble (BAT polyglot) | CRITICAL | Yes |
| Unknown non-zero preamble content | HIGH | Yes |
| Hidden data after PDF `%%EOF` | HIGH | Yes |
| Script payload in PixelData tail (uncompressed) | CRITICAL | Yes |
| Script payload in compressed PixelData | CRITICAL | Yes |
| Auto-run launcher at EOF | CRITICAL | Yes |
| Unknown trailing bytes at EOF | HIGH | Yes |
| Missing required DICOM tags | MEDIUM | No (manual review) |

**Workflow:**
1. Upload a `.dcm` and click **Scan for Threats**
2. Review each finding with evidence and location details
3. Tick **Approve removal** on the threats to fix
4. Click **Remove Selected Threats** — a cleaned DICOM is generated
5. Download the remediated file; before/after image preview is shown

---

## Security Audit Log

Full-width section at the bottom of every page. Records all actions:

| Severity | Example actions |
|----------|-----------------|
| **CRITICAL** | Metadata edit, DICOM export, threat embed, payload scan, file cleaned, simulated PHI/credential access |
| **HIGH** | Failed login, system config access |
| **MEDIUM** | Login/logout, image augmentation, module init |

Features: Refresh, Clear, and Download as CSV.

---

## Project structure

```
dicom_ai_security_demo/
├── app.py                          # Main Streamlit application entry point
├── requirements.txt
├── runtime.txt                     # Python version for Streamlit Cloud
├── packages.txt                    # apt packages for Streamlit Cloud (libgl1)
├── FUNCTIONALITY.md                # Detailed feature notes
├── .streamlit/
│   ├── config.toml
│   ├── secrets.toml.example
│   └── secrets.toml                # Local credentials (gitignored)
├── test_dicom_images/              # Sample clean CT DICOMs for testing
└── utils/
    ├── auth.py                     # Login, cookie session management
    ├── audit_logger.py             # Breach/audit log CSV + hidden AI simulation
    ├── breach_simulator.py         # Run Breach Simulation (UI-only demo)
    ├── dicom_handler.py            # Load, export, metadata, pixel utilities
    ├── dicom_safety.py             # Threat detection + remediation logic
    ├── embed_engine.py             # Safe embed engine (private DICOM tag)
    ├── image_editor.py             # Display, augmentations, 2D slice from volumes
    ├── payload_extractor.py        # Payload extraction logic (all patterns)
    ├── payload_extractor_ui.py     # Payload Extractor module UI
    ├── safety_validator_ui.py      # DICOM Safety Validator module UI
    ├── threat_embedder_ui.py       # DICOM Threat Embedder module UI (7-step wizard)
    └── threat_pattern_builder.py   # Pattern DICOM builders (PDF, EXE, pixel append)
```

---

## Configuration reference

| Variable / secret | Purpose |
|-------------------|---------|
| `DEMO_APP_USERNAME` | Login username |
| `DEMO_APP_PASSWORD` | Login password |
| `DEMO_AUTH_SECRET` | HMAC secret for session cookies |
| `st.secrets["credentials"]` | Username/password in Streamlit Cloud |
| `st.secrets["auth_secret"]` | Cookie signing secret |

---

## Known limitations

- **Security Demo** edits **one 2D slice** from multi-frame volumes; full 3D export is not supported.
- **PDF / encapsulated document DICOMs** cannot be image-edited in Security Demo.
- **EXE polyglot** and pattern embeds may not display in the in-app viewer but are valid for external tools and research.
- **Auto-run launcher** requires a `DicomAutoOpen` Windows file association to be registered on the target machine; it does not exploit a DICOM viewer vulnerability.
- **Payload Extractor** identifies payloads using this demo's magic markers (`<<<DCM_EMBEDDED_SCRIPT>>>`, `<<<DCM_EMBEDDED_FILE>>>`, `<<<DCM_FILE_LAUNCHER>>>`) and standard binary file signatures.
- **Session cookies** require `extra-streamlit-components`; install via `pip install -r requirements.txt`.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: extra_streamlit_components` | `pip install -r requirements.txt` using the **same Python** that runs Streamlit |
| Logged out on every refresh | Ensure cookies are enabled; redeploy after installing `extra-streamlit-components` |
| Auto-run not triggering on double-click | Register the `DicomAutoOpen` file association; verify `.dcm` extension is associated |
| Export error on embedded DICOM | Re-upload the file; export forces uncompressed transfer syntax |
| Shape `(200, 256, 256)` / channel errors | Multi-frame volume — app uses the middle slice |
| Cleaner shows 0 threats on a known bad file | File may already be cleaned, or uses a non-standard embedding format |
| Login fails | Check `.streamlit/secrets.toml` or env vars; default is `admin` / `demo123` |

---

## Deploying to Streamlit Cloud

1. Push repository to GitHub  
2. Create a Streamlit Cloud app pointing at `app.py`  
3. Add secrets in the Cloud dashboard:

```toml
[credentials]
username = "your-user"
password = "your-password"

auth_secret = "long-random-string"
```

4. Python version is read from `runtime.txt`; system packages from `packages.txt`.

---

## License & use

Use only in **controlled lab / training environments** with synthetic or de-identified data unless you have explicit authorization to test on real clinical systems.
