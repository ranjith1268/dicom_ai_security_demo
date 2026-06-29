# DICOM AI Security Demo

Educational **Streamlit** application for demonstrating security risks in medical imaging workflows: PHI metadata tampering, simulated hidden AI processing, audit logging, DICOM export, and **payload embedding/extraction** for security research and training.

> **Disclaimer:** This project is for **education and authorized security testing only**. Do not use it to hide malware in clinical systems or process real patient data without proper authorization.

---

## Table of contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the app](#running-the-app)
- [Authentication](#authentication)
- [Application tabs](#application-tabs)
  - [Security Demo](#1-security-demo)
  - [Payload Embedder](#2-payload-embedder)
  - [Payload Extractor](#3-payload-extractor)
- [Security Breach Logs dashboard](#security-breach-logs-dashboard)
- [Frequently asked questions](#frequently-asked-questions)
- [CLI tools](#cli-tools)
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
| **Steganography** | Scripts and files hidden inside DICOM using private tags or known test patterns |
| **Audit gaps** | Users see “success” in the UI while CRITICAL events accumulate in logs |

Three main tabs organize the workflow: **Security Demo**, **Payload Embedder**, and **Payload Extractor**.

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

**Standard:**

```bash
streamlit run app.py
```

**Alternative launcher:**

```bash
python scripts/run_app.py
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

Successful login, logout, and failed login attempts are written to `security_breach_logs.csv`.

---

## Application tabs

### 1. Security Demo

Upload a DICOM (`.dcm`), inspect metadata, manipulate the image, and export a modified file.

#### File upload

- Supports standard **2D image DICOMs** (CT, MR, DX, etc.)
- **Multi-frame volumes** (e.g. 200×256×256) display the **middle slice** for editing; export saves that single 2D frame
- **Encapsulated PDF / document DICOMs** show a clear warning — they have no image pixels for this viewer
- **Compressed transfer syntax** (JPEG, JPEG 2000, etc.) is decoded for display; export rewrites as uncompressed Explicit VR Little Endian

#### Modify metadata

- Edit **Patient Name** and click **Apply Changes**
- Changes are logged as **CRITICAL** in the breach logs

#### Image manipulation

| Action | Description |
|--------|-------------|
| Add Fracture / Add Tumor | Draw simulated findings on the image |
| Crop / Tilt / Heatmap / Blur / Edge Detection | Augmentations with optional “AI processing” |

**Image Augmentation with AI Processing:** Applying crop, tilt, heatmap, blur, or edge detection also runs a **hidden simulated process** that logs system config access, credential theft, PHI access, and data exfiltration — without obvious UI warning. This demonstrates “silent” backend behavior.

#### Export DICOM

- Saves current image + metadata to a new `.dcm`
- Patient Name in the download reflects metadata **after** Apply Changes
- RGB heatmaps are preserved on export and re-upload
- Adds `ImageComments`: `Modified by DICOM AI Security Demo`
- Export is logged as **CRITICAL**

#### Run Breach Simulation

Standalone **UI-only** demo: five timed messages simulating a vulnerability scan. Does **not** modify DICOM files, access real data, or write to the breach log CSV. Separate from the hidden AI augmentation logs.

---

### 2. Payload Embedder

Build test DICOM files with hidden payloads. The UI follows a **5-step wizard**:

1. **Choose embed mode** — Safe embed or Pattern embed  
2. **Select pattern**  
3. **Upload files** (contextual per pattern)  
4. **Options** (launcher, AV test signature, Chrome count when relevant)  
5. **Review & build** — checklist + **Build DICOM**

Built files and JSON logs are saved under `output/embed/` (gitignored).

#### Safe embed (recommended for viewer compatibility)

Payloads are stored in a **private DICOM tag** (`DEMO_EMBED` creator, group `0x7051`):

- **Pixels and standard metadata are not modified**
- DICOM viewers that ignore unknown private tags should **open and display normally**
- Patterns:
  - Append file (private tag)
  - Append script (private tag)
  - Built-in Chrome launcher (PowerShell)
  - Script + file (both)

**Legacy note:** Older builds appended payload bytes **after end-of-file**, which broke strict viewers. Re-embed with the current safe embed, or extract payloads from legacy files via **Payload Extractor**.

#### Pattern embed

Known security-research file patterns:

| Pattern | Description | Source DICOM required? |
|---------|-------------|------------------------|
| **PDF + hidden files** | Encapsulated PDF DICOM; files appended after PDF `%%EOF` (MP3+PDF.dcm style) | No — upload PDF + hidden files; **optional base DICOM** copies patient/study metadata |
| **EXE polyglot preamble** | MZ DOS stub at byte 0, `DICM` at byte 128 | Yes |
| **Pixel-data append** | Payload appended to `PixelData` tail | Yes |

#### Embedder options

| Option | Purpose |
|--------|---------|
| **Include extraction launcher (scripts)** | Stores a PowerShell helper in the private tag to **manually** find and run embedded scripts. Does **not** auto-execute in DICOM viewers. |
| **Attach AV test signature (Windows)** | Adds an alternate data stream (ADS) with EICAR test string for manual AV testing |
| **Chrome open count** | For built-in Chrome launcher patterns |

---

### 3. Payload Extractor

Upload any `.dcm` and scan for hidden content:

| Scan location | Used by |
|---------------|---------|
| Private tag (`DEMO_EMBED`) | Current safe embed |
| Pixel data tail | Pixel-data append pattern |
| End-of-file tail | Legacy safe embed |

Download extracted scripts, files, and launcher helpers individually.

---

## Security Breach Logs dashboard

Full-width section at the bottom of the app (all tabs). Records actions to `security_breach_logs.csv`:

| Severity | Example actions |
|----------|-----------------|
| **CRITICAL** | Metadata edit, DICOM export, payload embed, simulated PHI/credential access |
| **HIGH** | Failed login, system config access |
| **MEDIUM** | Login/logout, image crop/tilt, module init |

**Purpose:** Educational **audit trail** — shows what *would* be logged in a HIPAA-aware environment. CRITICAL warnings on every embed/export are **intentional** for training, not evidence of a real live attack.

Features:

- Refresh / Clear logs
- Download logs as CSV
- Severity breakdown and timeline view

---

## Frequently asked questions

### What does “Run Breach Simulation” do?

A **cosmetic UI demo only**. It displays five timed messages (vulnerability scan, weak auth, simulated exfiltration, etc.). It does not touch files, networks, or the breach log file.

### Is there a way to extract embedded items from a DICOM?

**Yes** — use the **Payload Extractor** tab. It scans private tags, pixel tails, and legacy EOF payloads and lets you download each item.

### What does “Include extraction launcher (scripts)” do?

It does **not** exploit a DICOM viewer vulnerability. It embeds a **PowerShell script** you must **run yourself** on the file path to locate `<<<DCM_EMBEDDED_SCRIPT>>>` markers and execute the payload. No viewer auto-runs it when opening the image.

### What is the Security Breach Logs dashboard for?

**Teaching and demo tracking** — simulates enterprise security / HIPAA audit logging. It is not a production SIEM or real-time threat detector.

---

## CLI tools

### Pattern DICOM builder

```bash
# Analyze a folder of DICOMs
python scripts/make_pattern_dicom.py analyze --folder path/to/dicoms

# Encapsulated PDF + hidden files after %%EOF
python scripts/make_pattern_dicom.py pdf-mp3 --pdf doc.pdf --attach audio.mp3 -o out.dcm

# EXE/DOS polyglot preamble
python scripts/make_pattern_dicom.py exe-polyglot -i scan.dcm -o polyglot.dcm

# EOF append (legacy pattern — prefer safe private-tag embed in the UI)
python scripts/make_pattern_dicom.py eof-append -i scan.dcm --attach file.bin -o out.dcm
```

### Batch metadata edit (local test folder)

```bash
python scripts/edit_test_dicom_metadata.py
```

---

## Project structure

```
dicom_ai_security_demo/
├── app.py                      # Main Streamlit application
├── requirements.txt
├── runtime.txt                 # Python version for Streamlit Cloud
├── packages.txt                # apt packages for Streamlit Cloud (libgl1)
├── security_breach_logs.csv    # Generated audit log (runtime)
├── output/embed/               # Embedded DICOM output (gitignored)
├── .streamlit/
│   ├── config.toml
│   ├── secrets.toml.example
│   └── secrets.toml            # Local credentials (gitignored)
├── scripts/
│   ├── run_app.py
│   ├── make_pattern_dicom.py
│   └── edit_test_dicom_metadata.py
└── utils/
    ├── auth.py                 # Login, cookie session
    ├── breach_simulator.py     # Run Breach Simulation (UI only)
    ├── dicom_handler.py        # Load, export, metadata, pixel trim
    ├── embed_engine.py         # Safe embed (private tag)
    ├── embed_extract.py        # Payload extraction logic
    ├── embed_ui.py             # Embedder + Extractor UI
    ├── embedded_risk_module.py # Breach log CSV + hidden AI simulation
    ├── image_editor.py         # Display, augmentations, 2D slice from volumes
    └── pattern_dicom_builder.py # PDF polyglot, EXE preamble, pixel append
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
| `DICOM_REFERENCE_FOLDER` | Default folder for CLI `analyze` |
| `DICOM_REFERENCE_EXE` | Path to reference file for MZ stub bytes |

---

## Known limitations

- **Security Demo** edits **one 2D slice** from multi-frame volumes; full 3D export is not supported.
- **PDF / encapsulated document DICOMs** cannot be displayed or image-edited in Security Demo.
- **EXE polyglot** and some pattern embeds may not display in the in-app viewer but are valid for external tools/research.
- **Payload Extractor** finds payloads using this demo’s formats (`<<<DCM_EMBEDDED_SCRIPT>>>`, `<<<DCM_EMBEDDED_FILE>>>`, private tag `DEMO_EMBED`).
- **Session cookies** require `extra-streamlit-components`; install with `pip install -r requirements.txt`.
- **Windows Application Control** policies may block some Python native DLLs (e.g. pandas was removed from the app for this reason).

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: extra_streamlit_components` | `pip install -r requirements.txt` using the **same Python** that runs Streamlit |
| Logged out on every refresh | Ensure cookies are enabled; redeploy after installing `extra-streamlit-components` |
| Safe embed breaks old viewers | Re-embed with current version (private tag), not EOF append |
| Export error on embedded DICOM | Re-upload file; export now forces uncompressed syntax |
| Shape `(200, 256, 256)` / channel errors | Multi-frame volume — app uses middle slice; re-upload after update |
| `dcmread: Expected file path... got bytes` | Fixed in embed UI — update to latest `embed_ui.py` |
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
