# DICOM AI Security Demo

Educational Streamlit app for medical imaging security risks: metadata tampering, hidden AI processing, audit logs, DICOM export, and **payload embedding** for security testing.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Or: `python scripts/run_app.py`

## Login

The app requires sign-in before use.

| Source | Credentials |
|--------|-------------|
| Default (local) | `admin` / `demo123` |
| `.streamlit/secrets.toml` | Copy from `secrets.toml.example` |
| Streamlit Cloud | App settings → Secrets → `[credentials]` |
| Environment | `DEMO_APP_USERNAME`, `DEMO_APP_PASSWORD` |

Login, logout, and failed attempts are recorded in the Security Breach Logs.

## Tabs

| Tab | Purpose |
|-----|---------|
| **Security Demo** | Upload DICOM, edit metadata, augment images, export, view simulated breach logs |
| **Payload Embedder** | Build test DICOMs with hidden payloads (safe EOF embed + pattern-based builds) |

## Payload Embedder

Two modes:

### Safe embed (recommended)
- Appends payload **after the DICOM file end**
- Pixels and metadata **unchanged** (works with JPEG/compressed DICOM)

### Pattern embed
| Pattern | Reference test file |
|---------|---------------------|
| PDF + hidden files | MP3+PDF.dcm, PDFGitPolyglot.dcm |
| EXE polyglot preamble | exe_embedded_dicom-1.dcm |
| Pixel-data append | DX / US / VL6_J2KR style |

## CLI scripts

```bash
# Analyze a folder of DICOMs
python scripts/make_pattern_dicom.py analyze --folder path/to/dicoms

# Build patterns from command line
python scripts/make_pattern_dicom.py pdf-mp3 --pdf doc.pdf --attach audio.mp3 -o out.dcm
python scripts/make_pattern_dicom.py exe-polyglot -i scan.dcm -o polyglot.dcm
python scripts/make_pattern_dicom.py eof-append -i scan.dcm --attach file.bin -o out.dcm

# Batch metadata edit (local test folder)
python scripts/edit_test_dicom_metadata.py
```

## Modules

| Module | Role |
|--------|------|
| `utils/embed_engine.py` | Safe EOF embedding engine |
| `utils/pattern_dicom_builder.py` | Pattern-based DICOM builders |
| `utils/embed_ui.py` | Payload Embedder Streamlit UI |

Output: `output/embed/` (gitignored)

Optional env vars:
- `DEMO_APP_USERNAME` / `DEMO_APP_PASSWORD` — login credentials (default: admin / demo123)
- `DICOM_REFERENCE_FOLDER` — default folder for `make_pattern_dicom.py analyze`
- `DICOM_REFERENCE_EXE` — path to exe_embedded reference for MZ stub bytes
