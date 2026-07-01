# Application Functionality Guide

This document describes **everything each main tab can do** in the DICOM AI Security Demo. It covers user-facing features only — not installation or deployment.

---

## Security Demo

Interactive workspace for uploading DICOM images, changing metadata, manipulating pixels, exporting modified files, and running standalone security simulations.

### DICOM upload & display

| Feature | What it does |
|---------|----------------|
| **Upload DICOM** | Accepts `.dcm` files via file uploader |
| **Load & validate** | Reads DICOM with pydicom; trims corrupt pixel tails from legacy embeds |
| **Display image** | Renders the image in the right panel |
| **2D images** | Full grayscale or RGB display with windowing normalization |
| **Multi-frame volumes** | Uses the **middle slice** (e.g. 200-frame MR → slice 101 of 200) |
| **Compressed DICOM** | Decodes JPEG / JPEG 2000 / other compressed transfer syntaxes for display |
| **RGB heatmaps** | Preserves RGB photometric interpretation when re-displaying exported heatmaps |
| **PDF / document DICOM** | Shows a warning — no image pixels to display |
| **Unsupported / corrupt pixels** | Shows a clear error message instead of a blank panel |

### Metadata viewing & editing

| Feature | What it does |
|---------|----------------|
| **View metadata** | Patient Name, Patient ID, Study Date, Modality, Image Comments, Photometric Interpretation |
| **Edit Patient Name** | Text field pre-filled from uploaded file |
| **Apply Changes** | Writes new Patient Name into the in-memory DICOM dataset |
| **Audit log** | Metadata changes logged as **CRITICAL** in Security Breach Logs |

### Image manipulation (quick actions)

| Feature | What it does |
|---------|----------------|
| **Add Fracture** | Draws a white line across the middle of the image |
| **Add Tumor** | Draws a filled circle at the image center |
| **Grayscale & RGB** | Works on both single-channel and color images |

### Image augmentation with AI

Select an augmentation type, configure it, then apply. **Each augmentation automatically triggers hidden simulated AI processing** (logged silently — see breach logs).

| Augmentation | Controls | Effect |
|--------------|----------|--------|
| **Crop** | Slider 5–40% | Crops from center by percentage |
| **Tilt** | Slider −45° to +45° | Rotates image around center |
| **Heatmap** | Apply button | Applies JET colormap (returns RGB image) |
| **Blur** | Kernel size 3–31 (odd) | Gaussian blur |
| **Edge Detection** | Apply button | Canny edge detection on grayscale |

**Hidden AI processing** (triggered by augmentations above) simulates and logs:

- Module initialization  
- System configuration access  
- Credential access  
- Patient data (PHI) access  
- Data packaging  
- Data transmission to external endpoint  
- Operation complete (silent to user)

### Export DICOM

| Feature | What it does |
|---------|----------------|
| **Download modified DICOM** | Saves current image + metadata as a new `.dcm` file |
| **Patient Name in export** | Uses metadata **after** Apply Changes |
| **New SOP Instance UID** | Each export gets a unique instance UID |
| **ImageComments tag** | Set to `Modified by DICOM AI Security Demo` |
| **RGB export** | Heatmaps saved as RGB uint8 for correct re-upload display |
| **Uncompressed output** | Rewrites as Explicit VR Little Endian (fixes compressed-source export) |
| **Single-frame export** | Multi-frame volumes export the currently displayed 2D slice only |
| **Filename** | `{PatientID}_modified.dcm` (sanitized) |
| **Audit log** | Export logged as **CRITICAL** |

### Standalone security tests

| Feature | What it does |
|---------|----------------|
| **Run Breach Simulation** | UI-only demo: 5 timed messages simulating vulnerability scan, weak auth, exfiltration, credential exposure. **Does not** modify files or write to breach logs |

### Display panel (right column)

| Feature | What it does |
|---------|----------------|
| **Educational expander** | Explains hidden AI threat model |
| **Patient Metadata JSON** | Live view of current metadata |
| **Current image** | Image preview with slice caption for volumes |

---

## Payload Embedder

Build test DICOM files with hidden scripts or files. Uses a **5-step wizard** UI.

### Step 1 — Choose embed mode

| Mode | Description |
|------|-------------|
| **Safe embed** | Payload stored in a **private DICOM tag** (`DEMO_EMBED`). Pixels and standard metadata unchanged. **Recommended** — DICOM viewers stay compatible |
| **Pattern embed** | Builds known security-research file structures (PDF polyglot, EXE preamble, pixel append) |

### Step 2 — Select pattern

#### Safe embed patterns

| Pattern | Required inputs | What gets embedded |
|---------|-----------------|-------------------|
| **Append file (private tag)** | Source DICOM + any file | File bytes in private tag |
| **Append script (private tag)** | Source DICOM + script (.ps1, .py, .bat, …) | Script bytes in private tag |
| **Built-in Chrome launcher** | Source DICOM only | PowerShell that opens Chrome N times |
| **Script + file (both)** | Source DICOM + script + file | Both in private tag |

#### Pattern embed patterns

| Pattern | Required inputs | What gets built |
|---------|-----------------|-----------------|
| **PDF + hidden files (MP3+PDF.dcm)** | PDF + file(s) to hide; optional base DICOM or manual Patient Name/ID | Encapsulated PDF DICOM; hidden files appended after PDF `%%EOF` |
| **EXE polyglot preamble** | Source DICOM | MZ DOS stub at byte 0, `DICM` at byte 128 |
| **Pixel-data append** | Source DICOM + payload file (or built-in Chrome script) | Payload appended to end of `PixelData` |

### Step 3 — Upload files

Contextual upload fields based on mode and pattern:

| Context | Upload fields |
|---------|---------------|
| **Safe embed** | Source DICOM (.dcm) + payload file(s) per pattern |
| **PDF pattern** | PDF document + hidden file(s) + optional base DICOM **or** manual Patient Name / Patient ID |
| **EXE polyglot** | Source DICOM only |
| **Pixel-data append** | Source DICOM + payload file or built-in Chrome script |

**DICOM validation** on upload shows patient info, modality, dimensions, transfer syntax.

**Base DICOM (PDF pattern):** Copies Patient Name, Patient ID, Study Date, Study/Series UIDs, and related tags from your DICOM into the new encapsulated PDF DICOM.

### Step 4 — Options

| Option | Applies to | What it does |
|--------|------------|--------------|
| **Include extraction launcher (scripts)** | Safe embed script patterns | Embeds a PowerShell helper to manually find and run `<<<DCM_EMBEDDED_SCRIPT>>>` payloads. **Does not auto-run in viewers** |
| **Attach AV test signature (Windows)** | All embed builds | Adds Windows alternate data stream with EICAR test string |
| **Chrome open count** | Chrome launcher / pixel-append Chrome | Number of Chrome instances to open (1–10) |

### Step 5 — Review & build

| Feature | What it does |
|---------|----------------|
| **Checklist** | Shows which requirements are met (mode, pattern, files, metadata) |
| **Build DICOM** | Runs embed engine; disabled until checklist is complete |
| **Progress spinner** | Shows build in progress |

### Build output

| Feature | What it does |
|---------|----------------|
| **Download DICOM** | Immediate download of embedded `.dcm` |
| **Download log (.json)** | Build metadata: method, hashes, payload size, pixel unchanged flag |
| **Local save** | Files written to `output/embed/` |
| **Build metrics** | Mode, pixels unchanged (Yes/No), output file size |
| **Audit log** | Embed event logged as **CRITICAL** in Security Breach Logs |
| **AV warning** | Extra notice if Windows ADS test signature was attached |

### Technical embed details (safe embed)

- Private creator: `DEMO_EMBED`, group `0x7051`  
- Script marker: `<<<DCM_EMBEDDED_SCRIPT>>>`  
- File marker: `<<<DCM_EMBEDDED_FILE>>>`  
- Launcher stored in private tag element `0x7051,1002` when enabled  

---

## Payload Extractor

Scan existing DICOM files for hidden payloads and download them.

### Upload

| Feature | What it does |
|---------|----------------|
| **Upload DICOM** | Accepts any `.dcm` for scanning |
| **No build required** | Works on files from this demo or compatible embedding formats |

### Scan locations

The extractor checks **three storage methods** in order:

| Location | Source |
|----------|--------|
| **Private tag** | Current safe embed (`DEMO_EMBED` block) |
| **Pixel data tail** | Pixel-data append pattern (bytes after expected pixel length) |
| **End-of-file tail** | Legacy safe embed (bytes after valid DICOM end) |

### Parsed payload types

| Type | Description |
|------|-------------|
| **Script** | PowerShell or other script found via `<<<DCM_EMBEDDED_SCRIPT>>>` |
| **File** | Arbitrary file found via `<<<DCM_EMBEDDED_FILE>>>` (includes original filename) |
| **Launcher** | Extraction helper script (`extract_launcher.ps1` or `eof_launcher.ps1`) |
| **Private blob** | Raw private-tag payload before parsing |

### Results & download

| Feature | What it does |
|---------|----------------|
| **Item count** | Shows how many embedded items were found |
| **Per-item details** | Filename, extraction method, byte size |
| **Download buttons** | Individual download for each extracted script/file |
| **MIME detection** | `.ps1`, `.py`, `.bat`, `.txt` served as text; others as binary |
| **No items found** | Clear warning when scan returns empty |

### Extraction methods shown in UI

| Method label | Meaning |
|--------------|---------|
| `private_tag` | Found inside `DEMO_EMBED` private DICOM tag |
| `pixel_tail` | Found appended after pixel data |
| `eof_tail` | Found after end of DICOM file (legacy embed) |

---

## Cross-tab behavior

| Behavior | Applies to |
|----------|------------|
| **Login required** | All three tabs |
| **Session persistence** | Login survives page refresh (cookie-based) |
| **Security Breach Logs** | Visible below all tabs; records actions from Security Demo and Payload Embedder |
| **Re-upload after embed** | Security Demo can open safe-embedded DICOMs; pattern embeds may vary by type |

---

## What each tab cannot do

| Tab | Limitation |
|-----|------------|
| **Security Demo** | Cannot edit PDF/document DICOMs as images; cannot export full 3D volumes (single slice only) |
| **Payload Embedder** | Cannot embed into files without required inputs; EXE polyglot may break some viewers by design |
| **Payload Extractor** | Only finds payloads using this demo’s formats; encrypted or custom steganography is not detected |
