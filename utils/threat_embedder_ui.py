"""Clean flow: upload → view → select pattern → choose payloads → embed → view → download."""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import pydicom
import streamlit as st

from utils.dicom_handler import extract_metadata, load_dicom
from utils.embed_engine import (
    EICAR_TEST_STRING,
    build_file_payload,
)
from utils.audit_logger import log_breach_event
from utils.image_editor import _extract_2d_image, dicom_to_image
from utils.threat_pattern_builder import (
    append_autorun_launcher,
    build_encapsulated_pdf_dicom_bytes,
    build_exe_polyglot_bytes,
    build_image_pixel_embed_bytes,
    build_raw_pdf_embed_bytes,
    build_raw_pixel_embed_bytes,
    embed_script_chrome_payload,
    embed_script_notepad_payload,
)

CHROME_OPEN_COUNT = 3
CUSTOM_PAYLOAD_ID = "custom_upload"

DEMO_TEXT_BYTES = b"DICOM Security Demo - demo text payload (clean flow).\n"

DEMO_PDF_BYTES = b"""%PDF-1.0
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 300 144]/Parent 2 0 R/Contents 4 0 R>>endobj
4 0 obj<</Length 44>>stream
BT /F1 24 Tf 50 100 Td (Clean Flow PDF) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000206 00000 n 
trailer<</Size 5/Root 1 0 R>>
startxref
303
%%EOF"""


@dataclass(frozen=True)
class PayloadPreset:
    preset_id: str
    label: str
    description: str
    filename: str


PAYLOAD_PRESETS: List[PayloadPreset] = [
    PayloadPreset(
        "demo_text",
        "Demo text file",
        "Sample text payload (demo_payload.txt)",
        "demo_payload.txt",
    ),
    PayloadPreset(
        "eicar",
        "EICAR test file",
        "Standard antivirus test string (eicar.com)",
        "eicar.com",
    ),
]

PRESET_BY_ID = {p.preset_id: p for p in PAYLOAD_PRESETS}


@dataclass
class PatternSpec:
    embed_id: str
    label: str
    description: str
    needs_image_dicom: bool
    filename_suffix: str


PATTERN_SPECS: List[PatternSpec] = [
    PatternSpec(
        "pattern_pdf",
        "PDF + hidden files (MP3+PDF.dcm)",
        "Encapsulated PDF DICOM — files appended after PDF %%EOF.",
        False,
        "pattern_pdf",
    ),
    PatternSpec(
        "pattern_exe",
        "EXE / BAT polyglot preamble",
        "Batch script preamble (bytes 0-127), DICM at byte 128. "
        "Rename downloaded .dcm → .bat and double-click to trigger popup.",
        True,
        "pattern_exe",
    ),
    PatternSpec(
        "pattern_pixel",
        "Pixel-data append",
        "Payload appended to PixelData (DX / US / VL6 style).",
        True,
        "pattern_pixel",
    ),
]

FLOW_STEPS = [
    "Upload Source DICOM",
    "Preview Image & Metadata",
    "Select Embed Pattern",
    "Configure Payload",
    "Run Embed",
    "Preview Embedded Result",
    "Download Embedded DICOM",
]

SPEC_BY_ID = {spec.embed_id: spec for spec in PATTERN_SPECS}


@dataclass
class EmbedSelection:
    pdf_bytes: Optional[bytes] = None
    pdf_metadata: Optional[dict] = None
    preserve_original_dicom: bool = False
    hidden_files: List[tuple[str, bytes]] = field(default_factory=list)
    pixel_payload: Optional[bytes] = None
    use_chrome_script: bool = False
    chrome_open_count: int = CHROME_OPEN_COUNT
    use_notepad_script: bool = False
    notepad_message: str = ""
    raw_embed_mode: bool = False
    raw_embed_files: List[tuple[str, bytes]] = field(default_factory=list)
    include_launcher: bool = True
    summary_lines: List[str] = field(default_factory=list)


def _preset_file_bytes(preset_id: str) -> tuple[str, bytes]:
    preset = PRESET_BY_ID[preset_id]
    if preset_id == "demo_text":
        return preset.filename, DEMO_TEXT_BYTES
    if preset_id == "eicar":
        return preset.filename, EICAR_TEST_STRING
    raise ValueError(f"Unknown preset: {preset_id}")


def _pixel_file_payload_bytes(preset_id: str, custom_file) -> bytes:
    if preset_id == "demo_text":
        name, data = _preset_file_bytes("demo_text")
        return build_file_payload(name, data)
    if preset_id == "eicar":
        name, data = _preset_file_bytes("eicar")
        return build_file_payload(name, data)
    if preset_id == CUSTOM_PAYLOAD_ID and custom_file:
        return build_file_payload(custom_file.name, custom_file.getvalue())
    raise ValueError("No payload selected.")


def _init_state() -> None:
    defaults = {
        "cf_upload_key": None,
        "cf_source_name": None,
        "cf_original_bytes": None,
        "cf_metadata": None,
        "cf_original_image": None,
        "cf_base_ds": None,
        "cf_selected_pattern": PATTERN_SPECS[0].embed_id,
        "cf_embedded_bytes": None,
        "cf_embedded_image": None,
        "cf_embed_done": False,
        "cf_last_embed_pattern": None,
        "cf_pdf_dicom_metadata": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _reset_embed_result() -> None:
    st.session_state.cf_embedded_bytes = None
    st.session_state.cf_embedded_image = None
    st.session_state.cf_embed_done = False
    st.session_state.cf_last_embed_pattern = None


def _try_load_image(dicom_bytes: bytes):
    try:
        return dicom_to_image(load_dicom(io.BytesIO(dicom_bytes)))
    except (ValueError, Exception):
        return None


def _step_header(number: int, title: str, done: bool) -> None:
    mark = "✅" if done else "⬜"
    st.markdown(f"### {mark} {number} · {title}")


def _get_spec() -> PatternSpec:
    return SPEC_BY_ID.get(st.session_state.cf_selected_pattern, PATTERN_SPECS[0])


def _render_preset_multiselect(key: str) -> List[str]:
    labels = [p.label for p in PAYLOAD_PRESETS]
    chosen_labels = st.multiselect(
        "Optional preset payload(s) to add",
        labels,
        default=[],
        key=key,
        disabled=not st.session_state.get("cf_base_ds"),
    )
    return [PRESET_BY_ID[p.preset_id].preset_id for p in PAYLOAD_PRESETS if p.label in chosen_labels]


def _render_preset_radio(key: str) -> str:
    options = [p.label for p in PAYLOAD_PRESETS] + ["Custom file upload"]
    ids = [p.preset_id for p in PAYLOAD_PRESETS] + [CUSTOM_PAYLOAD_ID]
    labels_map = {p.label: p.preset_id for p in PAYLOAD_PRESETS}
    labels_map["Custom file upload"] = CUSTOM_PAYLOAD_ID

    default_label = "Custom file upload"
    idx = options.index(default_label)
    if st.session_state.get(key) in ids:
        for lbl, pid in labels_map.items():
            if pid == st.session_state.get(key):
                idx = options.index(lbl)
                break

    choice = st.radio(
        "Select payload",
        options,
        index=idx,
        key=f"{key}_radio",
        disabled=not st.session_state.get("cf_base_ds"),
        label_visibility="collapsed",
    )
    preset_id = labels_map[choice]
    st.session_state[key] = preset_id
    preset = PRESET_BY_ID.get(preset_id)
    if preset:
        st.caption(preset.description)
    return preset_id


def _render_file_inputs(spec: PatternSpec) -> EmbedSelection:
    selection = EmbedSelection()

    with st.container(border=True):
        st.markdown(f"**Pattern:** {spec.label}")

        if spec.embed_id == "pattern_pdf":
            pdf_source = st.radio(
                "PDF document",
                ["Upload your PDF", "Use demo PDF (built-in)"],
                key="cf_pdf_source",
                disabled=not st.session_state.get("cf_base_ds"),
            )
            if pdf_source == "Upload your PDF":
                pdf_file = st.file_uploader(
                    "PDF file",
                    type=["pdf"],
                    key="cf_pdf_in",
                    disabled=not st.session_state.get("cf_base_ds"),
                )
                if pdf_file:
                    selection.pdf_bytes = pdf_file.getvalue()
                    selection.summary_lines.append(
                        f"PDF: `{pdf_file.name}` ({pdf_file.size:,} bytes)"
                    )
            else:
                selection.pdf_bytes = DEMO_PDF_BYTES
                selection.summary_lines.append(
                    f"PDF: `demo_document.pdf` (built-in, {len(DEMO_PDF_BYTES):,} bytes)"
                )

            st.markdown("**Metadata source** — extract from which DICOM?")
            metadata_source = st.radio(
                "Metadata source",
                ["Use step 1 DICOM", "Upload separate DICOM for metadata"],
                key="cf_metadata_source",
                disabled=not st.session_state.get("cf_base_ds"),
                label_visibility="collapsed",
            )

            if metadata_source == "Upload separate DICOM for metadata":
                pdf_dicom_file = st.file_uploader(
                    "DICOM file for metadata extraction",
                    type=["dcm"],
                    key="cf_pdf_dicom",
                    disabled=not st.session_state.get("cf_base_ds"),
                )
                if pdf_dicom_file:
                    try:
                        pdf_dicom_ds = load_dicom(io.BytesIO(pdf_dicom_file.getvalue()))
                        st.session_state.cf_pdf_dicom_metadata = extract_metadata(pdf_dicom_ds)
                        selection.pdf_metadata = st.session_state.cf_pdf_dicom_metadata
                        selection.summary_lines.append(
                            f"DICOM metadata from: `{pdf_dicom_file.name}` (uploaded)"
                        )
                        with st.expander("Loaded metadata"):
                            st.json(selection.pdf_metadata)
                    except Exception as error:
                        st.error(f"Could not load DICOM: {error}")
                        selection.pdf_metadata = None
            else:
                st.session_state.cf_pdf_dicom_metadata = None
                selection.pdf_metadata = st.session_state.cf_metadata

            selection.preserve_original_dicom = st.checkbox(
                "Embed original DICOM image as a recoverable hidden file",
                key="cf_pdf_preserve_dicom",
                help=(
                    "Stores the step-1 DICOM as `original_image.dcm` hidden after %%EOF. "
                    "Use Payload Extractor to recover it; DICOM Cleaner removes it along with other payloads."
                ),
                disabled=not st.session_state.get("cf_base_ds"),
            )
            if selection.preserve_original_dicom and st.session_state.cf_original_bytes:
                selection.summary_lines.append(
                    f"Preserve: `original_image.dcm` "
                    f"({len(st.session_state.cf_original_bytes):,} bytes) — recoverable via Payload Extractor"
                )

            st.markdown("**Hidden payload(s)** — appended after PDF `%%EOF`")

            selection.raw_embed_mode = st.toggle(
                "Raw embed mode (no magic markers — like MP3+PDF.dcm / PDFGitPolyglot.dcm sample files)",
                key="cf_pdf_raw_mode",
                help=(
                    "OFF: files are wrapped with demo magic markers (detectable by Extractor's standard scan). "
                    "ON: files appended as raw bytes — detectable only via binary signature analysis, "
                    "matching the structure of the provided sample DICOM threat files."
                ),
                disabled=not st.session_state.get("cf_base_ds"),
            )

            uploaded_hidden = st.file_uploader(
                "Files to hide (mp3, exe, pdf, zip, txt, …)",
                accept_multiple_files=True,
                key="cf_pdf_hidden",
                disabled=not st.session_state.get("cf_base_ds"),
            ) or []
            for f in uploaded_hidden:
                if selection.raw_embed_mode:
                    selection.raw_embed_files.append((f.name, f.getvalue()))
                else:
                    selection.hidden_files.append((f.name, f.getvalue()))
                selection.summary_lines.append(
                    f"Hide: `{f.name}` ({f.size:,} bytes) — {'raw' if selection.raw_embed_mode else 'wrapped'}"
                )

            if not selection.raw_embed_mode:
                preset_ids = _render_preset_multiselect("cf_pdf_presets")
                for pid in preset_ids:
                    name, data = _preset_file_bytes(pid)
                    selection.hidden_files.append((name, data))
                    selection.summary_lines.append(f"Hide: `{name}` ({len(data):,} bytes) — preset")

            active_metadata = selection.pdf_metadata or st.session_state.cf_metadata
            if active_metadata:
                selection.summary_lines.append(
                    f"Metadata: Patient `{active_metadata.get('Patient Name')}` / "
                    f"ID `{active_metadata.get('Patient ID')}`"
                )

        elif spec.embed_id == "pattern_exe":
            st.info(
                "**BAT/DICOM polyglot** — preamble is a 128-byte batch script. "
                "As `.bat` it executes; as `.dcm` it opens as a medical image. "
                "The auto-run launcher (below) also lets double-clicking the `.dcm` trigger the payload directly."
            )
            exe_script_choice = st.radio(
                "Script payload (embedded in pixel data for auto-run)",
                options=["notepad_script", "chrome_script"],
                format_func=lambda x: {
                    "notepad_script": "📝 Notepad — opens Notepad with a warning message",
                    "chrome_script": "🌐 Chrome — opens Chrome multiple times",
                }[x],
                key="cf_exe_script_choice",
                disabled=not st.session_state.get("cf_base_ds"),
            )
            selection.use_notepad_script = exe_script_choice == "notepad_script"
            selection.use_chrome_script = exe_script_choice == "chrome_script"

            if exe_script_choice == "notepad_script":
                default_msg = (
                    "WARNING: This DICOM file contained a hidden malicious script.\r\n\r\n"
                    "The BAT preamble executed silently when this file was opened.\r\n\r\n"
                    "--- DICOM AI Security Demo ---"
                )
                selection.notepad_message = st.text_area(
                    "Message to display in Notepad",
                    value=default_msg,
                    height=100,
                    key="cf_exe_notepad_msg",
                    disabled=not st.session_state.get("cf_base_ds"),
                )
                selection.chrome_open_count = CHROME_OPEN_COUNT
            else:
                selection.chrome_open_count = int(st.number_input(
                    "Chrome open count", min_value=1, max_value=10,
                    value=CHROME_OPEN_COUNT, key="cf_exe_chrome_count",
                    disabled=not st.session_state.get("cf_base_ds"),
                ))

            selection.include_launcher = st.toggle(
                "Append auto-run launcher (double-click .dcm to trigger payload)",
                value=True,
                key="cf_exe_launcher",
                help=(
                    "Appends a self-extracting launcher. "
                    "When DicomAutoOpen is registered, double-clicking the .dcm runs the embedded script automatically."
                ),
                disabled=not st.session_state.get("cf_base_ds"),
            )

            if st.session_state.cf_source_name:
                selection.summary_lines.append(f"Source DICOM: `{st.session_state.cf_source_name}`")
                selection.summary_lines.append("Preamble: 128-byte batch script")
                if selection.include_launcher:
                    selection.summary_lines.append("Launcher: auto-run on double-click")

        elif spec.embed_id == "pattern_pixel":
            st.markdown("**Payload** — appended after PixelData")

            script_choice = st.radio(
                "Choose payload type",
                options=["notepad_script", "chrome_script", "file_payload"],
                format_func=lambda x: {
                    "notepad_script": "📝 Notepad script — opens Notepad with a custom message (works on any Windows)",
                    "chrome_script": "🌐 Chrome script — opens Chrome multiple times",
                    "file_payload": "📁 File payload — embed a file (preset or upload)",
                }[x],
                key="cf_pixel_script_choice",
                disabled=not st.session_state.get("cf_base_ds"),
            )

            if script_choice == "notepad_script":
                selection.use_notepad_script = True
                default_msg = (
                    "WARNING: This DICOM file contained a hidden malicious script.\r\n\r\n"
                    "In a real attack, this payload could have been ransomware, a data exfiltration "
                    "tool, or remote access malware.\r\n\r\n"
                    "The DICOM image appeared completely normal in any viewer.\r\n\r\n"
                    "--- DICOM AI Security Demo ---"
                )
                selection.notepad_message = st.text_area(
                    "Message to display in Notepad",
                    value=default_msg,
                    height=140,
                    key="cf_notepad_msg",
                    disabled=not st.session_state.get("cf_base_ds"),
                )
                selection.summary_lines.append("Payload: built-in Notepad script — pixel append")

            elif script_choice == "chrome_script":
                selection.use_chrome_script = True
                selection.chrome_open_count = int(
                    st.number_input(
                        "Chrome open count",
                        min_value=1,
                        max_value=10,
                        value=CHROME_OPEN_COUNT,
                        key="cf_chrome_count",
                        disabled=not st.session_state.get("cf_base_ds"),
                    )
                )
                selection.summary_lines.append(
                    f"Payload: built-in Chrome script ({selection.chrome_open_count} opens) — pixel append"
                )

            else:
                raw_pixel = st.toggle(
                    "Raw embed mode (no magic markers — like exe_embedded_dicom-1.dcm sample file)",
                    key="cf_pixel_raw_mode",
                    help=(
                        "ON: file appended as raw bytes — detectable only via binary signature analysis. "
                        "OFF: wrapped with demo magic markers for standard extraction."
                    ),
                    disabled=not st.session_state.get("cf_base_ds"),
                )
                if raw_pixel:
                    selection.raw_embed_mode = True
                    raw_files = st.file_uploader(
                        "Files to hide in pixel tail (mp3, exe, zip, pdf, …)",
                        accept_multiple_files=True,
                        key="cf_pixel_raw_files",
                        disabled=not st.session_state.get("cf_base_ds"),
                    ) or []
                    for f in raw_files:
                        selection.raw_embed_files.append((f.name, f.getvalue()))
                        selection.summary_lines.append(
                            f"Payload: `{f.name}` ({f.size:,} bytes) — raw pixel append"
                        )
                else:
                    st.caption("Pick a preset payload or upload your own file:")
                    preset_id = _render_preset_radio("cf_pixel_preset")
                    if preset_id == CUSTOM_PAYLOAD_ID:
                        custom_file = st.file_uploader(
                            "Payload file (mp3, pdf, exe, txt, …)",
                            key="cf_pixel_custom",
                            disabled=not st.session_state.get("cf_base_ds"),
                        )
                        if custom_file:
                            selection.pixel_payload = _pixel_file_payload_bytes(preset_id, custom_file)
                            selection.summary_lines.append(
                                f"Payload: `{custom_file.name}` ({custom_file.size:,} bytes) — upload"
                            )
                    else:
                        selection.pixel_payload = _pixel_file_payload_bytes(preset_id, None)
                        name = PRESET_BY_ID[preset_id].filename
                        selection.summary_lines.append(
                            f"Payload: `{name}` — {PRESET_BY_ID[preset_id].label} (preset)"
                        )

            selection.include_launcher = st.toggle(
                "Append auto-run launcher (double-click .dcm to trigger payload)",
                value=True,
                key="cf_pixel_launcher",
                help=(
                    "Appends a self-extracting launcher to the DICOM. "
                    "Requires DicomAutoOpen to be registered as the .dcm file handler on the target machine. "
                    "When registered, double-clicking the .dcm file silently runs the embedded script."
                ),
                disabled=not st.session_state.get("cf_base_ds"),
            )
            if selection.include_launcher:
                selection.summary_lines.append("Launcher: auto-run on double-click (DicomAutoOpen)")

            if st.session_state.cf_source_name:
                selection.summary_lines.append(f"Image source: `{st.session_state.cf_source_name}`")

        if selection.summary_lines:
            st.markdown("**Will embed:**")
            for line in selection.summary_lines:
                st.markdown(f"- {line}")

    return selection


def _embed_ready(spec: PatternSpec, has_upload: bool, selection: EmbedSelection) -> tuple[bool, str]:
    if not has_upload:
        return False, "Upload a DICOM file in step 1 first."
    if spec.embed_id == "pattern_pdf":
        if not selection.pdf_bytes:
            return False, "Choose a PDF (upload or demo) in step 4."
        has_files = bool(selection.hidden_files or selection.raw_embed_files)
        if not has_files:
            return False, "Upload at least one file to hide after %%EOF."
        return True, ""
    if spec.embed_id == "pattern_exe":
        return bool(st.session_state.cf_original_bytes), "Upload a DICOM in step 1 first."
    if spec.embed_id == "pattern_pixel":
        if selection.use_chrome_script or selection.use_notepad_script:
            return bool(st.session_state.cf_original_bytes), "Step 1 image DICOM is required."
        if selection.raw_embed_mode:
            if not selection.raw_embed_files:
                return False, "Upload at least one file to embed in raw mode."
            return bool(st.session_state.cf_original_bytes), "Step 1 image DICOM is required."
        if not selection.pixel_payload:
            return False, "Select a preset payload or upload a custom file."
        return bool(st.session_state.cf_original_bytes), "Step 1 image DICOM is required."
    return False, "Unknown pattern."


def render_clean_flow() -> None:
    _init_state()

    st.subheader("7-Step Threat Embed Workflow")
    st.markdown(
        " | ".join(f"**{i}.** {title}" for i, title in enumerate(FLOW_STEPS, start=1))
    )

    _step_header(1, FLOW_STEPS[0], st.session_state.cf_base_ds is not None)
    uploaded = st.file_uploader(
        "Choose a `.dcm` file",
        type=["dcm"],
        key="cf_file_uploader",
        label_visibility="collapsed",
    )

    if uploaded is None:
        st.session_state.cf_upload_key = None
        st.session_state.cf_original_bytes = None
        st.session_state.cf_original_image = None
        st.session_state.cf_metadata = None
        st.session_state.cf_base_ds = None
        _reset_embed_result()
    else:
        upload_key = f"{uploaded.name}:{uploaded.size}"
        if st.session_state.cf_upload_key != upload_key:
            try:
                raw = uploaded.getvalue()
                ds = load_dicom(io.BytesIO(raw))
                image = dicom_to_image(ds)
                st.session_state.cf_upload_key = upload_key
                st.session_state.cf_source_name = uploaded.name
                st.session_state.cf_original_bytes = raw
                st.session_state.cf_base_ds = ds
                st.session_state.cf_original_image = image
                st.session_state.cf_metadata = extract_metadata(ds)
                _reset_embed_result()
            except ValueError as error:
                st.warning(str(error))
                raw = uploaded.getvalue()
                ds = load_dicom(io.BytesIO(raw))
                st.session_state.cf_upload_key = upload_key
                st.session_state.cf_source_name = uploaded.name
                st.session_state.cf_original_bytes = raw
                st.session_state.cf_base_ds = ds
                st.session_state.cf_original_image = None
                st.session_state.cf_metadata = extract_metadata(ds)
                _reset_embed_result()
            except Exception as error:
                st.error(f"Could not load DICOM: {error}")
                _reset_embed_result()

    has_upload = st.session_state.cf_base_ds is not None
    has_image = st.session_state.cf_original_image is not None

    _step_header(2, FLOW_STEPS[1], has_upload)
    if has_image:
        display_img, slice_info = _extract_2d_image(st.session_state.cf_original_image)
        caption = "Original image"
        if slice_info.get("is_volume"):
            caption += f" (slice {slice_info['frame_index'] + 1} of {slice_info['frame_count']})"
        st.image(display_img, caption=caption, width="stretch")
    elif has_upload:
        st.info("No image preview. Metadata from step 1 is still used for PDF pattern.")
    else:
        st.info("Upload a DICOM file to continue.")

    if has_upload and st.session_state.cf_metadata:
        with st.expander("Metadata"):
            st.json(st.session_state.cf_metadata)

    _step_header(3, FLOW_STEPS[2], has_upload)
    labels = [spec.label for spec in PATTERN_SPECS]
    ids = [spec.embed_id for spec in PATTERN_SPECS]
    current_idx = ids.index(st.session_state.cf_selected_pattern) if st.session_state.cf_selected_pattern in ids else 0
    selected_label = st.radio(
        "Pattern embed method",
        labels,
        index=current_idx,
        key="cf_pattern_radio",
        disabled=not has_upload,
        label_visibility="collapsed",
    )
    new_id = ids[labels.index(selected_label)]
    if new_id != st.session_state.cf_selected_pattern:
        st.session_state.cf_selected_pattern = new_id
        _reset_embed_result()

    spec = _get_spec()
    st.caption(spec.description)

    _step_header(4, FLOW_STEPS[3], has_upload)
    selection = _render_file_inputs(spec)

    ready, block_reason = _embed_ready(spec, has_upload, selection)
    _step_header(5, FLOW_STEPS[4], st.session_state.cf_embed_done)

    if st.button(
        "▶ Run Embed",
        type="primary",
        disabled=not ready,
        key="cf_embed_btn",
        width="stretch",
    ):
        try:
            with st.spinner(f"Building {spec.label}…"):
                if spec.embed_id == "pattern_pdf":
                    if selection.raw_embed_mode and selection.raw_embed_files:
                        # Build a PDF DICOM first, then append raw files after %%EOF
                        pdf_only_bytes = _build_pdf(
                            st.session_state.cf_base_ds,
                            selection.pdf_bytes,
                            [],
                            selection.pdf_metadata,
                        )
                        out_bytes, _ = build_raw_pdf_embed_bytes(
                            pdf_only_bytes,
                            selection.raw_embed_files,
                        )
                    else:
                        extra_hidden = list(selection.hidden_files)
                        if selection.preserve_original_dicom and st.session_state.cf_original_bytes:
                            extra_hidden.insert(
                                0,
                                ("original_image.dcm", st.session_state.cf_original_bytes),
                            )
                        out_bytes = _build_pdf(
                            st.session_state.cf_base_ds,
                            selection.pdf_bytes,
                            extra_hidden,
                            selection.pdf_metadata,
                        )
                elif spec.embed_id == "pattern_exe":
                    # Step 1: replace preamble with 128-byte BAT script
                    out_bytes, _ = build_exe_polyglot_bytes(st.session_state.cf_original_bytes)
                    # Step 2: also embed Chrome/Notepad script in pixel data (for auto-run launcher)
                    if selection.use_notepad_script:
                        pixel_payload = embed_script_notepad_payload(
                            selection.notepad_message or "DICOM AI Security Demo payload."
                        )
                    else:
                        pixel_payload = embed_script_chrome_payload(selection.chrome_open_count)
                    out_bytes, _ = build_image_pixel_embed_bytes(out_bytes, pixel_payload)
                    # Step 3: append auto-run launcher
                    if selection.include_launcher:
                        out_bytes = append_autorun_launcher(out_bytes)
                else:
                    if selection.raw_embed_mode and selection.raw_embed_files:
                        out_bytes, _ = build_raw_pixel_embed_bytes(
                            st.session_state.cf_original_bytes,
                            selection.raw_embed_files,
                        )
                    else:
                        if selection.use_notepad_script:
                            payload = embed_script_notepad_payload(selection.notepad_message)
                        elif selection.use_chrome_script:
                            payload = embed_script_chrome_payload(selection.chrome_open_count)
                        else:
                            payload = selection.pixel_payload
                        out_bytes, _ = build_image_pixel_embed_bytes(
                            st.session_state.cf_original_bytes,
                            payload,
                        )
                    if selection.include_launcher and not selection.raw_embed_mode:
                        out_bytes = append_autorun_launcher(out_bytes)

                st.session_state.cf_embedded_bytes = out_bytes
                st.session_state.cf_embedded_image = _try_load_image(out_bytes)
                st.session_state.cf_embed_done = True
                st.session_state.cf_last_embed_pattern = spec.embed_id
                log_breach_event(
                    action="DICOM Payload Embedded",
                    data_type="steganography",
                    data_accessed=(
                        f"{spec.label} into {st.session_state.cf_source_name}; "
                        f"endpoint=clean_flow"
                    ),
                    severity="CRITICAL",
                    endpoint="clean_flow",
                )
            st.rerun()
        except Exception as error:
            st.error(f"Embed failed: {error}")

    if not ready and block_reason:
        st.info(block_reason)

    _step_header(6, FLOW_STEPS[5], st.session_state.cf_embed_done)
    if st.session_state.cf_embed_done and st.session_state.cf_last_embed_pattern == spec.embed_id:
        preview = st.session_state.cf_embedded_image
        if preview is not None:
            display_emb, slice_info = _extract_2d_image(preview)
            cap = f"After embed — {spec.label}"
            if slice_info.get("is_volume"):
                cap += f" (slice {slice_info['frame_index'] + 1} of {slice_info['frame_count']})"
            st.image(display_emb, caption=cap, width="stretch")
            st.caption(
                "Image looks identical to the original — the payload is hidden in the pixel tail "
                "and is not visible to the human eye."
            )
        elif spec.embed_id == "pattern_pdf":
            emb = st.session_state.cf_embedded_bytes or b""
            with st.container(border=True):
                st.markdown("**Document DICOM created (Modality: DOC)**")
                st.markdown(
                    "This output is an **EncapsulatedPDF DICOM**, not an image DICOM.  \n"
                    "Standard image viewers will say 'cannot open' — that is expected.  \n\n"
                    "| | |\n|---|---|\n"
                    f"| Output size | `{len(emb):,}` bytes |\n"
                    f"| DICOM type | EncapsulatedPDF (SOPClass 1.2.840.10008.5.1.4.1.1.104.1) |\n"
                    "| Contains | PDF document + hidden files appended after `%%EOF` |"
                )
                st.info(
                    "Use the **Payload Extractor** tab to scan this file and download the hidden content. "
                    "Use the **DICOM Safety Validator** to detect and remove the hidden files."
                )
        elif spec.embed_id == "pattern_exe":
            with st.container(border=True):
                st.markdown("**BAT/EXE Polyglot DICOM created**")
                st.markdown(
                    "This file has a 128-byte batch script preamble before the DICM marker.  \n\n"
                    "| When opened as | Behaviour |\n|---|---|\n"
                    "| `.dcm` in DICOM viewer | Opens as normal medical image |\n"
                    "| Renamed to `.bat`, double-clicked on Windows | Runs script, shows demo popup |"
                )
    elif has_upload:
        st.info("Select payloads in step 4, then click **Run Embed**.")
    else:
        st.info("Complete earlier steps first.")

    _step_header(7, FLOW_STEPS[6], st.session_state.cf_embed_done)
    if (
        st.session_state.cf_embed_done
        and st.session_state.cf_embedded_bytes
        and st.session_state.cf_last_embed_pattern == spec.embed_id
    ):
        stem = Path(st.session_state.cf_source_name or "study").stem
        out_name = f"{stem}_{spec.filename_suffix}.dcm"
        emb = st.session_state.cf_embedded_bytes

        if spec.embed_id == "pattern_exe":
            include_launcher_exe = st.session_state.get("cf_exe_launcher", True)
            if include_launcher_exe:
                st.success(
                    f"**Double-click `{out_name}` directly** — payload runs automatically "
                    "(DicomAutoOpen handler). Or rename to `.bat` for the polyglot demo."
                )
            col_bat, col_dcm = st.columns(2)
            with col_bat:
                st.download_button(
                    "⬇️ Download as .bat (polyglot demo)",
                    emb,
                    f"{stem}_polyglot.bat",
                    "application/octet-stream",
                    type="primary",
                    key="cf_download_bat",
                    width="stretch",
                )
                st.caption("Double-click → BAT preamble runs → Notepad/Chrome opens")
            with col_dcm:
                st.download_button(
                    "⬇️ Download as .dcm (auto-run demo)",
                    emb,
                    out_name,
                    "application/dicom",
                    type="primary",
                    key="cf_download_dcm",
                    width="stretch",
                )
                st.caption("Double-click → DicomAutoOpen launcher → Notepad/Chrome opens")
            st.caption(f"{len(emb):,} bytes · same file content — two ways to trigger the payload")

        else:
            st.download_button(
                "⬇️ Download Embedded DICOM",
                emb,
                out_name,
                "application/dicom",
                type="primary",
                key="cf_download",
                width="stretch",
            )
            st.caption(f"{len(emb):,} bytes · pattern: {spec.label}")

        if spec.embed_id == "pattern_pixel":
            with st.container(border=True):
                st.markdown("**How to extract and run the hidden payload**")
                script_choice = st.session_state.get("cf_pixel_script_choice", "notepad_script")
                include_launcher = st.session_state.get("cf_pixel_launcher", True)
                if include_launcher and script_choice in ("notepad_script", "chrome_script"):
                    st.success(
                        f"**Double-click `{out_name}` directly** — the payload runs automatically "
                        "(requires DicomAutoOpen file handler to be registered on the machine)."
                    )
                st.markdown(
                    f"1. Download `{out_name}` — open in RadiAnt → looks like a **normal CT scan**\n"
                    "2. **Double-click** the `.dcm` file → payload runs automatically\n"
                    "   *(or go to Payload Extractor → scan → download `embedded.ps1` → run in PowerShell)*"
                )
                if script_choice == "notepad_script":
                    st.info("Notepad opens with your custom warning message.")
                elif script_choice == "chrome_script":
                    st.info("Chrome opens 3 times.")

        elif spec.embed_id == "pattern_pdf":
            with st.container(border=True):
                st.markdown("**How to recover hidden files**")
                st.markdown(
                    f"1. Download `{out_name}`\n"
                    "2. Go to **Payload Extractor** tab → upload → click Scan\n"
                    "3. Download the hidden file(s) found after PDF `%%EOF`\n\n"
                    "Or go to **DICOM Safety Validator** to detect and cleanly remove the threat."
                )
    else:
        st.info("Embed step must finish before download is available.")


def _build_pdf(
    base_ds: Optional[pydicom.Dataset],
    pdf_bytes: bytes,
    hidden_files: List[tuple[str, bytes]],
    pdf_metadata: Optional[dict] = None,
) -> bytes:
    if pdf_metadata:
        patient_name = str(pdf_metadata.get("Patient Name", "Demo^Patient"))
        patient_id = str(pdf_metadata.get("Patient ID", "DEMO001"))
    else:
        patient_name = str(getattr(base_ds, "PatientName", "Demo^Patient")) if base_ds else "Demo^Patient"
        patient_id = str(getattr(base_ds, "PatientID", "DEMO001")) if base_ds else "DEMO001"
    result, _ = build_encapsulated_pdf_dicom_bytes(
        pdf_bytes,
        hidden_files,
        patient_name,
        patient_id,
        base_ds=base_ds,
    )
    return result
