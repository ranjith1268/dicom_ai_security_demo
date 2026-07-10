"""Clean flow: upload → view → select pattern → choose payloads → embed → view → download."""

from __future__ import annotations

import io
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import pydicom
import streamlit as st

from utils.defender_scan import (
    STEGO_ENTERPRISE_URL,
    build_local_defender_scan_script,
    defender_runnable_on_server,
    resolve_scan_target,
    scan_with_defender,
    suggested_client_download_path,
)
from utils.defender_scan_ui import render_client_defender_scan
from utils.defender_bridge import bridge_base_url, is_bridge_port_open
from utils.dicom_handler import extract_metadata, load_dicom
from utils.dicom_handler_register import ensure_dicom_handler_registered
from utils.embed_engine import (
    EICAR_TEST_STRING,
    build_chrome_script_bytes,
    build_file_payload,
    build_modified_embedded_filename,
    build_script_payload,
)
from utils.audit_logger import log_breach_event
from utils.image_editor import _extract_2d_image, dicom_to_image
from utils.threat_pattern_builder import (
    build_encapsulated_pdf_dicom_bytes,
    build_exe_polyglot_bytes,
    build_eof_embed_bytes,
    build_image_pixel_embed_bytes,
    build_jpeg_script_embed,
    build_png_script_embed,
    build_raw_pdf_embed_bytes,
    build_raw_pixel_embed_bytes,
    build_script_payload as pattern_build_script_payload,
    embed_script_file_lister_payload,
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
        "128-byte batch preamble + valid DICOM in one file; script appended after EOF. "
        "Double-click runs the embedded script via the auto-run handler.",
        True,
        "pattern_exe",
    ),
    PatternSpec(
        "pattern_pixel",
        "Script / file append (EOF)",
        "Payload appended after the DICOM file end (reference pattern: *_modified_embedded_*.dcm). "
        "PixelData and metadata tags unchanged; optional auto-run launcher at EOF. "
        "Raw mode uses pixel-tail append.",
        True,
        "pattern_pixel",
    ),
]

FLOW_STEPS = [
    "Upload File (DICOM or Image)",
    "Preview",
    "Select Embed Method",
    "Configure Payload",
    "Run Embed",
    "Preview Embedded Result",
    "Download · Defender Scan · Stego Analysis",
]

EMBED_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "output" / "embed" / "latest"

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
    use_file_lister_script: bool = False
    use_custom_script: bool = False
    custom_script_bytes: Optional[bytes] = None
    custom_script_name: str = ""
    raw_embed_mode: bool = False
    raw_embed_files: List[tuple[str, bytes]] = field(default_factory=list)
    include_launcher: bool = True
    summary_lines: List[str] = field(default_factory=list)


def _custom_script_payload(filename: str, script_bytes: bytes) -> bytes:
    """Wrap custom upload as SCRIPT_MAGIC payload; preserve original filename in a header comment."""
    safe_name = filename.replace("\n", "").strip() or "script.ps1"
    body = f"# OriginalFilename: {safe_name}\n".encode("utf-8") + script_bytes
    return pattern_build_script_payload(body)


def _chrome_eof_payload(open_count: int = CHROME_OPEN_COUNT) -> bytes:
    """Chrome script payload matching the reference TCGA embed files."""
    return build_script_payload(build_chrome_script_bytes(open_count))


def _embedded_dicom_filename() -> str:
    ds = st.session_state.get("cf_base_ds")
    patient_id = str(getattr(ds, "PatientID", None) or Path(st.session_state.cf_source_name or "study").stem)
    return build_modified_embedded_filename(patient_id)


def _preset_file_bytes(preset_id: str) -> tuple[str, bytes]:
    preset = PRESET_BY_ID[preset_id]
    if preset_id == "demo_text":
        return preset.filename, DEMO_TEXT_BYTES
    if preset_id == "eicar":
        return preset.filename, EICAR_TEST_STRING
    raise ValueError(f"Unknown preset: {preset_id}")


def _is_script_filename(name: str) -> bool:
    return name.lower().endswith((".ps1", ".bat", ".cmd"))


def _embed_uploaded_payload(name: str, data: bytes) -> bytes:
    """Wrap upload as SCRIPT_MAGIC (executable) or FILE_MAGIC (attachment)."""
    if _is_script_filename(name):
        return pattern_build_script_payload(data)
    return build_file_payload(name, data)


def _pixel_file_payload_bytes(preset_id: str, custom_file) -> bytes:
    if preset_id == "demo_text":
        name, data = _preset_file_bytes("demo_text")
        return build_file_payload(name, data)
    if preset_id == "eicar":
        name, data = _preset_file_bytes("eicar")
        return build_file_payload(name, data)
    if preset_id == CUSTOM_PAYLOAD_ID and custom_file:
        return _embed_uploaded_payload(custom_file.name, custom_file.getvalue())
    raise ValueError("No payload selected.")


def _init_state() -> None:
    defaults = {
        "cf_upload_key": None,
        "cf_source_name": None,
        "cf_original_bytes": None,
        "cf_metadata": None,
        "cf_original_image": None,
        "cf_base_ds": None,
        "cf_file_kind": None,
        "cf_is_png": False,
        "cf_selected_pattern": PATTERN_SPECS[0].embed_id,
        "cf_embedded_bytes": None,
        "cf_embedded_image": None,
        "cf_embedded_path": None,
        "cf_embedded_filename": None,
        "cf_embed_done": False,
        "cf_last_embed_pattern": None,
        "cf_pdf_dicom_metadata": None,
        "cf_defender_result": None,
        "cf_image_payload_type": "notepad_script",
        "cf_input_type": "dicom",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _reset_embed_result() -> None:
    st.session_state.cf_embedded_bytes = None
    st.session_state.cf_embedded_image = None
    st.session_state.cf_embedded_path = None
    st.session_state.cf_embedded_filename = None
    st.session_state.cf_embed_done = False
    st.session_state.cf_last_embed_pattern = None
    st.session_state.cf_defender_result = None


def _detect_file_kind(name: str, raw: bytes) -> Optional[str]:
    lower = name.lower()
    if lower.endswith((".png", ".jpg", ".jpeg")):
        if raw.startswith(b"\x89PNG\r\n\x1a\n") or raw.startswith(b"\xff\xd8\xff"):
            return "image"
        return None
    try:
        load_dicom(io.BytesIO(raw))
        return "dicom"
    except Exception:
        return None


def _save_embedded_output(data: bytes, filename: str) -> Path:
    EMBED_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EMBED_OUTPUT_DIR / filename
    out_path.write_bytes(data)
    st.session_state.cf_embedded_path = str(out_path.resolve())
    st.session_state.cf_embedded_filename = filename
    return out_path


def _on_embed_download(filename: str) -> None:
    """After download, pre-fill the user's local path for Defender scan."""
    path = suggested_client_download_path(filename)
    st.session_state.cf_defender_scan_path_user = path
    st.session_state.cf_downloaded_filename = filename
    st.session_state[f"cf_defender_scan_path_{filename}"] = path


def _run_defender_scan(out_name: str, saved_path: str | None) -> None:
    """Button callback — set scan state without touching widget-bound session keys."""
    path_key = f"cf_defender_scan_path_{out_name}"
    scan_path = str(st.session_state.get(path_key, ""))
    target, source = resolve_scan_target(scan_path, out_name, saved_path)
    resolved_key = f"cf_defender_resolved_{out_name}"
    bridge_key = f"cf_bridge_scan_path_{out_name}"
    st.session_state[resolved_key] = str(target)

    if defender_runnable_on_server():
        result = scan_with_defender(target)
        result["resolve_source"] = source
        st.session_state.cf_defender_result = result
        st.session_state[bridge_key] = None
        log_breach_event(
            action="Windows Defender Scan",
            data_type="validation",
            data_accessed=f"{target} | status={result.get('status')} | source={source}",
            severity="CRITICAL" if result.get("threats_found") else "INFO",
            endpoint="threat_embedder",
        )
    else:
        st.session_state.cf_defender_result = None
        st.session_state[bridge_key] = str(target)
        log_breach_event(
            action="Windows Defender Scan (local bridge)",
            data_type="validation",
            data_accessed=f"{target} | bridge={bridge_base_url()}",
            severity="INFO",
            endpoint="threat_embedder",
        )


def _render_defender_and_stego(out_name: str, emb: bytes) -> None:
    """Windows Defender scan on the user's machine + StegoEnterprise portal link."""
    saved_path = st.session_state.get("cf_embedded_path")
    path_key = f"cf_defender_scan_path_{out_name}"
    resolved_key = f"cf_defender_resolved_{out_name}"
    bridge_key = f"cf_bridge_scan_path_{out_name}"

    if path_key not in st.session_state:
        st.session_state[path_key] = st.session_state.get(
            "cf_defender_scan_path_user",
            suggested_client_download_path(out_name),
        )

    st.markdown("### 🛡️ Windows Defender scan")

    if defender_runnable_on_server():
        st.caption(
            "Click **Scan** to run Windows Defender on this PC using the file path below."
        )
    else:
        st.caption(
            "**Hosted app:** Real Windows Defender runs only on your Windows PC, not on the cloud server. "
            "Click **Scan** to try the local bridge (`{url}`) if an instructor started it on this PC — "
            "otherwise use Payload Extractor and StegoEnterprise for analysis.".format(
                url=bridge_base_url()
            )
        )
        if sys.platform == "win32" and not is_bridge_port_open():
            st.warning(
                "Local Defender bridge is not running. Instructors can start it with "
                "`python scripts/defender_local_bridge.py` or `scripts\\start_defender_bridge.ps1`. "
                "End users on hosted Streamlit typically skip this step."
            )

    scan_path = st.text_input(
        "Path to the downloaded file on your Windows PC",
        placeholder=suggested_client_download_path(out_name),
        key=path_key,
        help="After you click Download, save the file and confirm its full path here.",
    )

    st.button(
        "🛡️ Scan with Windows Defender",
        key=f"cf_defender_scan_btn_{out_name}",
        width="stretch",
        type="primary",
        on_click=_run_defender_scan,
        args=(out_name, saved_path),
    )

    if st.session_state.get(resolved_key):
        st.caption(f"Resolved scan target: `{st.session_state[resolved_key]}`")

    bridge_scan_path = st.session_state.get(bridge_key)
    if bridge_scan_path:
        st.caption(f"Scanning on your PC: `{bridge_scan_path}`")
        widget_id = f"cf_bridge_widget_{out_name}_{abs(hash(bridge_scan_path))}"
        render_client_defender_scan(bridge_scan_path, widget_id)

    with st.expander("Advanced: download scan script (offline fallback)"):
        script_name = f"scan_{Path(out_name).stem}.ps1"
        st.download_button(
            "⬇️ Download Defender scan script (.ps1)",
            build_local_defender_scan_script(out_name, scan_path),
            script_name,
            "text/plain",
            key=f"cf_defender_script_{out_name}",
            width="stretch",
        )

    result = st.session_state.get("cf_defender_result")
    if result:
        if result.get("status") == "clean":
            st.success(result.get("message", "Clean"))
        elif result.get("threats_found"):
            st.error(result.get("message", "Threat detected"))
        elif not result.get("available"):
            st.warning(result.get("message", "Defender unavailable"))
        else:
            st.warning(result.get("message", "Scan completed"))
        if result.get("scanned_path"):
            st.caption(f"Scanned: `{result['scanned_path']}`")
        if result.get("detail"):
            with st.expander("Defender scan output"):
                st.code(result["detail"])

    st.divider()
    st.markdown("### 🔍 Steganography analysis — StegoEnterprise")
    st.caption(
        "Continue analysis in the StegoEnterprise portal (WetStone Labs) or use the "
        "built-in Payload Extractor."
    )
    col_stego, col_extract = st.columns(2)
    with col_stego:
        st.link_button(
            "Open StegoEnterprise Portal",
            STEGO_ENTERPRISE_URL,
            type="primary",
            width="stretch",
        )
    with col_extract:
        if st.button(
            "Open Payload Extractor",
            key=f"cf_goto_extractor_{out_name}",
            type="secondary",
            width="stretch",
        ):
            st.session_state.extract_prefill_bytes = emb
            st.session_state.extract_prefill_name = out_name
            st.session_state.extract_prefill_active = True
            st.session_state.extract_items = None
            st.session_state.extract_source = None
            st.session_state.app_mode = "🔍  Payload Extractor"
            st.rerun()

    st.divider()
    st.markdown("### Double-click auto-run (Windows)")
    if defender_runnable_on_server():
        st.caption(
            "On this PC, double-click the downloaded `.dcm` to run the hidden script "
            "(handler registered when you started the app locally). "
            "PowerShell runs invisibly — only the payload UI (e.g. Notepad) appears."
        )
    else:
        st.info(
            "**Hosted app:** Downloaded `.dcm` files open in your normal DICOM viewer when double-clicked. "
            "Silent auto-run is **not** available from the browser alone — it requires a one-time local "
            "`.dcm` handler (lab / instructor PCs). Use **Payload Extractor** above to recover and analyse "
            "embedded scripts."
        )


def _render_post_embed_tools(out_name: str, emb: bytes, mime: str) -> None:
    """Download, Windows Defender scan, and link to StegoEnterprise."""
    st.download_button(
        f"⬇️ Download `{out_name}`",
        emb,
        out_name,
        mime,
        type="primary",
        key=f"cf_download_main_{out_name}",
        width="stretch",
        on_click=_on_embed_download,
        args=(out_name,),
    )
    st.caption(
        f"{len(emb):,} bytes — after saving, use the path below for Defender "
        f"(typically `{suggested_client_download_path(out_name)}`)."
    )
    _render_defender_and_stego(out_name, emb)


def _render_image_payload_config() -> EmbedSelection:
    """Payload options for PNG/JPEG stego embed."""
    selection = EmbedSelection()
    with st.container(border=True):
        st.markdown("**Pattern:** Image stego — PNG/JPEG EOF append")
        st.caption(
            "Script is hidden after the image end marker. The picture looks identical "
            "in any viewer until analysed."
        )
        payload_type = st.radio(
            "Choose payload",
            ["notepad_script", "chrome_script", "file_lister_script", "custom_script"],
            format_func=lambda x: {
                "notepad_script": "📝 Notepad — opens Notepad with a warning message",
                "chrome_script": "🌐 Chrome — opens Chrome multiple times",
                "file_lister_script": "🗂️ File Lister — popup listing user files",
                "custom_script": "📜 Custom script — upload your own .ps1 / .bat file",
            }[x],
            key="cf_image_payload_type",
        )

        if payload_type == "notepad_script":
            selection.use_notepad_script = True
            selection.notepad_message = st.text_area(
                "Message to display in Notepad",
                value=(
                    "WARNING: This image file contained a hidden malicious script.\r\n\r\n"
                    "The payload was appended after the image data — the picture looked "
                    "completely normal in any viewer.\r\n\r\n"
                    "--- DICOM AI Security Demo ---"
                ),
                height=120,
                key="cf_image_notepad_msg",
            )
        elif payload_type == "chrome_script":
            selection.use_chrome_script = True
            selection.chrome_open_count = int(st.number_input(
                "Chrome open count", min_value=1, max_value=10,
                value=CHROME_OPEN_COUNT, key="cf_image_chrome_count",
            ))
        elif payload_type == "file_lister_script":
            selection.use_file_lister_script = True
            st.info(
                "A popup window will list files from Desktop, Documents, Downloads, "
                "Pictures, Music and Videos when the script runs."
            )
        else:
            selection.use_custom_script = True
            script_file = st.file_uploader(
                "Upload PowerShell or batch script (.ps1, .bat, .cmd)",
                type=["ps1", "bat", "cmd"],
                key="cf_image_custom_script",
            )
            if script_file:
                selection.custom_script_name = script_file.name
                selection.custom_script_bytes = script_file.getvalue()
                selection.pixel_payload = _custom_script_payload(script_file.name, selection.custom_script_bytes)
                selection.summary_lines.append(
                    f"Payload: `{script_file.name}` ({script_file.size:,} bytes) — custom script"
                )
                st.caption(
                    "Embedded with SCRIPT_MAGIC so Payload Extractor and manual "
                    "`powershell -File` execution work correctly."
                )
            else:
                st.warning("Upload a script file to continue.")
        if not selection.use_custom_script:
            selection.summary_lines.append(f"Payload: {payload_type} — image EOF append")
    return selection


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
                "**BAT/DICOM polyglot** — one `.dcm` file with a hidden 128-byte batch layer inside. "
                "DICOM viewers read from byte 128 and display the image normally. "
                "Double-click runs the embedded script automatically."
            )
            exe_script_choice = st.radio(
                "Script payload (appended after DICOM EOF for auto-run)",
                options=["notepad_script", "chrome_script", "file_lister_script", "custom_script"],
                format_func=lambda x: {
                    "notepad_script": "📝 Notepad — opens Notepad with a warning message",
                    "chrome_script": "🌐 Chrome — opens Chrome multiple times",
                    "file_lister_script": "🗂️ File Lister — lists user files in a popup window",
                    "custom_script": "📜 Custom script — upload your own .ps1 / .bat file",
                }[x],
                key="cf_exe_script_choice",
                disabled=not st.session_state.get("cf_base_ds"),
            )
            selection.use_notepad_script = exe_script_choice == "notepad_script"
            selection.use_chrome_script = exe_script_choice == "chrome_script"
            selection.use_file_lister_script = exe_script_choice == "file_lister_script"
            selection.use_custom_script = exe_script_choice == "custom_script"

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
            elif exe_script_choice == "chrome_script":
                selection.chrome_open_count = int(st.number_input(
                    "Chrome open count", min_value=1, max_value=10,
                    value=CHROME_OPEN_COUNT, key="cf_exe_chrome_count",
                    disabled=not st.session_state.get("cf_base_ds"),
                ))
            elif exe_script_choice == "custom_script":
                script_file = st.file_uploader(
                    "Upload PowerShell or batch script (.ps1, .bat, .cmd)",
                    type=["ps1", "bat", "cmd"],
                    key="cf_exe_custom_script",
                    disabled=not st.session_state.get("cf_base_ds"),
                )
                if script_file:
                    selection.custom_script_name = script_file.name
                    selection.custom_script_bytes = script_file.getvalue()
                    selection.pixel_payload = _custom_script_payload(script_file.name, selection.custom_script_bytes)
                    selection.summary_lines.append(
                        f"Pixel script: `{script_file.name}` — custom upload (auto-run compatible)"
                    )
                st.caption(
                    "Custom scripts are embedded with SCRIPT_MAGIC so the auto-run launcher "
                    "can find and execute them on double-click."
                )
            else:
                st.info(
                    "On double-click a popup window will appear listing files from the user's "
                    "Desktop, Documents, Downloads, Pictures, Music and Videos folders."
                )

            selection.include_launcher = st.toggle(
                "Append auto-run launcher (double-click .dcm to trigger payload)",
                value=True,
                key="cf_exe_launcher",
                help=(
                    "Stores a launcher after the DICOM EOF. "
                    "Double-clicking the .dcm runs the embedded script automatically."
                ),
                disabled=not st.session_state.get("cf_base_ds"),
            )

            if st.session_state.cf_source_name:
                selection.summary_lines.append(f"Source DICOM: `{st.session_state.cf_source_name}`")
                selection.summary_lines.append("Preamble: 128-byte batch script")
                if selection.include_launcher:
                    selection.summary_lines.append("Launcher: auto-run on double-click")

        elif spec.embed_id == "pattern_pixel":
            st.markdown("**Payload** — appended after DICOM EOF (reference embed pattern)")

            script_choice = st.radio(
                "Choose payload type",
                options=["notepad_script", "chrome_script", "file_lister_script", "custom_script", "file_payload"],
                format_func=lambda x: {
                    "notepad_script": "📝 Notepad script — opens Notepad with a custom message (works on any Windows)",
                    "chrome_script": "🌐 Chrome script — opens Chrome multiple times",
                    "file_lister_script": "🗂️ File Lister — popup window listing user files (Desktop, Documents, Downloads…)",
                    "custom_script": "📜 Custom script — upload your own .ps1 / .bat (auto-run compatible)",
                    "file_payload": "📁 File payload — embed a non-script file (mp3, pdf, exe, txt, …)",
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

            elif script_choice == "file_lister_script":
                selection.use_file_lister_script = True
                st.info(
                    "A hidden PowerShell script will scan **Desktop, Documents, Downloads, "
                    "Pictures, Music and Videos** and display all found files in a dark-themed "
                    "popup window — demonstrating silent file system access from a DICOM payload."
                )
                selection.summary_lines.append("Payload: File Lister script — popup with user file listing")

            elif script_choice == "custom_script":
                selection.use_custom_script = True
                script_file = st.file_uploader(
                    "Upload PowerShell or batch script (.ps1, .bat, .cmd)",
                    type=["ps1", "bat", "cmd"],
                    key="cf_pixel_custom_script",
                    disabled=not st.session_state.get("cf_base_ds"),
                )
                if script_file:
                    selection.custom_script_name = script_file.name
                    selection.custom_script_bytes = script_file.getvalue()
                    selection.pixel_payload = _custom_script_payload(script_file.name, selection.custom_script_bytes)
                    selection.summary_lines.append(
                        f"Payload: `{script_file.name}` ({script_file.size:,} bytes) — custom script"
                    )
                st.caption(
                    "Uses SCRIPT_MAGIC (not FILE_MAGIC) so double-click auto-run and "
                    "Payload Extractor both recognise it as an executable script."
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
                            "Payload file (mp3, pdf, exe, txt, … — not .ps1; use Custom script above)",
                            type=["mp3", "pdf", "exe", "txt", "zip", "bin"],
                            key="cf_pixel_custom",
                            disabled=not st.session_state.get("cf_base_ds"),
                        )
                        if custom_file:
                            selection.pixel_payload = _pixel_file_payload_bytes(preset_id, custom_file)
                            wrap = "script" if _is_script_filename(custom_file.name) else "file"
                            selection.summary_lines.append(
                                f"Payload: `{custom_file.name}` ({custom_file.size:,} bytes) — {wrap} upload"
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
                    "Stores a launcher after the DICOM EOF. "
                    "Double-clicking the .dcm silently runs the embedded script."
                ),
                disabled=not st.session_state.get("cf_base_ds"),
            )
            if selection.include_launcher:
                selection.summary_lines.append("Launcher: auto-run on double-click")

            if st.session_state.cf_source_name:
                selection.summary_lines.append(f"Image source: `{st.session_state.cf_source_name}`")

        if selection.summary_lines:
            st.markdown("**Will embed:**")
            for line in selection.summary_lines:
                st.markdown(f"- {line}")

    return selection


def _embed_ready(spec: PatternSpec, has_upload: bool, selection: EmbedSelection) -> tuple[bool, str]:
    file_kind = st.session_state.get("cf_file_kind")
    if not has_upload:
        return False, "Upload a DICOM or image file in step 1 first."

    if file_kind == "image":
        if selection.use_custom_script and not selection.pixel_payload:
            return False, "Upload a custom .ps1 / .bat script in step 4."
        return True, ""

    if spec.embed_id == "pattern_pdf":
        if not selection.pdf_bytes:
            return False, "Choose a PDF (upload or demo) in step 4."
        has_files = bool(selection.hidden_files or selection.raw_embed_files)
        if not has_files:
            return False, "Upload at least one file to hide after %%EOF."
        return True, ""
    if spec.embed_id == "pattern_exe":
        if selection.use_custom_script and not selection.pixel_payload:
            return False, "Upload a custom .ps1 / .bat script in step 4."
        return bool(st.session_state.cf_original_bytes), "Upload a DICOM in step 1 first."
    if spec.embed_id == "pattern_pixel":
        if selection.use_chrome_script or selection.use_notepad_script or selection.use_file_lister_script:
            return bool(st.session_state.cf_original_bytes), "Step 1 image DICOM is required."
        if selection.use_custom_script:
            if not selection.pixel_payload:
                return False, "Upload a custom .ps1 / .bat script in step 4."
            return bool(st.session_state.cf_original_bytes), "Step 1 DICOM is required."
        if selection.raw_embed_mode:
            if not selection.raw_embed_files:
                return False, "Upload at least one file to embed in raw mode."
            return bool(st.session_state.cf_original_bytes), "Step 1 image DICOM is required."
        if not selection.pixel_payload:
            return False, "Select a preset payload or upload a custom file."
        return bool(st.session_state.cf_original_bytes), "Step 1 image DICOM is required."
    return False, "Unknown pattern."


def _render_unified_embed() -> None:
    """Unified wizard: DICOM or PNG/JPEG upload → embed → download → Defender → stego link."""
    st.subheader("Threat Embed Workflow")
    st.markdown(
        " | ".join(f"**{i}.** {title}" for i, title in enumerate(FLOW_STEPS, start=1))
    )

    _step_header(1, FLOW_STEPS[0], st.session_state.cf_file_kind is not None)

    prev_input_type = st.session_state.get("_cf_input_type_prev", st.session_state.get("cf_input_type", "dicom"))
    input_type = st.radio(
        "File type",
        options=["dicom", "image"],
        format_func=lambda x: {
            "dicom": "DICOM — medical imaging file (.dcm)",
            "image": "Non-DICOM — standard image (.png, .jpg, .jpeg)",
        }[x],
        horizontal=True,
        key="cf_input_type",
    )

    if input_type != prev_input_type:
        st.session_state._cf_input_type_prev = input_type
        st.session_state.cf_upload_key = None
        st.session_state.cf_original_bytes = None
        st.session_state.cf_original_image = None
        st.session_state.cf_metadata = None
        st.session_state.cf_base_ds = None
        st.session_state.cf_file_kind = None
        _reset_embed_result()
    elif "_cf_input_type_prev" not in st.session_state:
        st.session_state._cf_input_type_prev = input_type

    if input_type == "dicom":
        upload_types = ["dcm"]
        upload_label = "Upload DICOM file (.dcm)"
        st.caption("Only `.dcm` files are accepted for this selection.")
    else:
        upload_types = ["png", "jpg", "jpeg"]
        upload_label = "Upload image file (.png, .jpg, .jpeg)"
        st.caption("Only PNG or JPEG images are accepted for this selection.")

    uploaded = st.file_uploader(
        upload_label,
        type=upload_types,
        key=f"cf_file_uploader_{input_type}",
        label_visibility="collapsed",
    )

    if uploaded is None:
        st.session_state.cf_upload_key = None
        st.session_state.cf_original_bytes = None
        st.session_state.cf_original_image = None
        st.session_state.cf_metadata = None
        st.session_state.cf_base_ds = None
        st.session_state.cf_file_kind = None
        _reset_embed_result()
    else:
        upload_key = f"{uploaded.name}:{uploaded.size}"
        if st.session_state.cf_upload_key != upload_key:
            raw = uploaded.getvalue()
            kind = _detect_file_kind(uploaded.name, raw)
            expected_kind = "dicom" if input_type == "dicom" else "image"
            if kind != expected_kind:
                st.error(
                    f"This file is not a valid {expected_kind.upper()} for the selected type. "
                    f"Switch the radio above or upload a different file."
                )
                st.session_state.cf_file_kind = None
            elif kind is None:
                st.error("Could not read this file. Upload a valid DICOM or PNG/JPEG image.")
                st.session_state.cf_file_kind = None
            else:
                st.session_state.cf_upload_key = upload_key
                st.session_state.cf_source_name = uploaded.name
                st.session_state.cf_original_bytes = raw
                st.session_state.cf_file_kind = kind
                st.session_state.cf_is_png = uploaded.name.lower().endswith(".png")

                if kind == "image":
                    st.session_state.cf_base_ds = None
                    st.session_state.cf_original_image = None
                    st.session_state.cf_metadata = {
                        "File Type": "PNG" if st.session_state.cf_is_png else "JPEG",
                        "Size (bytes)": len(raw),
                        "Filename": uploaded.name,
                    }
                else:
                    try:
                        ds = load_dicom(io.BytesIO(raw))
                        image = dicom_to_image(ds)
                        st.session_state.cf_base_ds = ds
                        st.session_state.cf_original_image = image
                        st.session_state.cf_metadata = extract_metadata(ds)
                    except ValueError as error:
                        st.warning(str(error))
                        ds = load_dicom(io.BytesIO(raw))
                        st.session_state.cf_base_ds = ds
                        st.session_state.cf_original_image = None
                        st.session_state.cf_metadata = extract_metadata(ds)
                    except Exception as error:
                        st.error(f"Could not load DICOM: {error}")
                        st.session_state.cf_file_kind = None
                        st.session_state.cf_base_ds = None
                _reset_embed_result()

    has_upload = st.session_state.cf_file_kind is not None
    file_kind = st.session_state.get("cf_file_kind")
    has_image_preview = file_kind == "image" or st.session_state.cf_original_image is not None

    _step_header(2, FLOW_STEPS[1], has_upload)
    if file_kind == "image" and st.session_state.cf_original_bytes:
        st.image(
            st.session_state.cf_original_bytes,
            caption=f"Original — {st.session_state.cf_source_name}",
            width="stretch",
        )
    elif has_image_preview:
        display_img, slice_info = _extract_2d_image(st.session_state.cf_original_image)
        caption = "Original image"
        if slice_info.get("is_volume"):
            caption += f" (slice {slice_info['frame_index'] + 1} of {slice_info['frame_count']})"
        st.image(display_img, caption=caption, width="stretch")
    elif has_upload:
        st.info("No image preview. Metadata from step 1 is still used for PDF pattern.")
    else:
        st.info("Upload a DICOM or image file to continue.")

    if has_upload and st.session_state.cf_metadata:
        with st.expander("File details"):
            st.json(st.session_state.cf_metadata)

    _step_header(3, FLOW_STEPS[2], has_upload)
    if file_kind == "image":
        st.info(
            "**Embed method:** Image stego — payload appended after PNG IEND / JPEG EOI. "
            "The image displays normally in any viewer."
        )
        spec = PatternSpec("pattern_image", "Image stego", "", False, "embedded")
    else:
        labels = [s.label for s in PATTERN_SPECS]
        ids = [s.embed_id for s in PATTERN_SPECS]
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
    if file_kind == "image":
        selection = _render_image_payload_config()
    else:
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
            with st.spinner("Building embedded file…"):
                if file_kind == "image":
                    raw_img = st.session_state.cf_original_bytes
                    if selection.use_notepad_script:
                        payload = embed_script_notepad_payload(selection.notepad_message)
                    elif selection.use_chrome_script:
                        payload = _chrome_eof_payload(selection.chrome_open_count)
                    elif selection.use_custom_script:
                        payload = selection.pixel_payload
                    else:
                        payload = embed_script_file_lister_payload()
                    if st.session_state.cf_is_png:
                        out_bytes, _ = build_png_script_embed(raw_img, payload)
                    else:
                        out_bytes, _ = build_jpeg_script_embed(raw_img, payload)
                    st.session_state.cf_last_embed_pattern = "pattern_image"
                    st.session_state.cf_embedded_image = None
                elif spec.embed_id == "pattern_pdf":
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
                    out_bytes, _ = build_exe_polyglot_bytes(st.session_state.cf_original_bytes)
                    if selection.use_notepad_script:
                        script_payload = embed_script_notepad_payload(
                            selection.notepad_message or "DICOM AI Security Demo payload."
                        )
                    elif selection.use_file_lister_script:
                        script_payload = embed_script_file_lister_payload()
                    elif selection.use_custom_script:
                        script_payload = selection.pixel_payload
                    else:
                        script_payload = _chrome_eof_payload(selection.chrome_open_count)
                    out_bytes, _ = build_eof_embed_bytes(
                        out_bytes,
                        script_payload,
                        source_name=st.session_state.cf_source_name or "upload.dcm",
                        include_launcher=selection.include_launcher,
                    )
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
                            payload = _chrome_eof_payload(selection.chrome_open_count)
                        elif selection.use_file_lister_script:
                            payload = embed_script_file_lister_payload()
                        elif selection.use_custom_script:
                            payload = selection.pixel_payload
                        else:
                            payload = selection.pixel_payload
                        out_bytes, _ = build_eof_embed_bytes(
                            st.session_state.cf_original_bytes,
                            payload,
                            source_name=st.session_state.cf_source_name or "upload.dcm",
                            include_launcher=selection.include_launcher,
                        )

                st.session_state.cf_embedded_bytes = out_bytes
                st.session_state.cf_embedded_image = _try_load_image(out_bytes) if file_kind == "dicom" else None
                st.session_state.cf_embed_done = True

                if (
                    file_kind == "dicom"
                    and selection.include_launcher
                    and sys.platform == "win32"
                ):
                    ensure_dicom_handler_registered()

                if file_kind == "image":
                    stem = Path(st.session_state.cf_source_name or "image").stem
                    ext = ".png" if st.session_state.cf_is_png else ".jpg"
                    out_fname = f"{stem}_embedded{ext}"
                    _save_embedded_output(out_bytes, out_fname)
                    log_breach_event(
                        action="Image File Embedded",
                        data_type="steganography",
                        data_accessed=f"Image stego into {st.session_state.cf_source_name}",
                        severity="CRITICAL",
                        endpoint="threat_embedder",
                    )
                else:
                    st.session_state.cf_last_embed_pattern = spec.embed_id
                    if spec.embed_id in ("pattern_pixel", "pattern_exe"):
                        out_fname = _embedded_dicom_filename()
                    else:
                        stem = Path(st.session_state.cf_source_name or "study").stem
                        out_fname = f"{stem}_{spec.filename_suffix}.dcm"
                    _save_embedded_output(out_bytes, out_fname)
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
    embed_pattern = st.session_state.cf_last_embed_pattern
    embed_matches = (
        st.session_state.cf_embed_done
        and (embed_pattern == spec.embed_id or (file_kind == "image" and embed_pattern == "pattern_image"))
    )

    if embed_matches:
        if file_kind == "image" and st.session_state.cf_embedded_bytes:
            raw_img = st.session_state.cf_original_bytes
            emb_img = st.session_state.cf_embedded_bytes
            added = len(emb_img) - len(raw_img)
            st.success(f"Payload embedded — {len(raw_img):,} → {len(emb_img):,} bytes (+{added:,} hidden)")
            col_before, col_after = st.columns(2)
            with col_before:
                st.image(raw_img, caption="Original", width="stretch")
            with col_after:
                st.image(emb_img, caption="Embedded (looks identical)", width="stretch")
        elif st.session_state.cf_embedded_image is not None:
            preview = st.session_state.cf_embedded_image
            display_emb, slice_info = _extract_2d_image(preview)
            cap = f"After embed — {spec.label}"
            if slice_info.get("is_volume"):
                cap += f" (slice {slice_info['frame_index'] + 1} of {slice_info['frame_count']})"
            st.image(display_emb, caption=cap, width="stretch")
            st.caption(
                "Image looks identical to the original — the payload is appended after the DICOM EOF "
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
    if embed_matches and st.session_state.cf_embedded_bytes:
        emb = st.session_state.cf_embedded_bytes
        out_name = st.session_state.cf_embedded_filename

        if file_kind == "image":
            if not out_name:
                stem = Path(st.session_state.cf_source_name or "image").stem
                ext = ".png" if st.session_state.cf_is_png else ".jpg"
                out_name = f"{stem}_embedded{ext}"
            mime = "image/png" if st.session_state.cf_is_png else "image/jpeg"
            _render_post_embed_tools(out_name, emb, mime)

        elif spec.embed_id == "pattern_exe":
            out_name = out_name or _embedded_dicom_filename()
            include_launcher_exe = st.session_state.get("cf_exe_launcher", True)
            if include_launcher_exe:
                st.info(
                    "Single polyglot `.dcm` file — double-click to run the embedded script. "
                    "The DICOM image remains valid for viewers."
                )
            _render_post_embed_tools(out_name, emb, "application/dicom")

        else:
            if spec.embed_id in ("pattern_pixel", "pattern_exe"):
                out_name = out_name or _embedded_dicom_filename()
            else:
                stem = Path(st.session_state.cf_source_name or "study").stem
                out_name = out_name or f"{stem}_{spec.filename_suffix}.dcm"

            if spec.embed_id == "pattern_pixel":
                with st.container(border=True):
                    st.markdown("**How to extract and run the hidden payload**")
                    script_choice = st.session_state.get("cf_pixel_script_choice", "notepad_script")
                    include_launcher = st.session_state.get("cf_pixel_launcher", True)
                    if include_launcher and script_choice in (
                        "notepad_script",
                        "chrome_script",
                        "file_lister_script",
                        "custom_script",
                    ):
                        st.success(
                            f"**Double-click `{out_name}`** — the hidden script runs automatically."
                        )
                    if script_choice == "notepad_script":
                        st.info("Notepad opens with your custom warning message.")
                    elif script_choice == "chrome_script":
                        st.info("Chrome opens multiple times.")
                    elif script_choice == "file_lister_script":
                        st.info("File lister popup shows user folder contents.")

            elif spec.embed_id == "pattern_pdf":
                with st.container(border=True):
                    st.markdown("**How to recover hidden files**")
                    st.caption("Use Payload Extractor or DICOM Safety Validator on the downloaded file.")

            _render_post_embed_tools(out_name, emb, "application/dicom")
    else:
        st.info("Embed step must finish before download is available.")


def render_clean_flow() -> None:
    _init_state()
    _render_unified_embed()


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
