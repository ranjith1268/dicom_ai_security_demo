"""Streamlit UI for DICOM payload embedding — private-tag safe embed + pattern builds."""

from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import pydicom
import streamlit as st

from utils.embed_engine import (
    EmbedOptions,
    embed_chrome_launcher,
    embed_script_and_file,
    embed_uploaded_file,
    embed_uploaded_script,
    save_embed_artifacts,
    validate_dicom,
)
from utils.embed_extract import extract_embedded_items
from utils.embedded_risk_module import log_breach_event
from utils.pattern_dicom_builder import (
    build_encapsulated_pdf_dicom_bytes,
    build_exe_polyglot_bytes,
    build_file_payload,
    build_image_pixel_embed_bytes,
    embed_script_chrome_payload,
)

SAFE_PATTERNS = {
    "Append file (private tag)": "Hide any file in a private DICOM tag — image unchanged, viewers stay compatible.",
    "Append script (private tag)": "Hide a .ps1 / .py / .bat script in a private DICOM tag.",
    "Built-in Chrome launcher": "Embed PowerShell that opens Chrome N times (private tag).",
    "Script + file (both)": "Embed one script and one file in a private DICOM tag.",
}

PATTERN_EMBEDS = {
    "PDF + hidden files (MP3+PDF.dcm)": "Encapsulated PDF DICOM — files appended after PDF %%EOF. Optional base DICOM for metadata.",
    "EXE polyglot preamble": "MZ DOS stub at byte 0, DICM at byte 128 (exe_embedded_dicom-1.dcm).",
    "Pixel-data append": "Payload appended to PixelData (DX / US style).",
}

MODE_HELP = {
    "Safe embed": "Stores payloads in a **private DICOM tag**. Pixels and metadata stay viewer-compatible.",
    "Pattern embed": "Builds **known test-file patterns** used in security research (PDF polyglot, EXE preamble, pixel append).",
}


def _log_embed_event(log: dict, extra: dict, source_name: str) -> None:
    item = extra.get("embedded_item") or extra.get("pattern", "payload")
    size = log.get("payload_bytes_total") or log.get("payload_bytes") or len(extra.get("attached", []))
    log_breach_event(
        action="DICOM Payload Embedded",
        data_type="steganography",
        data_accessed=(
            f"{item} ({size} bytes) into {source_name}; "
            f"method={log.get('method') or log.get('pattern')}; "
            f"pixels_unchanged={log.get('pixels_unchanged', log.get('pixels_unchanged_prefix'))}"
        ),
        severity="CRITICAL",
        endpoint="embed_engine",
    )


def _show_download(result: bytes, log: dict, extra: dict, stem: str, source_name: str) -> None:
    out_path, log_path, out_name, log_json = save_embed_artifacts(
        result, log, source_name, extra, out_stem=stem
    )

    st.success("Build complete — your files are ready.")

    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Mode", extra.get("flow", "embed"))
    with m2:
        unchanged = log.get("pixels_unchanged", log.get("pixels_unchanged_prefix"))
        st.metric("Pixels unchanged", "Yes" if unchanged else "No / N/A")
    with m3:
        st.metric("Output size", f"{len(result):,} B")

    d1, d2 = st.columns(2)
    with d1:
        st.download_button(
            "⬇️ Download DICOM",
            result,
            out_name,
            "application/dicom",
            key=f"dl_dcm_{stem}_{datetime.now().timestamp()}",
            type="primary",
            width="stretch",
        )
    with d2:
        st.download_button(
            "⬇️ Download log (.json)",
            log_json,
            Path(log_path).name,
            "application/json",
            key=f"dl_log_{stem}_{datetime.now().timestamp()}",
            width="stretch",
        )

    with st.expander("Build log (JSON)"):
        st.code(log_json, language="json")
    st.caption(f"Also saved to `{out_path}`")


def _run_safe_embed(
    pattern: str,
    options: EmbedOptions,
    dicom_bytes: bytes,
    dicom_name: str,
    script_file,
    attach_file,
) -> tuple[bytes, dict, dict]:
    extra = {"flow": "safe_embed", "pattern": pattern, "source_dicom": dicom_name}

    if pattern == "Built-in Chrome launcher":
        result, log = embed_chrome_launcher(dicom_bytes, options)
        extra["embedded_item"] = f"chrome_x{options.chrome_open_count}"
    elif pattern == "Append script (private tag)":
        result, log = embed_uploaded_script(dicom_bytes, script_file.getvalue(), options)
        extra["embedded_item"] = script_file.name
    elif pattern == "Append file (private tag)":
        result, log = embed_uploaded_file(
            dicom_bytes, attach_file.name, attach_file.getvalue(), options
        )
        extra["embedded_item"] = attach_file.name
    else:
        result, log = embed_script_and_file(
            dicom_bytes,
            script_file.getvalue(),
            attach_file.name,
            attach_file.getvalue(),
            options,
        )
        extra["embedded_item"] = f"{script_file.name} + {attach_file.name}"

    log["flow"] = "safe_embed"
    return result, log, extra


def _run_pattern_embed(
    pattern: str,
    options: EmbedOptions,
    patient_name: str,
    patient_id: str,
    dicom_bytes: bytes | None,
    dicom_name: str,
    pdf_file,
    attach_files: List,
    payload_file,
    use_chrome: bool,
    base_ds=None,
) -> tuple[bytes, dict, dict]:
    extra: dict = {"flow": "pattern_embed", "pattern": pattern}

    if pattern == "PDF + hidden files (MP3+PDF.dcm)":
        if not pdf_file or not attach_files:
            raise ValueError("Upload a PDF and at least one file to hide.")
        extras = [(f.name, f.getvalue()) for f in attach_files]
        result, log = build_encapsulated_pdf_dicom_bytes(
            pdf_file.getvalue(), extras, patient_name, patient_id, base_ds=base_ds
        )
        log["method"] = log["pattern"]
        log["pixels_unchanged"] = True
        log["metadata_unchanged"] = True
        extra.update({"pdf": pdf_file.name, "attached": [f.name for f in attach_files]})
        if base_ds is not None:
            extra["source_dicom"] = dicom_name
        return result, log, extra

    if not dicom_bytes:
        raise ValueError("Upload a source DICOM image for this pattern.")

    extra["source_dicom"] = dicom_name

    if pattern == "EXE polyglot preamble":
        result, log = build_exe_polyglot_bytes(dicom_bytes, dicom_name)
        log["method"] = log["pattern"]
        log["pixels_unchanged"] = True
        return result, log, extra

    if use_chrome:
        payload = embed_script_chrome_payload(options.chrome_open_count)
        extra["embedded_item"] = f"chrome_x{options.chrome_open_count}"
    else:
        if not payload_file:
            raise ValueError("Upload a payload file.")
        payload = build_file_payload(payload_file.name, payload_file.getvalue())
        extra["embedded_item"] = payload_file.name

    if pattern == "Pixel-data append":
        result, log = build_image_pixel_embed_bytes(dicom_bytes, payload, dicom_name)
        log["method"] = log["pattern"]
        log["pixels_unchanged"] = log.get("pixels_unchanged_prefix", False)
    else:
        raise ValueError(f"Unknown pattern: {pattern}")

    return result, log, extra


def _checklist_item(done: bool, label: str) -> None:
    icon = "✅" if done else "⬜"
    st.markdown(f"{icon} {label}")


def _compute_ready(
    flow: str,
    pattern: str,
    needs_dicom: bool,
    dicom_file,
    dicom_meta,
    pdf_file,
    attach_files,
    script_file,
    attach_file,
    payload_file,
    use_chrome,
) -> tuple[bool, list[str]]:
    missing: list[str] = []

    if needs_dicom:
        if not dicom_file:
            missing.append("Source DICOM image")
        elif not dicom_meta:
            missing.append("Valid DICOM (fix upload errors above)")

    if flow == "Safe embed":
        if pattern == "Append script (private tag)" and not script_file:
            missing.append("Script file to embed")
        elif pattern == "Append file (private tag)" and not attach_file:
            missing.append("File to embed")
        elif pattern == "Script + file (both)":
            if not script_file:
                missing.append("Script file")
            if not attach_file:
                missing.append("Additional file")
    elif pattern == "PDF + hidden files (MP3+PDF.dcm)":
        if not pdf_file:
            missing.append("PDF document")
        if not attach_files:
            missing.append("At least one file to hide")
    elif pattern == "Pixel-data append":
        if not use_chrome and not payload_file:
            missing.append("Payload file (or enable built-in Chrome script)")

    return len(missing) == 0, missing


def render_payload_extractor() -> None:
    """Top-level tab: scan DICOM files for hidden embedded payloads."""
    st.subheader("Payload Extractor")
    st.caption("Scan a DICOM file for hidden scripts and files, then download what is found.")

    with st.container(border=True):
        st.markdown("**1 · Upload DICOM**")
        extract_file = st.file_uploader(
            "DICOM file (.dcm)",
            type=["dcm"],
            key="extract_dicom_in",
            label_visibility="collapsed",
            help="Works with files built by this demo or compatible embedding patterns.",
        )

    if not extract_file:
        st.info("Upload a `.dcm` file to begin. Checks private tags, pixel tails, and legacy EOF payloads.")
        return

    st.markdown("**2 · Results**")
    items = extract_embedded_items(extract_file.getvalue())
    if not items:
        st.warning(f"No embedded payloads found in `{extract_file.name}`.")
        return

    st.success(f"Found **{len(items)}** embedded item(s) in `{extract_file.name}`.")
    for idx, item in enumerate(items):
        name = item.get("name", f"item_{idx}")
        method = item.get("method", "unknown")
        data = item.get("data", b"")
        with st.container(border=True):
            col_a, col_b = st.columns([3, 1])
            with col_a:
                st.markdown(f"**{name}**")
                st.caption(f"Method: `{method}` · {len(data):,} bytes")
            with col_b:
                mime = (
                    "text/plain"
                    if name.endswith((".ps1", ".py", ".bat", ".txt"))
                    else "application/octet-stream"
                )
                st.download_button(
                    "Download",
                    data,
                    name,
                    mime,
                    key=f"extract_dl_{idx}_{datetime.now().timestamp()}",
                    width="stretch",
                )


def _render_embed_tab() -> None:
    # ── Step 1: Mode ──────────────────────────────────────────────
    st.markdown("### 1 · Choose embed mode")
    flow = st.radio(
        "Mode",
        ["Safe embed", "Pattern embed"],
        horizontal=True,
        key="embed_flow",
        label_visibility="collapsed",
    )
    st.info(MODE_HELP[flow])

    # ── Step 2: Pattern ─────────────────────────────────────────
    st.markdown("### 2 · Select pattern")
    if flow == "Safe embed":
        pattern = st.selectbox(
            "Pattern",
            list(SAFE_PATTERNS.keys()),
            key="safe_pattern",
            label_visibility="collapsed",
        )
    else:
        pattern = st.selectbox(
            "Pattern",
            list(PATTERN_EMBEDS.keys()),
            key="pattern_embed_select",
            label_visibility="collapsed",
        )
    st.caption(PATTERN_EMBEDS.get(pattern) or SAFE_PATTERNS[pattern])

    is_pdf_pattern = flow == "Pattern embed" and pattern == "PDF + hidden files (MP3+PDF.dcm)"
    needs_dicom = not is_pdf_pattern
    needs_script_options = flow == "Safe embed" and pattern in (
        "Append script (private tag)",
        "Built-in Chrome launcher",
        "Script + file (both)",
    )
    needs_chrome_count = (
        flow == "Safe embed" and pattern == "Built-in Chrome launcher"
    ) or (flow == "Pattern embed" and pattern == "Pixel-data append")

    # ── Step 3: Files ─────────────────────────────────────────────
    st.markdown("### 3 · Upload files")

    dicom_file = None
    dicom_meta = None
    base_dicom_file = None
    pdf_file = None
    attach_files: List = []
    script_file = None
    attach_file = None
    payload_file = None
    use_chrome = False
    patient_name = "Demo^Patient"
    patient_id = "DEMO001"

    if is_pdf_pattern:
        with st.container(border=True):
            st.markdown("**PDF document** — becomes the encapsulated DICOM content.")
            pdf_file = st.file_uploader(
                "PDF file",
                type=["pdf"],
                key="embed_pdf_in",
                label_visibility="collapsed",
            )
            if pdf_file:
                st.caption(f"✓ `{pdf_file.name}` ({pdf_file.size:,} bytes)")

        with st.container(border=True):
            st.markdown("**Hidden payload(s)** — appended after the PDF `%%EOF` marker.")
            attach_files = st.file_uploader(
                "Files to hide (mp3, exe, pdf, …)",
                accept_multiple_files=True,
                key="embed_pdf_attach",
                label_visibility="collapsed",
            )
            if attach_files:
                for f in attach_files:
                    st.caption(f"✓ `{f.name}` ({f.size:,} bytes)")

        with st.container(border=True):
            st.markdown("**Patient metadata** — from a base DICOM or manual entry.")
            base_dicom_file = st.file_uploader(
                "Base DICOM (optional — copies patient/study tags)",
                type=["dcm"],
                key="embed_pdf_base_dicom",
            )
            if base_dicom_file:
                ok, msg, base_meta = validate_dicom(base_dicom_file.getvalue())
                if ok:
                    st.success(
                        f"Using metadata from base DICOM: "
                        f"**{base_meta.get('patient_name')}** / `{base_meta.get('patient_id')}`"
                    )
                else:
                    st.error(msg)
            else:
                col_p1, col_p2 = st.columns(2)
                with col_p1:
                    patient_name = st.text_input("Patient Name", "Demo^Patient", key="embed_pdf_patient_name")
                with col_p2:
                    patient_id = st.text_input("Patient ID", "DEMO001", key="embed_pdf_patient_id")

    elif needs_dicom:
        with st.container(border=True):
            st.markdown("**Source DICOM image** — the file that will carry the payload.")
            dicom_file = st.file_uploader(
                "DICOM file (.dcm)",
                type=["dcm"],
                key="embed_dicom_in",
                label_visibility="collapsed",
            )
            if dicom_file:
                ok, msg, dicom_meta = validate_dicom(dicom_file.getvalue())
                if ok:
                    st.success(msg)
                    with st.expander("View DICOM metadata"):
                        st.json(dicom_meta)
                else:
                    st.error(msg)

        with st.container(border=True):
            st.markdown("**Payload** — what to hide inside the DICOM.")

            if flow == "Safe embed":
                if pattern == "Built-in Chrome launcher":
                    st.info(
                        f"No file upload needed. A PowerShell Chrome launcher "
                        f"({int(st.session_state.get('embed_chrome_count', 3))} opens) will be embedded."
                    )
                elif pattern == "Append script (private tag)":
                    script_file = st.file_uploader("Script file (.ps1, .py, .bat, …)", key="embed_safe_script")
                elif pattern == "Append file (private tag)":
                    attach_file = st.file_uploader("Any file to hide", key="embed_safe_file")
                else:
                    script_file = st.file_uploader("Script file", key="embed_safe_script2")
                    attach_file = st.file_uploader("Additional file", key="embed_safe_file2")

            elif pattern == "EXE polyglot preamble":
                st.info("No extra upload needed — an MZ DOS stub is prepended automatically.")

            elif pattern == "Pixel-data append":
                use_chrome = st.checkbox(
                    "Use built-in Chrome script instead of uploading a file",
                    key="embed_pattern_chrome",
                )
                if not use_chrome:
                    payload_file = st.file_uploader("Payload file", key="embed_pattern_payload")

        if flow == "Pattern embed" and not pattern.startswith("PDF"):
            with st.container(border=True):
                st.markdown("**Patient metadata** (used if not already in source DICOM).")
                col_p1, col_p2 = st.columns(2)
                with col_p1:
                    patient_name = st.text_input("Patient Name", "Demo^Patient", key="embed_patient_name")
                with col_p2:
                    patient_id = st.text_input("Patient ID", "DEMO001", key="embed_patient_id")

    # ── Step 4: Options ───────────────────────────────────────────
    st.markdown("### 4 · Options")

    with st.container(border=True):
        if needs_script_options:
            include_launcher = st.checkbox(
                "Include extraction launcher (scripts)",
                value=True,
                help=(
                    "Stores a PowerShell helper in the private tag. "
                    "Does NOT auto-run in DICOM viewers — run manually to extract scripts."
                ),
            )
        else:
            include_launcher = False

        include_av = st.checkbox(
            "Attach AV test signature (Windows only)",
            value=False,
            help="Adds an alternate data stream for manual antivirus testing.",
        )

        if needs_chrome_count:
            chrome_count = st.number_input(
                "Chrome open count",
                min_value=1,
                max_value=10,
                value=3,
                key="embed_chrome_count",
            )
        else:
            chrome_count = 3

    options = EmbedOptions(
        include_launcher=include_launcher,
        include_av_test_stream=include_av,
        chrome_open_count=int(chrome_count),
    )

    # ── Step 5: Review & build ────────────────────────────────────
    st.markdown("### 5 · Review & build")

    ready, missing = _compute_ready(
        flow,
        pattern,
        needs_dicom,
        dicom_file,
        dicom_meta,
        pdf_file,
        attach_files,
        script_file,
        attach_file,
        payload_file,
        use_chrome,
    )

    with st.container(border=True):
        st.markdown("**Checklist**")
        _checklist_item(True, f"Mode: **{flow}**")
        _checklist_item(True, f"Pattern: **{pattern}**")
        if is_pdf_pattern:
            _checklist_item(pdf_file is not None, "PDF document uploaded")
            _checklist_item(bool(attach_files), "Hidden payload file(s) uploaded")
            _checklist_item(
                base_dicom_file is not None or (patient_name and patient_id),
                "Patient metadata set",
            )
        elif needs_dicom:
            _checklist_item(dicom_file is not None and dicom_meta is not None, "Valid source DICOM")
            if flow == "Safe embed" and pattern != "Built-in Chrome launcher":
                _checklist_item(
                    script_file is not None or attach_file is not None,
                    "Payload file(s) uploaded",
                )
            elif pattern == "Pixel-data append":
                _checklist_item(use_chrome or payload_file is not None, "Payload ready")

        if missing:
            st.warning("Still needed: " + ", ".join(missing))

    if st.button(
        "Build DICOM",
        type="primary",
        disabled=not ready,
        key="embed_build",
        width="stretch",
    ):
        try:
            with st.spinner("Building embedded DICOM…"):
                base_ds = None
                if is_pdf_pattern and base_dicom_file:
                    base_ds = pydicom.dcmread(
                        io.BytesIO(base_dicom_file.getvalue()), force=True
                    )

                if flow == "Safe embed":
                    result, log, extra = _run_safe_embed(
                        pattern,
                        options,
                        dicom_file.getvalue(),
                        dicom_file.name,
                        script_file,
                        attach_file,
                    )
                    stem = Path(dicom_file.name).stem + "_safe"
                    source_name = dicom_file.name
                else:
                    result, log, extra = _run_pattern_embed(
                        pattern,
                        options,
                        patient_name,
                        patient_id,
                        dicom_file.getvalue() if dicom_file else None,
                        dicom_file.name if dicom_file else (base_dicom_file.name if base_dicom_file else ""),
                        pdf_file,
                        attach_files or [],
                        payload_file,
                        use_chrome,
                        base_ds=base_ds,
                    )
                    stem = (
                        "MP3_PDF_pattern"
                        if pattern.startswith("PDF")
                        else Path(dicom_file.name).stem + "_pattern"
                        if dicom_file
                        else "pattern_build"
                    )
                    source_name = (
                        dicom_file.name
                        if dicom_file
                        else (base_dicom_file.name if base_dicom_file else pdf_file.name if pdf_file else "build")
                    )

            _log_embed_event(log, extra, source_name)
            st.divider()
            st.markdown("### Result")
            _show_download(result, log, extra, stem, source_name)

            if log.get("av_test_stream_attached"):
                st.warning(
                    "AV test signature attached (Windows ADS). Scan manually in Windows Security when ready."
                )
        except Exception as error:
            st.error(f"Build failed: {error}")


def render_payload_embedder() -> None:
    st.subheader("Payload Embedder")
    st.caption("Build test DICOM files with hidden payloads using safe or pattern-based methods.")
    _render_embed_tab()
