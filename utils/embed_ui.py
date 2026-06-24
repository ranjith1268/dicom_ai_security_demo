"""Streamlit UI for DICOM payload embedding — safe EOF embed + pattern-based builds."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

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
from utils.embedded_risk_module import log_breach_event
from utils.pattern_dicom_builder import (
    build_encapsulated_pdf_dicom_bytes,
    build_exe_polyglot_bytes,
    build_file_payload,
    build_image_pixel_embed_bytes,
    embed_script_chrome_payload,
)

SAFE_PATTERNS = {
    "Append file (end of DICOM)": "Hide any file after the DICOM — image unchanged.",
    "Append script (end of DICOM)": "Hide a .ps1 / .py / .bat script after the DICOM.",
    "Built-in Chrome launcher": "Embed PowerShell that opens Chrome N times.",
    "Script + file (both)": "Embed one script and one file after the DICOM.",
}

PATTERN_EMBEDS = {
    "PDF + hidden files (MP3+PDF.dcm)": "Encapsulated PDF DICOM — files appended after PDF %%EOF. No image DICOM needed.",
    "EXE polyglot preamble": "MZ DOS stub at byte 0, DICM at byte 128 (exe_embedded_dicom-1.dcm).",
    "Pixel-data append": "Payload appended to PixelData (DX / US style).",
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

    st.success("Done — download your files below.")

    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Mode", extra.get("flow", "embed"))
    with m2:
        unchanged = log.get("pixels_unchanged", log.get("pixels_unchanged_prefix"))
        st.metric("Pixels unchanged", "Yes" if unchanged else "No / N/A")
    with m3:
        st.metric("Output size", f"{len(result):,} B")

    with st.expander("Build log"):
        st.code(log_json, language="json")

    d1, d2 = st.columns(2)
    with d1:
        st.download_button(
            "Download DICOM",
            result,
            out_name,
            "application/dicom",
            key=f"dl_dcm_{stem}_{datetime.now().timestamp()}",
        )
    with d2:
        st.download_button(
            "Download log (.json)",
            log_json,
            Path(log_path).name,
            "application/json",
            key=f"dl_log_{stem}_{datetime.now().timestamp()}",
        )
    st.caption(f"Saved locally: `{out_path}`")


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
    elif pattern == "Append script (end of DICOM)":
        result, log = embed_uploaded_script(dicom_bytes, script_file.getvalue(), options)
        extra["embedded_item"] = script_file.name
    elif pattern == "Append file (end of DICOM)":
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
) -> tuple[bytes, dict, dict]:
    extra: dict = {"flow": "pattern_embed", "pattern": pattern}

    if pattern == "PDF + hidden files (MP3+PDF.dcm)":
        if not pdf_file or not attach_files:
            raise ValueError("Upload a PDF and at least one file to hide.")
        extras = [(f.name, f.getvalue()) for f in attach_files]
        result, log = build_encapsulated_pdf_dicom_bytes(
            pdf_file.getvalue(), extras, patient_name, patient_id
        )
        log["method"] = log["pattern"]
        log["pixels_unchanged"] = True
        log["metadata_unchanged"] = True
        extra.update({"pdf": pdf_file.name, "attached": [f.name for f in attach_files]})
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


def render_payload_embedder() -> None:
    st.subheader("DICOM Embedder")
    st.caption(
        "**Safe embed** — payload after file end (pixels & metadata untouched). "
        "**Pattern embed** — known test-file patterns (MP3+PDF, EXE polyglot, pixel append)."
    )

    with st.expander("Settings", expanded=True):
        flow = st.radio(
            "Embed mode",
            ["Safe embed", "Pattern embed"],
            horizontal=True,
            key="embed_flow",
        )
        if flow == "Safe embed":
            pattern = st.selectbox("Pattern", list(SAFE_PATTERNS.keys()), key="safe_pattern")
            st.caption(SAFE_PATTERNS[pattern])
        else:
            pattern = st.selectbox("Pattern", list(PATTERN_EMBEDS.keys()), key="pattern_embed_select")
            st.caption(PATTERN_EMBEDS[pattern])

        col_a, col_b, col_c = st.columns(3)
        with col_a:
            include_launcher = st.checkbox("Auto-run launcher (scripts)", value=True)
        with col_b:
            include_av = st.checkbox("AV test signature (Windows)", value=False)
        with col_c:
            chrome_count = st.number_input("Chrome open count", 1, 10, 3)

        patient_name = "Demo^Patient"
        patient_id = "DEMO001"
        if flow == "Pattern embed":
            patient_name = st.text_input("Patient Name", "Demo^Patient", key="embed_patient_name")
            patient_id = st.text_input("Patient ID", "DEMO001", key="embed_patient_id")

    options = EmbedOptions(
        include_launcher=include_launcher,
        include_av_test_stream=include_av,
        chrome_open_count=int(chrome_count),
    )

    st.markdown(f"### {flow}")
    needs_dicom = not (
        flow == "Pattern embed" and pattern == "PDF + hidden files (MP3+PDF.dcm)"
    )

    dicom_file = None
    dicom_meta = None
    pdf_file = None
    attach_files: List = []
    script_file = None
    attach_file = None
    payload_file = None
    use_chrome = False

    col1, col2 = st.columns(2)

    with col1:
        if needs_dicom:
            st.markdown("**1. Source DICOM image**")
            dicom_file = st.file_uploader("Select DICOM (.dcm)", type=["dcm"], key="embed_dicom_in")
            if dicom_file:
                ok, msg, dicom_meta = validate_dicom(dicom_file.getvalue())
                if ok:
                    st.success(msg)
                    with st.expander("DICOM info"):
                        st.json(dicom_meta)
                else:
                    st.error(msg)
        else:
            st.markdown("**1. PDF document**")
            pdf_file = st.file_uploader("Select PDF", type=["pdf"], key="embed_pdf_in")
            if pdf_file:
                st.caption(f"`{pdf_file.name}` — {pdf_file.size:,} bytes")

    with col2:
        st.markdown("**2. File(s) to hide inside DICOM**")

        if flow == "Safe embed":
            if pattern == "Built-in Chrome launcher":
                st.info(f"Embeds Chrome launcher ({options.chrome_open_count} opens). No extra file needed.")
            elif pattern == "Append script (end of DICOM)":
                script_file = st.file_uploader("Script file", key="embed_safe_script")
            elif pattern == "Append file (end of DICOM)":
                attach_file = st.file_uploader("Any file (mp3, pdf, exe, image…)", key="embed_safe_file")
            else:
                script_file = st.file_uploader("Script file", key="embed_safe_script2")
                attach_file = st.file_uploader("Additional file", key="embed_safe_file2")

        elif pattern == "PDF + hidden files (MP3+PDF.dcm)":
            attach_files = st.file_uploader(
                "Files to hide after PDF EOF (mp3, exe, …)",
                accept_multiple_files=True,
                key="embed_pdf_attach",
            )
        elif pattern == "EXE polyglot preamble":
            st.info("Only the DICOM image is needed. MZ stub is added automatically.")
        else:
            use_chrome = st.checkbox("Use built-in Chrome script instead of upload", key="embed_pattern_chrome")
            if not use_chrome:
                payload_file = st.file_uploader("Payload file", key="embed_pattern_payload")

    ready = True
    if needs_dicom:
        ready = dicom_file is not None and dicom_meta is not None
    if flow == "Safe embed":
        if pattern == "Append script (end of DICOM)":
            ready = ready and script_file is not None
        elif pattern == "Append file (end of DICOM)":
            ready = ready and attach_file is not None
        elif pattern == "Script + file (both)":
            ready = ready and script_file is not None and attach_file is not None
    elif pattern == "PDF + hidden files (MP3+PDF.dcm)":
        ready = pdf_file is not None and len(attach_files) > 0
    elif pattern == "Pixel-data append":
        ready = ready and (use_chrome or payload_file is not None)

    st.divider()

    if st.button("Build DICOM", type="primary", disabled=not ready, key="embed_build"):
        try:
            with st.spinner("Building…"):
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
                        dicom_file.name if dicom_file else "",
                        pdf_file,
                        attach_files or [],
                        payload_file,
                        use_chrome,
                    )
                    stem = (
                        "MP3_PDF_pattern"
                        if pattern.startswith("PDF")
                        else Path(dicom_file.name).stem + "_pattern"
                        if dicom_file
                        else "pattern_build"
                    )
                    source_name = dicom_file.name if dicom_file else (pdf_file.name if pdf_file else "build")

            _log_embed_event(log, extra, source_name)
            _show_download(result, log, extra, stem, source_name)

            if log.get("av_test_stream_attached"):
                st.warning(
                    "AV test signature attached (Windows ADS). Scan manually in Windows Security when ready."
                )
        except Exception as error:
            st.error(f"Build failed: {error}")
