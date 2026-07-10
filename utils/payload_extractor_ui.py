"""Payload Extractor UI — scan embedded DICOMs and download hidden items."""

from __future__ import annotations

import io
from datetime import datetime

import streamlit as st

from utils.dicom_handler import extract_metadata, load_dicom
from utils.payload_extractor import extract_embedded_items, extract_from_image_file
from utils.audit_logger import log_breach_event
from utils.image_editor import _extract_2d_image, dicom_to_image

METHOD_LABELS = {
    "exe_polyglot":    "EXE Polyglot — MZ Header in Preamble",
    "pdf_eof_append":  "PDF %%EOF Append — Hidden after PDF end",
    "pixel_tail":      "Pixel-Data Append — Hidden after image bytes",
    "private_tag":     "Private DICOM Tag",
    "eof_tail":        "EOF Append — Hidden after DICOM end",
    "eof_script":      "EOF Script Append — Hidden after DICOM end (viewer-safe)",
    "jpeg_eof_append": "JPEG EOI Append — Hidden after JPEG end marker",
    "png_iend_append": "PNG IEND Append — Hidden after PNG end chunk",
}


def render_payload_extractor() -> None:
    if "extract_items" not in st.session_state:
        st.session_state.extract_items = None
        st.session_state.extract_source = None

    prefill_active = st.session_state.get("extract_prefill_active", False)
    prefill_bytes = st.session_state.get("extract_prefill_bytes")
    prefill_name = st.session_state.get("extract_prefill_name", "embedded_file")

    if prefill_active and prefill_bytes:
        st.success(
            f"Loaded from Threat Embedder: **`{prefill_name}`** ({len(prefill_bytes):,} bytes). "
            "Click **Scan for Embedded Payloads** below to analyse."
        )
        if st.button("Clear preloaded file", key="extract_clear_prefill"):
            st.session_state.extract_prefill_active = False
            st.session_state.extract_prefill_bytes = None
            st.session_state.extract_prefill_name = None
            st.session_state.extract_items = None
            st.session_state.extract_source = None
            st.rerun()

    uploaded = st.file_uploader(
        "Upload file to scan (.dcm, .png, .jpg, .jpeg)",
        type=["dcm", "png", "jpg", "jpeg"],
        key="extract_dicom_in",
        label_visibility="collapsed",
    )

    if uploaded is None and not (prefill_active and prefill_bytes):
        st.session_state.extract_items = None
        st.session_state.extract_source = None
        st.info("Upload a `.dcm`, `.png`, or `.jpg` file to scan for embedded payloads.")
        return

    if uploaded is not None:
        upload_key = f"{uploaded.name}:{uploaded.size}"
        if st.session_state.get("extract_upload_key") != upload_key:
            st.session_state.extract_upload_key = upload_key
            st.session_state.extract_items = None
            st.session_state.extract_source = None
            st.session_state.extract_prefill_active = False
        raw = uploaded.getvalue()
        fname = uploaded.name
    else:
        raw = prefill_bytes
        fname = prefill_name

    is_image_file = fname.lower().endswith((".png", ".jpg", ".jpeg"))

    if is_image_file:
        st.image(raw, caption=f"Uploaded — {fname}", width="stretch")
    else:
        try:
            ds = load_dicom(io.BytesIO(raw))
            metadata = extract_metadata(ds)
        except Exception as error:
            st.error(f"Could not read DICOM: {error}")
            return

        col_img, col_meta = st.columns([1, 1])
        with col_img:
            try:
                image = dicom_to_image(ds)
                display, slice_info = _extract_2d_image(image)
                cap = f"Uploaded DICOM — {fname}"
                if slice_info.get("is_volume"):
                    cap += f" (slice {slice_info['frame_index'] + 1}/{slice_info['frame_count']})"
                st.image(display, caption=cap, width="stretch")
            except Exception:
                st.info("No image preview available for this DICOM (may be encapsulated PDF or no PixelData).")
        with col_meta:
            with st.expander("📋 DICOM Metadata", expanded=True):
                st.json(metadata)

    if st.button("🔍 Scan for Embedded Payloads", type="primary", key="extract_scan_btn"):
        if is_image_file:
            items = extract_from_image_file(raw)
        else:
            items = extract_embedded_items(raw)
        st.session_state.extract_items = items
        st.session_state.extract_source = fname
        log_breach_event(
            action="File Scanned",
            data_type="validation",
            data_accessed=f"payload_extractor scan on {fname}",
            severity="INFO",
            endpoint="payload_extractor",
        )

    items = st.session_state.get("extract_items")
    if items is None:
        return

    if not items:
        st.warning(
            f"No embedded payloads found in `{st.session_state.get('extract_source', fname)}`. "
            "The file may be clean or use an unknown embedding format."
        )
        return

    st.success(f"Found **{len(items)}** embedded payload item(s) in `{st.session_state.get('extract_source', fname)}`.")
    for idx, item in enumerate(items):
        name = item.get("name", f"payload_item_{idx + 1}")
        method = item.get("method", "unknown")
        data = item.get("data", b"")
        method_label = METHOD_LABELS.get(method, method)
        item_type = item.get("type", "file").replace("_", " ").title()
        with st.container(border=True):
            col_a, col_b = st.columns([3, 1])
            with col_a:
                st.markdown(f"**{name}**")
                st.caption(f"Type: {item_type}  ·  Embed Method: {method_label}  ·  {len(data):,} bytes")
                if item.get("description"):
                    st.caption(f"Details: {item['description']}")
            with col_b:
                is_text = name.endswith((".ps1", ".py", ".bat", ".txt", ".sh"))
                mime = "text/plain" if is_text else "application/octet-stream"
                st.download_button(
                    "⬇️ Download",
                    data,
                    name,
                    mime,
                    key=f"extract_dl_{idx}_{datetime.now().timestamp()}",
                    width="stretch",
                )
            # Extra usage tip per file type
            if name.endswith(".bat"):
                st.success(
                    f"**Double-click `{name}` to trigger the payload** — no terminal needed. "
                    "Save it anywhere and double-click in Windows Explorer."
                )
            elif name.endswith(".ps1"):
                st.caption(
                    f"To run locally: `powershell -ExecutionPolicy Bypass -File {name}`"
                )
                st.caption(
                    "Windows may warn this file came from the internet (Mark of the Web). "
                    "That is expected for browser downloads. Before running: "
                    f"`Unblock-File -LiteralPath .\\{name}` or right-click the saved file → **Unblock**."
                )
            elif method == "exe_polyglot" and name.endswith(".bat"):
                st.success(
                    "Double-click this `.bat` file to trigger the demo popup."
                )
            elif method == "exe_polyglot":
                st.caption(
                    "This is the raw 128-byte preamble. "
                    "Save as `.bat` and double-click to trigger."
                )
