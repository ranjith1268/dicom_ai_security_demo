"""DICOM Safety Validator & Cleaner — detect and remove embedding threats."""

from __future__ import annotations

import io
from pathlib import Path

import streamlit as st

from utils.dicom_handler import extract_metadata, load_dicom
from utils.dicom_safety import SafetyFinding, analyze_dicom, clean_dicom
from utils.audit_logger import log_breach_event
from utils.image_editor import _extract_2d_image, dicom_to_image

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "INFO": "🔵",
}

FINDING_TYPE_LABEL = {
    "polyglot_exe":     "EXE/DOS Polyglot Preamble",
    "polyglot_bat":     "BAT Script Polyglot Preamble",
    "polyglot_unknown": "Unknown Preamble Content",
    "embedded_file":    "Encapsulated PDF — Hidden Tail",
    "pixel_payload":    "Pixel-Data Append",
    "pixel_script":     "Pixel-Data Script Payload",
    "autorun_launcher": "Auto-Run Launcher (double-click exec)",
    "eof_append":       "EOF Trailing Data",
    "structural":       "Structural / Parse Error",
    "missing_tags":     "Missing Required Tags",
}


def _severity_for_findings(findings: list[SafetyFinding]) -> str:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
    if not findings:
        return "INFO"
    return max(findings, key=lambda f: order.get(f.severity, 0)).severity


def render_dicom_cleaner() -> None:
    if "cleaner_findings" not in st.session_state:
        st.session_state.cleaner_findings = None
        st.session_state.cleaner_source = None
        st.session_state.cleaner_original_bytes = None
        st.session_state.cleaner_cleaned_bytes = None

    uploaded = st.file_uploader(
        "Upload DICOM file (.dcm)",
        type=["dcm"],
        key="cleaner_dicom_in",
        label_visibility="collapsed",
    )

    if not uploaded:
        st.session_state.cleaner_findings = None
        st.session_state.cleaner_source = None
        st.session_state.cleaner_original_bytes = None
        st.session_state.cleaner_cleaned_bytes = None
        st.info("Upload a DICOM file to scan for threats.")
        return

    upload_key = f"{uploaded.name}:{uploaded.size}"
    if st.session_state.get("cleaner_upload_key") != upload_key:
        st.session_state.cleaner_upload_key = upload_key
        st.session_state.cleaner_findings = None
        st.session_state.cleaner_source = None
        st.session_state.cleaner_original_bytes = None
        st.session_state.cleaner_cleaned_bytes = None

    raw = uploaded.getvalue()
    original_size = len(raw)

    if st.button("🔍 Scan for Threats", type="primary", key="cleaner_scan_btn"):
        findings, _ = analyze_dicom(raw)
        st.session_state.cleaner_findings = findings
        st.session_state.cleaner_source = uploaded.name
        st.session_state.cleaner_original_bytes = raw
        st.session_state.cleaner_cleaned_bytes = None
        severity = _severity_for_findings(findings)
        log_breach_event(
            action="DICOM File Scanned",
            data_type="validation",
            data_accessed=(
                f"{len(findings)} finding(s) in {uploaded.name}; "
                f"severity={severity}"
            ),
            severity=severity if findings else "INFO",
            endpoint="dicom_cleaner",
        )

    findings: list[SafetyFinding] = st.session_state.get("cleaner_findings") or []
    if st.session_state.get("cleaner_source") != uploaded.name or st.session_state.cleaner_findings is None:
        st.caption("Click **Scan for Threats** to analyse the uploaded file.")
        return

    try:
        ds = load_dicom(io.BytesIO(raw))
        col_img, col_meta = st.columns([1, 1])
        with col_img:
            try:
                image = dicom_to_image(ds)
                display, slice_info = _extract_2d_image(image)
                cap = f"Uploaded — {uploaded.name}"
                if slice_info.get("is_volume"):
                    cap += f" (slice {slice_info['frame_index'] + 1}/{slice_info['frame_count']})"
                st.image(display, caption=cap, width="stretch")
            except Exception:
                st.info("No image preview (encapsulated PDF / no PixelData).")
        with col_meta:
            with st.expander("📋 Metadata (fully preserved during cleaning)", expanded=True):
                st.json(extract_metadata(ds))
    except Exception:
        pass

    if not findings:
        st.success("✅ No threats detected — file appears safe for all known embedding patterns.")
        return

    st.warning(f"⚠️ Found **{len(findings)}** security issue(s). Review each finding before approving removal.")

    selected_ids: set[str] = set()
    for finding in findings:
        emoji = SEVERITY_EMOJI.get(finding.severity, "⚪")
        type_label = FINDING_TYPE_LABEL.get(finding.finding_type, finding.finding_type)
        with st.container(border=True):
            st.markdown(f"**{emoji} {finding.severity}** &nbsp;|&nbsp; `{type_label}`")
            st.markdown(f"{finding.description}")
            st.caption(f"Location: `{finding.location}`")
            st.caption(f"Evidence: {finding.evidence}")
            if finding.size_bytes:
                st.caption(f"Size: {finding.size_bytes:,} bytes")
            st.caption(f"Recommendation: {finding.recommendation}")
            if finding.removable:
                if st.checkbox("Approve removal", key=f"cleaner_rm_{finding.finding_id}"):
                    selected_ids.add(finding.finding_id)
            else:
                st.caption("⚠️ Cannot be auto-removed — requires manual review.")

    removable_selected = [f for f in findings if f.finding_id in selected_ids and f.removable]
    if removable_selected and st.button(
        f"🧹 Remove {len(removable_selected)} Selected Threat(s)",
        type="primary",
        key="cleaner_apply_btn",
        disabled=not removable_selected,
    ):
        cleaned = clean_dicom(st.session_state.cleaner_original_bytes, selected_ids)
        st.session_state.cleaner_cleaned_bytes = cleaned
        log_breach_event(
            action="DICOM File Cleaned",
            data_type="remediation",
            data_accessed=(
                f"Removed {len(removable_selected)} threat(s) from "
                f"{st.session_state.cleaner_source}"
            ),
            severity="INFO",
            endpoint="dicom_cleaner",
        )
        st.rerun()

    cleaned_bytes = st.session_state.get("cleaner_cleaned_bytes")
    if cleaned_bytes:
        removed = original_size - len(cleaned_bytes)
        st.success(
            f"✅ Cleaned file ready — "
            f"{original_size:,} bytes → {len(cleaned_bytes):,} bytes "
            f"({removed:,} bytes of threat data removed)"
        )
        col_before, col_after = st.columns(2)
        with col_before:
            st.caption("**Before cleaning**")
            try:
                ds_before = load_dicom(io.BytesIO(raw))
                img_before = dicom_to_image(ds_before)
                disp_before, _ = _extract_2d_image(img_before)
                st.image(disp_before, caption="Original (with threats)", width="stretch")
            except Exception:
                st.info("No image preview.")
        with col_after:
            st.caption("**After cleaning**")
            try:
                ds_after = load_dicom(io.BytesIO(cleaned_bytes))
                img_after = dicom_to_image(ds_after)
                disp_after, _ = _extract_2d_image(img_after)
                st.image(disp_after, caption="Cleaned DICOM", width="stretch")
            except Exception:
                st.info("No image preview.")

        stem = Path(st.session_state.cleaner_source).stem
        st.download_button(
            "⬇️ Download Cleaned DICOM",
            cleaned_bytes,
            f"{stem}_cleaned.dcm",
            "application/dicom",
            type="primary",
            key="cleaner_download",
            width="stretch",
        )
