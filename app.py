import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import streamlit as st
from utils.threat_embedder_ui import render_clean_flow
from utils.payload_extractor_ui import render_payload_extractor
from utils.safety_validator_ui import render_dicom_cleaner
from utils.auth import require_login, render_user_bar
from utils.dicom_handler_register import ensure_dicom_handler_registered
from utils.audit_logger import (
    get_breach_logs,
    clear_breach_logs,
    logs_to_csv,
    count_by_severity,
)

st.set_page_config(
    page_title="DICOM Security Demo",
    layout="wide",
)
require_login()
render_user_bar()

if sys.platform == "win32":
    _handler_ok, _handler_msg = ensure_dicom_handler_registered()
    if not _handler_ok and "app_handler_warned" not in st.session_state:
        st.session_state.app_handler_warned = True
        st.sidebar.caption(f"⚠️ {_handler_msg}")

st.title("DICOM Security Research Platform")
st.caption(
    "Educational tool for demonstrating medical imaging security risks — "
    "embedding threats, extracting payloads, and validating DICOM files."
)

mode = st.radio(
    "Module",
    [
        "🧬  DICOM Threat Embedder",
        "🔍  Payload Extractor",
        "🛡️  DICOM Safety Validator",
    ],
    horizontal=True,
    key="app_mode",
    label_visibility="collapsed",
)

st.divider()

if mode == "🧬  DICOM Threat Embedder":
    st.header("DICOM Threat Embedder")
    st.caption("Embed threats into DICOM or standard images (PNG/JPG), then scan with Defender and analyse with the Payload Extractor.")
    render_clean_flow()

elif mode == "🔍  Payload Extractor":
    st.header("Payload Extractor")
    st.caption(
        "Scan a DICOM file for hidden payloads — EXE polyglot stubs, "
        "PDF-appended files, pixel-data tails, and private tags."
    )
    render_payload_extractor()

else:
    st.header("DICOM Safety Validator & Cleaner")
    st.caption(
        "Defensive companion to the Threat Embedder: detect embedding threats, "
        "review findings, and download a remediated DICOM."
    )
    render_dicom_cleaner()

st.divider()
st.subheader("📋 Security Audit Log")

col1, col2, col3 = st.columns(3)
with col1:
    if st.button("🔄 Refresh Logs", key="logs_refresh"):
        st.rerun()
with col2:
    if st.button("🗑️ Clear Logs", key="logs_clear"):
        clear_breach_logs()
        st.success("Logs cleared.")
        st.rerun()
with col3:
    breach_logs = get_breach_logs()
    if breach_logs:
        st.download_button(
            label="⬇️ Download Logs (CSV)",
            data=logs_to_csv(breach_logs),
            file_name="security_audit_log.csv",
            mime="text/csv",
            key="logs_download",
        )
    else:
        st.info("No log entries yet.")

breach_logs = get_breach_logs()
if breach_logs:
    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}
    display_rows = [
        {
            **row,
            "severity": (
                f"{severity_emoji.get(row.get('severity', ''), '⚪')} "
                f"{row.get('severity', '')}"
            ),
        }
        for row in breach_logs
    ]
    st.dataframe(display_rows, use_container_width=True)
else:
    st.caption("Embed, extract, scan, and clean actions are recorded here.")
