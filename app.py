import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

_DEBUG_IMPORTS = os.environ.get("DICOM_DEMO_DEBUG_IMPORTS", "1") == "1"


def _step(label):
    if _DEBUG_IMPORTS:
        print(f"[import-debug] {label}", file=sys.stderr, flush=True)


_step("start")
import streamlit as st
_step("streamlit imported")
import numpy as np
_step("numpy imported")
import cv2
_step("cv2 imported")
import pydicom
_step("pydicom imported")
from utils.threat_embedder_ui import render_clean_flow
_step("threat_embedder_ui imported")
from utils.payload_extractor_ui import render_payload_extractor
_step("payload_extractor_ui imported")
from utils.safety_validator_ui import render_dicom_cleaner
_step("safety_validator_ui imported")
from utils.auth import require_login, render_user_bar
_step("auth imported")
from utils.dicom_handler_register import ensure_dicom_handler_registered
_step("dicom_handler_register imported")
from utils.audit_logger import (
    get_breach_logs,
    clear_breach_logs,
    logs_to_csv,
    count_by_severity,
)
_step("audit_logger imported")

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
    try:
        from utils.defender_bridge import try_start_defender_bridge_background

        if try_start_defender_bridge_background():
            if "defender_bridge_started" not in st.session_state:
                st.session_state.defender_bridge_started = True
    except Exception:
        pass

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
    st.dataframe(display_rows, width="stretch")
else:
    st.caption("Embed, extract, scan, and clean actions are recorded here.")
