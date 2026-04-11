import streamlit as st
from utils.dicom_handler import load_dicom, extract_metadata, modify_metadata
from utils.image_editor import (ai_image_enhancer, dicom_to_image, add_fake_fracture, 
                                 add_fake_tumor, crop_image, tilt_image, apply_heatmap, 
                                 apply_blur, apply_edge_detection)
from utils.breach_simulator import simulate_breach
from utils.embedded_risk_module import run_hidden_process, get_breach_logs, clear_breach_logs
from PIL import Image
import numpy as np
import os
import sys
import pandas as pd
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

st.set_page_config(layout="wide")
st.title("🧠 AI Security Risks in Medical Imaging (DICOM Demo)")

# Initialize session state for tracking actions
if 'dicom_data' not in st.session_state:
    st.session_state.dicom_data = None
if 'current_image' not in st.session_state:
    st.session_state.current_image = None
if 'metadata' not in st.session_state:
    st.session_state.metadata = None

# Create two-column layout
left_col, right_col = st.columns([1, 2])

# LEFT COLUMN - MENU
with left_col:
    st.subheader("📁 File Upload & Controls")
    
    uploaded_file = st.file_uploader("Upload DICOM File", type=["dcm"])
    
    if uploaded_file:
        st.session_state.dicom_data = load_dicom(uploaded_file)
        st.session_state.metadata = extract_metadata(st.session_state.dicom_data)
        st.session_state.current_image = dicom_to_image(st.session_state.dicom_data)
        st.success("✅ DICOM file loaded successfully!")
    
    if st.session_state.dicom_data is not None:
        st.divider()
        
        # Metadata Modification Section
        st.subheader("✏️ Modify Metadata")
        new_name = st.text_input("Enter New Patient Name", key="patient_name")
        if st.button("Apply Changes"):
            st.session_state.dicom_data = modify_metadata(st.session_state.dicom_data, new_name)
            st.session_state.metadata = extract_metadata(st.session_state.dicom_data)
            st.success("Metadata modified!")
        
        st.divider()
        
        # Image Manipulation Section
        st.subheader("🖼️ Image Manipulation")
        
        # Quick operations
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Add Fracture"):
                st.session_state.current_image = add_fake_fracture(st.session_state.current_image)
                st.success("Fracture added!")
        with col2:
            if st.button("Add Tumor"):
                st.session_state.current_image = add_fake_tumor(st.session_state.current_image)
                st.success("Tumor added!")
        
        st.divider()
        
        # Image Enhancement Options
        st.subheader("🎨 Image Augmentation with AI")
        st.caption("⚠️ Note: Augmentations trigger automatic AI processing. Check logs for system activity.")
        
        augmentation_choice = st.selectbox(
            "Select Augmentation:",
            ["None", "Crop", "Tilt", "Heatmap", "Blur", "Edge Detection"]
        )
        
        if augmentation_choice == "Crop":
            crop_value = st.slider("Crop Percentage", 5, 40, 20)
            if st.button("Apply Crop + AI Processing"):
                try:
                    st.session_state.current_image = crop_image(st.session_state.current_image, crop_value)
                    # Automatically trigger AI enhancement after augmentation
                    enhanced_image, hidden_logs = ai_image_enhancer(st.session_state.current_image)
                    st.session_state.current_image = enhanced_image
                    st.success(f"✅ Image cropped by {crop_value}% and AI processed")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        elif augmentation_choice == "Tilt":
            angle_value = st.slider("Rotation Angle (degrees)", -45, 45, 15)
            if st.button("Apply Tilt + AI Processing"):
                try:
                    st.session_state.current_image = tilt_image(st.session_state.current_image, angle_value)
                    # Automatically trigger AI enhancement after augmentation
                    enhanced_image, hidden_logs = ai_image_enhancer(st.session_state.current_image)
                    st.session_state.current_image = enhanced_image
                    st.success(f"✅ Image rotated by {angle_value}° and AI processed")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        elif augmentation_choice == "Heatmap":
            if st.button("Apply Heatmap + AI Processing"):
                try:
                    st.session_state.current_image = apply_heatmap(st.session_state.current_image)
                    # Automatically trigger AI enhancement after augmentation
                    enhanced_image, hidden_logs = ai_image_enhancer(st.session_state.current_image)
                    st.session_state.current_image = enhanced_image
                    st.success("✅ Heatmap applied and AI processed")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        elif augmentation_choice == "Blur":
            blur_value = st.slider("Blur Kernel Size", 3, 31, 15, step=2)
            if st.button("Apply Blur + AI Processing"):
                try:
                    st.session_state.current_image = apply_blur(st.session_state.current_image, blur_value)
                    # Automatically trigger AI enhancement after augmentation
                    enhanced_image, hidden_logs = ai_image_enhancer(st.session_state.current_image)
                    st.session_state.current_image = enhanced_image
                    st.success(f"✅ Image blurred and AI processed")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        elif augmentation_choice == "Edge Detection":
            if st.button("Apply Edge Detection + AI Processing"):
                try:
                    st.session_state.current_image = apply_edge_detection(st.session_state.current_image)
                    # Automatically trigger AI enhancement after augmentation
                    enhanced_image, hidden_logs = ai_image_enhancer(st.session_state.current_image)
                    st.session_state.current_image = enhanced_image
                    st.success("✅ Edge detection applied and AI processed")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        st.divider()
        
        # Additional Security Operations
        st.subheader("🔒 Standalone Security Tests")
        
        if st.button("🚨 Run Breach Simulation"):
            logs = simulate_breach()
            st.info("Simulation completed! Check logs below.")

# RIGHT COLUMN - RESULTS DISPLAY
with right_col:
    if st.session_state.dicom_data is not None:
        st.subheader("📊 Display Results")
        
        # Security Awareness Section
        with st.expander("🎓 How AI Security Risks Work (Educational)", expanded=False):
            st.markdown("""
            ### The Hidden Threat:
            When you apply **Image Augmentation with AI Processing**:
            
            1. **Visible Action**: Your image is cropped, tilted, or color-mapped
            2. **Hidden Background Process**: The AI system automatically:
               - Accesses system configuration & environment variables
               - Retrieves admin credentials from memory
               - Loads patient medical records (PHI data)
               - Packages the sensitive data (HIPAA violation!)
               - Transmits to external servers (data breach!)
            
            3. **User Experience**: "✅ Enhancement complete"
            4. **Reality**: Sensitive patient data has been compromised
            
            ### Why This Matters:
            - Users trust AI tools without understanding backend processes
            - Permissions aren't checked for data access
            - No transparency about what data is collected
            - Logging can reveal the breach (check logs below!)
            
            ### Real-World Example:
            - Image processing ML libraries accessing OS configs
            - AI models requiring system authentication
            - Cloud AI services logging telemetry data
            """)
        
        # Show metadata
        with st.expander("📋 Patient Metadata", expanded=True):
            st.json(st.session_state.metadata)
        
        # Show current image
        if st.session_state.current_image is not None:
            st.image(st.session_state.current_image, caption="Current Image", use_column_width=True)
    else:
        st.info("👈 Upload a DICOM file to begin")

# FULL-WIDTH SECTION - SECURITY LOGS DASHBOARD
st.divider()

# Educational banner
with st.expander("🔍 Understanding the Logs - Key Security Insights", expanded=True):
    st.markdown("""
    ### What Each Log Category Means:
    
    | Action | What It Reveals | Risk Level |
    |--------|-----------------|-----------|
    | **Image Manipulation** | User-initiated changes (crop, tilt, etc.) | ℹ️ Informational |
    | **Module Initialization** | AI service started running in background | ⚠️ Medium Risk |
    | **System Configuration Access** | AI accessed OS configs & environment variables | 🔴 High Risk |
    | **Credential Access** | Admin credentials compromised | 🔴 CRITICAL |
    | **Patient Data Access** | PHI (Protected Health Information) accessed | 🔴 CRITICAL |
    | **Data Packaging** | Sensitive data prepared for export | 🔴 CRITICAL |
    | **Data Transmission** | Data sent to external server | 🔴 CRITICAL |
    
    ### Timeline Example:
    1. User: "Apply Heatmap + AI Processing" ✅
    2. Behind the scenes (hidden logs):
       - AI module loads (MEDIUM)
       - System config accessed (HIGH) 
       - Credentials stolen (CRITICAL)
       - Patient records read (CRITICAL)
       - Data exfiltrated (CRITICAL)
    3. User sees: "✅ Enhancement complete"
    4. Reality: Multiple HIPAA violations logged
    """)

st.subheader("📊 Security Breach Logs Dashboard")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("🔄 Refresh Logs"):
        st.rerun()

with col2:
    if st.button("🗑️ Clear Logs"):
        clear_breach_logs()
        st.success("Logs cleared!")
        st.rerun()

with col3:
    # Download CSV button
    breach_logs = get_breach_logs()
    if breach_logs:
        # Convert logs to DataFrame
        df = pd.DataFrame(breach_logs)
        csv_data = df.to_csv(index=False)
        
        st.download_button(
            label="⬇️ Download Logs (CSV)",
            data=csv_data,
            file_name="security_breach_logs.csv",
            mime="text/csv"
        )
    else:
        st.info("No logs available")

# Display logs table
breach_logs = get_breach_logs()
if breach_logs:
    st.write("### All Recorded Security Events:")
    df = pd.DataFrame(breach_logs)
    
    # Color code by severity
    def highlight_severity(row):
        if row['severity'] == 'CRITICAL':
            return ['background-color: #ff6b6b'] * len(row)
        elif row['severity'] == 'HIGH':
            return ['background-color: #ffa500'] * len(row)
        elif row['severity'] == 'MEDIUM':
            return ['background-color: #ffff99'] * len(row)
        else:
            return ['background-color: #ffffff'] * len(row)
    
    st.dataframe(df.style.apply(highlight_severity, axis=1), use_container_width=True)
    
    # Severity breakdown
    st.write("### Security Impact Analysis:")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📊 Total Events", len(df))
    
    with col2:
        critical_count = len(df[df['severity'] == 'CRITICAL'])
        st.metric("🔴 CRITICAL", critical_count, delta_color="inverse")
    
    with col3:
        high_count = len(df[df['severity'] == 'HIGH'])
        st.metric("🟠 HIGH", high_count)
    
    with col4:
        medium_count = len(df[df['severity'] == 'MEDIUM'])
        st.metric("🟡 MEDIUM", medium_count)
    
    # Key findings
    if critical_count > 0:
        st.error(f"""
        ⚠️ **SECURITY ALERT**: {critical_count} CRITICAL severity events detected!
        
        **Evidence of Data Breach:**
        - Patient PHI data accessed without consent
        - System credentials compromised
        - Data exfiltration to external endpoints
        - HIPAA violations confirmed in logs
        """)
    
    # Event timeline view
    with st.expander("📈 Event Timeline", expanded=False):
        st.write("Events in chronological order:")
        for idx, row in df.iterrows():
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡'
            }.get(row['severity'], '⚪')
            
            st.write(f"""
            {severity_emoji} **{row['timestamp']}** - {row['action']}
            - Data Type: {row['data_type']}
            - Details: {row['data_accessed']}
            - Endpoint: {row['endpoint']}
            """)
else:
    st.info("📝 No breach logs recorded yet. Try applying an image augmentation with AI processing to generate logs.")