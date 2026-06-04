import io

import cv2
import numpy as np
import pydicom
from pydicom.uid import generate_uid

from .embedded_risk_module import log_breach_event


def load_dicom(file):
    ds = pydicom.dcmread(file)
    return ds

def extract_metadata(ds):
    metadata = {
        "Patient Name": str(ds.get("PatientName", "Not Available")),
        "Patient ID": str(ds.get("PatientID", "Not Available")),
        "Study Date": str(ds.get("StudyDate", "Not Available")),
        "Modality": str(ds.get("Modality", "Not Available")),
        "Image Comments": str(ds.get("ImageComments", "Not Available")),
        "Photometric Interpretation": str(ds.get("PhotometricInterpretation", "Not Available")),
    }
    return metadata

def modify_metadata(ds, new_name="Anonymous"):
    old_name = str(ds.get("PatientName", "Not Available"))
    new_name = str(new_name).strip() or "Anonymous"
    ds.PatientName = new_name

    if old_name != new_name:
        log_breach_event(
            action="DICOM Metadata Modification",
            data_type="PHI_data",
            data_accessed=f"PatientName changed: '{old_name}' -> '{new_name}'",
            severity="CRITICAL",
            endpoint="dicom_editor",
        )

    return ds


EXPORT_COMMENT = "Modified by DICOM AI Security Demo"


def _is_rgb_image(image):
    img = np.asarray(image)
    return img.ndim == 3 and img.shape[-1] == 3


def _strip_windowing_tags(export_ds):
    for tag in ("RescaleSlope", "RescaleIntercept", "WindowCenter", "WindowWidth"):
        if tag in export_ds:
            del export_ds[tag]


def _set_uint8_pixel_tags(export_ds, rows, cols, samples=1):
    export_ds.Rows = rows
    export_ds.Columns = cols
    export_ds.SamplesPerPixel = samples
    export_ds.BitsAllocated = 8
    export_ds.BitsStored = 8
    export_ds.HighBit = 7
    export_ds.PixelRepresentation = 0


def build_export_dataset(ds, image):
    """Copy dataset with current UI pixels (preserve RGB heatmap) and export marker tag."""
    export_ds = ds.copy()
    img = np.asarray(image).astype(np.uint8)

    if img.size == 0:
        raise ValueError("Cannot export an empty image.")

    export_ds.ImageComments = EXPORT_COMMENT
    export_ds.SOPInstanceUID = generate_uid()
    _strip_windowing_tags(export_ds)

    if hasattr(export_ds, "NumberOfFrames"):
        del export_ds.NumberOfFrames

    if _is_rgb_image(img):
        export_ds.PhotometricInterpretation = "RGB"
        export_ds.PlanarConfiguration = 0
        _set_uint8_pixel_tags(export_ds, img.shape[0], img.shape[1], samples=3)
        export_ds.PixelData = img.tobytes()
    else:
        if img.ndim == 3:
            img = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
        export_ds.PhotometricInterpretation = "MONOCHROME2"
        _set_uint8_pixel_tags(export_ds, img.shape[0], img.shape[1], samples=1)
        export_ds.PixelData = img.tobytes()

    return export_ds


def export_dicom_bytes(ds, image):
    """Serialize modified DICOM (pixels + tags) for download."""
    export_ds = build_export_dataset(ds, image)
    buffer = io.BytesIO()
    pydicom.dcmwrite(buffer, export_ds)
    return buffer.getvalue()


def build_export_filename(ds, suffix="modified"):
    patient_id = str(ds.get("PatientID", "export"))
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in patient_id)
    return f"{safe}_{suffix}.dcm"


def log_dicom_export(ds, filename, size_bytes):
    """Record CRITICAL audit event when modified DICOM is downloaded."""
    patient_id = str(ds.get("PatientID", "Unknown"))
    patient_name = str(ds.get("PatientName", "Unknown"))
    log_breach_event(
        action="DICOM Export",
        data_type="data_exfiltration",
        data_accessed=(
            f"Downloaded '{filename}' ({size_bytes} bytes) - "
            f"PatientID={patient_id}, PatientName={patient_name}"
        ),
        severity="CRITICAL",
        endpoint="local_download",
    )