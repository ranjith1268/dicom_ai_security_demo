"""
Build DICOM files using known security-test embedding patterns:
  - MP3+PDF.dcm        → Encapsulated PDF + file appended after %%EOF
  - PDFGitPolyglot.dcm → Encapsulated document polyglot (PDF + payload)
  - exe_embedded_*     → EXE/DOS stub prepended before DICM (128-byte polyglot)
  - Image CT/DX/US     → Payload appended to PixelData or end of file
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pydicom
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import EncapsulatedPDFStorage, ExplicitVRLittleEndian, generate_uid

SCRIPT_MAGIC = b"<<<DCM_EMBEDDED_SCRIPT>>>"
FILE_MAGIC = b"<<<DCM_EMBEDDED_FILE>>>"


def _reference_exe_path() -> Optional[Path]:
    env = os.environ.get("DICOM_REFERENCE_EXE")
    if env:
        p = Path(env)
        if p.exists():
            return p
    bundled = Path(__file__).resolve().parents[1] / "reference_files" / "exe_embedded_dicom-1.dcm"
    if bundled.exists():
        return bundled
    return None


def get_dos_stub_128() -> bytes:
    """128-byte MZ stub — DICM must start at file offset 128."""
    ref = _reference_exe_path()
    if ref:
        return ref.read_bytes()[:128]
    stub = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"
        b"\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"P\x01\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!"
        b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
    )
    return stub + b"\x00" * (128 - len(stub))


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def concat_after_pdf_eof(pdf_bytes: bytes, extra_bytes: bytes) -> bytes:
    """MP3+PDF.dcm pattern: append payload immediately after the last %%EOF."""
    marker = b"%%EOF"
    eof_index = pdf_bytes.rfind(marker)
    if eof_index < 0:
        return pdf_bytes + extra_bytes
    insert_at = eof_index + len(marker)
    return pdf_bytes[:insert_at] + extra_bytes


def build_script_payload(script_bytes: bytes) -> bytes:
    return SCRIPT_MAGIC + len(script_bytes).to_bytes(4, "little") + script_bytes


def build_file_payload(filename: str, file_bytes: bytes) -> bytes:
    name_bytes = filename.encode("utf-8")
    return (
        FILE_MAGIC
        + len(name_bytes).to_bytes(2, "little")
        + name_bytes
        + len(file_bytes).to_bytes(4, "little")
        + file_bytes
    )


def create_encapsulated_pdf_dicom(
    pdf_bytes: bytes,
    extra_files: List[Tuple[str, bytes]],
    output_path: Path,
    patient_name: str = "Demo^Patient",
    patient_id: str = "DEMO001",
) -> Tuple[bytes, Dict[str, Any]]:
    """Create DICOM like MP3+PDF.dcm / PDFGitPolyglot.dcm."""
    encapsulated = pdf_bytes
    attached_names: List[str] = []
    for filename, file_bytes in extra_files:
        encapsulated = concat_after_pdf_eof(encapsulated, file_bytes)
        attached_names.append(filename)

    file_meta = Dataset()
    file_meta.MediaStorageSOPClassUID = EncapsulatedPDFStorage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.ImplementationClassUID = generate_uid()

    ds = FileDataset(str(output_path), {}, file_meta=file_meta, preamble=b"\0" * 128)
    now = datetime.now()
    ds.SpecificCharacterSet = "ISO_IR 100"
    ds.SOPClassUID = EncapsulatedPDFStorage
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.StudyDate = now.strftime("%Y%m%d")
    ds.ContentDate = now.strftime("%Y%m%d")
    ds.ContentTime = now.strftime("%H%M%S")
    ds.Modality = "DOC"
    ds.ConversionType = "WSD"
    ds.PatientName = patient_name
    ds.PatientID = patient_id
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.EncapsulatedDocument = encapsulated
    ds.MIMETypeOfEncapsulatedDocument = "application/pdf"

    ds.save_as(str(output_path))
    result_bytes = output_path.read_bytes()

    log = {
        "pattern": "encapsulated_pdf_multifile",
        "reference_file": "MP3+PDF.dcm / PDFGitPolyglot.dcm",
        "modality": "DOC",
        "output": output_path.name,
        "pdf_bytes": len(pdf_bytes),
        "encapsulated_bytes": len(encapsulated),
        "attached_files": attached_names,
        "hash_sha256": hashlib.sha256(result_bytes).hexdigest(),
    }
    return result_bytes, log


def build_encapsulated_pdf_dicom_bytes(
    pdf_bytes: bytes,
    extra_files: List[Tuple[str, bytes]],
    patient_name: str = "Demo^Patient",
    patient_id: str = "DEMO001",
) -> Tuple[bytes, Dict[str, Any]]:
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".dcm", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        return create_encapsulated_pdf_dicom(
            pdf_bytes, extra_files, tmp_path, patient_name, patient_id
        )
    finally:
        tmp_path.unlink(missing_ok=True)


def build_exe_polyglot_bytes(source_bytes: bytes, source_name: str = "upload.dcm") -> Tuple[bytes, Dict[str, Any]]:
    """EXE polyglot like exe_embedded_dicom-1.dcm — MZ at byte 0, DICM at byte 128."""
    dos_stub = get_dos_stub_128()
    if len(dos_stub) != 128:
        raise ValueError("DOS stub must be exactly 128 bytes.")
    raw = source_bytes
    if raw[128:132] == b"DICM":
        dicom_body = raw[128:]
    elif raw[:4] == b"DICM":
        dicom_body = raw
    else:
        raise ValueError("Source is not a valid DICOM (DICM header not found).")
    result = dos_stub + dicom_body
    log = {
        "pattern": "exe_polyglot_preamble",
        "reference_file": "exe_embedded_dicom-1.dcm",
        "source": source_name,
        "mz_at_offset": 0,
        "dicm_at_offset": 128,
        "hash_sha256": hashlib.sha256(result).hexdigest(),
    }
    return result, log


def build_image_pixel_embed_bytes(
    source_bytes: bytes, payload: bytes, source_name: str = "upload.dcm"
) -> Tuple[bytes, Dict[str, Any]]:
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".dcm", delete=False) as src_tmp:
        src_path = Path(src_tmp.name)
        src_path.write_bytes(source_bytes)
    out_path = src_path.with_name(src_path.stem + "_out.dcm")
    try:
        log = create_image_pixel_embed_dicom(src_path, payload, out_path)
        log["source"] = source_name
        return out_path.read_bytes(), log
    finally:
        src_path.unlink(missing_ok=True)
        out_path.unlink(missing_ok=True)


def create_exe_polyglot_dicom(
    source_dicom: Path,
    output_path: Path,
    dos_stub: Optional[bytes] = None,
) -> Dict[str, Any]:
    raw = source_dicom.read_bytes()
    dos_stub = dos_stub or get_dos_stub_128()
    if len(dos_stub) != 128:
        raise ValueError("DOS stub must be exactly 128 bytes.")

    if raw[128:132] == b"DICM":
        dicom_body = raw[128:]
    elif raw[:4] == b"DICM":
        dicom_body = raw
    else:
        raise ValueError("Source file is not a valid DICOM (DICM header not found).")

    result = dos_stub + dicom_body
    output_path.write_bytes(result)

    return {
        "pattern": "exe_polyglot_preamble",
        "reference_file": "exe_embedded_dicom-1.dcm",
        "output": output_path.name,
        "mz_at_offset": 0,
        "dicm_at_offset": 128,
        "source": source_dicom.name,
        "hash_sha256": hashlib.sha256(result).hexdigest(),
    }


def create_image_pixel_embed_dicom(
    source_dicom: Path,
    payload: bytes,
    output_path: Path,
) -> Dict[str, Any]:
    ds = pydicom.dcmread(source_dicom, force=True)
    if not hasattr(ds, "PixelData"):
        raise ValueError("Source DICOM has no PixelData.")

    original_pixels = bytes(ds.PixelData)
    ds.PixelData = original_pixels + payload
    ds.save_as(str(output_path))

    after = pydicom.dcmread(output_path, force=True)
    pixels_unchanged = bytes(after.PixelData[: len(original_pixels)]) == original_pixels

    return {
        "pattern": "image_pixel_append",
        "reference_file": "1.2.9.1.6.55765.dcm / VL6_J2KR style",
        "output": output_path.name,
        "source": source_dicom.name,
        "original_pixel_bytes": len(original_pixels),
        "payload_bytes": len(payload),
        "pixels_unchanged_prefix": pixels_unchanged,
        "hash_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
    }


def create_image_eof_embed_dicom(
    source_dicom: Path,
    payload: bytes,
    output_path: Path,
) -> Dict[str, Any]:
    raw = source_dicom.read_bytes()
    before = pydicom.dcmread(io.BytesIO(raw), force=True)
    original_pixels = bytes(getattr(before, "PixelData", b"") or b"")

    result = raw + payload
    output_path.write_bytes(result)

    after = pydicom.dcmread(output_path, force=True)
    after_pixels = bytes(getattr(after, "PixelData", b"") or b"")

    return {
        "pattern": "image_eof_append",
        "reference_file": "non-destructive embed (recommended)",
        "output": output_path.name,
        "source": source_dicom.name,
        "payload_bytes": len(payload),
        "pixels_unchanged": original_pixels == after_pixels,
        "hash_sha256": hashlib.sha256(result).hexdigest(),
    }


def embed_script_chrome_payload(open_count: int = 3) -> bytes:
    script = f"""# Opens Chrome {open_count} times
$chromePaths = @(
    "$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.exe",
    "${{env:ProgramFiles(x86)}}\\Google\\Chrome\\Application\\chrome.exe",
    "$env:LOCALAPPDATA\\Google\\Chrome\\Application\\chrome.exe"
)
$chrome = $chromePaths | Where-Object {{ Test-Path $_ }} | Select-Object -First 1
if (-not $chrome) {{ $chrome = (Get-Command chrome.exe -ErrorAction SilentlyContinue).Source }}
for ($i = 1; $i -le {open_count}; $i++) {{ Start-Process -FilePath $chrome; Start-Sleep -Milliseconds 800 }}
"""
    return build_script_payload(script.encode("utf-8"))


def analyze_dicom_folder(folder: Path) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for path in sorted(folder.glob("*.dcm")):
        raw = path.read_bytes()
        entry: Dict[str, Any] = {"file": path.name, "size": len(raw)}
        try:
            ds = pydicom.dcmread(path, force=True)
            entry["modality"] = str(getattr(ds, "Modality", "?"))
            entry["sop_class"] = str(getattr(ds, "SOPClassUID", ""))
            entry["pixel_data"] = len(getattr(ds, "PixelData", b"") or b"")
            entry["encapsulated_document"] = len(getattr(ds, "EncapsulatedDocument", b"") or b"")
            entry["mime"] = str(getattr(ds, "MIMETypeOfEncapsulatedDocument", ""))
        except Exception as error:
            entry["error"] = str(error)

        for label, sig in [("pdf", b"%PDF"), ("mp3", b"ID3"), ("exe", b"MZ"), ("dicm", b"DICM")]:
            entry[f"{label}_offset"] = raw.find(sig)
        results.append(entry)
    return results


def write_log(log: Dict[str, Any], output_path: Path) -> Path:
    log_path = output_path.with_suffix("").with_name(output_path.stem + "_build_log.json")
    log_path.write_text(json.dumps(log, indent=2), encoding="utf-8")
    return log_path
