"""Extract embedded payloads from DICOM files built by this demo."""

from __future__ import annotations

import io
from typing import Any, Dict, List, Optional, Tuple

import pydicom

from utils.embed_engine import FILE_LAUNCHER_MAGIC, FILE_MAGIC, SCRIPT_MAGIC

PRIVATE_CREATOR = "DEMO_EMBED"
PRIVATE_GROUP = 0x51


def _parse_script_payload(data: bytes, offset: int = 0) -> Optional[Tuple[bytes, int]]:
    if not data[offset:].startswith(SCRIPT_MAGIC):
        return None
    start = offset + len(SCRIPT_MAGIC)
    if len(data) < start + 4:
        return None
    length = int.from_bytes(data[start : start + 4], "little")
    script = data[start + 4 : start + 4 + length]
    return script, start + 4 + length


def _parse_file_payload(data: bytes, offset: int = 0) -> Optional[Tuple[str, bytes, int]]:
    if not data[offset:].startswith(FILE_MAGIC):
        return None
    start = offset + len(FILE_MAGIC)
    if len(data) < start + 2:
        return None
    name_len = int.from_bytes(data[start : start + 2], "little")
    name_start = start + 2
    name_end = name_start + name_len
    if len(data) < name_end + 4:
        return None
    filename = data[name_start:name_end].decode("utf-8", errors="replace")
    file_len = int.from_bytes(data[name_end : name_end + 4], "little")
    file_start = name_end + 4
    file_end = file_start + file_len
    return filename, data[file_start:file_end], file_end


def _scan_raw_for_payloads(raw: bytes) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    offset = 0
    while offset < len(raw):
        if raw[offset:].startswith(SCRIPT_MAGIC):
            parsed = _parse_script_payload(raw, offset)
            if not parsed:
                break
            script, next_offset = parsed
            found.append({"type": "script", "name": "embedded.ps1", "data": script, "offset": offset})
            offset = next_offset
            continue
        if raw[offset:].startswith(FILE_MAGIC):
            parsed = _parse_file_payload(raw, offset)
            if not parsed:
                break
            filename, file_bytes, next_offset = parsed
            found.append({"type": "file", "name": filename, "data": file_bytes, "offset": offset})
            offset = next_offset
            continue
        offset += 1
    return found


def extract_from_private_tag(ds: pydicom.Dataset) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    try:
        block = ds.private_block(PRIVATE_GROUP, PRIVATE_CREATOR)
    except KeyError:
        return results

    if 0x01 in block:
        payload = bytes(block[0x01].value)
        if payload:
            results.append({
                "type": "private_blob",
                "name": "private_tag_payload.bin",
                "data": payload,
                "method": "private_tag",
            })
            for item in _scan_raw_for_payloads(payload):
                item["method"] = "private_tag"
                results.append(item)

    if 0x02 in block:
        launcher = bytes(block[0x02].value)
        if launcher:
            results.append({
                "type": "launcher",
                "name": "extract_launcher.ps1",
                "data": launcher,
                "method": "private_tag",
            })
    return results


def extract_embedded_items(dicom_bytes: bytes) -> List[Dict[str, Any]]:
    """Return embedded scripts/files from private tag, pixel tail, or EOF tail."""
    results: List[Dict[str, Any]] = []
    ds = pydicom.dcmread(io.BytesIO(dicom_bytes), force=True)

    results.extend(extract_from_private_tag(ds))

    if hasattr(ds, "PixelData"):
        pixel_bytes = bytes(ds.PixelData)
        expected = 0
        if getattr(ds, "Rows", 0) and getattr(ds, "Columns", 0):
            spp = int(getattr(ds, "SamplesPerPixel", 1) or 1)
            bps = int(getattr(ds, "BitsAllocated", 8) or 8) // 8
            expected = int(ds.Rows) * int(ds.Columns) * spp * bps
            frames = int(getattr(ds, "NumberOfFrames", 1) or 1)
            expected *= frames
        tail = pixel_bytes[expected:] if expected and len(pixel_bytes) > expected else b""
        if tail:
            for item in _scan_raw_for_payloads(tail):
                item["method"] = "pixel_tail"
                results.append(item)

    dicom_len = len(dicom_bytes)
    try:
        clean = io.BytesIO()
        ds.save_as(clean, write_like_original=True)
        dicom_len = len(clean.getvalue())
    except Exception:
        pass

    eof_tail = dicom_bytes[dicom_len:]
    if eof_tail:
        if FILE_LAUNCHER_MAGIC in eof_tail:
            idx = eof_tail.find(FILE_LAUNCHER_MAGIC)
            launcher = eof_tail[idx + len(FILE_LAUNCHER_MAGIC) :]
            if launcher:
                results.append({
                    "type": "launcher",
                    "name": "eof_launcher.ps1",
                    "data": launcher,
                    "method": "eof_tail",
                })
        for item in _scan_raw_for_payloads(eof_tail):
            item["method"] = "eof_tail"
            results.append(item)

    # De-duplicate by offset+name
    seen = set()
    unique: List[Dict[str, Any]] = []
    for item in results:
        key = (item.get("method"), item.get("name"), item.get("offset"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
