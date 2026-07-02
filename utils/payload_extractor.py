"""Extract embedded payloads from DICOM files built by this demo."""

from __future__ import annotations

import io
from typing import Any, Dict, List, Optional, Tuple

import pydicom

from utils.dicom_handler import _expected_pixel_bytes
from utils.embed_engine import (
    FILE_LAUNCHER_MAGIC,
    FILE_MAGIC,
    SCRIPT_MAGIC,
    dicom_structure_end,
)

PRIVATE_CREATOR = "DEMO_EMBED"
PRIVATE_GROUP = 0x51

# Strong unambiguous file-start signatures → (extension, label)
# These appear only once at the beginning of a file, not repeated inside it.
BINARY_SIGNATURES: List[Tuple[bytes, str, str]] = [
    (b"MZ",                        ".exe",  "Windows EXE/DLL"),
    (b"%PDF",                      ".pdf",  "PDF Document"),
    (b"ID3",                       ".mp3",  "MP3 Audio (ID3 tag)"),
    (b"OggS",                      ".ogg",  "OGG Audio"),
    (b"fLaC",                      ".flac", "FLAC Audio"),
    (b"PK\x03\x04",                ".zip",  "ZIP Archive"),
    (b"Rar!\x1a\x07",              ".rar",  "RAR Archive"),
    (b"\x1f\x8b",                  ".gz",   "GZIP Archive"),
    (b"\x89PNG\r\n\x1a\n",         ".png",  "PNG Image"),
    (b"\xff\xd8\xff",              ".jpg",  "JPEG Image"),
    (b"GIF87a",                    ".gif",  "GIF Image"),
    (b"GIF89a",                    ".gif",  "GIF Image"),
    (b"PACK",                      ".pack", "Git Pack File"),
    (b"<<<DCM_EMBEDDED_SCRIPT>>>", ".ps1",  "Embedded PS1 Script (demo format)"),
    (b"<<<DCM_EMBEDDED_FILE>>>",   ".bin",  "Embedded File (demo format)"),
]

# Weak signatures — used only for identification, not as split boundaries
# (they appear repeatedly inside files, e.g. MP3 frame headers)
_WEAK_SIGNATURES: List[Tuple[bytes, str, str]] = [
    (b"\xff\xfb", ".mp3", "MP3 Audio"),
    (b"\xff\xf3", ".mp3", "MP3 Audio"),
    (b"\xff\xf2", ".mp3", "MP3 Audio"),
    (b"BM",       ".bmp", "BMP Image"),
]


def identify_bytes(data: bytes) -> Tuple[str, str]:
    """Return (suggested_extension, label) for a raw blob based on its header signature."""
    for sig, ext, label in BINARY_SIGNATURES:
        if data.startswith(sig):
            return ext, label
    for sig, ext, label in _WEAK_SIGNATURES:
        if data.startswith(sig):
            return ext, label
    return ".bin", "Unknown binary data"


def split_raw_files(data: bytes) -> List[Dict[str, Any]]:
    """Split a raw blob into discrete files using strong file-start signatures as boundaries.

    Only strong/unambiguous signatures (those that appear exactly once at the start
    of a file) are used as split points. Weak signatures like MP3 frame headers that
    repeat thousands of times inside a file are NOT used as boundaries.
    """
    if not data:
        return []

    # Collect only the FIRST occurrence of each strong signature
    boundary_positions: List[int] = []
    for sig, _, _ in BINARY_SIGNATURES:
        idx = data.find(sig)
        if idx >= 0:
            boundary_positions.append(idx)

    if not boundary_positions:
        ext, label = identify_bytes(data)
        return [{"start": 0, "data": data, "ext": ext, "label": label}]

    boundaries = sorted(set(boundary_positions))
    if boundaries[0] > 0:
        boundaries = [0] + boundaries

    segments = []
    for i, start in enumerate(boundaries):
        end = boundaries[i + 1] if i + 1 < len(boundaries) else len(data)
        chunk = data[start:end]
        if not chunk:
            continue
        ext, label = identify_bytes(chunk)
        segments.append({"start": start, "data": chunk, "ext": ext, "label": label})
    return segments


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


def extract_from_pdf_encapsulated(ds: pydicom.Dataset) -> List[Dict[str, Any]]:
    """Hidden bytes appended after %%EOF inside EncapsulatedDocument (PDF pattern)."""
    if not hasattr(ds, "EncapsulatedDocument"):
        return []
    doc = bytes(ds.EncapsulatedDocument)
    marker = b"%%EOF"
    eof_index = doc.rfind(marker)
    if eof_index < 0:
        return []
    tail = doc[eof_index + len(marker):]
    tail = tail.lstrip(b"\x00\r\n ")
    if not tail:
        return []
    results: List[Dict[str, Any]] = []
    # Try our magic-marker format first
    for item in _scan_raw_for_payloads(tail):
        item["method"] = "pdf_eof_append"
        results.append(item)
    if results:
        return results
    # Fall back to raw binary signature detection
    for i, seg in enumerate(split_raw_files(tail)):
        ext = seg["ext"]
        label = seg["label"]
        results.append({
            "type": "file",
            "name": f"hidden_payload_{i + 1}{ext}",
            "data": seg["data"],
            "method": "pdf_eof_append",
            "description": f"{label} — {len(seg['data']):,} bytes found after PDF %%EOF",
        })
    return results


def extract_polyglot_stub(dicom_bytes: bytes) -> List[Dict[str, Any]]:
    """Detect preamble payloads before DICM (EXE polyglot and BAT polyglot patterns)."""
    if len(dicom_bytes) < 132 or dicom_bytes[128:132] != b"DICM":
        return []
    preamble = dicom_bytes[:128]
    stripped = preamble.rstrip(b"\x00").rstrip(b" ")
    if not stripped:
        return []
    if preamble[:2] == b"MZ":
        return [{
            "type": "polyglot",
            "name": "mz_dos_stub.bin",
            "data": preamble,
            "method": "exe_polyglot",
            "description": "128-byte MZ/DOS header before DICM — Windows EXE polyglot",
        }]
    if preamble[:5] == b"@echo" or preamble[:1] == b"@":
        return [{
            "type": "polyglot",
            "name": "bat_preamble.bat",
            "data": stripped,
            "method": "exe_polyglot",
            "description": "128-byte batch script preamble before DICM — BAT/DICOM polyglot",
        }]
    # Generic non-zero preamble
    return [{
        "type": "polyglot",
        "name": "preamble_payload.bin",
        "data": stripped,
        "method": "exe_polyglot",
        "description": f"Non-zero DICOM preamble ({len(stripped)} bytes) before DICM",
    }]


def extract_embedded_items(dicom_bytes: bytes) -> List[Dict[str, Any]]:
    """Return embedded scripts/files from pattern embeds, private tag, pixel tail, or EOF tail."""
    results: List[Dict[str, Any]] = []
    results.extend(extract_polyglot_stub(dicom_bytes))

    ds = pydicom.dcmread(io.BytesIO(dicom_bytes), force=True)

    results.extend(extract_from_private_tag(ds))
    results.extend(extract_from_pdf_encapsulated(ds))

    if hasattr(ds, "PixelData"):
        pixel_bytes = bytes(ds.PixelData)
        expected = _expected_pixel_bytes(ds)

        if expected and len(pixel_bytes) > expected:
            # Uncompressed image — tail is everything after the expected pixel region
            tail = pixel_bytes[expected:]
        elif not expected:
            # Compressed image — only detect demo magic markers (no binary signature scan).
            for magic in (SCRIPT_MAGIC, FILE_MAGIC):
                idx = pixel_bytes.rfind(magic)
                if idx >= 0:
                    chunk = pixel_bytes[idx:]
                    parsed = _scan_raw_for_payloads(chunk)
                    for item in parsed:
                        item["method"] = "pixel_tail"
                        results.append(item)
                    break
            tail = b""
        else:
            tail = b""

        if tail:
            parsed = _scan_raw_for_payloads(tail)
            if parsed:
                for item in parsed:
                    item["method"] = "pixel_tail"
                    results.append(item)
            elif SCRIPT_MAGIC not in tail and FILE_MAGIC not in tail:
                # Only report raw binary tails when no demo markers — avoids noise on padding bytes
                for i, seg in enumerate(split_raw_files(tail)):
                    ext = seg["ext"]
                    label = seg["label"]
                    results.append({
                        "type": "file",
                        "name": f"pixel_hidden_{i + 1}{ext}",
                        "data": seg["data"],
                        "method": "pixel_tail",
                        "description": f"{label} — {len(seg['data']):,} bytes appended after PixelData",
                    })

    dicom_len = dicom_structure_end(dicom_bytes)
    eof_tail = dicom_bytes[dicom_len:]
    if eof_tail:
        launcher_idx = eof_tail.find(FILE_LAUNCHER_MAGIC)
        script_region = eof_tail[:launcher_idx] if launcher_idx >= 0 else eof_tail
        launcher_region = eof_tail[launcher_idx:] if launcher_idx >= 0 else b""

        if launcher_region:
            launcher = launcher_region[len(FILE_LAUNCHER_MAGIC) :]
            if launcher:
                results.append({
                    "type": "launcher",
                    "name": "eof_launcher.ps1",
                    "data": launcher,
                    "method": "eof_tail",
                })
        for item in _scan_raw_for_payloads(script_region):
            item["method"] = "eof_script" if item.get("type") == "script" else "eof_tail"
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

    # If a preamble polyglot was found, suppress generic pixel-tail raw-binary items
    # (compressed pixel streams can contain false-positive file signatures like GZIP/JPEG)
    has_polyglot = any(i.get("method") == "exe_polyglot" for i in unique)
    if has_polyglot:
        unique = [
            i for i in unique
            if not (i.get("method") == "pixel_tail" and i.get("type") == "file"
                    and i.get("name", "").startswith("pixel_hidden_"))
        ]

    return unique


def extract_from_image_file(raw: bytes) -> List[Dict[str, Any]]:
    """Extract payloads embedded after JPEG EOI or PNG IEND chunk.

    Supports:
    - JPEG: data appended after the last \\xFF\\xD9 (EOI) marker
    - PNG:  data appended after the IEND chunk (last 12 bytes of a valid PNG)

    Returns a list of extracted payload dicts compatible with the DICOM extractor format.
    """
    results: List[Dict[str, Any]] = []

    JPEG_SIG = b"\xff\xd8\xff"
    PNG_SIG  = b"\x89PNG\r\n\x1a\n"

    if raw.startswith(JPEG_SIG):
        EOI = b"\xff\xd9"
        eoi_idx = raw.rfind(EOI)
        if eoi_idx >= 0:
            tail = raw[eoi_idx + len(EOI):]
            if tail:
                parsed = _scan_raw_for_payloads(tail)
                if parsed:
                    for item in parsed:
                        item["method"] = "jpeg_eof_append"
                        results.append(item)
                else:
                    for i, seg in enumerate(split_raw_files(tail)):
                        results.append({
                            "type": "file",
                            "name": f"jpeg_hidden_{i + 1}{seg['ext']}",
                            "data": seg["data"],
                            "method": "jpeg_eof_append",
                            "description": f"{seg['label']} — {len(seg['data']):,} bytes after JPEG EOI",
                        })

    elif raw.startswith(PNG_SIG):
        IEND = b"IEND"
        iend_idx = raw.rfind(IEND)
        if iend_idx >= 0:
            # IEND chunk = "IEND" keyword + 4-byte CRC
            tail_start = iend_idx + len(IEND) + 4
            tail = raw[tail_start:]
            if tail:
                parsed = _scan_raw_for_payloads(tail)
                if parsed:
                    for item in parsed:
                        item["method"] = "png_iend_append"
                        results.append(item)
                else:
                    for i, seg in enumerate(split_raw_files(tail)):
                        results.append({
                            "type": "file",
                            "name": f"png_hidden_{i + 1}{seg['ext']}",
                            "data": seg["data"],
                            "method": "png_iend_append",
                            "description": f"{seg['label']} — {len(seg['data']):,} bytes after PNG IEND",
                        })

    return results
