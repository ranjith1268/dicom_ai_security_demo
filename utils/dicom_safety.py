"""Scan DICOM files for embedding threats and remediate removable findings."""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import List, Optional, Set

import pydicom

from utils.dicom_handler import _expected_pixel_bytes

PDF_EOF_MARKER = b"%%EOF"
SCRIPT_MAGIC    = b"<<<DCM_EMBEDDED_SCRIPT>>>"
FILE_MAGIC      = b"<<<DCM_EMBEDDED_FILE>>>"
LAUNCHER_MAGIC  = b"<<<DCM_FILE_LAUNCHER>>>"

REQUIRED_TAGS = ("PatientName", "PatientID", "Modality", "SOPClassUID")


@dataclass
class SafetyFinding:
    finding_id: str
    finding_type: str
    severity: str
    location: str
    description: str
    evidence: str
    size_bytes: int
    removable: bool
    recommendation: str


def analyze_dicom(dicom_bytes: bytes) -> tuple[List[SafetyFinding], Optional[pydicom.Dataset]]:
    findings: List[SafetyFinding] = []
    raw = dicom_bytes

    if len(raw) >= 132 and raw[128:132] == b"DICM":
        preamble = raw[:128]
        stripped = preamble.rstrip(b"\x00").rstrip(b" ")
        if stripped:
            if preamble[:2] == b"MZ":
                findings.append(SafetyFinding(
                    finding_id="polyglot_001",
                    finding_type="polyglot_exe",
                    severity="CRITICAL",
                    location="bytes 0-127 (preamble)",
                    description="MZ/DOS executable header in DICOM preamble (EXE polyglot)",
                    evidence="Preamble starts with 'MZ'; DICM at byte 128",
                    size_bytes=128,
                    removable=True,
                    recommendation="Zero-fill preamble to restore clean DICOM structure",
                ))
            elif stripped[:5] == b"@echo" or stripped[:1] == b"@":
                findings.append(SafetyFinding(
                    finding_id="polyglot_bat_001",
                    finding_type="polyglot_bat",
                    severity="CRITICAL",
                    location="bytes 0-127 (preamble)",
                    description="Batch script detected in DICOM preamble (BAT/DICOM polyglot)",
                    evidence=f"Preamble contains: {repr(stripped[:60])}",
                    size_bytes=128,
                    removable=True,
                    recommendation="Zero-fill preamble to restore clean DICOM structure",
                ))
            else:
                findings.append(SafetyFinding(
                    finding_id="polyglot_unknown_001",
                    finding_type="polyglot_unknown",
                    severity="HIGH",
                    location="bytes 0-127 (preamble)",
                    description="Non-zero DICOM preamble — possible hidden code",
                    evidence=f"Preamble content: {repr(stripped[:60])}",
                    size_bytes=len(stripped),
                    removable=True,
                    recommendation="Zero-fill preamble to restore clean DICOM structure",
                ))

    try:
        ds = pydicom.dcmread(io.BytesIO(raw), force=True)
    except Exception as error:
        findings.append(
            SafetyFinding(
                finding_id="struct_001",
                finding_type="structural",
                severity="HIGH",
                location="file",
                description="DICOM structure could not be parsed",
                evidence=str(error),
                size_bytes=0,
                removable=False,
                recommendation="File may be corrupt; manual review required",
            )
        )
        return findings, None

    if hasattr(ds, "EncapsulatedDocument"):
        doc = bytes(ds.EncapsulatedDocument)
        eof_index = doc.rfind(PDF_EOF_MARKER)
        if eof_index >= 0:
            tail = doc[eof_index + len(PDF_EOF_MARKER) :]
            if tail:
                findings.append(
                    SafetyFinding(
                        finding_id="pdf_payload_001",
                        finding_type="embedded_file",
                        severity="HIGH",
                        location=f"bytes after PDF %%EOF ({len(tail):,} bytes)",
                        description=f"Hidden data appended after PDF %%EOF ({len(tail):,} bytes)",
                        evidence=f"PDF %%EOF at offset {eof_index}; {len(tail):,} bytes follow",
                        size_bytes=len(tail),
                        removable=True,
                        recommendation="Remove appended files to ensure encapsulated PDF is clean",
                    )
                )

    if hasattr(ds, "PixelData"):
        pixel_bytes = bytes(ds.PixelData)
        expected = _expected_pixel_bytes(ds)

        if expected > 0 and len(pixel_bytes) > expected:
            # Uncompressed: tail is everything past the known pixel region
            extra = len(pixel_bytes) - expected
            tail = pixel_bytes[expected:]
            is_script = SCRIPT_MAGIC in tail or FILE_MAGIC in tail
            findings.append(SafetyFinding(
                finding_id="pixel_001",
                finding_type="pixel_script" if is_script else "pixel_payload",
                severity="CRITICAL" if is_script else "HIGH",
                location="PixelData (tail)",
                description=(
                    f"Hidden script payload appended to PixelData ({extra:,} bytes)"
                    if is_script else
                    f"Extra data appended to PixelData ({extra:,} bytes)"
                ),
                evidence=f"Expected {expected:,} bytes; actual {len(pixel_bytes):,} bytes; script markers: {is_script}",
                size_bytes=extra,
                removable=True,
                recommendation="Remove appended payload; pixel prefix contains the original image",
            ))
        elif not expected:
            # Compressed: scan for script magic markers using fast rfind
            for magic, label in [(SCRIPT_MAGIC, "embedded script"), (FILE_MAGIC, "embedded file")]:
                idx = pixel_bytes.rfind(magic)
                if idx >= 0:
                    tail_size = len(pixel_bytes) - idx
                    findings.append(SafetyFinding(
                        finding_id="pixel_script_001",
                        finding_type="pixel_script",
                        severity="CRITICAL",
                        location=f"PixelData (compressed, offset {idx:,})",
                        description=f"Hidden {label} found inside compressed PixelData ({tail_size:,} bytes)",
                        evidence=f"Magic marker '{magic.decode()}' found at offset {idx:,} in PixelData",
                        size_bytes=tail_size,
                        removable=True,
                        recommendation="Truncate PixelData at the script marker boundary to remove payload",
                    ))
                    break

    missing = [tag for tag in REQUIRED_TAGS if not getattr(ds, tag, None)]
    if missing:
        findings.append(
            SafetyFinding(
                finding_id="tags_001",
                finding_type="missing_tags",
                severity="MEDIUM",
                location="DICOM metadata",
                description=f"Missing recommended medical tags: {', '.join(missing)}",
                evidence=f"Tags absent: {', '.join(missing)}",
                size_bytes=0,
                removable=False,
                recommendation="Add missing tags from a trusted source; cannot auto-fix",
            )
        )

    dicom_len = len(raw)
    try:
        clean = io.BytesIO()
        ds.save_as(clean, write_like_original=True)
        dicom_len = len(clean.getvalue())
    except Exception:
        pass
    eof_tail = raw[dicom_len:]
    if eof_tail:
        has_launcher = LAUNCHER_MAGIC in eof_tail
        findings.append(SafetyFinding(
            finding_id="launcher_001" if has_launcher else "eof_001",
            finding_type="autorun_launcher" if has_launcher else "eof_append",
            severity="CRITICAL" if has_launcher else "HIGH",
            location=f"after DICOM end ({len(eof_tail):,} bytes)",
            description=(
                f"Auto-run launcher appended after DICOM ({len(eof_tail):,} bytes) — "
                "causes payload to execute on double-click via DicomAutoOpen handler"
                if has_launcher else
                f"Unknown data appended after DICOM structure ({len(eof_tail):,} bytes)"
            ),
            evidence=(
                f"FILE_LAUNCHER_MAGIC marker found; {len(eof_tail):,} bytes of launcher code"
                if has_launcher else
                f"{len(eof_tail):,} bytes after parsed DICOM end"
            ),
            size_bytes=len(eof_tail),
            removable=True,
            recommendation=(
                "Remove launcher to prevent auto-execution on double-click"
                if has_launcher else
                "Remove trailing bytes after the DICOM file end"
            ),
        ))

    return findings, ds


def clean_dicom(dicom_bytes: bytes, finding_ids: Set[str]) -> bytes:
    """Remove approved threats while preserving legitimate DICOM tags."""
    raw = dicom_bytes
    approved = set(finding_ids)

    # --- Preamble threats: zero-fill first 128 bytes ---
    _preamble_ids = {"polyglot_001", "polyglot_bat_001", "polyglot_unknown_001"}
    if _preamble_ids & approved and len(raw) >= 132 and raw[128:132] == b"DICM":
        raw = b"\x00" * 128 + raw[128:]

    ds = pydicom.dcmread(io.BytesIO(raw), force=True)

    # --- Encapsulated PDF tail ---
    if "pdf_payload_001" in approved and hasattr(ds, "EncapsulatedDocument"):
        doc = bytes(ds.EncapsulatedDocument)
        eof_index = doc.rfind(PDF_EOF_MARKER)
        if eof_index >= 0:
            ds.EncapsulatedDocument = doc[: eof_index + len(PDF_EOF_MARKER)]

    # --- Pixel tail (uncompressed) ---
    if "pixel_001" in approved and hasattr(ds, "PixelData"):
        pixel_bytes = bytes(ds.PixelData)
        expected = _expected_pixel_bytes(ds)
        if expected > 0 and len(pixel_bytes) > expected:
            ds.PixelData = pixel_bytes[:expected]

    # --- Script in compressed pixel data ---
    if "pixel_script_001" in approved and hasattr(ds, "PixelData"):
        pixel_bytes = bytes(ds.PixelData)
        for magic in (SCRIPT_MAGIC, FILE_MAGIC):
            idx = pixel_bytes.rfind(magic)
            if idx >= 0:
                ds.PixelData = pixel_bytes[:idx]
                break

    # --- Remove EOF tail / auto-run launcher ---
    _eof_ids = {"eof_001", "launcher_001"}
    if _eof_ids & approved:
        try:
            clean = io.BytesIO()
            ds.save_as(clean, write_like_original=True)
            raw = clean.getvalue()
            ds = pydicom.dcmread(io.BytesIO(raw), force=True)
        except Exception:
            pass

    out = io.BytesIO()
    ds.save_as(out, write_like_original=True)
    return out.getvalue()
