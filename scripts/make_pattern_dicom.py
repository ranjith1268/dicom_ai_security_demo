#!/usr/bin/env python3
"""
Create DICOM files using security-test embedding patterns.

Examples:
  python scripts/make_pattern_dicom.py analyze --folder path/to/dicoms

  python scripts/make_pattern_dicom.py pdf-mp3 --pdf doc.pdf --attach audio.mp3 --output out.dcm

  python scripts/make_pattern_dicom.py exe-polyglot --input scan.dcm --output polyglot.dcm

  python scripts/make_pattern_dicom.py pixel-append --input scan.dcm --attach payload.bin --output out.dcm

  python scripts/make_pattern_dicom.py eof-append --input scan.dcm --attach script.ps1 --output out.dcm

  python scripts/make_pattern_dicom.py chrome-script --input scan.dcm --output out.dcm --chrome-count 3
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.pattern_dicom_builder import (  # noqa: E402
    analyze_dicom_folder,
    build_file_payload,
    create_encapsulated_pdf_dicom,
    create_exe_polyglot_dicom,
    create_image_eof_embed_dicom,
    create_image_pixel_embed_dicom,
    embed_script_chrome_payload,
    read_bytes,
    write_log,
)

OUTPUT_DIR = ROOT / "output" / "embed"
DEFAULT_REFERENCE_FOLDER = os.environ.get("DICOM_REFERENCE_FOLDER", "")


def _resolve_output(path: str | None, default_name: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        return out
    return OUTPUT_DIR / default_name


def _load_payload(attach: str | None, attach_file: Path | None) -> bytes:
    if attach_file:
        return read_bytes(attach_file)
    if attach:
        return Path(attach).read_bytes()
    raise ValueError("Provide --attach or --attach-file")


def cmd_analyze(args: argparse.Namespace) -> None:
    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"Folder not found: {folder}")
        sys.exit(1)
    results = analyze_dicom_folder(folder)
    print(json.dumps(results, indent=2))
    if args.save:
        out = _resolve_output(args.save, "dicom_analysis.json")
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nSaved: {out}")


def cmd_pdf_mp3(args: argparse.Namespace) -> None:
    pdf_path = Path(args.pdf)
    if not pdf_path.exists():
        print(f"PDF not found: {pdf_path}")
        sys.exit(1)

    extra_files = []
    for attach in args.attach or []:
        p = Path(attach)
        if not p.exists():
            print(f"Attachment not found: {p}")
            sys.exit(1)
        extra_files.append((p.name, read_bytes(p)))

    out = _resolve_output(args.output, "encapsulated_pdf_multifile.dcm")
    _, log = create_encapsulated_pdf_dicom(
        read_bytes(pdf_path),
        extra_files,
        out,
        patient_name=args.patient_name,
        patient_id=args.patient_id,
    )
    log_path = write_log(log, out)
    print(f"Created: {out}")
    print(f"Pattern: {log['pattern']} (ref: {log['reference_file']})")
    print(f"Attached: {log['attached_files']}")
    print(f"Log: {log_path}")


def cmd_exe_polyglot(args: argparse.Namespace) -> None:
    source = Path(args.input)
    if not source.exists():
        print(f"DICOM not found: {source}")
        sys.exit(1)
    out = _resolve_output(args.output, "exe_polyglot.dcm")
    log = create_exe_polyglot_dicom(source, out)
    log_path = write_log(log, out)
    print(f"Created: {out}")
    print(f"Pattern: {log['pattern']} (ref: {log['reference_file']})")
    print(f"MZ at byte 0, DICM at byte {log['dicm_at_offset']}")
    print(f"Log: {log_path}")


def cmd_pixel_append(args: argparse.Namespace) -> None:
    source = Path(args.input)
    if not source.exists():
        print(f"DICOM not found: {source}")
        sys.exit(1)
    payload = _load_payload(args.attach, Path(args.attach_file) if args.attach_file else None)
    out = _resolve_output(args.output, "pixel_append.dcm")
    log = create_image_pixel_embed_dicom(source, payload, out)
    log_path = write_log(log, out)
    print(f"Created: {out}")
    print(f"Pattern: {log['pattern']}")
    print(f"Pixels prefix unchanged: {log['pixels_unchanged_prefix']}")
    print(f"Log: {log_path}")


def cmd_eof_append(args: argparse.Namespace) -> None:
    source = Path(args.input)
    if not source.exists():
        print(f"DICOM not found: {source}")
        sys.exit(1)
    attach_path = Path(args.attach_file) if args.attach_file else Path(args.attach)
    file_bytes = read_bytes(attach_path)
    payload = build_file_payload(attach_path.name, file_bytes)
    out = _resolve_output(args.output, "eof_append.dcm")
    log = create_image_eof_embed_dicom(source, payload, out)
    log_path = write_log(log, out)
    print(f"Created: {out}")
    print(f"Pattern: {log['pattern']}")
    print(f"Pixels unchanged: {log['pixels_unchanged']}")
    print(f"Log: {log_path}")


def cmd_chrome_script(args: argparse.Namespace) -> None:
    source = Path(args.input)
    if not source.exists():
        print(f"DICOM not found: {source}")
        sys.exit(1)
    payload = embed_script_chrome_payload(args.chrome_count)
    out = _resolve_output(args.output, "chrome_script.dcm")
    log = create_image_eof_embed_dicom(source, payload, out)
    log["chrome_open_count"] = args.chrome_count
    log_path = write_log(log, out)
    print(f"Created: {out}")
    print(f"Chrome opens: {args.chrome_count}")
    print(f"Pixels unchanged: {log['pixels_unchanged']}")
    print(f"Log: {log_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create DICOM files with security-test embedding patterns."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze all DICOMs in a folder")
    p_analyze.add_argument(
        "--folder",
        default=DEFAULT_REFERENCE_FOLDER or None,
        required=not bool(DEFAULT_REFERENCE_FOLDER),
        help="Folder with .dcm files (or set DICOM_REFERENCE_FOLDER env)",
    )
    p_analyze.add_argument("--save", help="Save JSON report path")
    p_analyze.set_defaults(func=cmd_analyze)

    p_pdf = sub.add_parser("pdf-mp3", help="Encapsulated PDF + files after %%EOF (MP3+PDF.dcm)")
    p_pdf.add_argument("--pdf", required=True, help="PDF file path")
    p_pdf.add_argument("--attach", action="append", help="File(s) to hide after PDF EOF")
    p_pdf.add_argument("--output", "-o", help="Output .dcm path")
    p_pdf.add_argument("--patient-name", default="Demo^Patient")
    p_pdf.add_argument("--patient-id", default="DEMO001")
    p_pdf.set_defaults(func=cmd_pdf_mp3)

    p_exe = sub.add_parser("exe-polyglot", help="DOS MZ stub + DICOM (exe_embedded_dicom-1.dcm)")
    p_exe.add_argument("--input", "-i", required=True, help="Source image DICOM")
    p_exe.add_argument("--output", "-o", help="Output .dcm path")
    p_exe.set_defaults(func=cmd_exe_polyglot)

    p_pix = sub.add_parser("pixel-append", help="Append payload to PixelData (DX/US style)")
    p_pix.add_argument("--input", "-i", required=True, help="Source image DICOM")
    g = p_pix.add_mutually_exclusive_group(required=True)
    g.add_argument("--attach", help="Payload file path")
    g.add_argument("--attach-file", help="Payload file path (alias)")
    p_pix.add_argument("--output", "-o", help="Output .dcm path")
    p_pix.set_defaults(func=cmd_pixel_append)

    p_eof = sub.add_parser("eof-append", help="Append file at end — pixels untouched")
    p_eof.add_argument("--input", "-i", required=True, help="Source image DICOM")
    g2 = p_eof.add_mutually_exclusive_group(required=True)
    g2.add_argument("--attach", help="File to embed")
    g2.add_argument("--attach-file", help="File to embed (alias)")
    p_eof.add_argument("--output", "-o", help="Output .dcm path")
    p_eof.set_defaults(func=cmd_eof_append)

    p_chr = sub.add_parser("chrome-script", help="Embed Chrome launcher script (eof-append)")
    p_chr.add_argument("--input", "-i", required=True, help="Source image DICOM")
    p_chr.add_argument("--output", "-o", help="Output .dcm path")
    p_chr.add_argument("--chrome-count", type=int, default=3, help="Times to open Chrome")
    p_chr.set_defaults(func=cmd_chrome_script)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
