"""Register .dcm double-click handler on Windows (per-user, no admin)."""

from __future__ import annotations

import sys
from pathlib import Path

PROG_ID = "DicomAutoOpen"


def handler_python_executable() -> Path:
    """Prefer pythonw.exe so double-click does not flash a console window."""
    exe = Path(sys.executable)
    if exe.stem.lower() == "python":
        pyw = exe.with_name("pythonw.exe")
        if pyw.is_file():
            return pyw
    return exe


def is_dicom_handler_registered() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.dcm") as key:
            value, _ = winreg.QueryValueEx(key, "")
        return value == PROG_ID
    except OSError:
        return False


def register_dicom_handler() -> tuple[bool, str]:
    """Wire .dcm double-click to scripts/open_embedded_dicom.py for the current user."""
    if sys.platform != "win32":
        return False, "Double-click auto-run is only available on Windows."

    handler = Path(__file__).resolve().parents[1] / "scripts" / "open_embedded_dicom.py"
    if not handler.is_file():
        return False, f"Handler not found: {handler}"

    python = handler_python_executable()
    command = f'"{python}" "{handler}" "%1"'

    try:
        import winreg

        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROG_ID}\shell\open\command"
        ) as key:
            winreg.SetValue(key, "", winreg.REG_SZ, command)

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.dcm") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, PROG_ID)
    except OSError as error:
        return False, f"Could not register .dcm handler: {error}"

    return True, "Double-click auto-run enabled for .dcm files."


def ensure_dicom_handler_registered() -> tuple[bool, str]:
    if is_dicom_handler_registered():
        return True, "Double-click auto-run already enabled."
    return register_dicom_handler()
