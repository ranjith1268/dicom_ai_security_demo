"""Windows Defender custom file scan helper (local Windows demo)."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

STEGO_ENTERPRISE_URL = "https://d3s0sxieusmkay.cloudfront.net/"


def _mpcmdrun_path() -> Optional[Path]:
    candidates = [
        Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe"),
        Path(r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe"),
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def defender_runnable_on_server() -> bool:
    """True when this Python process can invoke MpCmdRun (local Windows only)."""
    return platform.system() == "Windows" and _mpcmdrun_path() is not None


def suggested_client_download_path(filename: str) -> str:
    """Best-guess path where the user saved the download on their Windows PC."""
    if sys.platform == "win32":
        return str(Path.home() / "Downloads" / filename)
    return str(Path(f"C:/Users/YOUR_USERNAME/Downloads/{filename}"))


def resolve_scan_target(
    user_path: str,
    filename: str,
    server_copy: Optional[str] = None,
) -> tuple[Path, str]:
    """Pick a file to scan: user path first, then Downloads, then server copy."""
    tried: list[str] = []

    if user_path.strip():
        candidate = Path(user_path.strip())
        tried.append(str(candidate))
        if candidate.is_file():
            return candidate, "user_path"

    if sys.platform == "win32":
        downloads = Path.home() / "Downloads" / filename
        tried.append(str(downloads))
        if downloads.is_file():
            return downloads, "downloads_folder"

    if server_copy:
        server_path = Path(server_copy)
        tried.append(str(server_path))
        if server_path.is_file():
            return server_path, "server_copy"

    fallback = Path(user_path.strip()) if user_path.strip() else Path(suggested_client_download_path(filename))
    return fallback, "not_found:" + "; ".join(tried)


def build_local_defender_scan_script(filename: str, file_path: str = "") -> str:
    """PowerShell script the user runs on their Windows PC (for cloud / remote Streamlit)."""
    if file_path.strip():
        path_setup = f'$FilePath = "{file_path.strip()}"'
    else:
        path_setup = f'$FilePath = Join-Path $env:USERPROFILE "Downloads" "{filename}"'

    return f"""# DICOM Security Demo — scan downloaded file with Windows Defender on YOUR PC.
# Usage: powershell -ExecutionPolicy Bypass -File .\\scan_{filename}.ps1

{path_setup}
$MpCmdRun = Join-Path ${{env:ProgramFiles}} "Windows Defender\\MpCmdRun.exe"
if (-not (Test-Path $MpCmdRun)) {{
    $MpCmdRun = Join-Path ${{env:ProgramFiles(x86)}} "Windows Defender\\MpCmdRun.exe"
}}
if (-not (Test-Path $MpCmdRun)) {{
    Write-Host "ERROR: MpCmdRun.exe not found. Is Windows Defender installed?" -ForegroundColor Red
    exit 1
}}
if (-not (Test-Path $FilePath)) {{
    Write-Host "ERROR: File not found: $FilePath" -ForegroundColor Red
    Write-Host "Save the downloaded file to that path, or edit `$FilePath` at the top of this script."
    exit 1
}}

Write-Host "Scanning with Windows Defender: $FilePath" -ForegroundColor Cyan
& $MpCmdRun -Scan -ScanType 3 -File $FilePath
$code = $LASTEXITCODE
Write-Host ""
if ($code -eq 0) {{
    Write-Host "Result: No threats detected." -ForegroundColor Green
}} elseif ($code -eq 2) {{
    Write-Host "Result: Threat detected by Windows Defender." -ForegroundColor Red
}} else {{
    Write-Host "Result: Scan finished with exit code $code." -ForegroundColor Yellow
}}
Write-Host ""
Write-Host "Opening StegoEnterprise portal..." -ForegroundColor Cyan
Start-Process "{STEGO_ENTERPRISE_URL}"
exit $code
"""


def scan_with_defender(file_path: Path, timeout_sec: int = 120) -> Dict[str, Any]:
    """Run a Windows Defender custom scan on a single file on this machine."""
    if not file_path.is_file():
        return {
            "available": False,
            "success": False,
            "status": "error",
            "threats_found": False,
            "message": f"File not found: {file_path}",
            "detail": (
                "Save the downloaded file to the path above, then scan again. "
                f"Typical location: {suggested_client_download_path(file_path.name)}"
            ),
            "scanned_path": str(file_path),
        }

    if platform.system() != "Windows":
        return {
            "available": False,
            "success": False,
            "status": "unsupported",
            "threats_found": False,
            "message": (
                "This app is running on a Linux server (e.g. Streamlit Cloud). "
                "Windows Defender must scan the file on **your Windows PC** — "
                "download the scan script below and run it locally."
            ),
            "detail": "",
            "scanned_path": str(file_path),
        }

    mpcmd = _mpcmdrun_path()
    if mpcmd is None:
        return {
            "available": False,
            "success": False,
            "status": "unavailable",
            "threats_found": False,
            "message": "MpCmdRun.exe not found. Is Windows Defender installed?",
            "detail": "",
            "scanned_path": str(file_path),
        }

    cmd = [
        str(mpcmd),
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(file_path.resolve()),
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "success": False,
            "status": "timeout",
            "threats_found": False,
            "message": f"Defender scan timed out after {timeout_sec}s.",
            "detail": "",
            "scanned_path": str(file_path),
        }
    except Exception as error:
        return {
            "available": True,
            "success": False,
            "status": "error",
            "threats_found": False,
            "message": f"Failed to run Defender scan: {error}",
            "detail": "",
            "scanned_path": str(file_path),
        }

    output = (completed.stdout or "") + (completed.stderr or "")
    output = output.strip()

    threats_found = completed.returncode == 2
    clean = completed.returncode == 0

    if clean:
        status = "clean"
        message = "No threats detected by Windows Defender."
    elif threats_found:
        status = "threat_detected"
        message = "Windows Defender reported a threat in this file."
    else:
        status = "unknown"
        message = f"Scan finished with exit code {completed.returncode}. Review detail below."

    return {
        "available": True,
        "success": clean or threats_found,
        "status": status,
        "threats_found": threats_found,
        "message": message,
        "detail": output,
        "exit_code": completed.returncode,
        "scanned_path": str(file_path.resolve()),
    }
