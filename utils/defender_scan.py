"""Windows Defender custom file scan helper (local demo only)."""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional


def _mpcmdrun_path() -> Optional[Path]:
    candidates = [
        Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe"),
        Path(r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe"),
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def scan_with_defender(file_path: Path, timeout_sec: int = 120) -> Dict[str, Any]:
    """Run a Windows Defender custom scan on a single file.

    Returns a dict with keys: available, success, status, threats_found, message, detail.
    """
    file_path = file_path.resolve()
    if not file_path.is_file():
        return {
            "available": False,
            "success": False,
            "status": "error",
            "threats_found": False,
            "message": f"File not found: {file_path}",
            "detail": "",
        }

    if platform.system() != "Windows":
        return {
            "available": False,
            "success": False,
            "status": "unsupported",
            "threats_found": False,
            "message": "Windows Defender scan is only available when running on Windows.",
            "detail": "",
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
        }

    cmd = [
        str(mpcmd),
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(file_path),
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
        }
    except Exception as error:
        return {
            "available": True,
            "success": False,
            "status": "error",
            "threats_found": False,
            "message": f"Failed to run Defender scan: {error}",
            "detail": "",
        }

    output = (completed.stdout or "") + (completed.stderr or "")
    output = output.strip()

    # MpCmdRun exit codes: 0 = clean, 2 = threats found (common on Windows Defender)
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
        "scanned_path": str(file_path),
    }
