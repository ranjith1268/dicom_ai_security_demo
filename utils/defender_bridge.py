"""Local HTTP bridge — lets a remote Streamlit UI trigger Defender on the user's Windows PC."""

from __future__ import annotations

import html
import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from utils.defender_scan import STEGO_ENTERPRISE_URL, scan_with_defender

DEFENDER_BRIDGE_HOST = "127.0.0.1"
DEFENDER_BRIDGE_PORT = 8765

_BRIDGE_THREAD: Optional[threading.Thread] = None
_BRIDGE_STARTED = False


def bridge_base_url() -> str:
    return f"http://{DEFENDER_BRIDGE_HOST}:{DEFENDER_BRIDGE_PORT}"


def is_bridge_port_open() -> bool:
    try:
        with socket.create_connection((DEFENDER_BRIDGE_HOST, DEFENDER_BRIDGE_PORT), timeout=0.4):
            return True
    except OSError:
        return False


def _bridge_script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "defender_local_bridge.py"


def start_defender_bridge_background() -> bool:
    """Start the local bridge in a background process (Windows only)."""
    global _BRIDGE_STARTED
    if sys.platform != "win32":
        return False
    if is_bridge_port_open():
        _BRIDGE_STARTED = True
        return True

    script = _bridge_script_path()
    if not script.is_file():
        return False

    flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
    subprocess.Popen(
        [sys.executable, str(script)],
        creationflags=flags,
        close_fds=True,
    )
    _BRIDGE_STARTED = True
    return True


def _cors_headers(handler: BaseHTTPRequestHandler) -> None:
    origin = handler.headers.get("Origin", "*")
    handler.send_header("Access-Control-Allow-Origin", origin)
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.send_header("Access-Control-Max-Age", "86400")


def _render_result_html(result: Dict[str, Any]) -> str:
    status = result.get("status", "unknown")
    message = html.escape(str(result.get("message", "")))
    detail = html.escape(str(result.get("detail", "")))
    scanned = html.escape(str(result.get("scanned_path", "")))
    color = {"clean": "#0a7", "threat_detected": "#c00"}.get(status, "#a60")
    stego = html.escape(STEGO_ENTERPRISE_URL)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Defender Scan</title></head>
<body style="font-family:Segoe UI,sans-serif;padding:12px;margin:0;">
<h3 style="color:{color};margin:0 0 8px;">{message}</h3>
<p style="margin:0 0 8px;font-size:13px;">Scanned: <code>{scanned}</code></p>
<pre style="background:#f4f4f4;padding:8px;font-size:12px;white-space:pre-wrap;">{detail}</pre>
<p style="margin-top:12px;"><a href="{stego}" target="_blank">Open StegoEnterprise portal →</a></p>
</body></html>"""


class DefenderBridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        _cors_headers(self)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            body = json.dumps({"ok": True, "service": "defender_local_bridge"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            _cors_headers(self)
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/scan":
            params = parse_qs(parsed.query)
            file_path = (params.get("path") or [""])[0]
            wants_json = (params.get("format") or [""])[0].lower() == "json"
            result = scan_with_defender(Path(file_path))
            if wants_json:
                payload = json.dumps(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                _cors_headers(self)
                self.end_headers()
                self.wfile.write(payload)
            else:
                page = _render_result_html(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                _cors_headers(self)
                self.end_headers()
                self.wfile.write(page)
            return

        self.send_response(404)
        _cors_headers(self)
        self.end_headers()

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/scan":
            self.send_response(404)
            _cors_headers(self)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            data = {}
        file_path = str(data.get("path", ""))
        result = scan_with_defender(Path(file_path))
        payload = json.dumps(result).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        _cors_headers(self)
        self.end_headers()
        self.wfile.write(payload)


def run_defender_bridge_server() -> None:
    if sys.platform != "win32":
        print("Defender local bridge only runs on Windows.", file=sys.stderr)
        raise SystemExit(1)

    server = ThreadingHTTPServer((DEFENDER_BRIDGE_HOST, DEFENDER_BRIDGE_PORT), DefenderBridgeHandler)
    print(f"Defender local bridge listening on {bridge_base_url()}")
    print("Keep this window open while using Scan with Windows Defender in Streamlit.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBridge stopped.")


def try_start_defender_bridge_background() -> bool:
    """Idempotent — safe to call from Streamlit app startup on Windows."""
    if sys.platform != "win32":
        return False
    return start_defender_bridge_background()
