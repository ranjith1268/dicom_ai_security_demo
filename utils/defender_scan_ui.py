"""Streamlit widget that calls the local Defender bridge from the user's browser."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import streamlit.components.v1 as components

from utils.defender_bridge import bridge_base_url
from utils.defender_scan import STEGO_ENTERPRISE_URL


def render_client_defender_scan(file_path: str, widget_key: str) -> None:
    """Run Defender on the user's Windows PC via localhost bridge (browser fetch)."""
    path_json = json.dumps(file_path)
    bridge = bridge_base_url()
    stego = STEGO_ENTERPRISE_URL

    html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;margin:0;padding:8px;">
<div id="status">Calling Windows Defender on your PC…</div>
<pre id="detail" style="background:#f4f4f4;padding:8px;font-size:12px;white-space:pre-wrap;margin-top:8px;"></pre>
<p id="stego" style="margin-top:8px;display:none;">
  <a id="stego-link" href="{stego}" target="_blank" rel="noopener">Open StegoEnterprise portal →</a>
</p>
<script>
(async () => {{
  const status = document.getElementById("status");
  const detail = document.getElementById("detail");
  const stego = document.getElementById("stego");
  const path = {path_json};
  const bridge = {json.dumps(bridge)};

  try {{
    const health = await fetch(bridge + "/health", {{ method: "GET", mode: "cors" }});
    if (!health.ok) throw new Error("Bridge health check failed");

    const resp = await fetch(bridge + "/scan", {{
      method: "POST",
      mode: "cors",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ path: path }}),
    }});
    const data = await resp.json();

    let color = "#a60";
    if (data.status === "clean") color = "#0a7";
    if (data.threats_found) color = "#c00";

    status.innerHTML = '<strong style="color:' + color + '">' + (data.message || "Scan finished") + "</strong>";
    if (data.scanned_path) {{
      status.innerHTML += "<br><span style='font-size:13px'>Scanned: <code>" + data.scanned_path + "</code></span>";
    }}
    detail.textContent = data.detail || "";
  }} catch (err) {{
    status.innerHTML = (
      '<strong style="color:#c00">Could not reach the Defender bridge on this PC.</strong><br>' +
      '<span style="font-size:13px">On your Windows machine, run once per session:<br>' +
      '<code>python scripts/defender_local_bridge.py</code><br>' +
      'or <code>scripts\\\\start_defender_bridge.ps1</code></span>'
    );
    detail.textContent = String(err);
  }}
  stego.style.display = "block";
}})();
</script>
</body>
</html>
"""
    components.html(html, height=260, scrolling=True, key=widget_key)


def bridge_scan_result_from_session(session: Dict[str, Any], out_name: str) -> Optional[str]:
    return session.get(f"cf_bridge_scan_path_{out_name}")
