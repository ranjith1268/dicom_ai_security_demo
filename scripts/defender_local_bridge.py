#!/usr/bin/env python3
"""Run on the user's Windows PC — allows Streamlit (even on Streamlit Cloud) to trigger Defender."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from utils.defender_bridge import run_defender_bridge_server

if __name__ == "__main__":
    run_defender_bridge_server()
