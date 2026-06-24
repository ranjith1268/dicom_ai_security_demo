#!/usr/bin/env python3
"""Launch the combined DICOM security demo (includes Payload Embedder tab)."""

import subprocess
import sys
from pathlib import Path


def main() -> None:
    app_dir = Path(__file__).resolve().parents[1]
    app_path = app_dir / "app.py"
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app_path), "--server.headless", "true"],
        cwd=str(app_dir),
        check=False,
    )


if __name__ == "__main__":
    main()
