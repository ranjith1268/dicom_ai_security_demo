# Start the local Defender bridge (run once per session on your Windows PC).
# Required when using Streamlit Cloud / remote hosting so "Scan with Windows Defender" works.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$bridge = Join-Path $root "defender_local_bridge.py"

if (-not (Test-Path $bridge)) {
    Write-Host "ERROR: $bridge not found" -ForegroundColor Red
    exit 1
}

$python = (Get-Command python -ErrorAction Stop).Source
Write-Host "Starting Defender local bridge on http://127.0.0.1:8765 ..." -ForegroundColor Cyan
Write-Host "Keep this window open while using the Streamlit app." -ForegroundColor DarkGray
& $python $bridge
