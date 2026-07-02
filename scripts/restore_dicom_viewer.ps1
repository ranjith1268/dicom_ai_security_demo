# Restore the .dcm association saved before DicomAutoOpen registration.
# Run as Administrator.

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$fallbackFile = Join-Path $scriptDir "dicom_viewer_fallback.txt"

if (-not (Test-Path $fallbackFile)) {
    Write-Host "No fallback file found. Associate .dcm manually in Windows Settings." -ForegroundColor Yellow
    exit 1
}

$content = Get-Content $fallbackFile -Raw
if ($content -match "assoc:\s*\.dcm=([^\r\n]+)") {
    $progId = $Matches[1].Trim()
    if ($content -match "ftype:\s*([^\r\n]+)") {
        $ftypeLine = $Matches[1].Trim()
        if ($ftypeLine -match "^$progId=(.+)$") {
            cmd /c "assoc .dcm=$progId"
            cmd /c "ftype $ftypeLine"
            Write-Host "Restored: $progId" -ForegroundColor Green
            exit 0
        }
    }
    cmd /c "assoc .dcm=$progId"
    Write-Host "Restored assoc: $progId (ftype may need manual fix)" -ForegroundColor Yellow
    exit 0
}

Write-Host "Could not parse fallback. Open Windows Settings > Apps > Default apps > .dcm" -ForegroundColor Yellow
