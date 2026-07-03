# Register DicomAutoOpen — double-click .dcm runs the hidden embedded script (demo only).
# No Administrator required (uses current-user registry).
#
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\scripts\register_dicom_handler.ps1

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$handler = Join-Path $scriptDir "open_embedded_dicom.py"

if (-not (Test-Path $handler)) {
    Write-Host "ERROR: Handler not found: $handler" -ForegroundColor Red
    exit 1
}

$python = (Get-Command python -ErrorAction Stop).Source
$pythonw = Join-Path (Split-Path -Parent $python) "pythonw.exe"
if (Test-Path $pythonw) {
    $python = $pythonw
}
$command = "`"$python`" `"$handler`" `"%1`""
$progId = "DicomAutoOpen"

# Per-user registration (HKCU) — works without Administrator
New-Item -Path "HKCU:\Software\Classes\$progId\shell\open\command" -Force | Out-Null
Set-ItemProperty -LiteralPath "HKCU:\Software\Classes\$progId\shell\open\command" -Name "(default)" -Value $command
New-Item -Path "HKCU:\Software\Classes\.dcm" -Force | Out-Null
Set-ItemProperty -LiteralPath "HKCU:\Software\Classes\.dcm" -Name "(default)" -Value $progId

# Optional system-wide registration when running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    cmd /c "assoc .dcm=$progId" | Out-Null
    cmd /c "ftype $progId=$command" | Out-Null
    Write-Host "Also registered system-wide (assoc/ftype)." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "DicomAutoOpen registered for your user account." -ForegroundColor Green
Write-Host "  Python:  $python"
Write-Host "  Handler: $handler"
Write-Host ""
Write-Host "Double-click any embedded .dcm to run its hidden PowerShell script."
Write-Host "No DICOM viewer required."
Write-Host ""
Write-Host "To undo: .\scripts\unregister_dicom_handler.ps1"
