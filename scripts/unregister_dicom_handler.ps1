# Remove DicomAutoOpen .dcm handler for current user.

$ErrorActionPreference = "Stop"
$progId = "DicomAutoOpen"

Remove-Item -LiteralPath "HKCU:\Software\Classes\.dcm" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "HKCU:\Software\Classes\$progId" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removed per-user DicomAutoOpen registration." -ForegroundColor Green
Write-Host "Double-click .dcm will no longer run the demo script."
