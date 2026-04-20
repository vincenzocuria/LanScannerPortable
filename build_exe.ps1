# Build LanScanner.exe — bundle: oui_vendor.zlib + app_icon.ico (icona finestra ed exe)
Set-Location $PSScriptRoot
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "Esempio: python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements-build.txt"
    exit 1
}
foreach ($f in @("oui_vendor.zlib","app_icon.ico")) {
    if (-not (Test-Path $f)) { Write-Host "Manca $f"; exit 1 }
}
Get-Process LanScanner -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
pyinstaller --onefile --windowed --name LanScanner --clean --noconfirm `
  --icon app_icon.ico `
  --add-data "oui_vendor.zlib;." `
  --add-data "app_icon.ico;." `
  scan_lan.py
Write-Host "Output: dist\LanScanner.exe"
