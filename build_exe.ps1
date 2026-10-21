# Build LanScanner.exe: stessa procedura di build_exe.py (main.py + oui_vendor.zlib + icone, senza UPX)
Set-Location $PSScriptRoot
foreach ($f in @("oui_vendor.zlib", "app_icon.ico", "app_icon.png")) {
    if (-not (Test-Path $f)) { Write-Host "Manca $f"; exit 1 }
}
Get-Process LanScanner -ErrorAction SilentlyContinue | Stop-Process -Force
python build_exe.py
exit $LASTEXITCODE
