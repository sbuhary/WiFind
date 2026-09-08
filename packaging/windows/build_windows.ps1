param(
    [switch]$Installer
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $ProjectRoot

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

& ".\.venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt -r requirements-build.txt
& ".\.venv\Scripts\pyinstaller.exe" --clean --noconfirm "packaging\windows\WiFind.spec"
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

Write-Host "Portable executable created at: $ProjectRoot\dist\WiFind.exe"

if ($Installer) {
    $iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if ($iscc) {
        & $iscc.Source "packaging\windows\WiFind.iss"
        if ($LASTEXITCODE -ne 0) {
            throw "Inno Setup failed with exit code $LASTEXITCODE"
        }
        Write-Host "Installer created in: $ProjectRoot\dist\installer"
    } else {
        Write-Host "Inno Setup was not found. Falling back to Windows IExpress."
        & powershell -ExecutionPolicy Bypass -File "packaging\windows\build_iexpress_installer.ps1" -ProjectRoot $ProjectRoot
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "IExpress fallback failed with exit code $LASTEXITCODE"
        }
    }
}
