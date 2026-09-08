param(
    [switch]$Installer
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $ProjectRoot

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt -r requirements-build.txt
& ".\.venv\Scripts\pyinstaller.exe" --clean --noconfirm "packaging\windows\WiFind.spec"

Write-Host "Portable executable created at: $ProjectRoot\dist\WiFind.exe"

if ($Installer) {
    $iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if (-not $iscc) {
        Write-Host "Inno Setup was not found. Install it from https://jrsoftware.org/isinfo.php to build the setup installer."
        exit 0
    }

    & $iscc.Source "packaging\windows\WiFind.iss"
    Write-Host "Installer created in: $ProjectRoot\dist\installer"
}
