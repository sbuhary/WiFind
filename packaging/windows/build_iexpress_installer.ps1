param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot
)

$ErrorActionPreference = "Stop"

$DistDir = Join-Path $ProjectRoot "dist"
$InstallerDir = Join-Path $DistDir "installer"
$SedPath = Join-Path $InstallerDir "WiFind-IExpress.sed"
$OutputPath = Join-Path $InstallerDir "WiFind-Setup-IExpress.exe"
$SetupScript = Join-Path $ProjectRoot "packaging\windows\install_wifind.cmd"
$PortableExe = Join-Path $DistDir "WiFind.exe"

if (-not (Test-Path $PortableExe)) {
    throw "Portable executable not found at $PortableExe"
}

New-Item -ItemType Directory -Force -Path $InstallerDir | Out-Null

$escapedOutput = $OutputPath.Replace("\", "\\")
$escapedDist = $DistDir.Replace("\", "\\")
$escapedPackaging = (Split-Path -Parent $SetupScript).Replace("\", "\\")

$sed = @"
[Version]
Class=IEXPRESS
SEDVersion=3

[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=0
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=
DisplayLicense=
FinishMessage=WiFind installation has completed.
TargetName=$escapedOutput
FriendlyName=WiFind Setup
AppLaunched=install_wifind.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=install_wifind.cmd
UserQuietInstCmd=install_wifind.cmd
SourceFiles=SourceFiles

[SourceFiles]
SourceFiles0=$escapedDist
SourceFiles1=$escapedPackaging

[SourceFiles0]
WiFind.exe=

[SourceFiles1]
install_wifind.cmd=
"@

Set-Content -LiteralPath $SedPath -Value $sed -Encoding ASCII
& iexpress.exe /N $SedPath
if (-not (Test-Path $OutputPath)) {
    throw "IExpress did not create the expected installer at $OutputPath"
}

Write-Host "IExpress installer created at: $OutputPath"
