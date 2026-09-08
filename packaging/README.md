# Packaging WiFind

WiFind can be distributed to other Windows devices as either a portable administrator executable or a setup installer.

## Windows Prerequisites

- Python 3.10 or newer
- Npcap installed on the target machine: https://npcap.com/
- PowerShell
- Inno Setup if you want the preferred setup installer: https://jrsoftware.org/isinfo.php
- IExpress fallback is available on most Windows installations when Inno Setup is not installed.

## Build a Portable EXE

Run from the repository root:

```powershell
.\packaging\windows\build_windows.ps1
```

The portable executable will be created at:

```text
dist\WiFind.exe
```

Run it as Administrator. It starts the local WiFind server and opens the dashboard in the default browser.

## Build a Setup Installer

Run:

```powershell
.\packaging\windows\build_windows.ps1 -Installer
```

If Inno Setup is installed, the installer will be created in:

```text
dist\installer\
```

If Inno Setup is not installed, the build falls back to IExpress and creates:

```text
dist\installer\WiFind-Setup-IExpress.exe
```

## Distribution Notes

- The installer/executable does not bundle Npcap. Users must install Npcap separately because it is a packet capture driver.
- WiFind stores local aliases and device history under `%LOCALAPPDATA%\WiFind`.
- The app binds to `127.0.0.1:8765` and is intended to be used locally on the scanning machine.
