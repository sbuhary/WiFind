@echo off
setlocal

set "INSTALL_DIR=%ProgramFiles%\WiFind"
set "START_MENU=%ProgramData%\Microsoft\Windows\Start Menu\Programs"

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /Y "%~dp0WiFind.exe" "%INSTALL_DIR%\WiFind.exe" >nul

powershell -NoProfile -ExecutionPolicy Bypass -Command "$shell = New-Object -ComObject WScript.Shell; $shortcut = $shell.CreateShortcut('%START_MENU%\WiFind.lnk'); $shortcut.TargetPath = '%INSTALL_DIR%\WiFind.exe'; $shortcut.WorkingDirectory = '%INSTALL_DIR%'; $shortcut.Save()"

echo WiFind installed to %INSTALL_DIR%
start "" "%INSTALL_DIR%\WiFind.exe"
endlocal
