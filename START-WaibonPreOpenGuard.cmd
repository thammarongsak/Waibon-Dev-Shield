@echo off
setlocal
cd /d "%~dp0"
if not exist "scripts\Waibon-DevShield-Guard.ps1" (
  echo [ERROR] This launcher must be run from the extracted project folder.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Waibon-DevShield-Guard.ps1"
pause
