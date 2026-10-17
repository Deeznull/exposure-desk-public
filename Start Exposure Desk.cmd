@echo off
setlocal
title Exposure Desk - local launch
if exist "%~dp0runtime\node.exe" (
  "%~dp0runtime\node.exe" "%~dp0scripts\launch.mjs"
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\bootstrap.ps1"
)
if errorlevel 1 (
  echo Startup failed. Read the message above. No administrator setup is required.
  pause
)
endlocal
