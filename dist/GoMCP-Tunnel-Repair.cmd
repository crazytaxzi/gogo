@echo off
setlocal EnableExtensions
title GoMCP Tunnel Repair
color 0A
mode con cols=100 lines=32 >nul 2>&1
cls
echo.
echo ================================================================================================
echo                              GOMCP TUNNEL REPAIR
echo ================================================================================================
echo.
echo   Please leave this window open.
echo   Windows may ask for permission. Click YES.
echo.
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "REPAIR=%TEMP%\Repair-GoMCP-Tunnel.ps1"
echo Downloading the validated repair script from GitHub...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/crazytaxzi/gogo/main/install/Repair-GoMCP-Tunnel.ps1' -OutFile '%REPAIR%'"
if errorlevel 1 goto DOWNLOADFAIL
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%REPAIR%"
exit /b %errorlevel%
:DOWNLOADFAIL
color 4F
echo.
echo ================================================================================================
echo                              REPAIR DOWNLOAD FAILED
echo ================================================================================================
echo.
echo   Leave this window open and send Senti a picture of it.
echo.
pause
exit /b 1
