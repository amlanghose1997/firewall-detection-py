@echo off
REM pifw - One-click setup for Windows
REM Double-click this file or run from Command Prompt
REM For more options, use PowerShell: .\setup.ps1 help

echo.
echo   pifw - Prompt Injection Firewall Setup
echo   =======================================
echo.

REM Check if PowerShell is available
where pwsh >nul 2>&1
if %ERRORLEVEL% equ 0 (
    pwsh -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
) else (
    powershell -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
)

if %ERRORLEVEL% neq 0 (
    echo.
    echo Setup failed! Check the output above for errors.
    echo.
)

pause
