@echo off
rem Launch the privacy proxy with a real Python 3.12+.
rem PowerShell execution policy does not apply to batch files, so this works
rem in shells that refuse unsigned .ps1 scripts.
setlocal
set "PY=%REDACTRAIL_PYTHON%"
if not defined PY set "PY=%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"
if exist "%PY%" goto check
for %%i in (python.exe) do set "PY=%%~$PATH:i"
:check
if not exist "%PY%" goto missing
"%PY%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 3)" >nul 2>nul
if errorlevel 1 goto missing
pushd "%~dp0"
"%PY%" -m redactrail.proxy --port 8787 --upstream https://api.deepseek.com %*
set "CODE=%ERRORLEVEL%"
popd
exit /b %CODE%
:missing
echo Python 3.12+ not found. Set REDACTRAIL_PYTHON or install Python.
exit /b 2
