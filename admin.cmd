@echo off
rem Launch the review admin UI. Prefers Python 3.14+ because the audit reads
rem DSH sessions compressed as seekable zstd frames (compression.zstd).
setlocal
set "PY="
py -3.14 -c "import compression.zstd" >nul 2>nul
if not errorlevel 1 set "PY=py -3.14"
if not defined PY if defined REDACTRAIL_ADMIN_PYTHON set "PY=%REDACTRAIL_ADMIN_PYTHON%"
if not defined PY (
  set "BUNDLED=%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"
  if exist "%BUNDLED%" set "PY=%BUNDLED%"
)
if not defined PY goto missing
pushd "%~dp0"
%PY% -m redactrail.admin --port 8788 %*
set "CODE=%ERRORLEVEL%"
popd
exit /b %CODE%
:missing
echo Python 3.12+ not found. Set REDACTRAIL_ADMIN_PYTHON.
exit /b 2
