@echo off
rem Nightly session audit. Needs Python 3.14+ (compression.zstd) or zstd in PATH,
rem because DSH stores sessions as seekable zstd frames.
setlocal
set "PY="
py -3.14 -c "import compression.zstd" >nul 2>nul
if not errorlevel 1 set "PY=py -3.14"
if not defined PY if defined REDACTRAIL_REVIEW_PYTHON set "PY=%REDACTRAIL_REVIEW_PYTHON%"
if not defined PY (
  set "BUNDLED=%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"
  "%BUNDLED%" -c "import compression.zstd" >nul 2>nul
  if not errorlevel 1 set "PY=%BUNDLED%"
)
if not defined PY goto missing
pushd "%~dp0"
%PY% -m redactrail.review %*
set "CODE=%ERRORLEVEL%"
popd
exit /b %CODE%
:missing
echo Python 3.14+ (compression.zstd) or zstd in PATH not found. Set REDACTRAIL_REVIEW_PYTHON.
exit /b 2
