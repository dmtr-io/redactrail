# Запуск прокси одной командой: находит настоящий Python 3.12+ и стартует redactrail.proxy.
# В PATH на этой машине стоит заглушка Microsoft Store, поэтому кандидат проверяется
# запуском, а не только наличием файла.
#
#   .\run.ps1                      # 127.0.0.1:8787, strict, api.deepseek.com
#   .\run.ps1 -Port 8788 -Mode audit
#   .\run.ps1 -Upstream https://api.deepseek.com

param(
    [int]$Port = 8787,
    [string]$Upstream = "https://api.deepseek.com",
    [ValidateSet("strict", "audit", "off")]
    [string]$Mode = "strict"
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$candidates = @()
if ($env:REDACTRAIL_PYTHON) { $candidates += $env:REDACTRAIL_PYTHON }
$candidates += (Join-Path $env:USERPROFILE '.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe')
$onPath = Get-Command python -ErrorAction SilentlyContinue
if ($onPath) { $candidates += $onPath.Source }

$python = $null
foreach ($candidate in $candidates) {
    if (-not (Test-Path $candidate)) { continue }
    $version = & $candidate --version 2>&1
    if ($LASTEXITCODE -ne 0) { continue }
    if ($version -notmatch 'Python (\d+)\.(\d+)') { continue }
    $major = [int]$Matches[1]
    $minor = [int]$Matches[2]
    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 12)) { continue }
    $python = $candidate
    break
}

if (-not $python) {
    Write-Error 'Python 3.12+ не найден. Задайте REDACTRAIL_PYTHON или установите Python.'
    exit 2
}

Write-Host "Python: $python"
Push-Location $root
try {
    & $python -m redactrail.proxy --port $Port --upstream $Upstream --mode $Mode
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
