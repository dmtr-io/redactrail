# Локальный шлюз качества: прогон unit-тестов перед MR.
# GitLab Runner в этом инстансе нет, поэтому тесты запускаются здесь.
# Файл сохранён в UTF-8 с BOM: Windows PowerShell 5.1 иначе читает кириллицу как ANSI.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# Кандидаты в порядке предпочтения: явная настройка, бандл DSH, затем PATH.
# В PATH на этой машине стоит заглушка Microsoft Store, которая не запускается,
# поэтому кандидат проверяется запуском, а не только наличием файла.
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
    Write-Error 'Python 3.12+ не найден. Задайте REDACTRAIL_PYTHON.'
    exit 2
}

$tests = Join-Path $root 'tests'
if (-not (Test-Path $tests)) {
    Write-Host 'Тестов пока нет — прогон пропущен.'
    exit 0
}

Write-Host "Python: $python"
Push-Location $root
try {
    & $python -m unittest discover -s tests -t . -v
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        & $python 'scripts\bench_detectors.py' --corpus 'tests\corpus\pii_bench.jsonl' --gate
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'Бенчмарк детекторов ниже порогов.' -ForegroundColor Red
            $code = $LASTEXITCODE
        }
    }
}
finally {
    Pop-Location
}

if ($code -ne 0) {
    Write-Host "Тесты упали (exit $code)." -ForegroundColor Red
}
exit $code
