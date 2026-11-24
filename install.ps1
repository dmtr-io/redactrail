#Requires -Version 5.1
<#
.SYNOPSIS
Установка redactrail: локальный прокси-маскировщик для DeepSeek Harness.

.DESCRIPTION
Скачивает релиз с GitHub, распаковывает в каталог пользователя, создаёт policy.json
из примера, при необходимости ставит Python 3.12+, запускает прокси и админку.
Права администратора не нужны: всё ставится в профиль текущего пользователя.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File install.ps1

.EXAMPLE
powershell -ExecutionPolicy Bypass -File install.ps1 -Autostart

.EXAMPLE
powershell -ExecutionPolicy Bypass -File install.ps1 -SourcePath .\dist\redactrail-0.1.0.zip -NoStart
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "redactrail"),
    [int]$Port = 8787,
    [switch]$Autostart,
    [switch]$NoPython,
    [switch]$NoStart,
    [string]$SourcePath = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Repo = "dmtr-io/redactrail"
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

function Write-Step([string]$Text) {
    Write-Host ""
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Write-Note([string]$Text) {
    Write-Host "    $Text" -ForegroundColor DarkGray
}

function Fail([string]$Text) {
    Write-Host ""
    Write-Host "ОШИБКА: $Text" -ForegroundColor Red
    exit 1
}

function Get-Python {
    $attempts = @()
    if ($env:REDACTRAIL_PYTHON) {
        $attempts += ,@{ Exe = $env:REDACTRAIL_PYTHON; Args = @() }
    }
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        $attempts += ,@{ Exe = $launcher.Source; Args = @("-3.12") }
        $attempts += ,@{ Exe = $launcher.Source; Args = @("-3") }
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        $attempts += ,@{ Exe = $python.Source; Args = @() }
    }

    foreach ($attempt in $attempts) {
        $baseArgs = @($attempt.Args)
        try {
            $output = @(& $attempt.Exe @baseArgs -c "import sys; print(sys.version_info[0]*100+sys.version_info[1]); print(sys.executable)" 2>$null)
        } catch {
            continue
        }
        $lines = @($output | Where-Object { "$_" -ne "" })
        if ($lines.Count -lt 2) { continue }
        $number = 0
        if (-not [int]::TryParse(([string]$lines[0]).Trim(), [ref]$number)) { continue }
        if ($number -lt 312) { continue }
        $exe = ([string]$lines[1]).Trim()
        if (-not (Test-Path $exe)) { continue }
        return @{ Exe = $exe; Version = $number }
    }
    return $null
}

function Install-Python {
    Write-Step "Python 3.12+ не найден — устанавливаю"
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Note "пробую winget (для текущего пользователя)"
        & winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements 2>$null | Out-Null
        $found = Get-Python
        if ($found) { return $found }
    }

    $installer = Join-Path $env:TEMP "redactrail-python-3.12.10-amd64.exe"
    $url = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"
    Write-Note "скачиваю установщик: $url"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $installer
    Write-Note "ставлю Python без прав администратора"
    $process = Start-Process -FilePath $installer -Wait -PassThru -ArgumentList @(
        "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0",
        "Include_launcher=1", "InstallLauncherAllUsers=0"
    )
    if ($process.ExitCode -ne 0) {
        Fail "установщик Python завершился с кодом $($process.ExitCode)"
    }
    $env:Path = "$env:Path;$env:LOCALAPPDATA\Programs\Python\Python312;$env:LOCALAPPDATA\Programs\Python\Python312\Scripts"
    $found = Get-Python
    if (-not $found) {
        Fail "Python установлен, но не найден. Перезапусти PowerShell и повтори команду."
    }
    return $found
}

function Get-LatestVersion {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ "User-Agent" = "redactrail-installer" }
        return ([string]$release.tag_name).TrimStart("v")
    } catch {
        Fail "не удалось узнать последнюю версию. Укажи -Version или -SourcePath."
    }
}

function Get-Package([string]$Version) {
    if ($SourcePath) {
        $resolved = (Resolve-Path $SourcePath -ErrorAction SilentlyContinue)
        if (-not $resolved) { Fail "нет файла или папки: $SourcePath" }
        return $resolved.Path
    }

    $zip = Join-Path $env:TEMP "redactrail-$Version.zip"
    $url = "https://github.com/$Repo/releases/download/v$Version/redactrail-$Version.zip"
    $sumsUrl = "https://github.com/$Repo/releases/download/v$Version/SHA256SUMS"
    Write-Note "скачиваю $url"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
        $sumsFile = "$zip.sha256"
        Invoke-WebRequest -UseBasicParsing -Uri $sumsUrl -OutFile $sumsFile
        $expected = ((Get-Content $sumsFile -TotalCount 1) -split "\s+")[0].ToLowerInvariant()
        $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
        if ($expected -ne $actual) {
            Fail "контрольная сумма архива не совпала. Файл повреждён или подменён."
        }
        Write-Note "контрольная сумма совпала"
    } catch {
        Fail "не удалось скачать релиз. Если репозиторий приватный — используй -SourcePath <zip>."
    }
    return $zip
}

function Install-Tree([string]$Package, [string]$Target) {
    $temp = Join-Path $env:TEMP ("redactrail-install-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        $sourceRoot = $null
        $item = Get-Item $Package
        if ($item.PSIsContainer) {
            $sourceRoot = $item.FullName
        } else {
            Expand-Archive -Path $item.FullName -DestinationPath $temp -Force
            $top = @(Get-ChildItem $temp -Directory)
            if ($top.Count -ne 1) { Fail "в архиве должен быть один каталог верхнего уровня" }
            $sourceRoot = $top[0].FullName
        }
        New-Item -ItemType Directory -Path $Target -Force | Out-Null
        Get-ChildItem $sourceRoot -Force | Copy-Item -Destination $Target -Recurse -Force
    } finally {
        Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-Data([string]$Target) {
    New-Item -ItemType Directory -Path (Join-Path $Target "state") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $Target "audit") -Force | Out-Null
    $policy = Join-Path $Target "policy.json"
    if (Test-Path $policy) {
        Write-Note "policy.json уже есть — не трогаю"
        return
    }
    $example = Join-Path $Target "policy.example.json"
    if (-not (Test-Path $example)) { Fail "в архиве нет policy.example.json" }
    Copy-Item $example $policy
    Write-Note "создан policy.json из примера"
}

function Stop-Existing([int]$ProxyPort) {
    foreach ($listenPort in @($ProxyPort, ($ProxyPort + 1))) {
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $listenPort } |
            ForEach-Object {
                try {
                    $process = Get-Process -Id $_.OwningProcess -ErrorAction Stop
                    if ($process.ProcessName -match "python") {
                        Stop-Process -Id $_.OwningProcess -Force
                    }
                } catch { }
            }
    }
    Start-Sleep -Milliseconds 500
}

function Start-Redactrail([string]$PythonExe, [string]$Target, [int]$ProxyPort) {
    $Target = [System.IO.Path]::GetFullPath($Target)
    $windowless = Join-Path (Split-Path -Parent $PythonExe) "pythonw.exe"
    $exe = if (Test-Path $windowless) { $windowless } else { $PythonExe }
    $arguments = @(
        "-m", "redactrail.app",
        "--root", $Target,
        "--proxy-port", "$ProxyPort",
        "--admin-port", "$($ProxyPort + 1)"
    )
    Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $Target -WindowStyle Hidden
    $url = "http://127.0.0.1:$ProxyPort/health"
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        Start-Sleep -Milliseconds 500
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return $true }
        } catch { }
    }
    return $false
}

function Open-Admin([string]$Target, [int]$ProxyPort) {
    $urlFile = Join-Path $Target "state\admin-url.txt"
    if (Test-Path $urlFile) {
        $url = (Get-Content $urlFile -Raw).Trim()
        if ($url) { Start-Process $url; return }
    }
    Start-Process "http://127.0.0.1:$($ProxyPort + 1)/"
}

Write-Host ""
Write-Host "redactrail: установка" -ForegroundColor Green
Write-Note "каталог: $InstallDir"

$python = Get-Python
if ($python) {
    Write-Note ("Python {0}: {1}" -f $python.Version, $python.Exe)
} elseif ($NoPython) {
    Fail "Python 3.12+ не найден, а -NoPython запрещает установку. Поставь Python и повтори."
} else {
    $python = Install-Python
}

if (-not $Version) {
    if ($SourcePath) {
        $Version = "local"
    } else {
        $Version = Get-LatestVersion
    }
}
Write-Note "версия: $Version"

$package = Get-Package $Version
Install-Tree $package $InstallDir
Initialize-Data $InstallDir
Write-Note "файлы установлены"

if (-not $NoStart) {
    Stop-Existing $Port
    if (-not (Start-Redactrail $python.Exe $InstallDir $Port)) {
        Get-Content (Join-Path $InstallDir "state\app.log") -Tail 5 -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Note $_ }
        Get-Content (Join-Path $InstallDir "state\admin.log") -Tail 5 -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Note $_ }
        Get-Content (Join-Path $InstallDir "state\proxy.log") -Tail 5 -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Note $_ }
        Fail "прокси не ответил на /health. Смотри $InstallDir\state\app.log"
    }
    Write-Note "прокси отвечает: http://127.0.0.1:$Port/health"
}

if ($Autostart) {
    $autostart = Join-Path $InstallDir "scripts\install-autostart.ps1"
    if (-not (Test-Path $autostart)) { Fail "в архиве нет scripts\install-autostart.ps1" }
    Write-Step "включаю автозапуск"
    $env:REDACTRAIL_PYTHON = $python.Exe
    & powershell -NoProfile -ExecutionPolicy Bypass -File $autostart
    if ($LASTEXITCODE -ne 0) { Fail "не удалось включить автозапуск" }
    Write-Note "задачи redactrail и redactrail-audit зарегистрированы"
}

if (-not $NoStart) {
    Open-Admin $InstallDir $Port
}

Write-Host ""
Write-Host "Готово." -ForegroundColor Green
Write-Note "каталог: $InstallDir"
Write-Note "админка: http://127.0.0.1:$($Port + 1)/"
Write-Note "в DSH укажи baseURL: http://127.0.0.1:$Port"
Write-Note "остановить: scripts\uninstall-autostart.ps1 (если включён автозапуск) или закрой процесс pythonw"
Write-Note "удалить: powershell -ExecutionPolicy Bypass -File uninstall.ps1 -InstallDir `"$InstallDir`""
