#Requires -Version 5.1
<#
.SYNOPSIS
Удаление redactrail, установленного install.ps1.

.DESCRIPTION
Снимает автозапуск, останавливает процессы прокси и админки, удаляет код.
По умолчанию сохраняет policy.json, state/ и audit/ — там ключ псевдонимов
и журналы. С -Purge удаляет каталог целиком.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File uninstall.ps1

.EXAMPLE
powershell -ExecutionPolicy Bypass -File uninstall.ps1 -Purge -Force
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "redactrail"),
    [switch]$Purge,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Note([string]$Text) {
    Write-Host "    $Text" -ForegroundColor DarkGray
}

if (-not (Test-Path $InstallDir)) {
    Write-Host "redactrail не найден: $InstallDir"
    exit 0
}

if (-not $Force) {
    $answer = Read-Host "Удалить redactrail из $InstallDir? [y/N]"
    if ($answer -notmatch "^(y|Y|д|Д)") {
        Write-Host "отменено"
        exit 0
    }
}

Write-Host ""
Write-Host "redactrail: удаление" -ForegroundColor Green

$autostart = Join-Path $InstallDir "scripts\uninstall-autostart.ps1"
if (Test-Path $autostart) {
    Write-Note "снимаю автозапуск"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $autostart | Out-Null
}

foreach ($listenPort in @(8787, 8788)) {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $listenPort } |
        ForEach-Object {
            try {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction Stop
                if ($process.ProcessName -match "python") {
                    Stop-Process -Id $_.OwningProcess -Force
        Write-Note "остановлен процесс $($process.Id)"
                }
            } catch { }
        }
}
Start-Sleep -Milliseconds 500

if ($Purge) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "удалено вместе с policy.json, state/ и audit/: $InstallDir"
} else {
    Get-ChildItem $InstallDir -Force |
        Where-Object { $_.Name -notin @("state", "audit", "policy.json") } |
        Remove-Item -Recurse -Force
    Write-Host "код удалён."
    Write-Note "сохранены: policy.json, state/, audit/ в $InstallDir"
    Write-Note "удалить и их: $PSCommandPath -Purge -Force -InstallDir `"$InstallDir`""
}
