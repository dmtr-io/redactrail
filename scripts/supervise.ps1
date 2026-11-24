<#
Supervisor: держит прокси (8787) и админку (8788) запущенными.

Запускается планировщиком при входе в систему. Раз в 10 секунд проверяет порты и
поднимает то, что упало. Пишет короткий журнал в state/supervisor.log.
#>

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$logPath = Join-Path $root "state\supervisor.log"

function Write-Log([string]$Message) {
    try {
        $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$stamp $Message" | Out-File -FilePath $logPath -Append -Encoding utf8
    } catch {
        # журнал не должен ронять супервизор
    }
}

function Test-Port([int]$Port) {
    $connection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return [bool]$connection
}

function Start-Hidden([string]$File) {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $File -WorkingDirectory $root -WindowStyle Hidden
}

Write-Log "supervisor started (pid $PID)"
while ($true) {
    if (-not (Test-Port 8787)) {
        Start-Hidden "run.cmd"
        Write-Log "proxy: not listening, started"
    }
    if (-not (Test-Port 8788)) {
        Start-Hidden "admin.cmd"
        Write-Log "admin: not listening, started"
    }
    Start-Sleep -Seconds 10
}
