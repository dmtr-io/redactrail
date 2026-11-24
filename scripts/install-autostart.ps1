<#
Регистрирует автозапуск единого приложения redactrail (прокси + админка).

    powershell -ExecutionPolicy Bypass -File scripts\install-autostart.ps1
    powershell -ExecutionPolicy Bypass -File scripts\install-autostart.ps1 -AuditTime "04:30"
    powershell -ExecutionPolicy Bypass -File scripts\install-autostart.ps1 -NoAudit

Приложение запускается через pythonw.exe: без консольного окна и без браузера.
Браузер открывается только вручную — http://127.0.0.1:8788/
#>

param(
    [string]$AuditTime = "03:00",
    [switch]$NoAudit
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# Ищем python.exe, рядом с ним — pythonw.exe (без окна).
$candidates = @()
if ($env:REDACTRAIL_PYTHON) { $candidates += $env:REDACTRAIL_PYTHON }
$candidates += (Join-Path $env:USERPROFILE '.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe')
$onPath = Get-Command python -ErrorAction SilentlyContinue
if ($onPath) { $candidates += $onPath.Source }

$pythonw = $null
$python = $null
foreach ($candidate in $candidates) {
    if (-not (Test-Path $candidate)) { continue }
    $windowless = Join-Path (Split-Path -Parent $candidate) 'pythonw.exe'
    if (Test-Path $windowless) { $pythonw = $windowless; $python = $candidate; break }
}

if (-not $pythonw) {
    # Нет pythonw — запускаем python.exe, окно скроет планировщик.
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { $python = $candidate; $pythonw = $candidate; break }
    }
}
if (-not $pythonw) {
    Write-Error 'Python 3.12+ не найден. Задайте REDACTRAIL_PYTHON.'
    exit 2
}

# Совместимость с прежним именем: убираем старые задачи автозапуска.
foreach ($legacy in @('redactrail-supervisor', 'privacy-proxy', 'privacy-proxy-supervisor', 'privacy-proxy-audit')) {
    $old = Get-ScheduledTask -TaskName $legacy -ErrorAction SilentlyContinue
    if ($null -ne $old) {
        Unregister-ScheduledTask -TaskName $legacy -Confirm:$false
        Write-Host "старая задача $legacy удалена"
    }
}

$taskName = 'redactrail'
$action = New-ScheduledTaskAction `
    -Execute $pythonw `
    -Argument "-m redactrail.app --root `"$root`"" `
    -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description 'redactrail: прокси и админка одним процессом, без окон и браузера' `
    -Force | Out-Null

Write-Host "задача $taskName зарегистрирована (запуск при входе)"
Write-Host "запустить сейчас: Start-ScheduledTask -TaskName $taskName"
Write-Host "админка: http://127.0.0.1:8788/"

if (-not $NoAudit) {
    $auditName = 'redactrail-audit'
    $auditAction = New-ScheduledTaskAction `
        -Execute 'cmd.exe' `
        -Argument "/c `"$root\review.cmd`" --days 1 --limit 50" `
        -WorkingDirectory $root
    $auditTrigger = New-ScheduledTaskTrigger -Daily -At $AuditTime
    $auditSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Hours 4)
    Register-ScheduledTask `
        -TaskName $auditName `
        -Action $auditAction `
        -Trigger $auditTrigger `
        -Settings $auditSettings `
        -Description 'redactrail: ночной аудит сессий локальной моделью' `
        -Force | Out-Null
    Write-Host "задача $auditName зарегистрирована (каждый день в $AuditTime)"
}
