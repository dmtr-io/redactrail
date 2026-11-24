<#
Снимает автозапуск redactrail.

    powershell -ExecutionPolicy Bypass -File scripts\uninstall-autostart.ps1
#>

$ErrorActionPreference = "Continue"
foreach ($name in @('redactrail', 'redactrail-supervisor', 'redactrail-audit', 'privacy-proxy', 'privacy-proxy-supervisor', 'privacy-proxy-audit')) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        Write-Host "задача $name удалена"
    } else {
        Write-Host "задачи $name нет"
    }
}
