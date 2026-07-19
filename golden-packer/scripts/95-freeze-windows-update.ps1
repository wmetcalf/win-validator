$ErrorActionPreference = 'SilentlyContinue'
# Freeze Windows Update in the DEPLOYED image. This is the LAST provisioner: everything above has
# already patched the golden, so from here the image must be frozen — a disposable analysis worker
# has to be deterministic and must not self-patch or phone home to WU mid-job. Patching happens at
# golden REBUILD time, not at runtime.

# Policy: never auto-update, never reach out to WU internet locations.
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $au -Force | Out-Null
Set-ItemProperty -Path $au -Name NoAutoUpdate -Value 1 -Type DWord
Set-ItemProperty -Path $au -Name AUOptions   -Value 1 -Type DWord     # 1 = never check
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
New-Item -Path $wu -Force | Out-Null
Set-ItemProperty -Path $wu -Name DoNotConnectToWindowsUpdateInternetLocations -Value 1 -Type DWord

# Stop + hard-disable the update services. Set Start=4 in the registry as well as Set-Service, because
# WaaSMedicSvc (the "self-heal" service that re-enables Windows Update) resists Set-Service.
foreach ($svc in 'wuauserv','UsoSvc','WaaSMedicSvc') {
    Stop-Service $svc -Force -ErrorAction SilentlyContinue
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
    if (Test-Path $k) { Set-ItemProperty -Path $k -Name Start -Value 4 -Type DWord -ErrorAction SilentlyContinue }
}

# Disable the update-related scheduled tasks (Orchestrator / WaaSMedic scans).
foreach ($tp in '\Microsoft\Windows\WindowsUpdate\','\Microsoft\Windows\UpdateOrchestrator\','\Microsoft\Windows\WaaSMedic\') {
    Get-ScheduledTask -TaskPath $tp -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
}

$wuStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -ErrorAction SilentlyContinue).Start
"95-freeze-windows-update: NoAutoUpdate=1 wuauserv_start=$wuStart (4=disabled)"
