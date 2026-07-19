$ErrorActionPreference = 'Stop'
$p = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot'
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name DisableRootAutoUpdate -Type DWord -Value 0
$before = (Get-ChildItem Cert:\LocalMachine\Root).Count
certutil -generateSSTFromWU C:\roots.sst | Out-Null
certutil -syncWithWU C:\ctl | Out-Null
$after = (Get-ChildItem Cert:\LocalMachine\Root).Count
$act = New-ScheduledTaskAction -Execute 'certutil.exe' -Argument '-syncWithWU C:\ctl'
$trg = New-ScheduledTaskTrigger -Daily -At 3:00am
Register-ScheduledTask -TaskName 'CertStoreSync' -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
"roots: before=$before after=$after"
'30-cert-store-sync OK'
