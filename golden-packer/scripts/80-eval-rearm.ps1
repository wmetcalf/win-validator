$ProgressPreference='SilentlyContinue'
New-Item -Force -ItemType Directory C:\prov | Out-Null
$rearm = @'
$d = cscript //nologo C:\Windows\System32\slmgr.vbs /dlv 2>&1 | Out-String
Set-Content C:\prov\slmgr-dlv.txt $d
'@
Set-Content C:\prov\rearm-check.ps1 $rearm -Encoding utf8
$act=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-ExecutionPolicy Bypass -File C:\prov\rearm-check.ps1'
$trg=New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName 'EvalStatusLog' -Action $act -Trigger $trg -User SYSTEM -RunLevel Highest -Force | Out-Null
$dlv = cscript //nologo C:\Windows\System32\slmgr.vbs /dlv 2>&1 | Out-String
($dlv -split "`n" | Select-String -Pattern 'license status|expire|grace|rearm' | Select-Object -First 5) -join "`n"
'80-eval-rearm OK'
