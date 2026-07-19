$ProgressPreference='SilentlyContinue'
New-Item -Force -ItemType Directory C:\scan | Out-Null
Add-MpPreference -ExclusionPath C:\scan,'C:\Windows\Temp\scan'
# myatg validator: POST /validate writes uploaded bytes to %ProgramData%\myatg\uploads before checking
# them, and those samples are frequently LIVE malware -- an AV quarantine would delete the sample
# mid-validation and corrupt the verdict. The unsigned validator binary (WinVerifyTrust P/Invoke +
# spawning powershell/certutil + installing a service) also trips Defender heuristics. Exclude the
# upload dir + install path + process by NAME so this survives even if realtime protection is
# re-enabled later (Windows silently flips DisableRealtimeMonitoring back on Server SKUs).
New-Item -Force -ItemType Directory 'C:\ProgramData\myatg\uploads' | Out-Null
Add-MpPreference -ExclusionPath 'C:\ProgramData\myatg','C:\Program Files\myatg'
Add-MpPreference -ExclusionProcess 'C:\Program Files\myatg\myatg.exe'
Add-MpPreference -ExclusionExtension exe,dll,sys,scr,ocx,cpl,efi,msi,ps1,psm1,vbs,js,jse,vbe,wsf,hta,bat,cmd,jar,lnk,chm,com
Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableIOAVProtection $true -DisableArchiveScanning $true -DisableBehaviorMonitoring $true
Set-MpPreference -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
$s = Get-MpComputerStatus
"Realtime=$($s.RealTimeProtectionEnabled) Behavior=$($s.BehaviorMonitorEnabled)"
"ExclPaths=" + ((Get-MpPreference).ExclusionPath -join ';')
"ExclExtCount=" + (Get-MpPreference).ExclusionExtension.Count
"90-defender OK"
