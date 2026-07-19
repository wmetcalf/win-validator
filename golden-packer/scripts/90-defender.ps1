$ProgressPreference='SilentlyContinue'
New-Item -Force -ItemType Directory C:\scan | Out-Null
Add-MpPreference -ExclusionPath C:\scan,'C:\Windows\Temp\scan'
Add-MpPreference -ExclusionExtension exe,dll,sys,scr,ocx,cpl,efi,msi,ps1,psm1,vbs,js,jse,vbe,wsf,hta,bat,cmd,jar,lnk,chm,com
Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableIOAVProtection $true -DisableArchiveScanning $true -DisableBehaviorMonitoring $true
Set-MpPreference -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
$s = Get-MpComputerStatus
"Realtime=$($s.RealTimeProtectionEnabled) Behavior=$($s.BehaviorMonitorEnabled)"
"ExclPaths=" + ((Get-MpPreference).ExclusionPath -join ';')
"ExclExtCount=" + (Get-MpPreference).ExclusionExtension.Count
"90-defender OK"
