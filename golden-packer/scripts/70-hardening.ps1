$ProgressPreference='SilentlyContinue'
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Type DWord -Value 1 -ErrorAction SilentlyContinue
# realtime intentionally NOT enabled (validator handles untrusted files) - see 90-defender.ps1
try {
  Install-Module HardeningKitty -Force -Scope AllUsers -ErrorAction Stop
  Import-Module HardeningKitty
  Invoke-HardeningKitty -Mode Audit -SkipMachineInformation 2>&1 | Out-Null
  $hk = 'HardeningKitty audit ran'
} catch { $hk = "HardeningKitty skipped: $($_.Exception.Message)" }
"SMB1=$((Get-SmbServerConfiguration).EnableSMB1Protocol); $hk"
'70-hardening OK (safe subset + audit; full CIS/STIG HailMary deferred, snapshot-guarded)'
