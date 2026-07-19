$ErrorActionPreference = 'Stop'
$ConfirmPreference     = 'None'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Windows Update via PSWindowsUpdate's Invoke-WUJob. It registers + runs the install as a local SYSTEM
# scheduled task (session 0) — the context WU servicing wants, and which sidesteps the remote-session
# E_ACCESSDENIED. -IgnoreReboot: Packer owns the reboot (a windows-restart follows this).
#
# Deliberately a SINGLE best-effort pass: this WS2025-RTM-on-qemu base's CBS state never fully drains
# PackagesPending, so the rgl plugin's "loop until converged" reboot-loop wedges forever. We install
# what's applicable once and move on; the whole thing is wrapped so it can NEVER fail the build.
$flag = 'C:\Windows\Temp\wujob-done.flag'
try {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Install-Module PSWindowsUpdate -Force -Scope AllUsers
    }
    Import-Module PSWindowsUpdate

    Remove-Item $flag -Force -ErrorAction SilentlyContinue
    # Register + run-now a SYSTEM task that installs applicable updates. KB5094125 (the ~22GB checkpoint
    # cumulative) is EXCLUDED via -NotTitle: PROVEN it can't finalize live on a year-behind base -- its
    # finalization forces an uncontrolled reboot that kills the build (exit 2300218). A pre-integrated
    # VLSC/MSDN base ISO is the only route to having it.
    Invoke-WUJob -ComputerName localhost -Confirm:$false -RunNow -Script {
        Import-Module PSWindowsUpdate
        try {
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -Confirm:$false `
                -NotTitle 'KB5094125' *> C:\Windows\Temp\wujob.log
        } catch { $_ | Out-File C:\Windows\Temp\wujob.log -Append }
        New-Item -Path C:\Windows\Temp\wujob-done.flag -ItemType File -Force | Out-Null
    }

    # Wait for the SYSTEM job to signal done (up to 60 min).
    $deadline = (Get-Date).AddMinutes(60)
    while (-not (Test-Path $flag) -and (Get-Date) -lt $deadline) { Start-Sleep 20 }
    if (Test-Path $flag) {
        "20-windows-update(WUJob): done. hotfixes=$((Get-HotFix).Count)"
    } else {
        Write-Warning "20-windows-update(WUJob): job did not signal done in 60m (continuing)"
    }
} catch {
    Write-Warning "20-windows-update(WUJob): non-fatal error: $($_.Exception.Message)"
}
exit 0
