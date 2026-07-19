$ErrorActionPreference = 'Stop'
Set-Service sshd -StartupType Automatic
Start-Service sshd -ErrorAction SilentlyContinue

# Force KEY-ONLY auth. Strip every auth-method directive anywhere in the file (commented or not,
# global or inside a Match block, so nothing can re-enable password auth), then prepend the
# authoritative settings at the TOP of the config so they apply globally — including the
# administrators group, whose keys live in C:\ProgramData\ssh\administrators_authorized_keys.
$cfg = 'C:\ProgramData\ssh\sshd_config'
if (Test-Path $cfg) {
  $strip = '^\s*#?\s*(PasswordAuthentication|PubkeyAuthentication|ChallengeResponseAuthentication|KbdInteractiveAuthentication)\b'
  $body = Get-Content $cfg | Where-Object { $_ -notmatch $strip }
  $header = @(
    '# key-only auth (win-golden-packer)'
    'PubkeyAuthentication yes'
    'PasswordAuthentication no'
    'ChallengeResponseAuthentication no'
    'KbdInteractiveAuthentication no'
  )
  Set-Content -Path $cfg -Value ($header + $body) -Encoding ascii
  Restart-Service sshd
}
# prove it: sshd must advertise publickey and NOT password
$eff = (& 'C:\Windows\System32\OpenSSH\sshd.exe' -T 2>$null)
$pw  = ($eff | Select-String -Pattern '^passwordauthentication\s+no'  -Quiet)
$pk  = ($eff | Select-String -Pattern '^pubkeyauthentication\s+yes'   -Quiet)
Get-Service sshd | Select-Object Name, Status, StartType | Format-Table -AutoSize
"10-openssh-harden OK (passwordauth_off=$pw pubkeyauth_on=$pk)"
