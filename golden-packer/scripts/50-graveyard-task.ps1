$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'
$dir = 'C:\certgraveyard'; New-Item -Force -ItemType Directory $dir | Out-Null
$pull = @'
$ErrorActionPreference='Stop'
$dir='C:\certgraveyard'; $url='https://certgraveyard.org/api/download_csv'
$tmp=Join-Path $dir 'staging.csv'; $cur=Join-Path $dir 'cert_graveyard_database.csv'
try {
  Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 120
  if ((Get-Item $tmp).Length -gt 1000) {
    if (Test-Path $cur) { Copy-Item $cur (Join-Path $dir 'last-good.csv') -Force }
    Move-Item $tmp $cur -Force
    Set-Content (Join-Path $dir 'last-pull.txt') (Get-Date -Format o)
  } else { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
} catch { $_ | Out-File (Join-Path $dir 'pull-error.txt') }
'@
Set-Content -Path "$dir\pull.ps1" -Value $pull -Encoding utf8
powershell -ExecutionPolicy Bypass -File "$dir\pull.ps1"
$act=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -File $dir\pull.ps1"
$trg=New-ScheduledTaskTrigger -Daily -At 4am
Register-ScheduledTask -TaskName 'CertGraveyardPull' -Action $act -Trigger $trg -User SYSTEM -RunLevel Highest -Force | Out-Null
$cur="$dir\cert_graveyard_database.csv"
if (Test-Path $cur) { "graveyard CSV: $((Get-Item $cur).Length) bytes, $((Get-Content $cur | Measure-Object -Line).Lines) lines" } else { "graveyard CSV NOT pulled (see $dir\pull-error.txt)" }
'50-graveyard-task OK'
