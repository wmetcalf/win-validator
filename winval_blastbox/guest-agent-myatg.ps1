# Windows guest agent that serves the *myatg.exe* validator over plain HTTP.
#
#   POST http://<worker>:8765/validate?name=<filename>   body = raw file bytes
#        -> 200 application/json   (the myatg verdict)
#   GET  http://<worker>:8765/healthz                     -> 200 "ok"
#
# Debuggable with curl; no bespoke framing. The host client (winval_blastbox.vm_pool) speaks it.
#
# PERSISTENT-WORKER MODE: keeps ONE warm `myatg.exe --serve` child alive and feeds it one file
# path per request over its stdin (one JSON line back per file), instead of forking a fresh
# myatg.exe per request. That keeps the CLR JIT + trust/CRL caches hot, dropping binary jobs from
# ~0.5s (process fork) to ~tens of ms. myatg is C# (WinVerifyTrust) and does NOT degrade when
# reused. Crash-resilient: if the child dies (e.g. a parser crash on malformed input) it's
# restarted and that one request returns an error — a bad file can't wedge the worker. The whole
# VM still snapshot-reverts every N jobs, which also resets this child to its primed state.
#
# HttpListener under NETWORK SERVICE needs a URL ACL, baked into the golden:
#   netsh http add urlacl url=http://+:8765/ user="NT AUTHORITY\NETWORK SERVICE"
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
$AGENT='C:\agent'; $SCAN='C:\scan'; New-Item -Force -ItemType Directory $SCAN | Out-Null
$EXE="$AGENT\myatg.exe"
$GV='C:\certgraveyard\cert_graveyard_database.csv'
$csc='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

# Compile myatg.exe once (sources staged by the bake/pool); rebuild if sources are newer.
$needBuild = -not (Test-Path $EXE)
if(-not $needBuild){
  $exeT=(Get-Item $EXE).LastWriteTimeUtc
  foreach($s in @("$AGENT\myatg.cs","$AGENT\rdp_validate.cs")){
    if((Test-Path $s) -and ((Get-Item $s).LastWriteTimeUtc -gt $exeT)){ $needBuild=$true }
  }
}
if($needBuild){
  & $csc /nologo /r:System.Security.dll /out:$EXE "$AGENT\myatg.cs" "$AGENT\rdp_validate.cs" 2>&1 | Out-File "$AGENT\myatg-build.log"
}

# --- persistent myatg --serve child ---------------------------------------------------------
$script:child=$null
function Start-Serve {
  if($script:child -and -not $script:child.HasExited){ try{ $script:child.Kill() }catch{} }
  $psi=New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName=$EXE
  # NB: PowerShell variable names are case-insensitive, so this local must NOT be named $gv
  # (it would alias and blank the script-level $GV path before Test-Path reads it).
  $gvArg=''; if(Test-Path $GV){ $gvArg='--gv "'+$GV+'" ' }
  $psi.Arguments=$gvArg+'--serve'
  $psi.UseShellExecute=$false
  $psi.RedirectStandardInput=$true
  $psi.RedirectStandardOutput=$true
  $psi.StandardOutputEncoding=[System.Text.Encoding]::UTF8
  $p=[System.Diagnostics.Process]::Start($psi)
  $p.StandardInput.AutoFlush=$true
  # prime: run the full path once (warms JIT + CRL/OCSP cache), discard the verdict.
  try{ $p.StandardInput.WriteLine('C:\Windows\System32\whoami.exe'); [void]$p.StandardOutput.ReadLine() }catch{}
  $script:child=$p
}
function Validate-One($p){
  if(-not $script:child -or $script:child.HasExited){ Start-Serve }
  try{
    $script:child.StandardInput.WriteLine($p)
    $json=$script:child.StandardOutput.ReadLine()
    if($null -eq $json){ throw 'child eof' }
    return $json
  }catch{
    Start-Serve   # child died mid-request -> restart for subsequent jobs
    return '{"status":"UnknownError","error":"agent_serve_restart"}'
  }
}
Start-Serve

# Sanitize the request filename to an ASCII temp path (keep only a safe extension — all myatg
# routes on is .rdp + the script SIP type; the base name never affects a verdict since myatg hashes
# content). ASCII avoids any stdin-encoding ambiguity feeding the --serve child.
$script:reqid=0
function Scan-Path($fname){
  $ext=''
  if($fname){ $ext=[System.IO.Path]::GetExtension($fname); if($ext -notmatch '^\.[A-Za-z0-9]{1,8}$'){ $ext='' } }
  $script:reqid++
  Join-Path $SCAN ('s'+$script:reqid+$ext)
}

$listener=New-Object System.Net.HttpListener
$listener.Prefixes.Add('http://+:8765/')
$listener.Start()
while($true){
  $ctx=$listener.GetContext(); $req=$ctx.Request; $resp=$ctx.Response
  try{
    if($req.Url.AbsolutePath -eq '/healthz'){
      $body=[Text.Encoding]::UTF8.GetBytes('ok'); $resp.ContentType='text/plain'
    } elseif($req.Url.AbsolutePath -eq '/validate' -and $req.HttpMethod -eq 'POST'){
      $name=$req.QueryString['name']
      $ms=New-Object System.IO.MemoryStream; $req.InputStream.CopyTo($ms); $bytes=$ms.ToArray()
      $p=Scan-Path $name; [IO.File]::WriteAllBytes($p,$bytes)
      $json=Validate-One $p; Remove-Item $p -Force -EA SilentlyContinue
      if(-not $json){ $json='{"status":"UnknownError","error":"agent_exec"}' }
      $body=[Text.Encoding]::UTF8.GetBytes($json); $resp.ContentType='application/json'
    } else {
      $resp.StatusCode=404; $body=[Text.Encoding]::UTF8.GetBytes('not found')
    }
    $resp.ContentLength64=$body.Length; $resp.OutputStream.Write($body,0,$body.Length)
  } catch {
    try{ $resp.StatusCode=500; $eb=[Text.Encoding]::UTF8.GetBytes('{"status":"UnknownError","error":"agent_http"}'); $resp.OutputStream.Write($eb,0,$eb.Length) }catch{}
  } finally { try{ $resp.OutputStream.Close() }catch{} }
}
