$ErrorActionPreference = 'Stop'
foreach ($t in 'C:\Windows\System32\kernel32.dll','C:\Windows\System32\ntdll.dll') {
  $s = Get-AuthenticodeSignature $t
  "{0}: Status={1} IsOSBinary={2} Type={3}" -f (Split-Path $t -Leaf), $s.Status, $s.IsOSBinary, $s.SignatureType
  if ($s.Status -ne 'Valid') { throw "authenticode selftest FAILED on $t : $($s.Status)" }
}
$sig = Get-AuthenticodeSignature C:\Windows\System32\kernel32.dll
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$chain.ChainPolicy.RevocationMode = 'Online'
$chain.ChainPolicy.RevocationFlag = 'EntireChain'
$ok = $chain.Build($sig.SignerCertificate)
"online-revocation chain build ok=$ok elements=$($chain.ChainElements.Count)"
'40-authenticode-selftest OK'
