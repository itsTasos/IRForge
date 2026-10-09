param([Parameter(Mandatory=$true)][string]$CertificateThumbprint,[Parameter(Mandatory=$true)][string]$Path,[string]$TimestampServer='http://timestamp.digicert.com')
$ErrorActionPreference='Stop'
$irforgeCertificate=Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint"
if(!$irforgeCertificate.HasPrivateKey){throw 'The owner-supplied certificate has no private key'}
$irforgeResult=Set-AuthenticodeSignature -LiteralPath $Path -Certificate $irforgeCertificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer
if($irforgeResult.Status -ne 'Valid'){throw "Signing failed: $($irforgeResult.StatusMessage)"}
$irforgeResult | Format-List Path,Status,SignerCertificate
