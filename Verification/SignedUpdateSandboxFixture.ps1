param([switch]$UntrustedOnly,[switch]$AllowGuestTestTrust)
$ErrorActionPreference='Stop'
Start-Transcript C:\InstallerOutput\signing-fixture-log.txt
try{
  if($env:USERNAME -ne 'WDAGUtilityAccount' -or -not (Test-Path 'C:\PublishedVerifier\Verification.exe')){throw 'This fixture may run only in its disposable Windows Sandbox guest.'}
  if(-not $UntrustedOnly -and (-not $AllowGuestTestTrust -or -not (Test-Path 'C:\InstallerInput\permit-guest-test-trust.txt'))){throw 'Explicit guest-only test-certificate trust authorization required.'}
  [IO.Directory]::CreateDirectory('C:\SigningFixture\App') | Out-Null
  Copy-Item -Path 'C:\PublishedVerifier\*' -Destination 'C:\SigningFixture\App' -Recurse
  # All keys and trust changes live only in this disposable guest. No PFX/private key is exported.
  function TestCertificate([string]$subject){
    $cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(1)
    foreach($name in @('Root','TrustedPublisher') | Where-Object {-not $UntrustedOnly}){
      $store=New-Object Security.Cryptography.X509Certificates.X509Store $name,LocalMachine
      try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$store.Add($cert)}finally{$store.Dispose()}
    }
    return $cert
  }
  $cert=TestCertificate 'CN=Installer Analyzer isolated fixture A'
  $other=TestCertificate 'CN=Installer Analyzer isolated fixture B'
  [IO.File]::WriteAllText('C:\SigningFixture\expected-test-thumbprint.txt',$cert.Thumbprint)
  $code=@'
using System;
using System.IO;
using System.Reflection;
[assembly:AssemblyProduct("Installer Analyzer for ImmyBot")]
[assembly:AssemblyFileVersion("99.0.0.0")]
[assembly:AssemblyVersion("99.0.0.0")]
public static class FixtureSetup {
  public static void Main(string[] args) {
    if (Array.IndexOf(args,"/SILENT") < 0 || Array.IndexOf(args,"/CLOSEAPPLICATIONS") < 0) Environment.Exit(2);
    File.WriteAllText(@"C:\InstallerOutput\signed-handoff-launched.txt","Inert isolated setup handoff; no application installed.");
  }
}
'@
  Add-Type -TypeDefinition $code -OutputAssembly C:\SigningFixture\InstallerAnalyzer-Setup.exe -OutputType WindowsApplication
  Copy-Item C:\SigningFixture\InstallerAnalyzer-Setup.exe C:\SigningFixture\OtherPublisher-Setup.exe
  foreach($pair in @(@('C:\SigningFixture\App\Verification.exe',$cert),@('C:\SigningFixture\InstallerAnalyzer-Setup.exe',$cert),@('C:\SigningFixture\OtherPublisher-Setup.exe',$other))){
    $signature=Set-AuthenticodeSignature -FilePath $pair[0] -Certificate $pair[1] -HashAlgorithm SHA256
    $signature=Get-AuthenticodeSignature -FilePath $pair[0]
    [pscustomobject]@{File=$pair[0];Status=[string]$signature.Status;Message=$signature.StatusMessage;Thumbprint=$signature.SignerCertificate.Thumbprint} | ConvertTo-Json -Compress | Add-Content C:\InstallerOutput\signature-status.jsonl
    if($UntrustedOnly){if($null -eq $signature.SignerCertificate -or $signature.Status -notin @('NotTrusted','UnknownError')){throw ('Expected embedded untrusted signature; got '+$signature.Status)}}
    elseif($signature.Status -ne 'Valid'){throw ('Signing produced an unexpected status: '+$signature.Status)}
  }
  $arguments=if($UntrustedOnly){'C:\InstallerOutput\Handoff --signed-untrusted'}else{'C:\InstallerOutput\Handoff --signed-handoff C:\SigningFixture\InstallerAnalyzer-Setup.exe'}
  $info=New-Object Diagnostics.ProcessStartInfo
  $info.FileName='C:\SigningFixture\App\Verification.exe';$info.Arguments=$arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  $process=New-Object Diagnostics.Process;$process.StartInfo=$info;[void]$process.Start()
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  if(-not $process.WaitForExit(90000)){try{$process.Kill()}catch{};throw 'Signed handoff timed out'}
  [IO.File]::WriteAllText('C:\InstallerOutput\handoff-stdout.txt',$stdout.GetAwaiter().GetResult())
  [IO.File]::WriteAllText('C:\InstallerOutput\handoff-stderr.txt',$stderr.GetAwaiter().GetResult())
  [IO.File]::WriteAllText('C:\InstallerOutput\verifier-exit-code.txt',[string]$process.ExitCode)
  if($process.ExitCode -ne 0 -or -not (Test-Path C:\InstallerOutput\Handoff\PASS.txt)){throw 'Signed handoff fixture failed; see output/error artifacts'}
  Copy-Item C:\InstallerOutput\Handoff\PASS.txt C:\InstallerOutput\PASS.txt
}catch{$_ | Out-String | Set-Content C:\InstallerOutput\error.txt}finally{Stop-Transcript;Set-Content C:\InstallerOutput\done.txt 'done'}
