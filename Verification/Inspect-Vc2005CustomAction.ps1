param([Parameter(Mandatory=$true)][string]$Msi,[Parameter(Mandatory=$true)][string]$Output)
# Read-only MSI database inspection. No vendor DLL is loaded or executed.
$ErrorActionPreference='Stop'
$engine=$null;$db=$null;$view=$null;$record=$null;$binaryView=$null;$binary=$null
try {
 $engine=New-Object -ComObject WindowsInstaller.Installer
 $db=$engine.OpenDatabase([IO.Path]::GetFullPath($Msi),0)
 $view=$db.OpenView('SELECT `Source`, `Target` FROM `CustomAction` WHERE `Action` = ''SxsInstallCA''')
 $view.Execute();$record=$view.Fetch()
 if(-not $record){throw 'SxsInstallCA not found'}
 $name=$record.StringData(1);$target=$record.StringData(2)
 if($name -notmatch '^[A-Za-z0-9_.]+$'){throw 'Unexpected binary stream name'}
 $binaryView=$db.OpenView(('SELECT `Data` FROM `Binary` WHERE `Name` = ''{0}''' -f $name))
 $binaryView.Execute();$binary=$binaryView.Fetch()
 if(-not $binary){throw 'Custom action binary not found'}
 $stream=New-Object IO.MemoryStream
 try {
  do {
   $chunk=$binary.ReadStream(1,65536,1)
   if($chunk){foreach($character in $chunk.ToCharArray()){$stream.WriteByte([byte][char]$character)}}
   if($stream.Length -gt 4MB){throw 'Custom action binary exceeds inspection budget'}
  } while($chunk.Length -gt 0)
  [IO.File]::WriteAllBytes([IO.Path]::GetFullPath($Output),$stream.ToArray())
 } finally {$stream.Dispose()}
 $signature=Get-AuthenticodeSignature -LiteralPath $Output
 [pscustomobject]@{Source=$name;Target=$target;Bytes=(Get-Item $Output).Length;Sha256=(Get-FileHash $Output).Hash;Signature=$signature.Status.ToString();Signer=$signature.SignerCertificate.Subject}|ConvertTo-Json
} finally {
 foreach($item in @($binary,$binaryView,$record,$view,$db,$engine)){if($item){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($item)}}
}
