param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[ValidatePattern('^[A-Za-z0-9-]+$')][string]$SnapshotName='Bits-Completion',[int]$DotNetChecks=447,[int]$PowerShellChecks=93,[ValidatePattern('^[A-Z0-9][A-Z0-9-]*\.md$')][string]$ReportName='BITS-COMPLETED-DOWNLOADS.md')
$ErrorActionPreference='Stop'
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$candidate=Join-Path $ProjectRoot ('outputs\'+$SnapshotName+'-Candidate')
$buildLabel='0.12.10-'+$SnapshotName.ToLowerInvariant()+'-20261029'
if(-not(Test-Path -LiteralPath (Join-Path $candidate 'InstallerAnalyzer.exe'))){throw 'Publish the candidate first'}
$production=@(Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'InstallerAnalyzer') -Recurse -File | Where-Object {$_.FullName -notmatch '\\(bin|obj)\\'})
$source=@($production)+@(Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'Verification') -Recurse -File | Where-Object {$_.FullName -notmatch '\\(bin|obj)\\'})
foreach($relative in @('ROADMAP-STATUS.md','ROADMAP-ACCEPTANCE.md',('outputs\'+$ReportName),'outputs\ACTIVE-ROADMAP-WORK.json')){$source+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)}
function SourceRecord($file){[ordered]@{Path=$file.FullName.Substring($ProjectRoot.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}}
$actualLabel=(Get-Item -LiteralPath (Join-Path $candidate 'InstallerAnalyzer.exe')).VersionInfo.ProductVersion
if($actualLabel -ne $buildLabel){throw ('Published build label mismatch: '+$actualLabel)}
$info=[ordered]@{BaseVersion='0.12.10';InformationalVersion=$buildLabel;PublishedRelease=$false;Signed=$false;AutomatedChecks=($DotNetChecks+$PowerShellChecks);DotNetWpfChecks=$DotNetChecks;PowerShellChecks=$PowerShellChecks;VerificationReport=$ReportName;LiveVerification='See the verification report and its location pointers for exact current acceptance and limits';ExecutableSha256=(Get-FileHash -LiteralPath (Join-Path $candidate 'InstallerAnalyzer.exe')).Hash;NativeSqliteSha256=(Get-FileHash -LiteralPath (Join-Path $candidate 'e_sqlite3.dll')).Hash;SourceFiles=@($production | Sort-Object FullName | ForEach-Object {SourceRecord $_})}
$info|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $candidate 'BUILD-INFO.json') -Encoding UTF8
@"
Installer Analyzer development candidate
$buildLabel

Extract all files together and run InstallerAnalyzer.exe. The runtime is included; keep native DLLs beside the EXE.

Includes the development increment described in $ReportName and prior security/runtime fixes. Unsigned development output. The full roadmap remains open; see BUILD-INFO.json and $ReportName for exact scope, verification and limits.
"@ | Set-Content -LiteralPath (Join-Path $candidate 'README.txt') -Encoding UTF8
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Package([string]$path,[object[]]$files,[string]$base){
 $stream=[IO.File]::Open($path,[IO.FileMode]::Create,[IO.FileAccess]::Write)
 $archive=New-Object IO.Compression.ZipArchive($stream,[IO.Compression.ZipArchiveMode]::Create,$false)
 $manifest=@()
 try{
  foreach($file in ($files|Sort-Object FullName)){
   $name=$file.FullName.Substring($base.Length+1).Replace('\','/')
   [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$file.FullName,$name,[IO.Compression.CompressionLevel]::Optimal)|Out-Null
   $manifest+=@{Path=$name;Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
  }
  $entry=$archive.CreateEntry('PACKAGE-MANIFEST.json');$writer=New-Object IO.StreamWriter($entry.Open());try{$writer.Write(($manifest|ConvertTo-Json -Depth 4))}finally{$writer.Dispose()}
 }finally{$archive.Dispose();$stream.Dispose()}
 $verify=[IO.Compression.ZipFile]::OpenRead($path)
 try{
  foreach($record in $manifest){$entry=$verify.GetEntry($record.Path);if($null -eq $entry){throw ('Missing archive entry '+$record.Path)};$input=$entry.Open();$sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($input)).Replace('-','');if($actual -ne $record.Sha256){throw ('Archive hash mismatch '+$record.Path)}}finally{$sha.Dispose();$input.Dispose()}}
 }finally{$verify.Dispose()}
 Write-Output ('PASS verified '+$manifest.Count+' entries: '+$path)
}
$portable=Join-Path $ProjectRoot ('outputs\InstallerAnalyzer-0.12.10-'+$SnapshotName+'-Development-20261029.zip')
$sources=Join-Path $ProjectRoot ('outputs\InstallerAnalyzer-'+$SnapshotName+'-Source-20261029.zip')
Package $portable @(Get-ChildItem -LiteralPath $candidate -File|Where-Object {$_.Extension -ne '.pdb'}) $candidate
Package $sources $source $ProjectRoot
@($portable,$sources)|ForEach-Object {((Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetFileName($_))}|Set-Content -LiteralPath (Join-Path $ProjectRoot ('outputs\SHA256SUMS-'+$SnapshotName.ToUpperInvariant()+'-20261029.txt')) -Encoding ASCII
