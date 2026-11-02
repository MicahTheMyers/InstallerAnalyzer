param(
 [string]$ProjectRoot,
 [Parameter(Mandatory=$true)][string]$DotNet,
 [string]$SnapshotName='InstallShield-Recorder',
 [string]$SnapshotDate='20261029',
 [int]$DotNetChecks=451,
 [int]$PowerShellChecks=108
)
$ErrorActionPreference='Stop'
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
if($SnapshotName -notmatch '^[A-Za-z0-9-]+$'){throw 'Invalid snapshot name'}
if($SnapshotDate -notmatch '^\d{8}$'){throw 'Invalid snapshot date'}
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$label='0.12.10-'+$SnapshotName.ToLowerInvariant()+'-'+$SnapshotDate
$stage=Join-Path $ProjectRoot ('verification-results\source-package-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage|Out-Null
$sources=@()
foreach($folder in @('InstallerAnalyzer','Verification')){
 $sources+=Get-ChildItem -LiteralPath (Join-Path $ProjectRoot $folder) -Recurse -File|Where-Object {$_.FullName -notmatch '\\(bin|obj|Build|\.vs|\.git)\\'}
}
foreach($relative in @('ROADMAP-STATUS.md','ROADMAP-ACCEPTANCE.md','outputs\ACTIVE-ROADMAP-WORK.json','outputs\INSTALLSHIELD-RECORDER.md','outputs\SANDBOX-DISPLAY-RECOVERY.md','outputs\INSTALLSHIELD-VENDOR-REPLAY.md','outputs\BITS-COMPLETED-DOWNLOADS.md')){
 $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
}
if($SnapshotName -eq 'Startup-Performance'){
 foreach($relative in @('outputs\STARTUP-PERFORMANCE.md','outputs\Startup-Performance-Before.txt','outputs\Startup-Performance-After.txt')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -eq 'Startup-Readiness'){
 foreach($relative in @('outputs\STARTUP-READINESS.md','outputs\STARTUP-PERFORMANCE.md','outputs\Startup-Readiness-Live.txt','outputs\Startup-Bootstrap-Checks.txt')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -in @('App-Control','Analyze-Toggle','Test-Mode-Scroll','UI-Fixes','Performance','Claude-Assistant','Taskbar-Fix','NetFx3-Provisioning','Sandbox-NetFx3-Fix')){
 foreach($relative in @('outputs\APP-CONTROL-AND-RECORDING.md','outputs\STARTUP-READINESS.md','outputs\STARTUP-PERFORMANCE.md','outputs\App-Control-Final-Checks.txt','outputs\App-Control-Live-Acceptance.json')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -in @('Analyze-Toggle','Test-Mode-Scroll','UI-Fixes','Performance','Claude-Assistant','Taskbar-Fix','NetFx3-Provisioning','Sandbox-NetFx3-Fix')){
 foreach($relative in @('outputs\ANALYZE-TOGGLE-FIX.md','outputs\Analyze-Toggle-Checks.txt')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -in @('Test-Mode-Scroll','UI-Fixes','Performance','Claude-Assistant','Taskbar-Fix','NetFx3-Provisioning','Sandbox-NetFx3-Fix')){
 foreach($relative in @('outputs\TEST-MODE-SCROLL-FIX.md','outputs\Test-Mode-Scroll-Checks.txt')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -in @('UI-Fixes','Performance','Claude-Assistant','Taskbar-Fix','NetFx3-Provisioning','Sandbox-NetFx3-Fix')){
 foreach($relative in @('outputs\ACCENT-SELECTION-FIX.md','outputs\Accent-Selection-Checks.txt','outputs\SIDEBAR-ICONS-AND-ALIGNMENT.md','outputs\Sidebar-Icons-Checks.txt','outputs\SANDBOX-ELAPSED-TIMER.md','outputs\Sandbox-Elapsed-Checks.txt','outputs\NETFX3-OFFLINE-TRIAL.md','outputs\NATIVE-LOGO-QUALITY.md','outputs\Native-Logo-Quality-Checks.txt')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -in @('Performance','Claude-Assistant','Taskbar-Fix','NetFx3-Provisioning','Sandbox-NetFx3-Fix')){
 foreach($relative in @('outputs\PERFORMANCE-REVIEW-20261030.md','outputs\PERFORMANCE-OPTIMIZATIONS.md','outputs\Performance-Work-Checks.txt','outputs\Performance-Measurements.json')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -in @('Claude-Assistant','Taskbar-Fix','NetFx3-Provisioning','Sandbox-NetFx3-Fix')){
 foreach($relative in @('outputs\CLAUDE-READONLY-ASSISTANT.md','outputs\Claude-Assistant-Checks.txt')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -in @('Taskbar-Fix','NetFx3-Provisioning','Sandbox-NetFx3-Fix')){
 foreach($relative in @('outputs\MAXIMIZED-TASKBAR-FIX.md','outputs\Taskbar-Work-Checks.txt')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -in @('NetFx3-Provisioning','Sandbox-NetFx3-Fix')){
 foreach($relative in @('outputs\NETFX3-PROVISIONING.md','outputs\NetFx3-Production-Checks.txt','outputs\NetFx3-Provisioning-Fixtures.txt','outputs\NetFx3-Existing-PS-Checks.txt','outputs\NetFx3-Source-Syntax.txt','outputs\NetFx3-Production-Live.json','outputs\NETFX3-FULL-VM-ACCEPTANCE.md')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
if($SnapshotName -eq 'Sandbox-NetFx3-Fix'){
 foreach($relative in @('outputs\NETFX3-SANDBOX-INVESTIGATION.md','outputs\NetFx3-Sandbox-Final-Checks.txt','outputs\NetFx3-Sandbox-PS-Checks.txt','outputs\NetFx3-Sandbox-Timeout-Fixtures.txt','outputs\NetFx3-Sandbox-Build.txt','outputs\NetFx3-Sandbox-Syntax.txt','outputs\NetFx3-Sandbox-Acceptance.json')){
  $sources+=Get-Item -LiteralPath (Join-Path $ProjectRoot $relative)
 }
}
$names=@()
foreach($source in $sources){
 $relative=$source.FullName.Substring($ProjectRoot.Length+1)
 $destination=Join-Path $stage $relative
 New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force|Out-Null
 Copy-Item -LiteralPath $source.FullName -Destination $destination
 $names+=$relative.Replace('\','/')
}
$readme=@"
Installer Analyzer latest development source
$label
Base application version: 0.12.10. This is an unsigned development snapshot.

QUICK START ON WINDOWS X64
1. Extract this entire ZIP into a folder.
2. Install the .NET 8 SDK if it is not already installed.
3. Double-click BUILD-LATEST.cmd in the extracted folder.
4. Keep all generated files together and run Build\InstallerAnalyzer.exe.
   The publish includes the runtime. NuGet restore needs internet access.

Alternatively, InstallerAnalyzer\Build.bat can install the SDK using winget
and publish the application into InstallerAnalyzer\Build.

Windows Sandbox must be available and enabled for installer lifecycle tests.
Launch the app, enable Test Mode in Settings, and use Full Analysis to record
InstallShield responses. Recording phases require wizard interaction; the
subsequent replay phases must complete unattended. No product license or
activation test is included in the recording acceptance.

LATEST CHANGES AND LIMITS
Sandbox-NetFx3-Fix adds guest-only repair of matching missing .NET resource
components and the exact Sandbox update placeholder, plus a hash-verified
Microsoft NetFx3 source download on supported x64 builds. Fresh Sandbox runtime
verification passed; a separate VM is no longer required for this case.
See outputs\NETFX3-SANDBOX-INVESTIGATION.md for evidence and build limits.
Windows build 28000+ still requires a separately provisioned standalone runtime.

Taskbar-Fix snapshots constrain maximized windows to the current monitor's
usable work area so the taskbar does not clip the footer. Version 0.12.10.
See outputs\MAXIMIZED-TASKBAR-FIX.md.

Claude-Assistant snapshots add Claude (Anthropic) under Settings > AI Assist,
with a separate Windows-protected API key and model selection. Enable Test Mode
and AI Assist, choose Claude, enter a model ID available to your Anthropic API
account, and save its API key. Requests remain read-only and explicit-send only.
API usage is billed separately from chat subscriptions. No live API call was
used in acceptance; see outputs\CLAUDE-READONLY-ASSISTANT.md.

Includes the shared schema-3 InstallShield recording engine, response/log
validation and diagnostic replay logs, plus earlier updater/security,
prerequisite, payload and BITS work. $($DotNetChecks+$PowerShellChecks) automated checks passed in the source
workspace: $DotNetChecks .NET/WPF and $PowerShellChecks PowerShell. The live Analyzer-created recording
still needs complete interactive recording and unattended lifecycle acceptance.

Startup-Performance snapshots also skip approximately 10 seconds of unnecessary
cleanup on confirmed empty Sandbox sessions, load hidden histories on navigation,
and defer automatic update checks until after the first rendered frame.
See outputs\STARTUP-PERFORMANCE.md for the exact measured scope and limits.

Startup-Readiness snapshots include those optimizations, a three-minute startup
budget, visible startup progress, and preserved host/guest startup errors.
See outputs\STARTUP-READINESS.md. A visible desktop alone is not analysis proof.

The Sandbox graphics workaround under Verification is OPTIONAL and UNPROVEN.
Do not run it on the new machine unless that machine has the same display
problem. It is not part of building or launching Installer Analyzer.

App-Control snapshots classify correlated enforced Code Integrity blocks and
export bounded diagnostic evidence. Installer Sandboxes use software graphics.
Verification catalog helpers are manual disposable-guest experiments, never
automatic application repairs. No Windows catalog or vendor installer is bundled.
See outputs\APP-CONTROL-AND-RECORDING.md for the live evidence and open milestone.

See ROADMAP-STATUS.md, ROADMAP-ACCEPTANCE.md and outputs reports for exact scope.
Historical fixture scripts may refer to the original machine's D: USB drive,
artifact pointers or test inputs. Those are not required to build the app;
vendor installers, private keys, local databases and runtime outputs are absent.

BUILD AND CHECK FROM A TERMINAL
dotnet build Verification\Verification.csproj -c Release
dotnet run --project Verification\Verification.csproj -c Release --no-build -- verification-results\local-checks

PACKAGE-MANIFEST.json contains the SHA-256 of each packaged source file.
"@
[IO.File]::WriteAllText((Join-Path $stage 'START-HERE.txt'),$readme)
$names+='START-HERE.txt'
$builder=@"
@echo off
setlocal
cd /d "%~dp0"
where dotnet >nul 2>&1
if errorlevel 1 (
 echo Install the .NET 8 SDK, then run this file again.
 echo https://dotnet.microsoft.com/download/dotnet/8.0
 pause
 exit /b 1
)
dotnet publish "InstallerAnalyzer\InstallerAnalyzer.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:InformationalVersion=$label -o "Build"
if errorlevel 1 (
 echo Build failed. Review the messages above.
 pause
 exit /b 1
)
echo Build complete. Run Build\InstallerAnalyzer.exe with its adjacent files.
pause
"@
[IO.File]::WriteAllText((Join-Path $stage 'BUILD-LATEST.cmd'),$builder)
$names+='BUILD-LATEST.cmd'
& $DotNet build (Join-Path $stage 'Verification\Verification.csproj') -c Release -p:UseSharedCompilation=false --nologo *> (Join-Path $ProjectRoot 'outputs\Latest-Source-Clean-Build.txt')
if($LASTEXITCODE -ne 0){throw 'Clean staged-source build failed; see outputs\Latest-Source-Clean-Build.txt'}
$info=[ordered]@{InformationalVersion=$label;BaseVersion='0.12.10';PublishedRelease=$false;SourceOnly=$true;CleanStagedBuildPassed=$true;AutomatedAcceptanceChecks=($DotNetChecks+$PowerShellChecks);LiveAnalyzerResponseRecordingValidated=$false;CreatedAt=[DateTimeOffset]::Now.ToString('o')}
[IO.File]::WriteAllText((Join-Path $stage 'SOURCE-SNAPSHOT.json'),($info|ConvertTo-Json))
$names+='SOURCE-SNAPSHOT.json'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=Join-Path $ProjectRoot ('outputs\InstallerAnalyzer-0.12.10-'+$SnapshotName+'-Source-'+$SnapshotDate+'.zip')
$stream=[IO.File]::Open($zip,[IO.FileMode]::Create,[IO.FileAccess]::Write)
$archive=New-Object IO.Compression.ZipArchive($stream,[IO.Compression.ZipArchiveMode]::Create,$false)
$manifest=@()
try{
 foreach($name in ($names|Sort-Object -Unique)){
  $file=Join-Path $stage $name
  [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$file,$name,[IO.Compression.CompressionLevel]::Optimal)|Out-Null
  $manifest+=[ordered]@{Path=$name;Sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash}
 }
 $entry=$archive.CreateEntry('PACKAGE-MANIFEST.json');$writer=New-Object IO.StreamWriter($entry.Open())
 try{$writer.Write(($manifest|ConvertTo-Json -Depth 4))}finally{$writer.Dispose()}
}finally{$archive.Dispose();$stream.Dispose()}
$verify=[IO.Compression.ZipFile]::OpenRead($zip)
try{
 if($verify.Entries.Count -ne $manifest.Count+1){throw 'Archive entry count mismatch'}
 foreach($record in $manifest){
  $entry=$verify.GetEntry($record.Path);if($null -eq $entry){throw ('Missing entry '+$record.Path)}
  $inputStream=$entry.Open();$sha=[Security.Cryptography.SHA256]::Create()
  try{if([BitConverter]::ToString($sha.ComputeHash($inputStream)).Replace('-','') -ne $record.Sha256){throw ('Archive checksum mismatch '+$record.Path)}}finally{$sha.Dispose();$inputStream.Dispose()}
 }
}finally{$verify.Dispose()}
$hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $ProjectRoot ('outputs\SHA256SUMS-'+$SnapshotName.ToUpperInvariant()+'-SOURCE-'+$SnapshotDate+'.txt')) -Value ($hash+'  '+[IO.Path]::GetFileName($zip)) -Encoding ASCII
Write-Output ('PASS clean staged-source build and '+$manifest.Count+' verified files: '+$zip)
Write-Output ('SHA256 '+$hash)
Write-Output ('Bytes '+(Get-Item -LiteralPath $zip).Length)
