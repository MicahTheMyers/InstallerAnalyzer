param([string]$ProjectRoot)
$ErrorActionPreference='Stop'
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxNetFx3Provisioning.cs'))
$body=[regex]::Match($source,'(?s)NetFx3ProvisioningScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
# Load function definitions only. All servicing, guest queries and runtime execution are mocked.
$ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)|ForEach-Object {Invoke-Expression $_.Extent.Text}
$count=0
function Check($test,$name){if(-not $test){throw ('FAIL '+$name)};$script:count++;'PASS '+$name}
function Reset {
 $script:result=@{RebootRequired=$false;UiTextEvidence=@();NetFx3Provisioning=[ordered]@{Status='Not required';Detail='';Evidence='';RuntimeVerified=$false;Provisioned=$false;Attempted=$false;ExitCode=$null;RequiresFullWindowsVM=$false;RestartNeeded=$false}}
 $script:NetFx3Terminal=$false;$script:NetFx3Attempted=$false;$script:Calls=0;$script:Queries=0;$script:Build=26100;$script:RuntimeGood=$true;$script:Exit=0;$script:Before='Disabled with Payload Removed';$script:After='Enabled';$script:Guest=$true;$script:Offline=$false;$script:Args='';$script:CoreCalls=0;$script:Server='';$script:UseServer=0;$script:PolicyWrites=0;$script:Restarts=0;$script:RepairManifest=$false
}
function Get-CimInstance {param($ClassName) [pscustomobject]@{Model=$(if($script:Guest){'Virtual Machine'}else{'Physical computer'})}}
function Test-Path {param($LiteralPath) if($LiteralPath -eq 'C:\InstallerInput\NetFx3RepairSource\source-manifest.json'){return $script:RepairManifest};if($LiteralPath -eq 'C:\InstallerInput\NetFx3Source'){return $script:Offline};return $true}
function Get-ItemProperty {param($LiteralPath) [pscustomobject]@{CurrentBuild=$script:Build;WUServer=$script:Server;UseWUServer=$script:UseServer}}
function Set-ItemProperty {param($LiteralPath,$Name,$Value,$ErrorAction) $script:PolicyWrites++; if($Name -ne 'UseWUServer' -or $Value -ne 0){throw 'Unexpected policy mutation'}}
function Restart-Service {param($Name,[switch]$Force,$ErrorAction) if($Name -ne 'wuauserv'){throw 'Unexpected service restart'};$script:Restarts++}
function Write-Checkpoint {param($stage)}
function Get-NetFx3FeatureState {$script:Queries++;if($script:Queries -eq 1){return $script:Before};return $script:After}
function Test-NetFx3Runtime {return $script:RuntimeGood}
function Get-NetFx3Source {param($build) if($script:Offline){return 'C:\InstallerInput\NetFx3Source'};return ''}
function Invoke-NetFx3Command {param($file,$arguments,$log,$seconds) $script:Calls++;$script:Args=$arguments;[pscustomobject]@{ExitCode=$script:Exit;Text='fixture';TimedOut=($script:Exit -eq -2)}}
function FailExpected {param($fragment) try{Ensure-NetFx3 'This application requires .NET Framework 3.5';throw 'Expected failure not raised'}catch{Check ($_.Exception.Message -like ('*'+$fragment+'*')) ('Failure explained: '+$fragment)}}
Reset;Ensure-NetFx3 '';Check ($script:Calls -eq 0 -and $script:Queries -eq 0) 'No requirement means no runtime/servicing queries'
Reset;$script:Guest=$false;FailExpected 'restricted';Check ($script:Calls -eq 0) 'Host context never serviced'
Reset;Ensure-NetFx3 'CLR v2.0 metadata';Check ($result.NetFx3Provisioning.Provisioned -and $result.NetFx3Provisioning.RuntimeVerified -and $script:Calls -eq 1) 'Single verified provisioning attempt'
Ensure-NetFx3 'same requirement';Check ($script:Calls -eq 1) 'Repeated requests do not reinstall verified runtime'
Check ($script:Args -like '*/NoRestart*' -and $script:Args -notlike '*Source*') 'Online command cannot reboot and uses Windows Update default'
Reset;$script:Offline=$true;Ensure-NetFx3 'explicit requirement';Check ($script:Args -like '*/LimitAccess /Source:"C:\InstallerInput\NetFx3Source"') 'Optional guest source uses DISM offline mode'
foreach($code in @(12006,14098,-2)) {Reset;$script:Exit=$code;FailExpected 'No installer retry';Check ($result.NetFx3Provisioning.Blocked -and -not $result.NetFx3Provisioning.RequiresFullWindowsVM -and -not $result.NetFx3Provisioning.Provisioned) ('Failed/timed-out command is not provisioned: '+$code);FailExpected 'No installer retry';Check ($script:Calls -eq 1) 'Failure never loops servicing'}
Reset;$script:Exit=3010;FailExpected 'REBOOT REQUIRED';Check ($result.RebootRequired -and -not $result.NetFx3Provisioning.RuntimeVerified) '3010 stops installer until guest reboot'
Reset;$script:Before='Enable Pending';FailExpected 'REBOOT REQUIRED';Check ($script:Calls -eq 0) 'Pending feature is not reprovisioned'
Reset;$script:After='Disabled';FailExpected 'not both verified';Check (-not $result.NetFx3Provisioning.Provisioned) 'Exit zero alone is not success'
Reset;$script:RuntimeGood=$false;FailExpected 'not both verified';Check (-not $result.NetFx3Provisioning.RuntimeVerified) 'Runtime probe failure prevents installer continuation'
Reset;$script:Before='Enabled';Ensure-NetFx3 'CLR2';Check ($script:Calls -eq 0 -and $result.NetFx3Provisioning.Status -eq 'Already available') 'Existing runtime verified without servicing'
Reset;$script:Before='Unknown';FailExpected 'feature state';Check ($script:Calls -eq 0) 'Unknown feature state never triggers blind install'
Reset;$script:Build=28000;$script:RuntimeGood=$false;FailExpected 'standalone installer';Check ($script:Calls -eq 0 -and $script:Queries -eq 0) 'Standalone-only builds never use NetFx3 DISM'
foreach($text in @('missing DLL','.NET Framework 4.8 is required','.NET Framework 3.5 is optional','.NET Framework 3.5 is not required')){Check (-not(Test-NetFx3RequirementText $text)) ('No unrelated provisioning trigger: '+$text)}
$engine=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxIssRecorder.cs'))
$wrapper=[regex]::Match($engine,'(?s)function Invoke-InstallCandidate\(.*?\r?\n}\r?\n').Value
Invoke-Expression $wrapper
function Invoke-InstallCandidateCore {param($candidate,$target) $script:CoreCalls++;if($script:CoreCalls -eq 1){$script:result.UiTextEvidence+=@([pscustomobject]@{Labels=@('This application requires .NET Framework 3.5')});return [pscustomobject]@{ExitCode=1603;UiDetected=$true}};return [pscustomobject]@{ExitCode=0;UiDetected=$false}}
Reset;$reply=Invoke-InstallCandidate ([pscustomobject]@{Kind='Exe'})
Check ($reply.ExitCode -eq 0 -and $script:CoreCalls -eq 2 -and $script:Calls -eq 1) 'One installer retry after verified provisioning'
Reset;$script:Exit=12006;try{Invoke-InstallCandidate ([pscustomobject]@{Kind='Exe'})|Out-Null}catch{};Check ($script:CoreCalls -eq 1 -and $script:Calls -eq 1) 'Failed provisioning does not retry installer'
foreach($candidateServer in @('https://real-wsus.example:8531','http://127.0.0.1:80','other-server:80')){
 Reset;$script:UseServer=1;$script:Server=$candidateServer;Prepare-NetFx3Sandbox
 Check ($script:PolicyWrites -eq 0 -and $script:Restarts -eq 0) ('Preserve non-placeholder update source: '+$candidateServer)
}
Reset;$script:UseServer=1;$script:Server='127.0.0.1:80';Prepare-NetFx3Sandbox
Check ($script:PolicyWrites -eq 1 -and $script:Restarts -eq 1 -and $result.NetFx3Provisioning.GuestUpdateSourceAdjusted) 'Repair exact Sandbox placeholder once using guest update service'
Reset;$script:UseServer=0;$script:Server='127.0.0.1:80';Prepare-NetFx3Sandbox
Check ($script:PolicyWrites -eq 0) 'Already unselected placeholder needs no policy mutation'
function Get-Content {param($LiteralPath,[switch]$Raw) return '{"Schema":99,"Entries":[],"Bytes":0}'}
Reset;$script:UseServer=1;$script:Server='127.0.0.1:80';$script:RepairManifest=$true
try{Prepare-NetFx3Sandbox;throw 'Expected manifest rejection'}catch{Check ($_.Exception.Message -like '*Invalid NetFx3 repair-source manifest*' -and $script:PolicyWrites -eq 0) 'Invalid source manifest rejected before guest policy changes'}
function Get-Content {param($LiteralPath,[switch]$Raw) return '{"Schema":1,"Entries":[{"Component":"..\\Windows\\System32","Files":[]}],"Bytes":0}'}
Reset;$script:UseServer=1;$script:Server='127.0.0.1:80';$script:RepairManifest=$true
try{Prepare-NetFx3Sandbox;throw 'Expected component rejection'}catch{Check ($_.Exception.Message -like '*Invalid NetFx3 component identity*' -and $script:PolicyWrites -eq 0) 'Component traversal rejected before source reads or policy changes'}
"RESULT: $count passed, 0 failed"
