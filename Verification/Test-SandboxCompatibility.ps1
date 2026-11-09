$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\InstallerAnalyzer\Services\SandboxCompatibility.cs'))
$raw=[regex]::Match($source,'(?s)SandboxCompatibilityScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
. ([scriptblock]::Create($raw))
$originalUser=$env:USERNAME
$script:writes=0;$script:nativeCalls=0
function Set-ItemProperty {$script:writes++;throw 'Unexpected host registry write'}
function Invoke-NetFx3Command {$script:nativeCalls++;throw 'Unexpected native command'}
$result=@{}
Ensure-SandboxInstallerCompatibility $false
if($writes -or $nativeCalls -or $result.SandboxCompatibility.Requested){throw 'Disabled mode performed work'}
Write-Output 'PASS disabled mode performs no registry or native operations'
$result=@{};$env:USERNAME='FixtureHostAccount';$failed=$false
try {Ensure-SandboxInstallerCompatibility $true}catch{$failed=$_.Exception.Message -like 'SANDBOX COMPATIBILITY FAILED:*'}
if(-not $failed -or $writes -or $nativeCalls){throw 'Host guard failed'}
Write-Output 'PASS host context is rejected before any registry or native operation'
try {
 $env:USERNAME='WDAGUtilityAccount'
 function Get-CimInstance {[pscustomobject]@{Model='Virtual Machine'}}
 function Test-Path {$true}
 function Get-ItemProperty {[pscustomobject]@{VerifiedAndReputablePolicyState=$script:state}}
 function Set-ItemProperty {param($LiteralPath,$Name,$Value,$Type,$ErrorAction);$script:writes++;$script:state=$Value}
 function Invoke-NetFx3Command {$script:nativeCalls++;[pscustomobject]@{ExitCode=$script:exitCode;Text=$script:text;TimedOut=$false}}
 function Write-Checkpoint {}
 function Set-Content {}
 foreach($case in @('enabled','already-off','native-failure','operation-failure')){
  $result=@{};$script:writes=0;$script:nativeCalls=0
  $script:state=if($case -eq 'already-off'){0}else{1}
  $script:exitCode=if($case -eq 'native-failure'){5}else{0}
  $script:text=if($case -eq 'operation-failure'){'{"OperationResult":5}'}else{'{"OperationResult":0}'}
  $failed=$false
  try{Ensure-SandboxInstallerCompatibility $true}catch{$failed=$true}
  if($case -in @('enabled','already-off')){
   if($failed -or -not $result.SandboxCompatibility.Prepared -or $nativeCalls -ne 1 -or $state -ne 0){throw ('Preparation failed: '+$case)}
   if($case -eq 'already-off' -and $writes -ne 0){throw 'Already-off mode rewrote the registry'}
  }elseif(-not $failed -or $result.SandboxCompatibility.Prepared -or $result.SandboxCompatibility.Status -ne 'Failed'){throw ('Failure did not stop launch: '+$case)}
  Write-Output ('PASS mocked guest case: '+$case)
 }
}finally{$env:USERNAME=$originalUser}
Write-Output 'RESULT: 6 compatibility checks passed; no host registry or native operations executed'
