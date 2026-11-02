param([Parameter(Mandatory=$true)][string]$BuildFolder,[Parameter(Mandatory=$true)][string]$DotNetPath,[string]$SourceDirectory='D:\',[string]$ProjectRoot,[string]$OutputFolder)
$ErrorActionPreference='Stop'
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
$verification=Join-Path $BuildFolder 'Verification.dll'
if(-not (Test-Path -LiteralPath $verification)){throw 'Built verification assembly required'}
if(-not $OutputFolder){$OutputFolder=Join-Path $ProjectRoot ('verification-results\payload-retests-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $OutputFolder){throw 'Retest output directory must be new'}
New-Item -ItemType Directory -Path $OutputFolder | Out-Null
$wsb=Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wsb.exe'
function Assert-EmptySandbox {
  $state=(& $wsb list --raw | Out-String) | ConvertFrom-Json
  if($LASTEXITCODE -ne 0 -or @($state.WindowsSandboxEnvironments).Count){throw 'Confirmed empty Sandbox state required before continuing'}
}
Assert-EmptySandbox
$cases=@(
  @{Name='ccsetup630.exe';Mode='--live-runner'},
  @{Name='Claude Setup.exe';Mode='--live'},
  @{Name='MSTeamsSetup.exe';Mode='--live'},
  @{Name='ChromeSetup.exe';Mode='--live'}
)
$records=@()
foreach($case in $cases){
  Assert-EmptySandbox
  $source=Join-Path $SourceDirectory $case.Name
  $hash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
  $folder=Join-Path $OutputFolder ([IO.Path]::GetFileNameWithoutExtension($case.Name))
  $log=Join-Path $OutputFolder ($case.Name+'.log')
  Write-Output ('RETEST '+$case.Name+' '+$case.Mode)
  $retestErrorMode=$ErrorActionPreference
  try{$ErrorActionPreference='Continue'; & $DotNetPath $verification $folder $case.Mode $source *> $log; $code=$LASTEXITCODE}
  finally{$ErrorActionPreference=$retestErrorMode}
  $after=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
  $records+=[pscustomobject]@{Installer=$case.Name;Mode=$case.Mode;ExitCode=$code;Folder=$folder;Log=$log;Sha256Before=$hash;Sha256After=$after;SourcePreserved=($hash -eq $after)}
  [IO.File]::WriteAllText((Join-Path $OutputFolder 'retest-summary.json'),($records | ConvertTo-Json -Depth 5))
  if($hash -ne $after){throw ('Source bytes changed: '+$case.Name)}
  Assert-EmptySandbox
  Write-Output ('RETEST RESULT '+$case.Name+': exit '+$code+'; source hash preserved')
}
Write-Output ('RETESTS COMPLETE: '+$OutputFolder)
