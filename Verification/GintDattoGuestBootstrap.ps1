$ErrorActionPreference='Stop'
. C:\InstallerInput\helper.ps1
$script:UseGintPrerequisites=$true
$result=[ordered]@{Stage='Preparing disposable guest';NetFx3Provisioning=[ordered]@{Status='Not required';Evidence='';Detail='';Attempted=$false;Provisioned=$false;RuntimeVerified=$false;RequiresFullWindowsVM=$false;RestartNeeded=$false;ExitCode=$null}}
function Write-Checkpoint($stage){$result.Stage=$stage;$result|ConvertTo-Json -Depth 6|Set-Content C:\InstallerOutput\checkpoint.json}
function Set-AnalysisHeartbeat($stage){Set-Content C:\InstallerOutput\heartbeat.txt ((Get-Date).ToString('o')+' '+$stage)}
try {
 Ensure-SandboxInstallerCompatibility $true
 Ensure-GintWindowsCatalog
 Ensure-GintVbScript
 Ensure-NetFx3 'gINT Datto replay guest requires .NET Framework 3.5'
 # Guest preparation is separate from the exported target script. No OS image files ship in the kit.
 Expand-Archive -LiteralPath C:\InstallerInput\kit.zip -DestinationPath C:\GintDattoKit
 Write-Checkpoint 'Ready for LocalSystem Datto component replay'
 Set-Content C:\InstallerOutput\datto-ready.flag 'ready'
 $end=(Get-Date).AddMinutes(25)
 while((Get-Date) -lt $end){
  if(Test-Path C:\InstallerOutput\datto-result.json){
   try{$final=Get-Content C:\InstallerOutput\datto-result.json -Raw|ConvertFrom-Json;$final|ConvertTo-Json -Depth 7|Set-Content C:\InstallerOutput\result.json;exit}catch{}
  }
  Start-Sleep 2
 }
 throw 'LocalSystem replay exceeded its execution budget.'
}catch{@{Passed=$false;Error=$_.Exception.Message}|ConvertTo-Json|Set-Content C:\InstallerOutput\result.json}
