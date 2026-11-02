param([Parameter(Mandatory=$true)][string]$ResultRoot,[string]$SourceFolder,[string]$GuestScriptPath)
$ErrorActionPreference='Stop'
$wsb=Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wsb.exe'
function Ids { $text=& $wsb list --raw; if($LASTEXITCODE -ne 0){throw 'Sandbox inventory unavailable'}; @((($text|Out-String)|ConvertFrom-Json).WindowsSandboxEnvironments|ForEach-Object Id) }
if(@(Ids).Count){throw 'Existing Sandbox left untouched'}
$inputFolder=Join-Path $ResultRoot 'Input';$outputFolder=Join-Path $ResultRoot 'Output'
New-Item -ItemType Directory -Path $inputFolder,$outputFolder -Force|Out-Null
$source=[IO.File]::ReadAllText((Join-Path (Split-Path $PSScriptRoot -Parent) 'InstallerAnalyzer\Services\SandboxNetFx3Provisioning.cs'))
$helper=[regex]::Match($source,'(?s)NetFx3ProvisioningScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
[IO.File]::WriteAllText((Join-Path $inputFolder 'helper.ps1'),$helper)
if($SourceFolder){$cache=Join-Path $inputFolder 'NetFx3Source';New-Item -ItemType Directory -Path $cache|Out-Null;Copy-Item (Join-Path $SourceFolder '*NetFx3*.cab') $cache}
@'
$ErrorActionPreference='Stop'
. C:\InstallerInput\helper.ps1
$result=[ordered]@{RebootRequired=$false;NetFx3Provisioning=[ordered]@{Status='Not required';Evidence='';Detail='';Attempted=$false;Provisioned=$false;RuntimeVerified=$false;RequiresFullWindowsVM=$false;RestartNeeded=$false;ExitCode=$null}}
function Set-AnalysisHeartbeat($stage){Set-Content C:\InstallerOutput\analysis-heartbeat.txt $stage}
function Write-Checkpoint($stage){$result|ConvertTo-Json -Depth 6|Set-Content C:\InstallerOutput\checkpoint.json}
Set-AnalysisHeartbeat 'NetFx3 helper fixture started'
try {Ensure-NetFx3 'This application requires .NET Framework 3.5'} catch {$result['Failure']=$_.Exception.Message}
$result|ConvertTo-Json -Depth 6|Set-Content C:\InstallerOutput\result.json
'@ | Set-Content (Join-Path $inputFolder 'Record-Iss.ps1')
if($GuestScriptPath){Copy-Item -LiteralPath $GuestScriptPath -Destination (Join-Path $inputFolder 'Record-Iss.ps1') -Force}
$i=[Security.SecurityElement]::Escape($inputFolder);$o=[Security.SecurityElement]::Escape($outputFolder)
$xml="<Configuration><vGPU>Disable</vGPU><MappedFolders><MappedFolder><HostFolder>$i</HostFolder><SandboxFolder>C:\InstallerInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder><MappedFolder><HostFolder>$o</HostFolder><SandboxFolder>C:\InstallerOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder></MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\InstallerInput\Record-Iss.ps1</Command></LogonCommand></Configuration>"
$config=Join-Path $ResultRoot 'netfx3.wsb';[IO.File]::WriteAllText($config,$xml)
$owned=$null
try {
 Start-Process -FilePath $config -WindowStyle Hidden
 $deadline=[DateTime]::UtcNow.AddMinutes(15)
 while([DateTime]::UtcNow -lt $deadline){
  if(-not $owned){$current=@(Ids);if($current.Count -gt 1){throw 'Ambiguous Sandbox ownership'};if($current.Count -eq 1){$owned=$current[0];$owned|Set-Content (Join-Path $ResultRoot 'owned-sandbox-id.txt')}}
  if(Test-Path (Join-Path $outputFolder 'result.json')){break}
  Start-Sleep 2
 }
 if(-not(Test-Path (Join-Path $outputFolder 'result.json'))){throw 'No bounded guest result; no runtime success claimed'}
 Get-Content (Join-Path $outputFolder 'result.json')
} finally {
 if($owned -and (@(Ids) -contains $owned)){& $wsb stop --id $owned|Out-Null}
 @(Ids)|ConvertTo-Json|Set-Content (Join-Path $ResultRoot 'remaining-environments.json')
}
