param([Parameter(Mandatory=$true)][string]$FixtureScript,[Parameter(Mandatory=$true)][string]$PublishedFolder,[Parameter(Mandatory=$true)][string]$OutputFolder,[int]$TimeoutSeconds=180)
$ErrorActionPreference='Stop'
$wsb=Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wsb.exe'
function Ids {$state=(& $wsb list --raw|Out-String)|ConvertFrom-Json;if($LASTEXITCODE -ne 0){throw 'Cannot confirm Sandbox state'};return @($state.WindowsSandboxEnvironments|ForEach-Object {$_.Id})}
if(@(Ids).Count){throw 'An existing Sandbox is running; it was left untouched'}
if(Test-Path -LiteralPath $OutputFolder){throw 'Output directory must be new'}
$inputPath=Join-Path $OutputFolder 'Input';$outputPath=Join-Path $OutputFolder 'Output';New-Item -ItemType Directory -Path $inputPath,$outputPath|Out-Null
Copy-Item -LiteralPath $FixtureScript -Destination (Join-Path $inputPath 'fixture.ps1')
function Map([string]$hostPath,[string]$guestPath,[bool]$readOnly){return '<MappedFolder><HostFolder>'+[Security.SecurityElement]::Escape([IO.Path]::GetFullPath($hostPath))+'</HostFolder><SandboxFolder>'+$guestPath+'</SandboxFolder><ReadOnly>'+$readOnly.ToString().ToLowerInvariant()+'</ReadOnly></MappedFolder>'}
$config='<Configuration><MappedFolders>'+(Map $inputPath 'C:\InstallerInput' $true)+(Map $PublishedFolder 'C:\PublishedVerifier' $true)+(Map $outputPath 'C:\InstallerOutput' $false)+'</MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\InstallerInput\fixture.ps1</Command></LogonCommand></Configuration>'
$path=Join-Path $OutputFolder 'fixture.wsb';[IO.File]::WriteAllText($path,$config)
try{
  Start-Process -FilePath $path -WindowStyle Hidden
  $until=[DateTime]::UtcNow.AddSeconds([Math]::Min(600,[Math]::Max(15,$TimeoutSeconds)))
  while(-not (Test-Path (Join-Path $outputPath 'done.txt')) -and [DateTime]::UtcNow -lt $until){Start-Sleep -Seconds 2}
  foreach($file in @('stdout.txt','stderr.txt','error.txt')){if(Test-Path (Join-Path $outputPath $file)){Get-Content (Join-Path $outputPath $file)|Write-Output}}
  if(-not (Test-Path (Join-Path $outputPath 'PASS.txt'))){throw ('Guest fixture failed: '+$OutputFolder)}
  Get-Content (Join-Path $outputPath 'PASS.txt')|Write-Output
}finally{foreach($id in @(Ids)){& $wsb stop --id $id|Out-Null}}
