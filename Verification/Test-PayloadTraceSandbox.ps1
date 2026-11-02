param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[string]$OutputFolder,[string]$FixtureScript=(Join-Path $PSScriptRoot 'PayloadTraceSandboxFixture.ps1'))
$ErrorActionPreference='Stop'
$wsb=Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wsb.exe'
function SandboxIds {
  $state=(& $wsb list --raw | Out-String) | ConvertFrom-Json
  if($LASTEXITCODE -ne 0){throw 'Cannot query Sandbox state'}
  return @($state.WindowsSandboxEnvironments | ForEach-Object {$_.Id})
}
if(@(SandboxIds).Count){throw 'Fresh isolated Sandbox required; existing session left untouched'}
if(-not $OutputFolder){$OutputFolder=Join-Path $ProjectRoot ('verification-results\trace-sandbox-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $OutputFolder){throw 'Fixture output folder must be new'}
$inputPath=Join-Path $OutputFolder 'Input';$outputPath=Join-Path $OutputFolder 'Output'
New-Item -ItemType Directory -Path $inputPath,$outputPath | Out-Null
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxPayloadTrace.cs'))
$worker=[regex]::Match($source,'(?s)PayloadTraceWorkerScript = """\r?\n(.*?)\r?\n""";')
if(-not $worker.Success){throw 'Worker source not found'}
[IO.File]::WriteAllText((Join-Path $inputPath 'worker.ps1'),$worker.Groups[1].Value)
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'InstallerAnalyzer\Services\PayloadTraceReducer.cs') -Destination (Join-Path $inputPath 'PayloadTraceReducer.cs')
Copy-Item -LiteralPath $FixtureScript -Destination (Join-Path $inputPath 'fixture.ps1')
$config='<Configuration><MappedFolders><MappedFolder><HostFolder>'+[Security.SecurityElement]::Escape($inputPath)+'</HostFolder><SandboxFolder>C:\InstallerInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder><MappedFolder><HostFolder>'+[Security.SecurityElement]::Escape($outputPath)+'</HostFolder><SandboxFolder>C:\InstallerOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder></MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\InstallerInput\fixture.ps1</Command></LogonCommand></Configuration>'
$configPath=Join-Path $OutputFolder 'fixture.wsb';[IO.File]::WriteAllText($configPath,$config)
try{
  Start-Process -FilePath $configPath -WindowStyle Hidden
  $until=[DateTime]::UtcNow.AddSeconds(120)
  while(-not (Test-Path -LiteralPath (Join-Path $outputPath 'done.txt')) -and [DateTime]::UtcNow -lt $until){Start-Sleep -Seconds 2}
  if(-not (Test-Path -LiteralPath (Join-Path $outputPath 'PASS.txt'))){
    if(Test-Path -LiteralPath (Join-Path $outputPath 'error.txt')){Get-Content -LiteralPath (Join-Path $outputPath 'error.txt') | Write-Output}
    throw ('Real Sandbox trace fixture failed; artifacts: '+$OutputFolder)
  }
  Get-Content -LiteralPath (Join-Path $outputPath 'PASS.txt') | Write-Output
  Write-Output ('PASS real Sandbox trace fixture: '+$OutputFolder)
}finally{foreach($id in @(SandboxIds)){& $wsb stop --id $id | Out-Null}}
