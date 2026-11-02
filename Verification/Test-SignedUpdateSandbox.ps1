param([Parameter(Mandatory=$true)][string]$PublishedFolder,[string]$ProjectRoot,[string]$OutputFolder,[switch]$UntrustedOnly,[switch]$AllowGuestTestTrust)
$ErrorActionPreference='Stop'
if(-not $UntrustedOnly -and -not $AllowGuestTestTrust){throw 'Explicit guest-only certificate trust authorization required; use -UntrustedOnly to leave trust stores unchanged.'}
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
$wsb=Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wsb.exe'
function Ids {$state=(& $wsb list --raw | Out-String)|ConvertFrom-Json;if($LASTEXITCODE -ne 0){throw 'Cannot query Sandbox state'};return @($state.WindowsSandboxEnvironments|ForEach-Object {$_.Id})}
if(@(Ids).Count){throw 'Fresh isolated Sandbox required; existing session left untouched'}
if(-not $OutputFolder){$OutputFolder=Join-Path $ProjectRoot ('verification-results\signed-handoff-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $OutputFolder){throw 'Fixture directory must be new'}
$inputPath=Join-Path $OutputFolder 'Input';$outputPath=Join-Path $OutputFolder 'Output'
New-Item -ItemType Directory -Path $inputPath,$outputPath | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'SignedUpdateSandboxFixture.ps1') -Destination (Join-Path $inputPath 'fixture.ps1')
if($AllowGuestTestTrust){[IO.File]::WriteAllText((Join-Path $inputPath 'permit-guest-test-trust.txt'),'Explicit permission for synthetic test certificates in this disposable guest only.')}
function Map([string]$hostPath,[string]$guestPath,[bool]$readOnly){return '<MappedFolder><HostFolder>'+[Security.SecurityElement]::Escape($hostPath)+'</HostFolder><SandboxFolder>'+$guestPath+'</SandboxFolder><ReadOnly>'+$readOnly.ToString().ToLowerInvariant()+'</ReadOnly></MappedFolder>'}
$mode=if($UntrustedOnly){' -UntrustedOnly'}else{' -AllowGuestTestTrust'}
$config='<Configuration><MappedFolders>'+(Map $inputPath 'C:\InstallerInput' $true)+(Map ([IO.Path]::GetFullPath($PublishedFolder)) 'C:\PublishedVerifier' $true)+(Map $outputPath 'C:\InstallerOutput' $false)+'</MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\InstallerInput\fixture.ps1'+$mode+'</Command></LogonCommand></Configuration>'
$configPath=Join-Path $OutputFolder 'signing-fixture.wsb';[IO.File]::WriteAllText($configPath,$config)
try{
  Start-Process -FilePath $configPath -WindowStyle Hidden
  $until=[DateTime]::UtcNow.AddSeconds(180)
  while(-not (Test-Path -LiteralPath (Join-Path $outputPath 'done.txt')) -and [DateTime]::UtcNow -lt $until){Start-Sleep -Seconds 2}
  if(-not (Test-Path -LiteralPath (Join-Path $outputPath 'PASS.txt'))){
    foreach($file in @('error.txt','handoff-stderr.txt')){if(Test-Path (Join-Path $outputPath $file)){Get-Content (Join-Path $outputPath $file)|Write-Output}}
    throw ('Signed updater fixture failed; evidence: '+$OutputFolder)
  }
  Get-Content (Join-Path $outputPath 'handoff-stdout.txt') | Write-Output
  Write-Output ('PASS isolated real-Authenticode fixture: '+$OutputFolder)
}finally{foreach($id in @(Ids)){& $wsb stop --id $id | Out-Null}}
