param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[string]$VendorFolder='D:\InstallerAnalyzer-Test-Inputs\RSPile-3.033',[ValidateSet('/s','/s /a /s')][string]$PrefixArguments='/s /a /s')
$ErrorActionPreference='Stop'
$config=[ordered]@{InstallerFile='rsp3033j11s.exe';ProductName='RSPile';ProductVersion='3.033';Publisher='Rocscience';Sha256='836D1500D36E2885F58CEB082616766A92867EFBDA95290B5986266B3B4EF32F';PrefixArguments=$PrefixArguments}
$wsb=Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wsb.exe'
function Ids {$state=(& $wsb list --raw|Out-String)|ConvertFrom-Json;if($LASTEXITCODE -ne 0){throw 'Cannot confirm Sandbox state'};return @($state.WindowsSandboxEnvironments|ForEach-Object {$_.Id})}
if(@(Ids).Count){throw 'An existing Sandbox was left untouched'}
$root=Join-Path $ProjectRoot ('verification-results\installshield-vendor-'+[guid]::NewGuid().ToString('N'))
$inputPath=Join-Path $root 'Input';$outputPath=Join-Path $root 'Output';New-Item -ItemType Directory -Path $inputPath,$outputPath|Out-Null
Set-Content (Join-Path $ProjectRoot 'outputs\InstallShield-Vendor-Live-Location.txt') $root
$engineRoot=(Get-Content (Join-Path $ProjectRoot 'outputs\Bits-Completion-Test-Location.txt') -Raw).Trim()
Copy-Item -LiteralPath (Join-Path $engineRoot 'roadmap\Generated-InstallShield.ps1') -Destination (Join-Path $inputPath 'DiscoveryEngine.ps1')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'InstallShieldVendorReplayFixture.ps1') -Destination (Join-Path $inputPath 'fixture.ps1')
$config|ConvertTo-Json|Set-Content (Join-Path $inputPath 'replay-config.json')
$before=Get-FileHash -LiteralPath (Join-Path $VendorFolder $config.InstallerFile)
function Map([string]$hostPath,[string]$guestPath,[bool]$readOnly){'<MappedFolder><HostFolder>'+[Security.SecurityElement]::Escape([IO.Path]::GetFullPath($hostPath))+'</HostFolder><SandboxFolder>'+$guestPath+'</SandboxFolder><ReadOnly>'+$readOnly.ToString().ToLowerInvariant()+'</ReadOnly></MappedFolder>'}
$xml='<Configuration><MappedFolders>'+(Map $inputPath 'C:\InstallerInput' $true)+(Map $VendorFolder 'C:\PublishedVerifier' $true)+(Map $outputPath 'C:\InstallerOutput' $false)+'</MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\InstallerInput\fixture.ps1</Command></LogonCommand></Configuration>'
$path=Join-Path $root 'fixture.wsb';[IO.File]::WriteAllText($path,$xml);$ownedId=$null
try {
 Start-Process -FilePath $path -WindowStyle Hidden
 $until=[DateTime]::UtcNow.AddMinutes(15)
 while(-not(Test-Path (Join-Path $outputPath 'done.txt')) -and [DateTime]::UtcNow -lt $until){
   if($null -eq $ownedId){$current=@(Ids);if($current.Count -eq 1){$ownedId=$current[0]}elseif($current.Count -gt 1){throw 'Sandbox ownership ambiguous; unrelated sessions will be left untouched'}}
   Start-Sleep -Seconds 2
 }
 if(Test-Path (Join-Path $outputPath 'error.txt')){Get-Content (Join-Path $outputPath 'error.txt')|Write-Output}
 if(-not(Test-Path (Join-Path $outputPath 'PASS.txt'))){throw ('Vendor replay did not pass: '+$root)}
 Get-Content (Join-Path $outputPath 'PASS.txt')|Write-Output
}finally {
 if($null -ne $ownedId -and @(Ids) -contains $ownedId){& $wsb stop --id $ownedId|Out-Null}
 if((Get-FileHash -LiteralPath (Join-Path $VendorFolder $config.InstallerFile)).Hash -ne $before.Hash){throw 'USB input hash changed'}
 Write-Output ('USB source preserved; artifacts: '+$root)
}
