param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[string]$VendorFolder='D:\InstallerAnalyzer-Test-Inputs\RSPile-3.033')
$ErrorActionPreference='Stop'
$expected='836D1500D36E2885F58CEB082616766A92867EFBDA95290B5986266B3B4EF32F'
$source=Join-Path $VendorFolder 'rsp3033j11s.exe'
if((Get-FileHash -LiteralPath $source).Hash -ne $expected){throw 'Unexpected installer bytes'}
$testRoot=(Get-Content (Join-Path $ProjectRoot 'outputs\InstallShield-Recorder-Test-Location.txt') -Raw).Trim()
$root=Join-Path $ProjectRoot ('verification-results\iss-record-live-'+[guid]::NewGuid().ToString('N'))
$inputPath=Join-Path $root 'Input';$outputPath=Join-Path $root 'Output'
New-Item -ItemType Directory -Path $inputPath,$outputPath | Out-Null
Copy-Item -LiteralPath $source -Destination (Join-Path $inputPath 'rsp3033j11s.exe')
Copy-Item -LiteralPath (Join-Path $testRoot 'roadmap\Generated-RSPile-Recorder.ps1') -Destination (Join-Path $inputPath 'Record-Iss.ps1')
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'InstallerAnalyzer\Services\PayloadTraceReducer.cs') -Destination $inputPath
# No vendor response file is mapped or copied into this recording run.
$guard=@'
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount'){throw 'Disposable Sandbox account required'}
try {
 if((Get-FileHash -LiteralPath 'C:\InstallerInput\rsp3033j11s.exe').Hash -ne '836D1500D36E2885F58CEB082616766A92867EFBDA95290B5986266B3B4EF32F'){throw 'Guest installer hash mismatch'}
 & 'C:\InstallerInput\Record-Iss.ps1'
}catch{$_ | Out-String | Set-Content 'C:\InstallerOutput\fixture-error.txt'}
'@
[IO.File]::WriteAllText((Join-Path $inputPath 'guard.ps1'),$guard)
function Map([string]$hostPath,[string]$guestPath,[bool]$readOnly){'<MappedFolder><HostFolder>'+[Security.SecurityElement]::Escape([IO.Path]::GetFullPath($hostPath))+'</HostFolder><SandboxFolder>'+$guestPath+'</SandboxFolder><ReadOnly>'+$readOnly.ToString().ToLowerInvariant()+'</ReadOnly></MappedFolder>'}
$xml='<Configuration><MappedFolders>'+(Map $inputPath 'C:\InstallerInput' $true)+(Map $outputPath 'C:\InstallerOutput' $false)+'</MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\InstallerInput\guard.ps1</Command></LogonCommand></Configuration>'
[IO.File]::WriteAllText((Join-Path $root 'record.wsb'),$xml)
Get-ChildItem -LiteralPath $VendorFolder -File | Get-FileHash | Select-Object Path,Hash | ConvertTo-Json | Set-Content (Join-Path $root 'usb-before.json')
Set-Content (Join-Path $ProjectRoot 'outputs\InstallShield-Recording-Live-Location.txt') $root
Write-Output ('Prepared recording fixture; no installer launched: '+$root)
