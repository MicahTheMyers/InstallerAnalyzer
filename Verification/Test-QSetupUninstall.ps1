param([string]$Repository=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
$text=Get-Content -LiteralPath (Join-Path $Repository 'InstallerAnalyzer\Services\SandboxIssRecorder.cs') -Raw
$core=[regex]::Match($text,'(?s)function Split-Command.*?(?=\r?\nfunction )').Value
$normalizer=[regex]::Match($text,'(?s)function Normalize-QSetupUninstallCommand.*?(?=\r?\nfunction )').Value
if(-not $core -or -not $normalizer){throw 'Production helpers missing'}
. ([scriptblock]::Create($core))
. ([scriptblock]::Create($normalizer))
$count=0
function Check($ok,[string]$name){if(-not $ok){throw $name};$script:count++;Write-Output "PASS $name"}
$InstallerKind='QSetup'
$command='"C:\Program Files (x86)\Ensoft\Lpile2022\Uninstall_Lpile2022_12.exe" /silent'
Check ((Normalize-QSetupUninstallCommand $command) -eq ($command+' /Hide')) 'QSetup registered quiet command also hides removal wizard'
Check ((Normalize-QSetupUninstallCommand ($command+' /HIDE')) -eq ($command+' /HIDE')) 'Existing hidden switch is preserved without duplication'
Check ((Normalize-QSetupUninstallCommand ($command+' /product=7')) -eq ($command+' /product=7 /Hide')) 'Vendor product selector and silent arguments are preserved'
Check ([string]::IsNullOrEmpty((Normalize-QSetupUninstallCommand ''))) 'Empty command remains empty for discovery'
$InstallerKind='Nsis'
Check ((Normalize-QSetupUninstallCommand $command) -eq $command) 'Other installer families do not receive QSetup flags'
Check ($text.Contains('$uninstallCommand=Normalize-QSetupUninstallCommand ([string]$primary.QuietUninstallString)')) 'Initial and final uninstall share the normalized validated command'
Write-Output "RESULT: $count passed, 0 failed"
