param([string]$ProjectRoot)
$ErrorActionPreference='Stop'
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxIssRecorder.cs'))
foreach($name in @('Split-Command','Select-Primary','Assert-BootstrapperDiscoveryComplete')){
 $body=[regex]::Match($source,'(?s)function '+[regex]::Escape($name)+'\(.*?\r?\n}\r?\n').Value
 if(-not $body){throw ('Missing function '+$name)}
 Invoke-Expression $body
}
$count=0
function Check($value,$name){if(-not $value){throw ('FAIL '+$name)};$script:count++;'PASS '+$name}
$Installer='C:\InstallerInput\Gint.exe'
$RequiredPrimaryProduct='gINT'
$client=[pscustomobject]@{Key='client';DisplayName='CONNECTION Client';Publisher='Bentley Systems, Incorporated';InstallLocation='C:\Client';UninstallString='client.exe /uninstall';QuietUninstallString='client.exe /quiet /uninstall';DisplayVersion='10.0'}
$access=[pscustomobject]@{Key='access';DisplayName='Microsoft Access database engine 2010';Publisher='Microsoft Corporation';UninstallString='msiexec.exe /x {00000000-0000-0000-0000-000000000001}';DisplayVersion='14.0'}
Check ($null -eq (Select-Primary @($client,$access))) 'Prerequisite-only gINT discovery has no primary application'
$product=[pscustomobject]@{Key='gint';DisplayName='gINT CONNECT Edition 10.02.00.04';Publisher='Bentley Systems, Incorporated';UninstallString='msiexec.exe /x {192AEB44-6992-44B8-B66D-D0781DC50768}';DisplayVersion='10.02.00.04'}
Check ((Select-Primary @($client,$access,$product)).Key -eq 'gint') 'Requested gINT wins over Bentley CONNECTION Client'
$other=[pscustomobject]@{Key='other';DisplayName='gINT CONNECT Edition';Publisher='Different vendor';UninstallString='other.exe'}
Check ($null -eq (Select-Primary @($other,$client))) 'Name match with unrelated publisher is rejected'
$partial=[pscustomobject]@{Key='partial';DisplayName='gINTerface helper';Publisher='Bentley Systems, Incorporated';UninstallString='helper.exe'}
Check ($null -eq (Select-Primary @($partial,$client))) 'Product token boundary prevents partial-name helper match'
try{Assert-BootstrapperDiscoveryComplete ([pscustomobject]@{TimedOut=$true;Primary=$product});throw 'Expected timeout rejection'}catch{Check ($_.Exception.Message -like 'BOOTSTRAPPER TIMEOUT:*') 'Timeout refuses lifecycle removal even when an entry has appeared'}
try{Assert-BootstrapperDiscoveryComplete ([pscustomobject]@{TimedOut=$false;Primary=$null});throw 'Expected missing primary rejection'}catch{Check ($_.Exception.Message -like 'PRIMARY APPLICATION NOT FOUND:*') 'Completed prerequisite-only run refuses lifecycle removal'}
Assert-BootstrapperDiscoveryComplete ([pscustomobject]@{TimedOut=$false;Primary=$product})
Check $true 'Completed expected-product discovery may proceed to validation'
$RequiredPrimaryProduct='';Check ((Select-Primary @($client)).Key -eq 'client') 'Unscoped discovery retains existing generic selection behavior'
$Installer='C:\InstallerInput\AcroRdrDCx642600322075_MUI.exe'
$RequiredPrimaryProduct='Adobe Acrobat'
$core=[pscustomobject]@{Key='APPX::AdobeAcrobatReaderCoreApp';DisplayName='AdobeAcrobatReaderCoreApp';Publisher='Adobe Inc.';WindowsInstaller=0;QuietUninstallString='Remove-AppxPackage';InstallLocation='C:\Program Files\WindowsApps';DisplayVersion='26.0.0.1'}
$acrobat=[pscustomobject]@{Key='acrobat-desktop';DisplayName='Adobe Acrobat (64-bit)';Publisher='Adobe';WindowsInstaller=1;ProductCode='{AC76BA86-1033-FF00-7760-BC15014EA700}';UninstallString='MsiExec.exe /I{AC76BA86-1033-FF00-7760-BC15014EA700}';DisplayVersion='26.003.22075'}
Check ($null -eq (Select-Primary @($core,$access))) 'Reader core AppX and unrelated MSI cannot satisfy the desktop target'
Check ((Select-Primary @($core,$acrobat)).Key -eq 'acrobat-desktop') 'Reader desktop MSI takes precedence over the auxiliary AppX'
$RequiredPrimaryProduct=''
$InstallerKind='WixBurn'
$Installer='C:\InstallerInput\windowsdesktop-runtime-10.0.14-win-x64.exe'
$resolver=[pscustomobject]@{Key='resolver';DisplayName='Microsoft .NET Host FX Resolver - 10.0.14 (x64)';WindowsInstaller=1;UninstallString='msiexec.exe /x {3887007B-C74B-4DF7-8155-F3838C013D2C}';DisplayVersion='10.0.14'}
$bundle=[pscustomobject]@{Key='desktop';DisplayName='Microsoft Windows Desktop Runtime 10.0.14 (x64)';QuietUninstallString='"C:\ProgramData\Package Cache\{29A18B06-B190-4463-9FFC-BC0D70D80B7C}\windowsdesktop-runtime-10.0.14-win-x64.exe" /uninstall /quiet';DisplayVersion='10.0.14'}
Check ((Select-Primary @($resolver,$bundle)).Key -eq 'desktop') 'Burn bundle wins over child MSI using the exact cached EXE and uninstall operation'
$bundle.QuietUninstallString=$bundle.QuietUninstallString.Replace(' /uninstall',' /repair')
Check ((Select-Primary @($resolver,$bundle)).Key -eq 'resolver') 'A repair command does not establish the bundle uninstall identity'
"RESULT: $count passed, 0 failed; no installer or uninstaller launched"
