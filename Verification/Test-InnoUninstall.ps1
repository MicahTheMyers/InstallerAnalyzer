param([string]$Repository=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
$source=Get-Content -LiteralPath (Join-Path $Repository 'InstallerAnalyzer\Services\SandboxIssRecorder.cs') -Raw
foreach($name in @('Split-Command','Normalize-QSetupUninstallCommand','Get-InnoUninstallCommand','Get-MsiUninstallCommand','Get-SilentUninstallCandidates')){
    $helper=[regex]::Match($source,"(?s)function ${name}\b.*?(?=\r?\nfunction )").Value
    if(-not $helper){throw "Missing production helper $name"}
    . ([scriptblock]::Create($helper))
}

$InstallerKind='InnoSetup'
$SilentInstallArguments='/VERYSILENT /SP-'
$path='"C:\Program Files\Microsoft VS Code\unins000.exe"'
$silent="$path /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
$entry=[pscustomobject]@{QuietUninstallString="$path /SILENT";UninstallString=$path}
if((Get-InnoUninstallCommand $entry.QuietUninstallString) -ne $silent){throw 'Registered /SILENT must be replaced'}
if((Get-InnoUninstallCommand $path) -ne $silent){throw 'Plain registered command must receive silent arguments'}
if((Get-InnoUninstallCommand $silent) -ne $silent){throw 'Existing flags must not be duplicated'}
$log='/LOG="C:\Logs\uninstall /SILENT progress.txt"'
$expected="$path $log /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
if((Get-InnoUninstallCommand "$path /silent $log") -ne $expected){throw 'Quoted argument values must be preserved'}
$candidates=@(Get-SilentUninstallCandidates $entry)
if($candidates.Count -ne 1 -or $candidates[0] -ne $silent){throw 'Final validation must use the same fully silent command'}
if(Get-InnoUninstallCommand 'msiexec.exe /x {EA457B21-F73E-494C-ACAB-524FDE069978}'){throw 'Inno flags must not be applied to other executables'}
$InstallerKind='Nsis'
if(Get-InnoUninstallCommand $entry.QuietUninstallString){throw 'Other installer families must keep their registered commands'}
Write-Output 'RESULT: 7 passed, 0 failed'
