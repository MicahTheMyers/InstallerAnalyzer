param([Parameter(Mandatory=$true)][string]$GeneratedRoot)
$ErrorActionPreference='Stop'
$count=0
function Check([bool]$condition,[string]$name){if(-not $condition){throw ('FAIL '+$name)};$script:count++;Write-Output ('PASS '+$name)}
$folder=Join-Path $GeneratedRoot "response files [fixture] O'Brien"
Set-Location -LiteralPath $folder
$InstallerFile=Join-Path $folder 'setup.exe';$InstallerFolder=$folder
$probe=[pscustomobject]@{Calls=0;File='';Arguments=$null;ExitCode=0}
# Every generated script runs with this process-launch boundary mocked. No installer executes.
function Start-Process {param($FilePath,$ArgumentList,[switch]$Wait,[switch]$PassThru)
 $probe.Calls++;$probe.File=$FilePath;$probe.Arguments=$ArgumentList;return [pscustomobject]@{ExitCode=$probe.ExitCode}
}
$install=Join-Path $folder 'Install.ps1';$uninstall=Join-Path $folder 'Uninstall.ps1'
$setup=Join-Path $folder 'setup.iss';$removal=Join-Path $folder 'uninstall.iss'
& $install
Check ($probe.Calls -eq 1 -and $probe.File -eq $InstallerFile -and $probe.Arguments -eq ('/s /f1"'+$setup+'"')) 'Literal bracket/space/apostrophe response path reaches mocked install launch quoted'
Move-Item -LiteralPath $setup -Destination ($setup+'.held')
try {$before=$probe.Calls;$failed=$false;try {& $install}catch{$failed=$_.Exception.Message.Contains('setup.iss was not found')};Check ($failed -and $probe.Calls -eq $before) 'Missing install response file fails before process launch'}finally{Move-Item -LiteralPath ($setup+'.held') -Destination $setup}
$probe.ExitCode=3010;& $install
Check ($probe.Calls -eq 2) 'Install response script accepts a reboot-required result without executing a reboot'
$probe.ExitCode=1603;$failed=$false;try{& $install}catch{$failed=$_.Exception.Message.Contains('1603')}
Check $failed 'Install response script reports unsuccessful installer exit codes'
$probe.ExitCode=0;& $uninstall
Check ($probe.File -eq 'cmd.exe' -and ($probe.Arguments -join ' ').Contains('/f1"'+$removal+'"')) 'Validated uninstall script finds staged literal response file and quotes its path'
Move-Item -LiteralPath $removal -Destination ($removal+'.held')
try {$before=$probe.Calls;$failed=$false;try{& $uninstall}catch{$failed=$_.Exception.Message.Contains('Unable to locate uninstall.iss')};Check ($failed -and $probe.Calls -eq $before) 'Missing uninstall response file fails before process launch'}finally{Move-Item -LiteralPath ($removal+'.held') -Destination $removal}
$probe.ExitCode=1605;& $uninstall
Check ($probe.File -eq 'cmd.exe') 'Validated response uninstall accepts product-already-absent result'
$probe.ExitCode=1603;$failed=$false;try{& $uninstall}catch{$failed=$_.Exception.Message.Contains('1603')}
Check $failed 'Validated response uninstall reports unsuccessful exit codes'
Write-Output ('RESULT: '+$count+' passed, 0 failed; process launch mocked throughout')
