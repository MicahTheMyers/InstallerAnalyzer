param([string]$ProjectRoot)
$ErrorActionPreference='Stop'
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxIssRecorder.cs'))
foreach($name in @('Save-BootstrapperLogSnapshot','Save-BootstrapperPrerequisiteLogs','Assert-BootstrapperDiscoveryComplete','Update-BootstrapperExitEvidence','Test-BootstrapperChainExited')){
 $body=[regex]::Match($source,'(?s)function '+[regex]::Escape($name)+'\(.*?\r?\n}\r?\n').Value
 if(-not $body){throw ('Missing function '+$name)};Invoke-Expression $body
}
function Write-DebugEvent($message,$detail){}
$count=0
function Check($ok,$name){if(-not $ok){throw ('FAIL '+$name)};$script:count++;'PASS '+$name}
$root=Join-Path $ProjectRoot ('verification-results\prerequisite-logs-'+[guid]::NewGuid().ToString('N'))
$temp=Join-Path $root 'temp';$out=Join-Path $root 'output';New-Item -ItemType Directory -Path $temp,$out -Force|Out-Null
$since=(Get-Date).AddMinutes(-1)
$good=Join-Path $temp 'CONNECTION_Client_20261103160000.log';[IO.File]::WriteAllText($good,'installer handoff log')
$alternate=Join-Path $temp 'Setup_CONNECTIONClientx64_10.00.17.010_20261103.msi.log';[IO.File]::WriteAllText($alternate,'MSI installation log')
$old=Join-Path $temp 'CONNECTION_Client_old.log';[IO.File]::WriteAllText($old,'old installation');(Get-Item $old).LastWriteTime=(Get-Date).AddDays(-1)
[IO.File]::WriteAllText((Join-Path $temp 'unrelated.log'),'unrelated data')
$nested=Join-Path $temp 'Bentley\Logs';New-Item -ItemType Directory -Path $nested -Force|Out-Null;[IO.File]::WriteAllText((Join-Path $nested 'CONNECTION_Client_app.log'),'application/authentication data')
$before=(Get-FileHash $good).Hash
$saved=@(Save-BootstrapperPrerequisiteLogs $true 'gINT' $out $temp $since)
Check ($saved.Count -eq 2) 'Current installation and MSI logs are retained for observed CONNECTION Client setup'
Check (@($saved | Where-Object {$_.Source -eq $old -or $_.Source.EndsWith('unrelated.log') -or $_.Source.Contains('Bentley\Logs')}).Count -eq 0) 'Old, unrelated and nested application logs remain outside collection'
Check ((Get-FileHash $good).Hash -eq $before) 'Prerequisite log snapshot leaves its source unchanged'
Check (@(Save-BootstrapperPrerequisiteLogs $false 'gINT' $out $temp $since).Count -eq 0) 'No collection without observing the setup process'
Check (@(Save-BootstrapperPrerequisiteLogs $true '' $out $temp $since).Count -eq 0) 'No collection for an unscoped product'
foreach($index in 1..10){[IO.File]::WriteAllText((Join-Path $temp ('CONNECTION_Client_'+$index+'.log')),'bounded fixture')}
Check (@(Save-BootstrapperPrerequisiteLogs $true 'gINT' $out $temp $since).Count -eq 8) 'Prerequisite log count is bounded'
$RequiredPrimaryProduct='gINT'
try{Assert-BootstrapperDiscoveryComplete ([pscustomobject]@{TimedOut=$true;Primary=$null;MainMsiStarted=$false;ActiveProcesses=@('Setup_CONNECTIONclientx64_10_00_17_010.exe')});throw 'Expected timeout'}catch{Check ($_.Exception.Message -like 'BOOTSTRAPPER TIMEOUT: CONNECTION Client setup*main MSI had not started*') 'Pre-main timeout identifies the unfinished CONNECTION Client handoff'}
try{Assert-BootstrapperDiscoveryComplete ([pscustomobject]@{TimedOut=$true;Primary=$null;MainMsiStarted=$true;ActiveProcesses=@('msiexec.exe')});throw 'Expected timeout'}catch{Check ($_.Exception.Message -like 'BOOTSTRAPPER TIMEOUT: Installer activity*') 'Main-MSI timeout retains its separate outcome'}
$vcLog=Join-Path $temp 'dd_vcredist_x86_20261105.log'
[IO.File]::WriteAllText($vcLog,'fixture exit status')
Check (@(Save-BootstrapperPrerequisiteLogs $false 'gINT' $out $temp $since $true).Count -eq 1) 'Visual C++ log capture works before CONNECTION Client starts'
Check (@(Save-BootstrapperPrerequisiteLogs $false 'gINT' $out $temp $since).Count -eq 0) 'Unobserved prerequisite log is excluded'
$tracked=New-Object 'System.Collections.Generic.HashSet[int]'
$handles=@{}
$exits=New-Object 'System.Collections.Generic.List[object]'
$child=Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-Command','Start-Sleep -Seconds 2; exit 37') -WindowStyle Hidden -PassThru
try{
 [void]$tracked.Add($child.Id)
 $observed=[pscustomobject]@{ProcessId=$child.Id;Name='powershell.exe';ParentProcessId=$PID}
 Update-BootstrapperExitEvidence @($observed) $tracked $handles $exits
 if(-not $child.WaitForExit(10000)){throw 'Fixture did not exit'}
 Update-BootstrapperExitEvidence @() $tracked $handles $exits
 Check ($exits.Count -eq 1 -and $exits[0].Status -eq 'Exited' -and $exits[0].ExitCode -eq 37) 'A retained real process handle records its actual nonzero exit code'
 Update-BootstrapperExitEvidence @() $tracked $handles $exits
 Check ($exits.Count -eq 1) 'Repeated collection does not duplicate exit evidence'
 Check (Test-BootstrapperChainExited @() $tracked $handles $child.Id) 'Confirmed root and descendant exit ends discovery without waiting for the application timeout'
 Check (-not (Test-BootstrapperChainExited @($observed) $tracked $handles $child.Id)) 'An owned process still present prevents early termination'
 Check (-not (Test-BootstrapperChainExited @() $tracked @{} $child.Id)) 'Missing exit evidence cannot prove the setup chain has exited'
 $RequiredPrimaryProduct='gINT'
 try {
   Assert-BootstrapperDiscoveryComplete ([pscustomobject]@{TimedOut=$false;MainMsiFailure=$null;EndedWithoutPrimary=$true;Primary=$null})
   throw 'Expected chain exit'
 }catch{Check ($_.Exception.Message -like 'INSTALLER CHAIN EXITED:*gINT*') 'Early chain exit reports the missing target and captured exit evidence'}
}finally{
 foreach($record in $handles.Values){if($record.Process){$record.Process.Dispose()}}
 if(-not $child.HasExited){$child.Kill()}
 $child.Dispose()
}

"RESULT: $count passed, 0 failed; only inert fixture files created"
