param([string]$ProjectRoot)
$ErrorActionPreference='Stop'
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxIssRecorder.cs'))
foreach($name in @('Save-BootstrapperLogSnapshot','Find-BootstrapperMainMsi','Find-TrackedPrerequisite','Update-InstallWait','Save-BootstrapperMsiLogs','Get-BootstrapperMainMsiStatus','Get-BootstrapperSettleDeadline','Assert-BootstrapperDiscoveryComplete')){
 $body=[regex]::Match($source,'(?s)function '+[regex]::Escape($name)+'\(.*?\r?\n}\r?\n').Value
 if(-not $body){throw ('Missing function '+$name)};Invoke-Expression $body
}
function Write-DebugEvent($message,$detail){}
function Write-Checkpoint($message){}
$count=0
function Check($ok,$name){if(-not $ok){throw ('FAIL '+$name)};$script:count++;'PASS '+$name}
$tracked=New-Object 'System.Collections.Generic.HashSet[int]';[void]$tracked.Add(8108)
$main=[pscustomobject]@{ProcessId=8108;Name='msiexec.exe';CommandLine='MsiExec.exe /I gINT.msi /L* ..\gINTSetupLog.txt INSTALL32BITONLY=0'}
Check ((Find-BootstrapperMainMsi @($main) $tracked 'gINT').ProcessId -eq 8108) 'Actual reported main-MSI command starts the main-product phase'
$other=[pscustomobject]@{ProcessId=99;Name='msiexec.exe';CommandLine=$main.CommandLine}
Check ($null -eq (Find-BootstrapperMainMsi @($other) $tracked 'gINT')) 'Unrelated process cannot extend the analysis budget'
$prerequisite=[pscustomobject]@{ProcessId=8108;Name='msiexec.exe';CommandLine='msiexec.exe /i vcredist.msi /qb!'}
Check ($null -eq (Find-BootstrapperMainMsi @($prerequisite) $tracked 'gINT')) 'Prerequisite MSI cannot reset the main-product budget'
Check ($null -eq (Find-BootstrapperMainMsi @($main) $tracked '')) 'Unscoped discovery does not invent a main MSI'
$quoted=[pscustomobject]@{ProcessId=8108;Name='MsiExec.exe';CommandLine='msiexec.exe /package "C:\Vendor Folder\gINT.msi"'}
Check ((Find-BootstrapperMainMsi @($quoted) $tracked 'gINT').ProcessId -eq 8108) 'Quoted full MSI path is recognized'
$start=[datetime]'2026-11-03T09:00:00'
$connection=[pscustomobject]@{ProcessId=8108;Name='Setup_CONNECTIONClientx64_10.00.17.010.exe'}
$vc=[pscustomobject]@{ProcessId=8108;Name='VC_redist.x64.exe'}
$runtimeMsi=[pscustomobject]@{ProcessId=8108;Name='msiexec.exe';CommandLine='msiexec /i "C:\Vendor Folder\dotnet-runtime-8.msi" /qn'}
Check ((Find-TrackedPrerequisite @($connection) $tracked 100).ProcessId -eq 8108) 'Tracked Bentley prerequisite is recognized'
Check ((Find-TrackedPrerequisite @($vc) $tracked 100).ProcessId -eq 8108) 'Visual C++ prerequisite is recognized'
Check ((Find-TrackedPrerequisite @($runtimeMsi) $tracked 100).ProcessId -eq 8108) 'Quoted runtime MSI path is recognized'
Check ($null -eq (Find-TrackedPrerequisite @($vc) $tracked 8108)) 'A runtime chosen as the root is itself the application'
Check ($null -eq (Find-TrackedPrerequisite @($main) $tracked 100)) 'Application MSI is not a prerequisite'
$connection.ProcessId=99
Check ($null -eq (Find-TrackedPrerequisite @($connection) $tracked 100)) 'Unrelated setup cannot activate the prerequisite wait'
$clock=@{Deadline=$start.AddMinutes(15);Limit=$start.AddMinutes(50);ApplicationSeconds=900;Waiting=$false;Seen=$false}
Update-InstallWait $clock $null $start.AddMinutes(10)
Check ($clock.Deadline -eq $start.AddMinutes(15)) 'No prerequisite leaves the original timer alone'
Update-InstallWait $clock $vc $start.AddMinutes(14)
Check ($clock.Waiting -and $clock.Deadline -eq $start.AddMinutes(29)) 'A late prerequisite gets its own fifteen-minute window'
Update-InstallWait $clock $runtimeMsi $start.AddMinutes(25)
Check ($clock.Deadline -eq $start.AddMinutes(29)) 'Overlapping prerequisite activity cannot perpetually reset the deadline'
Update-InstallWait $clock $null $start.AddMinutes(28)
Check (-not $clock.Waiting -and $clock.Deadline -eq $start.AddMinutes(43)) 'Application receives its full window after prerequisites exit'
Update-InstallWait $clock $vc $start.AddMinutes(42)
Check ($clock.Deadline -eq $start.AddMinutes(50)) 'Later prerequisite still respects the overall cap'

$root=Join-Path $ProjectRoot ('verification-results\bootstrapper-diagnostics-'+[guid]::NewGuid().ToString('N'))
$temp=Join-Path $root 'temp';$payload=Join-Path $temp 'IXP000.TMP';$out=Join-Path $root 'output'
New-Item -ItemType Directory -Path $payload,$out -Force|Out-Null
$msi=Join-Path $payload 'gINT.msi';[IO.File]::WriteAllText($msi,'inert fixture; never execute')
$log=Join-Path $temp 'gINTSetupLog.txt';[IO.File]::WriteAllText($log,'gINT diagnostic data',[Text.Encoding]::Unicode)
$before=(Get-FileHash -LiteralPath $log).Hash
$snapshots=@(Save-BootstrapperMsiLogs @($msi,$msi) 'gINT' $out $temp)
Check ($snapshots.Count -eq 1 -and [IO.File]::ReadAllText((Join-Path $out $snapshots[0].File)) -eq 'gINT diagnostic data') 'Observed main MSI parent log is retained once'
Check ((Get-FileHash -LiteralPath $log).Hash -eq $before) 'Diagnostic capture leaves the vendor log unchanged'
$outside=Join-Path $root 'outside';New-Item -ItemType Directory -Path $outside -Force|Out-Null
[IO.File]::WriteAllText((Join-Path $outside 'gINTSetupLog.txt'),'must not capture')
Check (@(Save-BootstrapperMsiLogs @((Join-Path $outside 'gINT.msi')) 'gINT' $out $temp).Count -eq 0) 'Logs outside the allowed guest temp root are excluded'
Check (@(Save-BootstrapperMsiLogs @((Join-Path $payload 'other.msi')) 'gINT' $out $temp).Count -eq 0) 'Unrelated MSI names do not trigger log capture'
[IO.File]::WriteAllText($log,('A'*2500000),[Text.Encoding]::Unicode)
$snapshots=@(Save-BootstrapperMsiLogs @($msi) 'gINT' $out $temp)
$saved=Join-Path $out $snapshots[0].File
Check ($snapshots[0].Truncated -and (Get-Item -LiteralPath $saved).Length -le 4194306 -and [IO.File]::ReadAllText($saved).StartsWith('AAAA')) 'Large Unicode logs retain a bounded readable tail'
$statusLine='Windows Installer installed the product. Product Name: gINT CONNECT Edition 10.02.00.04. Product Version: 10.02.00.04. Installation success or error status: '
$failureFile=Join-Path $out 'main-status.txt'
$statusSnapshot=[pscustomobject]@{File='main-status.txt'}
[IO.File]::WriteAllLines($failureFile,[string[]]@('The error code is 2738. The arguments are: , ,',($statusLine+'1603.')))
$failure=Get-BootstrapperMainMsiStatus @($statusSnapshot) $out 'gINT'
Check ($failure.ExitCode -eq 1603 -and $failure.VbScriptUnavailable) 'Final main MSI failure retains VBScript evidence'
$RequiredPrimaryProduct='gINT'
try {
 Assert-BootstrapperDiscoveryComplete ([pscustomobject]@{TimedOut=$false;MainMsiFailure=$failure;Primary=[pscustomobject]@{Key='registered'}})
 throw 'Expected main MSI failure'
}catch {Check ($_.Exception.Message -like 'INSTALL FAILED:*1603*2738*') 'Product registration does not override a failed main MSI'}
Check ($null -eq (Get-BootstrapperMainMsiStatus @($statusSnapshot) $out 'Another product')) 'Unrelated MSI status cannot veto the install'
foreach($status in @(0,1641,3010)){
 [IO.File]::AppendAllText($failureFile,[Environment]::NewLine+$statusLine+$status+'.'+[Environment]::NewLine)
 Check ((Get-BootstrapperMainMsiStatus @($statusSnapshot) $out 'gINT').ExitCode -eq $status) ('Latest successful MSI status '+$status+' supersedes an earlier failure')
}

$deadline=$start.AddMinutes(15)
$primary=[pscustomobject]@{Key='registered'}
$success=[pscustomobject]@{ExitCode=0}
Check ((Get-BootstrapperSettleDeadline $success $primary $false $false $deadline) -eq $deadline.AddSeconds(60)) 'Verified success gives setup sixty seconds to settle'
Check ($null -eq (Get-BootstrapperSettleDeadline $failure $primary $false $false $deadline)) 'MSI failure cannot extend the deadline'
Check ($null -eq (Get-BootstrapperSettleDeadline $null $primary $false $false $deadline)) 'Registration alone cannot extend the deadline'
Check ($null -eq (Get-BootstrapperSettleDeadline $success $null $false $false $deadline)) 'Success without product registration cannot extend the deadline'
Check ($null -eq (Get-BootstrapperSettleDeadline $success $primary $true $false $deadline)) 'Settling window cannot renew itself'
Check ($null -eq (Get-BootstrapperSettleDeadline $success $primary $false $true $deadline)) 'Active prerequisite prevents a settling window'

"RESULT: $count passed, 0 failed; only inert fixture files created"
