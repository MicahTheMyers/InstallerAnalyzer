param([Parameter(Mandatory=$true)][string]$GeneratedFolder)
$ErrorActionPreference='Stop'
$count=0
function Check([bool]$ok,[string]$name) { if(-not $ok){throw ('FAIL '+$name)}; $script:count++; Write-Output ('PASS '+$name) }
$files=@(Get-ChildItem -LiteralPath $GeneratedFolder -Filter 'Generated-*.ps1')
foreach($file in $files){
  $tokens=$null;$errors=$null
  $null=[System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
  Check ($errors.Count -eq 0) ('Windows PowerShell syntax: '+$file.Name)
  if($errors.Count){$errors | Format-List | Out-String | Write-Output}
}
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($files[0].FullName,[ref]$tokens,[ref]$errors)
$names=@('Get-MsiPrerequisiteProbeEvidence','Get-PendingRebootEvidence','Update-PendingRebootEvidence','Get-ComponentEvidenceSnapshot','Set-InstalledComponentEvidence','Set-RemovedComponentEvidence','Observe-InstallerTree','Initialize-DetectionEvidence','Set-DetectionRemovalEvidence','Complete-RoadmapRemovalEvidence','Get-DetectionBaselinePresence','Get-ApplicationRegistryPresence','Resolve-KnownMsiFormat','Get-MsiApplicationRegistryBaseline','Add-MsiApplicationRegistryCandidates','Test-NativeMsiProductDetected','New-RuntimeObservation')
foreach($function in $ast.FindAll({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $names},$true)){
  . ([scriptblock]::Create($function.Extent.Text))
}
# Only the named helper definitions are loaded. Installer execution and watchdog startup are never run on the host.
$script:Registry=@{}
$script:MockServices=@();$script:MockDrivers=@();$script:MockTasks=@();$script:MockConnections=@();$script:MockPackages=@()
$script:MockFail=''
function Test-Path {param([string]$LiteralPath) return $script:Registry.ContainsKey($LiteralPath)}
function Get-ItemProperty {param([string]$LiteralPath,$Name,$ErrorAction) if(-not $script:Registry.ContainsKey($LiteralPath)){Write-Error -Message 'Not found' -Category ObjectNotFound -ErrorAction Stop};return $script:Registry[$LiteralPath]}
# Discovery entry points are mocked here: no filesystem inventory, runtime query or installer is run on the host.
function Add-DetailedDetectionCandidates {param($entry)}
function Get-RuntimeEnvironmentSnapshot {param($phase) return @()}
$script:DetectionDirectoryBaseline=@()
function Get-AppxPackage {param($ErrorAction) return $script:MockPackages}
function Get-CimInstance {
 param($Namespace,$ClassName,$OperationTimeoutSec,$ErrorAction)
 if($ClassName -eq $script:MockFail){throw 'Fixture query unavailable'}
 switch($ClassName) {
 'Win32_Service' {return $script:MockServices}
 'Win32_SystemDriver' {return $script:MockDrivers}
 'MSFT_ScheduledTask' {return $script:MockTasks}
 'MSFT_NetTCPConnection' {return $script:MockConnections}
 default {throw ('Unexpected fixture CIM class: '+$ClassName)}
 }
}
$result=[ordered]@{DetectionStrategies=@();Components=@();ProcessTree=@();NetworkActivity=@();RuntimeEnvironment=@();RebootRequired=$false;NewRebootIndicators=@();EvidenceCollectionComplete=$false}
$entry=[pscustomobject]@{Key='HKLM:\Fixture\Product';ProductCode='{11111111-1111-1111-1111-111111111111}';DisplayVersion='1.0';DisplayName='Example'}
Initialize-DetectionEvidence $entry @()
Check ($result.DetectionStrategies.Count -eq 3) 'MSI, registry and version detection candidates generated'
Check ($result.DetectionStrategies[0].Type -eq 'MsiProductCode' -and $result.DetectionStrategies[0].BeforeInstall -eq $false) 'MSI ProductCode ranks first with measured absent baseline'
$script:Registry[$entry.Key]=[pscustomobject]@{DisplayVersion='1.0'}
Set-DetectionRemovalEvidence
Check (@($result.DetectionStrategies|Where-Object {$_.AfterUninstall -ne $true}).Count -eq 0) 'Still-present registry identity does not claim removal'
$script:Registry.Clear()
Set-DetectionRemovalEvidence
Check (@($result.DetectionStrategies|Where-Object {$_.AfterUninstall -ne $false}).Count -eq 0) 'Removed registry identities record absent detection'
Initialize-DetectionEvidence $entry @($entry)
Check (@($result.DetectionStrategies|Where-Object {$_.BeforeInstall -ne $true}).Count -eq 0) 'Preexisting identity cannot become a fresh detection proof'
$msix=[pscustomobject]@{Key='APPX::Example';ProductCode='Example_1.0_x64';DisplayName='Example';DisplayVersion='1.0'}
Initialize-DetectionEvidence $msix @([pscustomobject]@{ProductCode='Example_0.9_x64'})
Check ($result.DetectionStrategies[0].Identity -eq 'Example_1.0_x64' -and $result.DetectionStrategies[0].BeforeInstall -eq $false) 'MSIX detection uses exact package identity rather than filename'
$script:MockPackages=@([pscustomobject]@{PackageFullName='Example_0.9_x64'})
Set-DetectionRemovalEvidence
Check ($result.DetectionStrategies[0].AfterUninstall -eq $false) 'A different installed MSIX version does not fabricate presence'
$fileEntry=[pscustomobject]@{Key='FILE::C:\Fixture';InstallLocation='C:\Fixture';DisplayVersion='1'}
Initialize-DetectionEvidence $fileEntry @()
Check ($null -eq $result.DetectionStrategies[0].BeforeInstall) 'Unmeasured filesystem baseline stays unknown'

$script:BeforeComponents=[pscustomobject]@{Items=@();Succeeded=@('Service','Driver','Scheduled task')}
$script:MockServices=@([pscustomobject]@{Name='ExampleSvc';DisplayName='Example Service';PathName='C:\Example\service.exe';StartMode='Auto'})
$script:MockDrivers=@([pscustomobject]@{Name='ExampleDriver';DisplayName='Example Driver';PathName='C:\Example\driver.sys';StartMode='Manual'})
$script:MockTasks=@([pscustomobject]@{TaskPath='\Example\';TaskName='Update';Actions=@([pscustomobject]@{Execute='C:\Example\update.exe'})})
Set-InstalledComponentEvidence
Check ($result.Components.Count -eq 3) 'Service, driver and scheduled task deltas captured'
$script:MockServices=@();$script:MockDrivers=@();$script:MockTasks=@()
Set-RemovedComponentEvidence
Check (@($result.Components|Where-Object {$_.AfterUninstall -ne $false}).Count -eq 0) 'Removal verifies component absence'
$script:MockFail='Win32_SystemDriver'
Set-RemovedComponentEvidence
# Already measured evidence remains; a fresh failed read must not manufacture new false values.
$result.Components[1].AfterUninstall=$null
Set-RemovedComponentEvidence
Check ($null -eq $result.Components[1].AfterUninstall) 'Failed driver query preserves unknown absence state'
$script:MockFail=''
$script:MockServices=@(1..2001 | ForEach-Object {[pscustomobject]@{Name=('Service'+$_);DisplayName='Fixture';PathName='C:\Fixture\service.exe';StartMode='Manual'}})
$boundedSnapshot=Get-ComponentEvidenceSnapshot
Check ('Service' -notin $boundedSnapshot.Succeeded) 'A truncated component inventory cannot establish complete service absence'
$script:MockServices=@()

$script:EvidenceStarted=Get-Date
$script:LastNetworkProbe=[datetime]::MinValue
$script:ProcessEvidenceSeen=@{};$script:NetworkEvidenceSeen=@{};$script:ObservedBirthsByPid=@{}
$tracked=New-Object 'System.Collections.Generic.HashSet[int]'
[void]$tracked.Add(42);[void]$tracked.Add(77)
$all=@(
[pscustomobject]@{ProcessId=42;ParentProcessId=1;CreationDate=$script:EvidenceStarted.AddSeconds(1);Name='setup.exe';ExecutablePath='C:\Fixture\setup.exe';CommandLine='setup.exe /quiet'},
[pscustomobject]@{ProcessId=77;ParentProcessId=1;CreationDate=$script:EvidenceStarted.AddHours(-1);Name='old.exe';ExecutablePath='C:\Other\old.exe';CommandLine='old.exe'},
[pscustomobject]@{ProcessId=999;ParentProcessId=1;CreationDate=$script:EvidenceStarted.AddSeconds(1);Name='unrelated.exe';ExecutablePath='C:\Other\unrelated.exe';CommandLine='unrelated.exe'}
)
$script:MockConnections=@([pscustomobject]@{State=5;OwningProcess=42},[pscustomobject]@{State=5;OwningProcess=77},[pscustomobject]@{State=5;OwningProcess=999})
Observe-InstallerTree $all $tracked
Check ($result.ProcessTree.Count -eq 1 -and $result.ProcessTree[0].ProcessId -eq 42) 'Process evidence excludes untracked and preexisting process identities'
Check ($result.NetworkActivity.Count -eq 1 -and $result.NetworkActivity[0].ProcessId -eq 42) 'Network observations are limited to new installer-tree processes'
Check ($result.NetworkActivity[0].Evidence -match 'not established') 'Connections are not misreported as proven downloads'
Observe-InstallerTree $all $tracked
Check ($result.ProcessTree.Count -eq 1 -and $result.NetworkActivity.Count -eq 1) 'Repeated process/network observations are bounded and deduplicated'
$all[0].CreationDate=$script:EvidenceStarted.AddSeconds(10)
$script:LastNetworkProbe=[datetime]::MinValue
Observe-InstallerTree $all $tracked
Check ($result.ProcessTree.Count -eq 1 -and $result.NetworkActivity.Count -eq 1) 'PID reuse does not attribute a later unrelated process or its network connections to the installer'
function Write-Checkpoint {param([string]$stage) $script:LastEvidenceCheckpoint=$stage}
$script:BeforeRebootEvidence=@()
Complete-RoadmapRemovalEvidence
Check ($result.EvidenceCollectionComplete -and $script:LastEvidenceCheckpoint -eq 'Final absence verification evidence complete') 'Final evidence is marked complete before the host-recoverable checkpoint is published'
$script:MsiStaticMetadata=[pscustomobject]@{RegistryProbes=@(
 [pscustomobject]@{Property='WINDOWS_LABEL';Root=2;Key='SOFTWARE\Microsoft\Windows NT\CurrentVersion';Name='ProductName';Type=18;ConditionDescription='Read-only fixture'},
 [pscustomobject]@{Property='MISSING_VALUE';Root=2;Key=('SOFTWARE\InstallerAnalyzer-Nonexistent-'+[guid]::NewGuid().ToString('N'));Name='Runtime';Type=2;ConditionDescription='Fixture missing value'},
 [pscustomobject]@{Property='FORMATTED';Root=2;Key='SOFTWARE\[UNRESOLVED_PROPERTY]';Name='Runtime';Type=2;ConditionDescription='Fixture unresolved property'},
 [pscustomobject]@{Property='FILE_SIGNATURE';Root=2;Key='SOFTWARE\Microsoft';Name='Runtime';Type=0;ConditionDescription='File locator is not a raw registry value'}
)}
$probes=@(Get-MsiPrerequisiteProbeEvidence)
Check ($probes.Count -eq 4 -and $probes[0].ValuePresent -eq $true -and $probes[0].RegistryView -eq 'Registry64') 'MSI registry probe observes the requested registry view without collecting the value'
Check ($probes[1].ValuePresent -eq $false -and $null -eq $probes[2].ValuePresent -and $null -eq $probes[3].ValuePresent) 'Missing, formatted and file-locator registry probes retain distinct evidence states'
Check (-not ($probes[0].PSObject.Properties.Name -contains 'Value')) 'Prerequisite probes do not collect raw registry contents'

# Newly added fixtures. These run only from the normal generated-script harness after application loading is approved.
$children=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
[void]$children.Add('C:\Fixture\Existing')
$script:DetectionDirectoryBaseline=@([pscustomobject]@{Root='C:\Fixture';Exists=$true;Children=@{'C:\Fixture'=$children};Complete=@{'C:\Fixture'=$true}})
Check ((Get-DetectionBaselinePresence 'C:\Fixture\NewApp\app.exe' $true) -eq $false) 'An absent parent directory establishes a new executable baseline'
Check ($null -eq (Get-DetectionBaselinePresence 'C:\Fixture\Existing\app.exe' $true)) 'An existing parent does not establish whether a particular executable existed'
$script:DetectionDirectoryBaseline[0].Complete['C:\Fixture']=$false
Check ($null -eq (Get-DetectionBaselinePresence 'C:\Fixture\NewApp' $false)) 'An incomplete directory enumeration cannot fabricate absence'
Check ($null -eq (Get-DetectionBaselinePresence 'C:\Unmeasured\app.exe' $true)) 'Paths outside measured roots retain an unknown baseline'

function Get-NativeMsiProductState {param($code) return $script:MockMsiState}
$script:MockMsiState=-1
Check ((Test-NativeMsiProductDetected '{11111111-1111-1111-1111-111111111111}') -eq $false) 'Native MSI unknown-product state proves absence in the queried context'
$script:MockMsiState=5
Check ((Test-NativeMsiProductDetected '{11111111-1111-1111-1111-111111111111}') -eq $true) 'Native MSI installed state proves presence'
foreach($state in @(2,$null)){
  $script:MockMsiState=$state;$failed=$false
  try{$null=Test-NativeMsiProductDetected '{11111111-1111-1111-1111-111111111111}'}catch{$failed=$true}
  Check $failed 'Other-user or unavailable MSI state cannot prove absence'
}
$script:MsiStaticMetadata=[pscustomobject]@{ProductName="Fixture's Product";Manufacturer='Fixture';ProductVersion='1';ProductCode='{11111111-1111-1111-1111-111111111111}';UpgradeCode='';ApplicationRegistry=@()}
Check ((Resolve-KnownMsiFormat 'Software\[Manufacturer]\[ProductName]') -eq "Software\Fixture\Fixture's Product") 'Known MSI property values are resolved as data'
Check ((Resolve-KnownMsiFormat 'Software\[UNRESOLVED]') -eq 'Software\[UNRESOLVED]') 'Unresolved MSI formatting is preserved for explicit unknown handling'
$observation=New-RuntimeObservation 'Fixture Runtime' 'Registered' '1.2' 'x64' 'Fixture' 'Before install'
Check (-not $observation.RequirementEstablished -and $observation.MeasuredAt) 'Runtime availability never establishes a prerequisite requirement'

$script:BeforeRebootEvidence=@('PendingFileRenameOperations state OLD')
$result.NewRebootIndicators=@();$result.RebootRequired=$false
$script:Registry['HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager']=[pscustomobject]@{PendingFileRenameOperations=@('C:\Private\Source','C:\Private\Target')}
Update-PendingRebootEvidence
Check ($result.RebootRequired -and $result.NewRebootIndicators[0] -like 'PendingFileRenameOperations state *' -and ($result.NewRebootIndicators -join '') -notmatch 'Private') 'Changed pending file operations flag reboot without collecting their private paths'
$script:BeforeRebootEvidence=@(Get-PendingRebootEvidence);$result.RebootRequired=$false;$result.NewRebootIndicators=@()
Update-PendingRebootEvidence
Check (-not $result.RebootRequired) 'Unchanged preexisting pending file operations do not become new installer reboot evidence'
Write-Output ('RESULT: '+$count+' passed, 0 failed')

