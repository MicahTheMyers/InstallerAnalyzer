using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string RoadmapEvidenceScript = """
$script:EvidenceStarted=Get-Date
$script:LastNetworkProbe=[DateTime]::MinValue
$script:ProcessEvidenceSeen=@{}
$script:ObservedBirthsByPid=@{}
$script:NetworkEvidenceSeen=@{}
$script:UiEvidenceSeen=@{}
function Record-InstallerUiEvidence($window,$tracked) {
  if($null -eq $window -or -not $tracked.Contains([int]$window.Pid) -or @($result.UiTextEvidence).Count -ge 32){return}
  $key=([string]$window.Pid+'|'+[string]$window.Hwnd)
  if($script:UiEvidenceSeen.ContainsKey($key)){return}
  try {
    if(-not $script:ObservedBirthsByPid.ContainsKey([string]$window.Pid)){return}
    $process=Get-Process -Id $window.Pid -ErrorAction Stop
    $known=[datetime]$script:ObservedBirthsByPid[[string]$window.Pid]
    if([Math]::Abs(($process.StartTime-$known).TotalMilliseconds) -gt 1){return}
    $labels=@([InstallerAnalyzerWindowProbe]::ReadStaticLabels([long]$window.Hwnd,[int]$window.Pid) | Where-Object {
      ($_ -match '(?i)\.net|framework|netfx|visual c\+\+|webview|directx|java|\.dll|missing|required|prerequisite|reboot|restart|sign[ -]?in|log[ -]?in|authentication|optional|also install|additional software|bundled' -or
       $_ -match '(?i)^\s*<?\s*&?(?:back|next|finish|cancel|ok|yes|no|retry|install|remove|repair|change)\s*>?\s*$') -and
      $_ -notmatch '(?i)password|passwd|api.?key|secret|token|licen[cs]e\s*(key|number)|serial\s*(number|key)'
    } | Select-Object -First 16)
    if($labels.Count -gt 0){
      $result.UiTextEvidence+=@([PSCustomObject]@{ProcessId=[int]$window.Pid;Process=[string]$process.ProcessName;WindowTitle=[string]$window.Title;Phase=[string]$result.WorkflowStage;Labels=@($labels)})
      if(@($labels | Where-Object {$_ -match '(?i)(?:reboot|restart) (?:is )?required|must (?:reboot|restart)' -and $_ -notmatch '(?i)no (?:reboot|restart)|not required|does not require'}).Count -gt 0){$result.RebootRequired=$true}
      $script:UiEvidenceSeen[$key]=$true
    }
  }catch{}
}
$script:MsiStaticMetadata=$null
try {$script:MsiStaticMetadata=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__MSI_METADATA__')) | ConvertFrom-Json)}catch{}
function Get-MsiPrerequisiteProbeEvidence {
  $observations=@()
  foreach($probe in @($script:MsiStaticMetadata.RegistryProbes | Select-Object -First 64)){
    $observation=[ordered]@{Property=[string]$probe.Property;Target=([string]$probe.Root+'|'+[string]$probe.Key+'|'+[string]$probe.Name);RegistryView=if(([int]$probe.Type -band 16) -ne 0){'Registry64'}else{'Registry32'};ValuePresent=$null;Evidence='Registry probe not measured.';ConditionDescription=[string]$probe.ConditionDescription}
    $base=$null;$key=$null
    try {
      if(([int]$probe.Type -band 15) -ne 2){$observation.Evidence='File/directory RegLocator signatures need file signature evaluation; not treated as raw registry values.'}
      elseif(([string]$probe.Key -match '\[|\]' -or [string]$probe.Name -match '\[|\]')){$observation.Evidence='Formatted MSI registry path requires property resolution; not expanded speculatively.'}
      else {
        $hive=switch([int]$probe.Root){0{[Microsoft.Win32.RegistryHive]::ClassesRoot}1{[Microsoft.Win32.RegistryHive]::CurrentUser}2{[Microsoft.Win32.RegistryHive]::LocalMachine}3{[Microsoft.Win32.RegistryHive]::Users}default{$null}}
        if($null -eq $hive){$observation.Evidence='Registry root is not supported for this probe.'}
        else {
          $view=if(([int]$probe.Type -band 16) -ne 0){[Microsoft.Win32.RegistryView]::Registry64}else{[Microsoft.Win32.RegistryView]::Registry32}
          $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
          $key=$base.OpenSubKey([string]$probe.Key,$false)
          $observation.ValuePresent=($null -ne $key -and @($key.GetValueNames() | Where-Object {$_ -eq [string]$probe.Name}).Count -gt 0)
          $observation.Evidence='Read-only Sandbox registry observation. Raw registry values are not collected; presence alone does not evaluate an MSI launch condition.'
        }
      }
    }catch{$observation.Evidence='Registry observation unavailable; absence is unknown.'}
    finally {if($null -ne $key){$key.Dispose()};if($null -ne $base){$base.Dispose()}}
    $observations+=@([PSCustomObject]$observation)
  }
  return $observations
}
function Get-PendingRebootEvidence {
  $found=@()
  foreach($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')){
    if(Test-Path -LiteralPath $key){$found+=$key}
  }
  try {
    $pending=@((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations)
    if(@($pending | Where-Object {$_}).Count -gt 0){
      $hash=[Security.Cryptography.SHA256]::Create()
      try{$digest=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($pending -join [char]0)))).Replace('-','')}
      finally{$hash.Dispose()}
      $found+=('PendingFileRenameOperations state '+$digest)
    }
  }catch{}
  return $found
}
function Update-PendingRebootEvidence {
  try {
    $new=@(Get-PendingRebootEvidence | Where-Object {$_ -notin $script:BeforeRebootEvidence})
    $result.NewRebootIndicators=@(@($result.NewRebootIndicators)+$new | Select-Object -Unique)
    if($new.Count -gt 0){$result.RebootRequired=$true}
  }catch{}
}
function Get-ComponentEvidenceSnapshot {
  $items=@(); $succeeded=@()
  foreach($spec in @(@('Service','root\cimv2','Win32_Service'),@('Driver','root\cimv2','Win32_SystemDriver'),@('Scheduled task','root\Microsoft\Windows\TaskScheduler','MSFT_ScheduledTask'))){
    try {
      $rows=@(Get-CimInstance -Namespace $spec[1] -ClassName $spec[2] -OperationTimeoutSec 3 -ErrorAction Stop)
      foreach($row in $rows | Select-Object -First 2000){
        if($spec[0] -eq 'Scheduled task'){
          $items+=[PSCustomObject]@{Kind=$spec[0];Name=($row.TaskPath+$row.TaskName);DisplayName=$row.TaskName;Path=(@($row.Actions | ForEach-Object {$_.Execute}) -join '; ');StartupType='Scheduled'}
        }else{$items+=[PSCustomObject]@{Kind=$spec[0];Name=$row.Name;DisplayName=$row.DisplayName;Path=$row.PathName;StartupType=$row.StartMode}}
      }
      if($rows.Count -le 2000){$succeeded+=$spec[0]}
    }catch{}
  }
  return [PSCustomObject]@{Items=@($items);Succeeded=@($succeeded)}
}
function Set-InstalledComponentEvidence {
  Update-PendingRebootEvidence
  try{
    $result.RuntimeEnvironment+=@(Get-RuntimeEnvironmentSnapshot 'After initial install')
    $snapshot=Get-ComponentEvidenceSnapshot
    $prior=@($script:BeforeComponents.Items | ForEach-Object {$_.Kind+'|'+$_.Name})
    $result.Components=@($snapshot.Items | Where-Object {$_.Kind -in $script:BeforeComponents.Succeeded -and $_.Kind -in $snapshot.Succeeded -and ($_.Kind+'|'+$_.Name) -notin $prior} | Select-Object -First 128 | ForEach-Object {
      [PSCustomObject]@{Kind=$_.Kind;Name=$_.Name;DisplayName=$_.DisplayName;Path=$_.Path;StartupType=$_.StartupType;BeforeInstall=$false;AfterInstall=$true;AfterUninstall=$null}
    })
  }catch{}
}
function Set-RemovedComponentEvidence {
  if(@($result.Components).Count -eq 0){return}
  try{
    $snapshot=Get-ComponentEvidenceSnapshot
    $remaining=@($snapshot.Items | ForEach-Object {$_.Kind+'|'+$_.Name})
    foreach($component in $result.Components){
      if($component.Kind -in $snapshot.Succeeded){$component.AfterUninstall=(($component.Kind+'|'+$component.Name) -in $remaining)}
    }
  }catch{}
}
function Observe-InstallerTree($all,$tracked) {
  try {
    foreach($item in @($all | Where-Object {$tracked.Contains([int]$_.ProcessId)})){
      $created=if($item.CreationDate){[datetime]$item.CreationDate}else{$null}
      if($null -eq $created -or $created -lt $script:EvidenceStarted){continue}
      $processKey=[string]$item.ProcessId
      if($script:ObservedBirthsByPid.ContainsKey($processKey) -and $script:ObservedBirthsByPid[$processKey] -ne $created.ToString('o')){continue}
      $parent=@($all | Where-Object {$_.ProcessId -eq $item.ParentProcessId}) | Select-Object -First 1
      $parentKey=[string]$item.ParentProcessId
      if($null -ne $parent -and $parent.CreationDate -and $script:ObservedBirthsByPid.ContainsKey($parentKey) -and $script:ObservedBirthsByPid[$parentKey] -ne ([datetime]$parent.CreationDate).ToString('o')){continue}
      $key=([string]$item.ProcessId+'|'+$created.ToString('o'))
      if(-not $script:ProcessEvidenceSeen.ContainsKey($key) -and @($result.ProcessTree).Count -lt 256){
        $script:ProcessEvidenceSeen[$key]=$true
        $script:ObservedBirthsByPid[$processKey]=$created.ToString('o')
        $result.ProcessTree+=@([PSCustomObject]@{ProcessId=[int]$item.ProcessId;ParentProcessId=[int]$item.ParentProcessId;Name=[string]$item.Name;Path=[string]$item.ExecutablePath;CommandLine=[string]$item.CommandLine;CreatedAt=$created.ToString('o')})
      }
    }
    if(((Get-Date)-$script:LastNetworkProbe).TotalSeconds -lt 10){return}
    $script:LastNetworkProbe=Get-Date
    foreach($connection in @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetTCPConnection -OperationTimeoutSec 2 -ErrorAction SilentlyContinue | Where-Object {$_.State -eq 5 -and $tracked.Contains([int]$_.OwningProcess)})){
      $owner=@($all | Where-Object {$_.ProcessId -eq $connection.OwningProcess -and $_.CreationDate -and ([datetime]$_.CreationDate) -ge $script:EvidenceStarted}) | Select-Object -First 1
      if($null -eq $owner){continue}
      $observedKey=([string]$owner.ProcessId+'|'+([datetime]$owner.CreationDate).ToString('o'))
      if(-not $script:ProcessEvidenceSeen.ContainsKey($observedKey)){continue}
      $key=[string]$connection.OwningProcess+'|'+[string]$owner.CreationDate
      if(-not $script:NetworkEvidenceSeen.ContainsKey($key) -and @($result.NetworkActivity).Count -lt 128){
        $script:NetworkEvidenceSeen[$key]=$true
        $result.NetworkActivity+=@([PSCustomObject]@{ProcessId=[int]$connection.OwningProcess;Process=[string]$owner.Name;ProcessCreatedAt=([datetime]$owner.CreationDate).ToString('o');ObservedAt=(Get-Date).ToString('o');Evidence='Established TCP connection observed; remote address omitted. Download and Internet requirement not established.';Attribution='Installer process tree'})
      }
    }
  }catch{}
}
function Initialize-DetectionEvidence($entry,$beforeEntries) {
  $rules=@()
  if($entry.Key -like 'APPX::*'){
    $rules+= [PSCustomObject]@{Type='MsixPackageIdentity';Identity=[string]$entry.ProductCode;RegistryPath='';Version=[string]$entry.DisplayVersion;Rank=98;BeforeInstall=[bool](@($beforeEntries|Where-Object {$_.ProductCode -eq $entry.ProductCode}).Count);AfterInstall=$true;AfterUninstall=$null}
  } elseif($entry.Key -like 'MSI::*'){
    $beforeNative=if($null -eq $script:NativeMsiBaselineState -or $script:NativeMsiBaselineState -notin @(-1,1,5)){$null}else{$script:NativeMsiBaselineState -ne -1}
    $rules+=[PSCustomObject]@{Type='MsiProductCode';Identity=[string]$entry.ProductCode;RegistryPath='';Provider='WindowsInstallerProductState';Version=[string]$entry.DisplayVersion;Rank=100;BeforeInstall=$beforeNative;AfterInstall=$true;AfterUninstall=$null}
  } elseif($entry.Key -like 'FILE::*'){
    $rules+= [PSCustomObject]@{Type='InstallationDirectory';Identity=[string]$entry.InstallLocation;RegistryPath='';Version=$null;Rank=40;BeforeInstall=(Get-DetectionBaselinePresence $entry.InstallLocation);AfterInstall=[bool](Test-Path -LiteralPath $entry.InstallLocation);AfterUninstall=$null}
  } else {
    if($entry.ProductCode -match '^\{[0-9A-Fa-f-]{36}\}$'){
      $rules+=[PSCustomObject]@{Type='MsiProductCode';Identity=[string]$entry.ProductCode;RegistryPath=[string]$entry.Key;Version=$null;Rank=100;BeforeInstall=[bool](@($beforeEntries|Where-Object {$_.ProductCode -eq $entry.ProductCode}).Count);AfterInstall=$true;AfterUninstall=$null}
    }
    $rules+=[PSCustomObject]@{Type='UninstallRegistryKey';Identity=[string]$entry.Key;RegistryPath=[string]$entry.Key;Version=$null;Rank=90;BeforeInstall=[bool](@($beforeEntries|Where-Object {$_.Key -eq $entry.Key}).Count);AfterInstall=$true;AfterUninstall=$null}
    if($entry.DisplayVersion){
      $rules+=[PSCustomObject]@{Type='RegistryAndVersion';Identity=[string]$entry.Key;RegistryPath=[string]$entry.Key;Version=[string]$entry.DisplayVersion;Rank=88;BeforeInstall=[bool](@($beforeEntries|Where-Object {$_.Key -eq $entry.Key -and $_.DisplayVersion -eq $entry.DisplayVersion}).Count);AfterInstall=$true;AfterUninstall=$null}
    }
  }
  $result.DetectionStrategies=@($rules | Sort-Object Rank -Descending)
  Add-DetailedDetectionCandidates $entry
}
function Set-DetectionRemovalEvidence {
  foreach($rule in @($result.DetectionStrategies)){
    try{
      if($rule.Type -eq 'MsixPackageIdentity'){$rule.AfterUninstall=[bool](@(Get-AppxPackage -ErrorAction Stop | Where-Object {$_.PackageFullName -eq $rule.Identity}).Count)}
      elseif($rule.Type -eq 'ApplicationRegistryValue'){$rule.AfterUninstall=Get-ApplicationRegistryPresence $rule}
      elseif($rule.Type -eq 'MsiProductCode' -and $rule.Provider -eq 'WindowsInstallerProductState'){
        $state=Get-NativeMsiProductState ([string]$rule.Identity)
        if($null -eq $state -or $state -notin @(-1,5)){$rule.AfterUninstall=$null}else{$rule.AfterUninstall=($state -eq 5)}
      }
      elseif($rule.Type -in @('ExecutablePathAndVersion','ServiceAndExecutable')){$rule.AfterUninstall=Get-DetailedDetectionPresence $rule}
      elseif($rule.Type -eq 'InstallationDirectory'){
        try{$rule.AfterUninstall=[bool](Get-Item -LiteralPath $rule.Identity -ErrorAction Stop).PSIsContainer}
        catch{if($_.CategoryInfo.Category -eq 'ObjectNotFound'){$rule.AfterUninstall=$false}else{$rule.AfterUninstall=$null}}
      }
      else {
        try{$entry=Get-ItemProperty -LiteralPath $rule.RegistryPath -ErrorAction Stop}
        catch{if($_.CategoryInfo.Category -eq 'ObjectNotFound'){$rule.AfterUninstall=$false}else{$rule.AfterUninstall=$null};continue}
        if($rule.Type -eq 'RegistryAndVersion'){$rule.AfterUninstall=($entry.DisplayVersion -eq $rule.Version)}else{$rule.AfterUninstall=$true}
      }
    }catch{$rule.AfterUninstall=$null}
  }
}
function Complete-RoadmapRemovalEvidence {
  Set-DetectionRemovalEvidence
  Set-RemovedComponentEvidence
  try{$result.RuntimeEnvironment+=@(Get-RuntimeEnvironmentSnapshot 'After uninstall')}catch{}
  Update-PendingRebootEvidence
  if(Get-Command Stop-PayloadTrace -ErrorAction SilentlyContinue){Stop-PayloadTrace}
  $result.EvidenceCollectionComplete=$true
  Write-Checkpoint 'Final absence verification evidence complete'
}
""";
}

