$ErrorActionPreference='Stop'
. C:\InstallerInput\helper.ps1
$result=[ordered]@{RuntimeVerified=$false;TermsAccepted=$false;InstallerLifecycleValidated=$false;NetFx3Provisioning=[ordered]@{Status='Not required';Evidence='';Detail='';Attempted=$false;Provisioned=$false;RuntimeVerified=$false;RequiresFullWindowsVM=$false;RestartNeeded=$false;ExitCode=$null}}
function Set-AnalysisHeartbeat($stage){Set-Content C:\InstallerOutput\analysis-heartbeat.txt ((Get-Date).ToString('o')+'|'+$stage)}
function Write-Checkpoint($stage){$result['Stage']=$stage;$result|ConvertTo-Json -Depth 8|Set-Content C:\InstallerOutput\checkpoint.json}
function Read-MsiProperties($path){
 $engine=$null;$db=$null;$view=$null
 try{
  $engine=New-Object -ComObject WindowsInstaller.Installer;$db=$engine.OpenDatabase($path,0)
  $view=$db.OpenView('SELECT `Property`,`Value` FROM `Property`');$view.Execute();$values=[ordered]@{}
  while($row=$view.Fetch()){try{$key=$row.StringData(1);if($key -in @('ProductName','ProductVersion','Manufacturer','ProductCode','UpgradeCode','ALLUSERS','INSTALLDIR','ISSETUPDRIVEN','SETUPEXEDIR')){$values[$key]=$row.StringData(2)}}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($row)}}
  return $values
 }catch{return @{ReadError=$_.Exception.Message}}finally{foreach($obj in @($view,$db,$engine)){if($null -ne $obj){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($obj)}}}
}
try{
 Ensure-NetFx3 'User-requested investigation: gINT requires .NET Framework 3.5 in the disposable Sandbox.'
 $result.RuntimeVerified=$result.NetFx3Provisioning.RuntimeVerified
 if(-not $result.RuntimeVerified){throw 'Runtime preflight did not pass'}
 $started=Get-Date
 $root=Start-Process -FilePath C:\InstallerInput\Gint.exe -PassThru
 $tracked=New-Object 'System.Collections.Generic.HashSet[int]';[void]$tracked.Add($root.Id)
 $seen=@{};$files=@{};$windows=@{}
 Write-Checkpoint 'Tracing gINT native launcher without silent or recording switches'
 $deadline=(Get-Date).AddMinutes(7)
 while((Get-Date) -lt $deadline){
  Set-AnalysisHeartbeat 'gint-bootstrapper-trace'
  $all=@(Get-CimInstance Win32_Process)
  $changed=$true;while($changed){$changed=$false;foreach($p in $all){if($tracked.Contains([int]$p.ParentProcessId) -and $tracked.Add([int]$p.ProcessId)){$changed=$true}}}
  foreach($p in $all){if($tracked.Contains([int]$p.ProcessId) -and -not $seen.ContainsKey([int]$p.ProcessId)){$seen[[int]$p.ProcessId]=[ordered]@{Pid=$p.ProcessId;Parent=$p.ParentProcessId;Name=$p.Name;Path=$p.ExecutablePath;CommandLine=$p.CommandLine}}}
  foreach($p in @(Get-Process)){if($p.MainWindowHandle -ne 0){$key=$p.Id.ToString()+'|'+$p.MainWindowTitle;$windows[$key]=[ordered]@{Pid=$p.Id;Name=$p.ProcessName;Title=$p.MainWindowTitle}}}
  foreach($dir in @($env:TEMP,'C:\BentleyDownloads','C:\Bentley','C:\ProgramData\Package Cache')){
   if(-not(Test-Path -LiteralPath $dir)){continue}
   foreach($f in @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -ge $started.AddMinutes(-1) -and $_.Extension -in @('.msi','.exe','.ini','.prq')} | Select-Object -First 1500)){
    if($files.ContainsKey($f.FullName)){continue}
    $item=[ordered]@{Path=$f.FullName;Bytes=$f.Length;Version=$null;Msi=$null}
    if($f.Extension -eq '.exe'){$v=$f.VersionInfo;$item.Version=[ordered]@{ProductName=$v.ProductName;Description=$v.FileDescription;Company=$v.CompanyName;OriginalFilename=$v.OriginalFilename;Version=$v.FileVersion}}
    if($f.Extension -eq '.msi'){$item.Msi=Read-MsiProperties $f.FullName}
    if($f.Name -in @('Settings.ini','setup.ini') -and $f.Length -lt 131072){$item['ConfigurationText']=[IO.File]::ReadAllText($f.FullName)}
    $files[$f.FullName]=$item
   }
  }
  [ordered]@{RuntimeVerified=$result.RuntimeVerified;Stage='Tracing';Processes=@($seen.Values);Files=@($files.Values);Windows=@($windows.Values);TermsAccepted=$false;InstallerLifecycleValidated=$false}|ConvertTo-Json -Depth 10|Set-Content C:\InstallerOutput\gint-trace.json
  if(Test-Path C:\InstallerInput\finish-trace.flag){break}
  Start-Sleep 3
 }
 $result['ProcessCount']=$seen.Count;$result['FileCount']=$files.Count;$result['Stage']='Trace complete; no lifecycle acceptance claimed'
}catch{$result['Failure']=$_.Exception.Message}
$result|ConvertTo-Json -Depth 8|Set-Content C:\InstallerOutput\result.json
