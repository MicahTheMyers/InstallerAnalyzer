$ErrorActionPreference='Stop'
$result=[ordered]@{Purpose='Isolate vendor prerequisite command from user trace';CredentialsEntered=$false;UserInterfaceAutomated=$false;MainGintLaunched=$false;Snapshots=@()}
try {
 $started=Get-Date
 $process=Start-Process -FilePath C:\InstallerInput\Setup_CONNECTIONClientx64_10_00_17_010.exe -ArgumentList @('/q:a','/c:"msiexec /qb!"','/log','C:\InstallerOutput\CONNECTION_Client_control.log') -PassThru
 $tracked=New-Object 'System.Collections.Generic.HashSet[int]';[void]$tracked.Add($process.Id)
 $observed=@{};$until=(Get-Date).AddMinutes(12)
 while((Get-Date) -lt $until){
  $all=@(Get-CimInstance Win32_Process);$changed=$true
  while($changed){$changed=$false;foreach($p in $all){if($tracked.Contains([int]$p.ParentProcessId) -and $tracked.Add([int]$p.ProcessId)){$changed=$true}}}
  foreach($p in $all){if($tracked.Contains([int]$p.ProcessId)){$observed[[int]$p.ProcessId]=[ordered]@{Pid=$p.ProcessId;Parent=$p.ParentProcessId;Name=$p.Name;CommandLine=$p.CommandLine}}}
  $process.Refresh()
  $result['RootExited']=$process.HasExited
  if($process.HasExited){$result['RootExitCode']=$process.ExitCode}
  $result['ActiveSetup']=@($all | Where-Object {$tracked.Contains([int]$_.ProcessId) -and $_.Name -match '(?i)^Setup_CONNECTIONClient'} | Select-Object ProcessId,Name)
  $result['Windows']=@(Get-Process | Where-Object {$_.MainWindowHandle -ne 0} | Select-Object ProcessName,MainWindowTitle)
  $result['Processes']=@($observed.Values)
  $result|ConvertTo-Json -Depth 7|Set-Content C:\InstallerOutput\connection-observation.json
  Set-Content C:\InstallerOutput\analysis-heartbeat.txt ((Get-Date).ToString('o')+'|connection-handoff-control')
  if($process.HasExited -and @($result.ActiveSetup).Count -eq 0){break}
  Start-Sleep 3
 }
 $result['ConnectionEntries']=@(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like '*CONNECTION Client*'} | Select-Object DisplayName,DisplayVersion,WindowsInstaller,PSChildName)
 $result['TimedOut']=((Get-Date) -ge $until)
}catch{$result['Failure']=$_.Exception.Message}
$result|ConvertTo-Json -Depth 7|Set-Content C:\InstallerOutput\result.json
