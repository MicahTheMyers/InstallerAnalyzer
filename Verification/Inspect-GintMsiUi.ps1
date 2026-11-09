$ErrorActionPreference='Stop'
$result=[ordered]@{Purpose='Inspect main MSI UI startup only';InstallAccepted=$false;TermsAccepted=$false;RuntimeProvisioningAttempted=$false;Windows=@()}
try {
 $client="$env:WINDIR\System32\msiexec.exe"
 $msiArguments=@('/i','C:\InstallerInput\gINT.msi','/L*V!','C:\InstallerOutput\gint-direct-ui.log')
 if(Test-Path C:\InstallerInput\use-x86.flag){$client="$env:WINDIR\SysWOW64\msiexec.exe";$msiArguments+=@('INSTALL32BITONLY=0')}
 $result['Client']=$client
 $process=Start-Process -FilePath $client -ArgumentList $msiArguments -PassThru
 $result['Pid']=$process.Id
 $until=(Get-Date).AddMinutes(3)
 while((Get-Date) -lt $until){
  $result.Windows=@(Get-Process | Where-Object {$_.MainWindowHandle -ne 0} | Select-Object Id,ProcessName,MainWindowTitle)
  $result['Processes']=@(Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'" | Select-Object ProcessId,ParentProcessId,CommandLine)
  $result|ConvertTo-Json -Depth 5|Set-Content C:\InstallerOutput\ui-observation.json
  if(@($result.Windows | Where-Object {$_.ProcessName -eq 'msiexec' -and $_.MainWindowTitle -like 'gINT*Setup'}).Count){$result['ProductWindowObserved']=$true;break}
  Set-Content C:\InstallerOutput\analysis-heartbeat.txt ((Get-Date).ToString('o')+'|main-msi-ui-inspection')
  if(Test-Path C:\InstallerInput\finish-ui.flag){break}
  Start-Sleep 2
 }
 $process.Refresh();$result['Exited']=$process.HasExited
 if($process.HasExited){$result['ExitCode']=$process.ExitCode}
}catch{$result['Failure']=$_.Exception.Message}
$result|ConvertTo-Json -Depth 5|Set-Content C:\InstallerOutput\result.json
