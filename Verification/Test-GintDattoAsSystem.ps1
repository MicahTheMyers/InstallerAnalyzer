$ErrorActionPreference='Stop'
$result=[ordered]@{Passed=$false;Checks=0;Phases=@();DattoTenantValidated=$false}
function Check($condition,$description){if(-not $condition){throw $description};$result.Checks++;Write-Output ('PASS '+$description)}
try {
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Disposable guest LocalSystem context required'}
 if((Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or -not(Test-Path C:\InstallerInput\Record-Iss.ps1)){throw 'Disposable guest required'}
 $kit='C:\GintDattoKit'
 $before=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState
 function Run-Component($action){
  $info=New-Object Diagnostics.ProcessStartInfo
  $info.FileName='C:\Windows\System32\cmd.exe';$info.Arguments='/d /c Component.cmd';$info.WorkingDirectory=$kit
  $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  if($null -eq $action){$info.EnvironmentVariables.Remove('IAAction')}else{$info.EnvironmentVariables['IAAction']=$action}
  $process=[Diagnostics.Process]::Start($info)
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  try {
   if(-not $process.WaitForExit(1500000)){throw 'Datto component replay timed out.'}
   $phase=[pscustomobject]@{Action=$action;ExitCode=$process.ExitCode;Output=($stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult())}
   $result.Phases+=@($phase)
   $result|ConvertTo-Json -Depth 6|Set-Content C:\InstallerOutput\datto-checkpoint.json
   return $phase
  }finally{$process.Dispose()}
 }
 $phase=Run-Component $null;Check ($phase.ExitCode -eq 0 -and $phase.Output.Contains('IA_ACTION=Detect') -and $phase.Output.Contains('IA_DETECTED=0')) 'Unset action safely detects absence'
 $phase=Run-Component 'Invalid';Check ($phase.ExitCode -eq 1) 'Unknown action is rejected'
 $payload=Join-Path $kit 'vc8redist_x86.exe';$held=$payload+'.held'
 Move-Item -LiteralPath $payload -Destination $held
 try {
  $phase=Run-Component 'Install';Check ($phase.ExitCode -eq 1 -and -not $phase.Output.Contains('IA_STEP=')) 'Missing prerequisite attachment prevents installer execution'
  Set-Content -LiteralPath $payload -Value 'tampered inert data'
  $phase=Run-Component 'Install';Check ($phase.ExitCode -eq 1 -and $phase.Output.Contains('checksum mismatch') -and -not $phase.Output.Contains('IA_STEP=')) 'Changed prerequisite attachment is refused before execution'
 }finally{if(Test-Path -LiteralPath $payload){Remove-Item -LiteralPath $payload};Move-Item -LiteralPath $held -Destination $payload}
 foreach($cycle in 1,2){
  $phase=Run-Component 'Install';Check ($phase.ExitCode -eq 0 -and $phase.Output.Contains('IA_DETECTED=1')) ('LocalSystem gINT install cycle '+$cycle)
  $phase=Run-Component 'Install';Check ($phase.ExitCode -eq 0 -and -not $phase.Output.Contains('IA_STEP=')) ('Repeated install skips all installer actions cycle '+$cycle)
  $phase=Run-Component 'Detect';Check ($phase.ExitCode -eq 0 -and $phase.Output.Contains('IA_DETECTED=1')) ('Measured presence cycle '+$cycle)
  $phase=Run-Component 'Uninstall';Check ($phase.ExitCode -eq 0 -and $phase.Output.Contains('IA_DETECTED=0')) ('LocalSystem gINT removal cycle '+$cycle)
  $phase=Run-Component 'Uninstall';Check ($phase.ExitCode -eq 0 -and -not $phase.Output.Contains('IA_STEP=')) ('Repeated removal is skipped cycle '+$cycle)
 }
 $engine=New-Object -ComObject WindowsInstaller.Installer
 try{Check ($engine.ProductState('{710F4C1C-CC18-4C49-8CBF-51240C89A1A2}') -eq 5 -and $engine.ProductState('{90140000-00D1-0409-0000-0000000FF1CE}') -eq 5) 'gINT removal preserves shared prerequisites'}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine)}
 Check ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState -eq $before) 'Exported component leaves target Smart App Control unchanged'
 $result.Passed=$true
}catch{$result['Error']=$_.Exception.Message}
$result|ConvertTo-Json -Depth 7|Set-Content C:\InstallerOutput\datto-result.json
