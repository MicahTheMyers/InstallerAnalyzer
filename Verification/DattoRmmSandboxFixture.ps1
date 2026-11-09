$ErrorActionPreference='Stop'
$result=[ordered]@{Passed=$false;Identity=$null;Checks=0;Phases=@();Failure=$null;TenantValidated=$false}
function Check($value,$name){if(-not $value){throw ('FAIL '+$name)};$result.Checks++;$name|Add-Content C:\InstallerOutput\datto-checks.txt}
try {
 if((Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or -not(Test-Path C:\InstallerInput\kit.zip)){throw 'Disposable test guest required'}
 $result.Identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 Check ($result.Identity -eq 'S-1-5-18') 'Real LocalSystem fixture identity'
 $userResult=Get-Content C:\InstallerOutput\non-system-result.json -Raw|ConvertFrom-Json
 Check $userResult.Rejected 'Production component refuses non-System execution before checking payloads'
 $kit=Join-Path $env:TEMP ('InstallerAnalyzer-Datto-'+[guid]::NewGuid().ToString('N'))
 Expand-Archive -LiteralPath C:\InstallerInput\kit.zip -DestinationPath $kit
 function Run-Component($action) {
   $info=New-Object Diagnostics.ProcessStartInfo
   $info.FileName=$env:ComSpec;$info.Arguments='/d /s /c ""'+(Join-Path $kit 'Component.cmd')+'""';$info.WorkingDirectory=$kit
   $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
   if($null -eq $action){$info.EnvironmentVariables.Remove('IAAction')}else{$info.EnvironmentVariables['IAAction']=$action}
   $process=[Diagnostics.Process]::Start($info);$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
   if(-not $process.WaitForExit(720000)){$process.Kill();throw 'Component test timed out'}
   $text=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
   $phase=[ordered]@{Action=$action;ExitCode=$process.ExitCode;Output=$text;At=[DateTimeOffset]::UtcNow.ToString('o')}
   $result.Phases+=@($phase);$process.Dispose()
   $result|ConvertTo-Json -Depth 6|Set-Content C:\InstallerOutput\datto-checkpoint.json
   return [pscustomobject]$phase
 }
 $phase=Run-Component $null;Check ($phase.ExitCode -eq 0 -and $phase.Output.Contains('IA_ACTION=Detect') -and $phase.Output.Contains('IA_DETECTED=0')) 'Unset IAAction defaults to safe detection of absence'
 $phase=Run-Component 'Invalid';Check ($phase.ExitCode -eq 1) 'Unknown action fails rather than running an installer'
 $payload=Join-Path $kit 'installer.exe';$held=$payload+'.held'
 Move-Item -LiteralPath $payload -Destination $held
 try {
   $phase=Run-Component 'Install';Check ($phase.ExitCode -eq 1) 'Missing installer attachment fails'
   Set-Content -LiteralPath $payload -Value 'tampered inert file'
   $phase=Run-Component 'Install';Check ($phase.ExitCode -eq 1 -and $phase.Output.Contains('checksum mismatch')) 'Tampered installer is refused before execution'
 }finally{if(Test-Path -LiteralPath $payload){Remove-Item -LiteralPath $payload};Move-Item -LiteralPath $held -Destination $payload}
 foreach($cycle in 1,2){
   $phase=Run-Component 'Install';Check ($phase.ExitCode -eq 0 -and $phase.Output.Contains('IA_DETECTED=1')) ('LocalSystem install and measured detection cycle '+$cycle)
   $phase=Run-Component 'Install';Check ($phase.ExitCode -eq 0 -and -not $phase.Output.Contains('Starting ')) ('Repeated install is skipped when detected, cycle '+$cycle)
   $phase=Run-Component 'Detect';Check ($phase.ExitCode -eq 0 -and $phase.Output.Contains('IA_DETECTED=1')) ('Explicit detection of presence cycle '+$cycle)
   $phase=Run-Component 'Uninstall';Check ($phase.ExitCode -eq 0 -and $phase.Output.Contains('IA_DETECTED=0')) ('LocalSystem uninstall and measured absence cycle '+$cycle)
   $phase=Run-Component 'Uninstall';Check ($phase.ExitCode -eq 0 -and -not $phase.Output.Contains('Starting ')) ('Repeated uninstall is skipped when absent, cycle '+$cycle)
 }
 # Execute generated MSI command assembly with only its native-process boundary mocked.
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile('C:\InstallerInput\MsiArgumentFixture.ps1',[ref]$tokens,[ref]$errors)
 Check ($errors.Count -eq 0) 'Generated MSI component syntax'
 $ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)|ForEach-Object {Invoke-Expression $_.Extent.Text}
 function Start-Process {param($FilePath,$ArgumentList,[switch]$Wait,[switch]$PassThru);$script:CapturedArguments=$ArgumentList;[pscustomobject]@{ExitCode=0}}
 $InstallerFile=Join-Path $kit "fixture O'Brien.msi";Set-Content -LiteralPath $InstallerFile -Value 'Inert MSI fixture; native launch is mocked';$null=Invoke-IAInstall
 Check ($script:CapturedArguments.Contains('PROPERTY="$(data)"') -and $script:CapturedArguments.Contains("OBRIEN='value'")) 'MSI properties remain literal data in generated commands'
 $result.Passed=$true
}catch{$result.Failure=$_.Exception.Message}
$result|ConvertTo-Json -Depth 6|Set-Content C:\InstallerOutput\result.json
