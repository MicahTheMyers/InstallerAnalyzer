$ErrorActionPreference='Stop'
$result=[ordered]@{Passed=$false;Phases=@();Failure=$null;Scope='Actual generated deployment scripts and package replay; no manual wizard input'}
try {
 if($env:USERNAME -ne 'WDAGUtilityAccount' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine'){throw 'Disposable Sandbox required'}
 $config=Get-Content C:\InstallerInput\deployment-config.json -Raw|ConvertFrom-Json
 $InstallerFolder=Join-Path $env:TEMP ('InstallerAnalyzer-RecordedDeployment-'+[guid]::NewGuid().ToString('N'))
 Expand-Archive -LiteralPath C:\InstallerInput\package.zip -DestinationPath $InstallerFolder
 $InstallerFile=Join-Path $InstallerFolder $config.InstallerFile
 if((Get-FileHash -LiteralPath $InstallerFile -Algorithm SHA256).Hash -ne $config.Sha256){throw 'Exported installer hash mismatch'}
 Set-Location -LiteralPath $InstallerFolder
 function Test-DeploymentDetection {
   $value=@(& C:\InstallerInput\Detect.ps1)
   if($value.Count -ne 1 -or $value[0] -isnot [bool]){throw 'Detection script must return exactly one Boolean'}
   return $value[0]
 }
 if(Test-DeploymentDetection){throw 'Fresh guest unexpectedly detects the application'}
 foreach($cycle in 1,2){
   foreach($phase in @('Install','Uninstall')){
     $step=[ordered]@{Cycle=$cycle;Phase=$phase;StartedAt=[DateTimeOffset]::UtcNow.ToString('o');CompletedAt=$null;DetectedAfter=$null}
     $result.Phases+=@($step)
     $result|ConvertTo-Json -Depth 6|Set-Content C:\InstallerOutput\deployment-checkpoint.json
     & ('C:\InstallerInput\'+$phase+'.ps1') *>> C:\InstallerOutput\deployment-script-output.txt
     $expected=$phase -eq 'Install';$matched=$false
     for($attempt=0;$attempt -lt 10;$attempt++){
       $detected=Test-DeploymentDetection
       if($detected -eq $expected){$matched=$true;break}
       Start-Sleep 3
     }
     $step.DetectedAfter=$detected;$step.CompletedAt=[DateTimeOffset]::UtcNow.ToString('o')
     if(-not $matched){throw ('Generated '+$phase+' did not establish the expected detection state')}
   }
 }
 $result.Passed=$true
}catch{$result.Failure=$_.Exception.Message}
$result|ConvertTo-Json -Depth 6|Set-Content C:\InstallerOutput\result.json
