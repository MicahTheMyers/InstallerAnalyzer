$ErrorActionPreference='Stop'
$result=[ordered]@{Scope='Vendor response-file replay acceptance only; not Analyzer recording or catalog proof';Success=$false;Phases=@();Error=$null;RebootRequired=$false;ActivationAttempted=$false;InstallerExecuted=$false;McAfeeProtection=$false}
$McAfeeWatchdog=$null
function Save-Result {$result|ConvertTo-Json -Depth 8|Set-Content C:\InstallerOutput\vendor-replay.json -Encoding UTF8}
function Snapshot {
 $paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
 return @(Get-ItemProperty $paths -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName}|ForEach-Object {[pscustomobject]@{Key=$_.PSPath;Name=[string]$_.DisplayName;Version=[string]$_.DisplayVersion;Publisher=[string]$_.Publisher;UninstallString=[string]$_.UninstallString;InstallLocation=[string]$_.InstallLocation}})
}
function Invoke-ReplayPhase([string]$phase,[bool]$install) {
 $log='C:\InstallerOutput\'+$phase+'.log'
 $response=if($install){'C:\ReplayFixture\setup.iss'}else{'C:\ReplayFixture\uninstall.iss'}
 $arguments=$config.PrefixArguments+$(if($install){''}else{' /uninst'})+' /f1"'+$response+'" /f2"'+$log+'"'
 $step=[ordered]@{Phase=$phase;Arguments=$arguments;StartedAt=[DateTime]::UtcNow.ToString('o');CompletedAt=$null;ExitCode=$null;LogResultCode=$null;Detected=$null;UiDetected=$false;Windows=@();WorkerWindows=@();Outcome='Running'}
 $result.Phases+=@([pscustomobject]$step);$index=$result.Phases.Count-1;Save-Result
 $started=[DateTime]::UtcNow;$process=Start-Process -FilePath $Installer -ArgumentList $arguments -PassThru
 $result.InstallerExecuted=$true;$ids=@{([string]$process.Id)=$true};$idle=0;$seconds=if($phase -eq 'initial-install'){420}else{240};$until=[DateTime]::UtcNow.AddSeconds($seconds)
 try {
  while([DateTime]::UtcNow -lt $until){
   $process.Refresh();$all=@(Get-CimInstance Win32_Process -OperationTimeoutSec 3 -ErrorAction Stop)
   for($depth=0;$depth -lt 5;$depth++){$added=$false;foreach($item in $all){if($ids.ContainsKey([string]$item.ParentProcessId) -and -not $ids.ContainsKey([string]$item.ProcessId) -and $item.CreationDate.ToUniversalTime() -ge $started.AddSeconds(-1)){$ids[[string]$item.ProcessId]=$true;$added=$true}};if(-not $added){break}}
   $live=@($all|Where-Object {$ids.ContainsKey([string]$_.ProcessId) -and $_.CreationDate.ToUniversalTime() -ge $started.AddSeconds(-1)})
   if(([DateTime]::UtcNow-$started).TotalSeconds -gt 8){
    $windows=@([InstallerAnalyzerWindowProbe]::VisibleWindows([int[]]@($live|ForEach-Object {$_.ProcessId})))
    foreach($window in $windows){
      $parts=$window -split '\|',3;$labels=@([InstallerAnalyzerWindowProbe]::ReadStaticLabels([long]$parts[0],[int]$parts[1]))
      if($parts[2] -eq '<untitled visible window>' -and $labels.Count -eq 0){$result.Phases[$index].WorkerWindows=@(@($result.Phases[$index].WorkerWindows)+$window|Select-Object -Unique|Select-Object -First 20)}
      else{$result.Phases[$index].UiDetected=$true;$result.Phases[$index].Windows=@(@($result.Phases[$index].Windows)+$window|Select-Object -Unique|Select-Object -First 20)}
    }
   }
   if($process.HasExited -and $live.Count -eq 0){$idle++}else{$idle=0}
   if($idle -ge 4){break}
   Save-Result;Start-Sleep -Seconds 1
  }
  if(-not $process.HasExited -or $idle -lt 4){throw ('Bounded replay timeout at '+$phase)}
  $result.Phases[$index].ExitCode=$process.ExitCode
  if($process.ExitCode -eq 3010){$result.RebootRequired=$true}
  if(Test-Path -LiteralPath $log){$content=Get-Content -LiteralPath $log -Raw;$matches=[regex]::Matches($content,'(?m)^\s*ResultCode\s*=\s*(-?\d+)\s*$');if($matches.Count -eq 1){$result.Phases[$index].LogResultCode=[int]$matches[0].Groups[1].Value}}
  $snapshot=Snapshot;$matches=@($snapshot|Where-Object {$_.Name -eq $config.ProductName -and $_.Publisher -eq $config.Publisher -and $_.Version -eq $config.ProductVersion})
  $result.Phases[$index].Detected=($matches.Count -eq 1)
  if($install){$snapshot|ConvertTo-Json -Depth 4|Set-Content ('C:\InstallerOutput\'+$phase+'-registrations.json')}
  if($process.ExitCode -notin @(0,3010)){throw ($phase+' returned '+$process.ExitCode)}
  if($result.Phases[$index].LogResultCode -ne 0){throw ($phase+' lacks a successful InstallShield ResultCode=0 log')}
  if($result.Phases[$index].UiDetected){throw ($phase+' displayed visible UI: '+($result.Phases[$index].Windows -join '; '))}
  if($install -and $matches.Count -ne 1){throw ($phase+' did not establish a unique expected installed identity')}
  if(-not $install -and @($snapshot|Where-Object {$_.Name -eq $config.ProductName -and $_.Publisher -eq $config.Publisher}).Count -ne 0){throw ($phase+' left the application registered')}
  $result.Phases[$index].Outcome='Passed'
 }finally{$result.Phases[$index].CompletedAt=[DateTime]::UtcNow.ToString('o');$process.Dispose();Save-Result}
}
try {
 if($env:USERNAME -ne 'WDAGUtilityAccount'){throw 'Disposable Sandbox guest required'}
 $config=Get-Content C:\InstallerInput\replay-config.json -Raw|ConvertFrom-Json
 if($config.InstallerFile -notmatch '^[A-Za-z0-9_.-]+\.exe$' -or $config.PrefixArguments -notin @('/s','/s /a /s')){throw 'Unsupported fixture input'}
 New-Item -ItemType Directory -Path C:\ReplayFixture -Force|Out-Null
 foreach($name in @($config.InstallerFile,'setup.iss','uninstall.iss')){Copy-Item -LiteralPath ('C:\PublishedVerifier\'+$name) -Destination ('C:\ReplayFixture\'+$name)}
 $Installer='C:\ReplayFixture\'+$config.InstallerFile
 if((Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash -ne $config.Sha256){throw 'Guest installer hash mismatch'}
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile('C:\InstallerInput\DiscoveryEngine.ps1',[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Production helper source does not parse'}
 foreach($function in $ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Start-McAfeeWatchdog','Stop-McAfeeWatchdog')},$true)){. ([scriptblock]::Create($function.Extent.Text))}
 $probe=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.Contains('public static class InstallerAnalyzerWindowProbe')},$true))
 if($probe.Count -ne 1){throw 'Production read-only window probe missing'}
 Add-Type -TypeDefinition $probe[0].Value
 $BlockBundledMcAfee=$true;$McAfeeWatchdogLog=Join-Path $env:TEMP 'InstallerAnalyzer-McAfeeWatchdog.log';$McAfeeWatchdog=Start-McAfeeWatchdog
 if($null -eq $McAfeeWatchdog){throw 'Required bundle protection not started'};$result.McAfeeProtection=$true
 $baseline=Snapshot;$baseline|ConvertTo-Json -Depth 4|Set-Content C:\InstallerOutput\baseline-registrations.json
 if(@($baseline|Where-Object {$_.Name -eq $config.ProductName}).Count){throw 'Fixture baseline already contains target product'}
 Invoke-ReplayPhase 'initial-install' $true
 Invoke-ReplayPhase 'initial-uninstall' $false
 Invoke-ReplayPhase 'reinstall' $true
 Invoke-ReplayPhase 'final-uninstall' $false
 $result.Success=$true
 Set-Content C:\InstallerOutput\PASS.txt 'PASS vendor InstallShield response files: fresh install/removal, clean reinstall/final absence, exact identity, ResultCode=0 logs and no titled/control-bearing installer UI after startup grace; untitled worker windows retained separately. No activation attempted; Analyzer recording is not claimed.'
}catch{$result.Error=$_.Exception.Message;$_|Out-String|Set-Content C:\InstallerOutput\error.txt}finally{
 if($null -ne $McAfeeWatchdog){Stop-McAfeeWatchdog}
 $logNumber=0
 foreach($logRoot in @($env:TEMP,'C:\Windows\Temp')){
   foreach($log in @(Get-ChildItem -LiteralPath $logRoot -Filter '*.log' -File -ErrorAction SilentlyContinue|Where-Object {$_.Name -match '(?i)vc|dd_|runtime|rocscience|sentinel|hasp'}|Sort-Object LastWriteTime -Descending|Select-Object -First 8)){
     ('FILE '+$log.Name)|Set-Content ('C:\InstallerOutput\runtime-tail-'+$logNumber+'.txt');Get-Content -LiteralPath $log.FullName -Tail 40 -ErrorAction SilentlyContinue|Add-Content ('C:\InstallerOutput\runtime-tail-'+$logNumber+'.txt');$logNumber++
   }
 }
 Save-Result;Set-Content C:\InstallerOutput\done.txt 'done'
}
