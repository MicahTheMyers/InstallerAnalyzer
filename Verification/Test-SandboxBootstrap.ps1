param([Parameter(Mandatory=$true)][string]$GeneratedRoot)
$ErrorActionPreference='Stop'
$template=[IO.File]::ReadAllText((Join-Path $GeneratedRoot 'sandbox-startup\Start-Analysis.ps1'))
$count=0
foreach($case in @('valid','parse-error','runtime-error')){
 $folder=Join-Path $GeneratedRoot ('bootstrap-'+$case);$inputPath=Join-Path $folder 'Input';$outputPath=Join-Path $folder 'Output'
 New-Item -ItemType Directory -Path $inputPath,$outputPath|Out-Null
 $script=if($case -eq 'valid'){"Set-Content -LiteralPath '"+(Join-Path $outputPath 'analysis-heartbeat.txt').Replace("'","''")+"' -Value 'inert fixture ready'"}elseif($case -eq 'parse-error'){'if ('}else{"throw 'inert runtime fixture failure'"}
 [IO.File]::WriteAllText((Join-Path $inputPath 'Record-Iss.ps1'),$script)
 $bootstrap=$template.Replace('C:\InstallerInput',$inputPath.Replace("'","''")).Replace('C:\InstallerOutput',$outputPath.Replace("'","''"))
 $path=Join-Path $inputPath 'Start-Analysis.ps1';[IO.File]::WriteAllText($path,$bootstrap)
 & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $path
 $code=$LASTEXITCODE
 if(-not(Test-Path -LiteralPath (Join-Path $outputPath 'sandbox-guest-startup.json'))){throw ('Missing bootstrap marker: '+$case)}
 $count++;Write-Output ('PASS bootstrap marker: '+$case)
 if($case -eq 'valid'){
  if($code -ne 0 -or -not(Test-Path -LiteralPath (Join-Path $outputPath 'analysis-heartbeat.txt'))){throw 'Valid bootstrap did not hand off'}
  if(Test-Path -LiteralPath (Join-Path $outputPath 'sandbox-guest-startup-error.txt')){throw 'Valid bootstrap wrote a failure'}
 }else{
  if($code -ne 1 -or -not(Test-Path -LiteralPath (Join-Path $outputPath 'sandbox-guest-startup-error.txt'))){throw ('Guest failure not captured: '+$case)}
  if(Test-Path -LiteralPath (Join-Path $outputPath 'analysis-heartbeat.txt')){throw 'Failed fixture manufactured a heartbeat'}
 }
 $count+=2;Write-Output ('PASS correct handoff/exit and failure evidence: '+$case)
}
Write-Output ('RESULT: '+$count+' bootstrap checks passed; only inert scripts executed')
