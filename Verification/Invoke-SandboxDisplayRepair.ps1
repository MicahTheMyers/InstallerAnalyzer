param([ValidateSet('Apply','Restore')][string]$Mode='Apply')
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
$helper=Join-Path $PSScriptRoot 'Set-SandboxSoftwareDecoding.ps1'
$backup=Join-Path $project 'outputs\Sandbox-Software-Decoding-Original.json'
$log=Join-Path $project ('outputs\Sandbox-Software-Decoding-'+$Mode+'.txt')
function Quote-Literal([string]$value){"'"+$value.Replace("'","''")+"'"}
$statement='try { & '+(Quote-Literal $helper)+' -Mode '+$Mode+' -BackupPath '+(Quote-Literal $backup)+' *> '+(Quote-Literal $log)+'; exit 0 } catch { $_ | Out-String | Add-Content -LiteralPath '+(Quote-Literal $log)+'; exit 1 }'
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($statement))
# This launcher is for the user to run. Windows presents its normal administrator
# prompt; this script never supplies credentials or automates that prompt.
$process=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded)
if(Test-Path -LiteralPath $log){Get-Content -LiteralPath $log|Write-Output}
if($process.ExitCode -ne 0){throw ('Graphics workaround did not complete. See '+$log)}
Write-Output 'Done. This changes the graphics decoding policy only; the Sandbox display still needs verification on a fresh connection.'
