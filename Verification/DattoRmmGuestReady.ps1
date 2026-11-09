$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount'){throw 'Sandbox user required'}
Set-Location C:\InstallerInput\guard
& $env:ComSpec /d /c Component.cmd > C:\InstallerOutput\datto-non-system.txt 2>&1
[ordered]@{ExitCode=$LASTEXITCODE;Rejected=(($LASTEXITCODE -eq 1) -and ((Get-Content C:\InstallerOutput\datto-non-system.txt -Raw) -match 'Run this machine-wide component as LocalSystem'))}|ConvertTo-Json|Set-Content C:\InstallerOutput\non-system-result.json
Set-Content C:\InstallerOutput\datto-ready.txt 'Ready for LocalSystem test'
