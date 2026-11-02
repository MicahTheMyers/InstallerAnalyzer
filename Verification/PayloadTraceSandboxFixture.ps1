$ErrorActionPreference='Stop'
Start-Transcript C:\InstallerOutput\fixture-log.txt
try{
[IO.Directory]::CreateDirectory('C:\InstallerTrace') | Out-Null
[IO.Directory]::CreateDirectory('C:\TraceFixture') | Out-Null
$worker=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\InstallerInput\worker.ps1' -WindowStyle Hidden -PassThru
$deadline=[DateTime]::UtcNow.AddSeconds(20)
while(-not (Test-Path C:\InstallerTrace\ready.txt) -and [DateTime]::UtcNow -lt $deadline -and -not $worker.HasExited){Start-Sleep -Milliseconds 100}
if(-not (Test-Path C:\InstallerTrace\ready.txt)){throw 'Collector not ready'}
$child=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command "Start-Sleep 1;[IO.File]::WriteAllText(''C:\TraceFixture\payload.msi'',''inert fixture bytes'');Start-Sleep 1"' -WindowStyle Hidden -PassThru
$birth=$child.StartTime.ToString('o')
$other=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command "Start-Sleep 1;[IO.File]::WriteAllText(''C:\TraceFixture\other.exe'',''inert fixture bytes'');Start-Sleep 1"' -WindowStyle Hidden -PassThru
$otherBirth=$other.StartTime.ToString('o')
$child.WaitForExit()
$other.WaitForExit()
@([pscustomobject]@{ProcessId=$child.Id;CreatedAt=$birth;Name='powershell.exe'},[pscustomobject]@{ProcessId=$other.Id;CreatedAt=$otherBirth;Name='powershell.exe'}) | ConvertTo-Json | Set-Content C:\InstallerTrace\scope.json
[IO.File]::WriteAllText('C:\InstallerTrace\stop.txt','stop')
if(-not $worker.WaitForExit(25000)){throw 'Worker did not finish in time'}
Copy-Item C:\InstallerTrace\result.json C:\InstallerOutput\trace-result.json
$trace=Get-Content C:\InstallerTrace\result.json -Raw | ConvertFrom-Json
if(@($trace.Files | Where-Object {$_.ProcessId -eq $child.Id -and $_.Path -eq 'C:\TraceFixture\payload.msi' -and $_.Operation -eq 'Write completed' -and $_.Bytes -eq 19}).Count -ne 1){throw ('Expected scoped completed file write absent: '+($trace | ConvertTo-Json -Depth 5 -Compress))}
if(@($trace.Files | Where-Object {$_.ProcessId -eq $other.Id -and $_.Path -eq 'C:\TraceFixture\other.exe' -and $_.Operation -eq 'Write completed' -and $_.Bytes -eq 19}).Count -ne 1){throw 'Second scoped process write absent'}
[IO.File]::WriteAllText('C:\InstallerOutput\PASS.txt','Real kernel file open/write/completion attributed to two distinct fixture process lifetimes; inert bytes only.')
}catch{$_ | Out-String | Set-Content C:\InstallerOutput\error.txt;if(Test-Path C:\InstallerTrace\result.json){Copy-Item C:\InstallerTrace\result.json C:\InstallerOutput\trace-result.json}}finally{Stop-Transcript;Set-Content C:\InstallerOutput\done.txt 'done'}
