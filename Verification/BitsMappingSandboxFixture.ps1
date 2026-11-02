$ErrorActionPreference='Stop'
Start-Transcript C:\InstallerOutput\fixture-log.txt
try {
  if($env:USERNAME -ne 'WDAGUtilityAccount'){throw 'Sandbox guest required'}
  New-Item -ItemType Directory -Path C:\InstallerTrace,C:\TraceFixture -Force | Out-Null
  # Inert HTTP fixture. BITS traffic stays inside the guest; no external endpoint is used.
  Add-Type -TypeDefinition @'
using System;using System.Net;using System.Net.Sockets;using System.Text;using System.Threading;
public static class FixtureServer {
 public static void Start() { new Thread(Run) {IsBackground=true}.Start(); }
 static void Run() { var listener=new TcpListener(IPAddress.Loopback,18888);listener.Start();
  while(true) { using(var client=listener.AcceptTcpClient()) using(var stream=client.GetStream()) {
   var input=new byte[32768];var count=0;
   while(count<input.Length) {var n=stream.Read(input,count,input.Length-count);if(n<=0)break;count+=n;if(Encoding.ASCII.GetString(input,0,count).Contains("\r\n\r\n"))break;}
   var request=Encoding.ASCII.GetString(input,0,count);var body=Encoding.ASCII.GetBytes("inert BITS fixture bytes");
   var header=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: "+body.Length+"\r\nContent-Type: application/octet-stream\r\nLast-Modified: Wed, 28 Oct 2026 00:00:00 GMT\r\nConnection: close\r\n\r\n");
   stream.Write(header,0,header.Length);if(!request.StartsWith("HEAD "))stream.Write(body,0,body.Length);
  }}
 }
}
'@
  [FixtureServer]::Start()
  $worker=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\InstallerInput\worker.ps1' -WindowStyle Hidden -PassThru
  $until=[DateTime]::UtcNow.AddSeconds(20)
  while(-not(Test-Path C:\InstallerTrace\ready.txt) -and [DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 100}
  if(-not(Test-Path C:\InstallerTrace\ready.txt)){throw 'Collector not ready'}
  @'
$ErrorActionPreference='Stop'
try {
 Import-Module BitsTransfer
 $job=Start-BitsTransfer -Source 'http://127.0.0.1:18888/private/payload.msi?token=fixture-secret' -Destination 'C:\TraceFixture\payload.msi' -Asynchronous -TransferType Download
 $until=[DateTime]::UtcNow.AddSeconds(45)
 while($job.JobState -notin @('Transferred','Error') -and [DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 200}
 if($job.JobState -ne 'Transferred'){throw ('BITS state '+$job.JobState+': '+$job.ErrorDescription)}
 Complete-BitsTransfer -BitsJob $job
 if([IO.File]::ReadAllText('C:\TraceFixture\payload.msi') -ne 'inert BITS fixture bytes'){throw 'Fixture byte mismatch'}
 Set-Content C:\InstallerTrace\download-pass.txt 'PASS inert loopback download'
} catch {$_ | Out-String | Set-Content C:\InstallerTrace\download-error.txt}
'@ | Set-Content C:\TraceFixture\download.ps1
  $child=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\TraceFixture\download.ps1' -WindowStyle Hidden -PassThru
  $birth=$child.StartTime.ToString('o')
  if(-not $child.WaitForExit(55000)){throw 'BITS child timed out'}
  if(-not(Test-Path C:\InstallerTrace\download-pass.txt)){throw (Get-Content C:\InstallerTrace\download-error.txt -Raw)}
  @([pscustomobject]@{ProcessId=$child.Id;CreatedAt=$birth;Name='powershell.exe'}) | ConvertTo-Json | Set-Content C:\InstallerTrace\scope.json
  Set-Content C:\InstallerTrace\stop.txt 'stop'
  if(-not $worker.WaitForExit(25000)){throw 'Collector did not finish'}
  Copy-Item C:\InstallerTrace\result.json C:\InstallerOutput\trace-result.json
  $trace=Get-Content C:\InstallerTrace\result.json -Raw | ConvertFrom-Json
  $mappings=@($trace.BitsMappings | Where-Object {$_.ProcessId -eq $child.Id -and $_.Path -eq 'C:\TraceFixture\payload.msi' -and $_.RequestedOrigin -eq 'http://127.0.0.1:18888'})
  if($mappings.Count -ne 1){throw ('Expected BITS mapping absent: '+($trace | ConvertTo-Json -Depth 6 -Compress))}
  if((Get-Content C:\InstallerOutput\trace-result.json -Raw).Contains('fixture-secret')){throw 'URL secret leaked'}
  Set-Content C:\InstallerOutput\PASS.txt 'PASS real loopback BITS download; event mapping tied to observed client lifetime; URL path/query omitted; production report makes no completion claim.'
} catch { $_ | Out-String | Set-Content C:\InstallerOutput\error.txt
  if(Test-Path C:\InstallerTrace\result.json){Copy-Item C:\InstallerTrace\result.json C:\InstallerOutput\trace-result.json}
} finally {Stop-Transcript;Set-Content C:\InstallerOutput\done.txt 'done'}
