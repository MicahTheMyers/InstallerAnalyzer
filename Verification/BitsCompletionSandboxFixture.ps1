$ErrorActionPreference='Stop'
Start-Transcript C:\InstallerOutput\fixture-log.txt
try {
 if($env:USERNAME -ne 'WDAGUtilityAccount'){throw 'Fresh Sandbox guest required'}
 New-Item -ItemType Directory -Path C:\InstallerTrace,C:\TraceFixture -Force|Out-Null
 Add-Type -TypeDefinition @'
using System;using System.Net;using System.Net.Sockets;using System.Text;using System.Threading;
public static class CompletionFixtureServer {
 public static int Redirects,FinalHits;
 public static void Start(){new Thread(()=>Run(18888)){IsBackground=true}.Start();new Thread(()=>Run(18889)){IsBackground=true}.Start();}
 static void Run(int port){var listener=new TcpListener(IPAddress.Loopback,port);listener.Start();
  while(true){try{using(var client=listener.AcceptTcpClient())using(var stream=client.GetStream()){
   stream.ReadTimeout=5000;var input=new byte[32768];var count=0;
   while(count<input.Length){var n=stream.Read(input,count,input.Length-count);if(n<=0)break;count+=n;if(Encoding.ASCII.GetString(input,0,count).Contains("\r\n\r\n"))break;}
   var request=Encoding.ASCII.GetString(input,0,count);var body=Encoding.ASCII.GetBytes("inert BITS fixture bytes");var status="200 OK";var extra="";
   if(request.Contains(" /redirect")){Interlocked.Increment(ref Redirects);status="302 Found";extra="Location: http://127.0.0.1:18889/final/payload.msi\r\n";body=new byte[0];}
   else if(request.Contains(" /fail")){status="404 Not Found";body=new byte[0];}
   if(port==18889)Interlocked.Increment(ref FinalHits);
   var header=Encoding.ASCII.GetBytes("HTTP/1.1 "+status+"\r\n"+extra+"Content-Length: "+body.Length+"\r\nContent-Type: application/octet-stream\r\nLast-Modified: Wed, 28 Oct 2026 00:00:00 GMT\r\nConnection: close\r\n\r\n");stream.Write(header,0,header.Length);if(!request.StartsWith("HEAD "))stream.Write(body,0,body.Length);
  }}catch(System.IO.IOException){}catch(SocketException){}}
 }
}
'@
 [CompletionFixtureServer]::Start()
 $worker=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\InstallerInput\worker.ps1' -WindowStyle Hidden -PassThru
 $until=[DateTime]::UtcNow.AddSeconds(25)
 while(-not(Test-Path C:\InstallerTrace\bits-ready.txt) -and [DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 100}
 if(-not(Test-Path C:\InstallerTrace\bits-ready.txt)){throw 'BITS observer not ready'}
 @'
$ErrorActionPreference='Stop';$rows=@()
try{
 Import-Module BitsTransfer
 foreach($name in @('good','redirect','cancel','unacked','changed','failed')){
  $endpoint=if($name -eq 'redirect'){'redirect'}elseif($name -eq 'failed'){'fail'}else{'direct'}
  $path='C:\TraceFixture\'+$name+'.msi'
  $job=Start-BitsTransfer -Source ('http://127.0.0.1:18888/'+$endpoint+'/payload.msi?token=fixture-secret') -Destination $path -Asynchronous -TransferType Download
  $row=[pscustomobject]@{Name=$name;JobId=[string]$job.JobId;Path=$path;TransferredAt='';AckBefore='';AckAfter='';State=''};$rows+=@($row)
  $until=[DateTime]::UtcNow.AddSeconds(30)
  while($job.JobState -notin @('Transferred','Error','TransientError') -and [DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 100}
  $row.State=[string]$job.JobState
  if($name -eq 'failed'){
   if($job.JobState -notin @('Error','TransientError')){throw 'Expected HTTP failure absent'}
   continue
  }
  if($job.JobState -ne 'Transferred'){throw ('Unexpected BITS state '+$name+': '+$job.JobState)}
  $row.TransferredAt=[DateTime]::UtcNow.ToString('o')
  $probe=Get-BitsTransfer -JobId $job.JobId
  $shape=[pscustomobject]@{Name=$name;State=[string]$probe.JobState;Type=[string]$probe.TransferType;JobBytesTotal=[string]$probe.BytesTotal;JobBytesTransferred=[string]$probe.BytesTransferred;FilesTotal=$probe.FilesTotal;FilesTransferred=$probe.FilesTransferred;FileCount=$probe.FileList.Count;FileComplete=$probe.FileList[0].IsTransferComplete;FileBytesTotal=[string]$probe.FileList[0].BytesTotal;FileBytesTransferred=[string]$probe.FileList[0].BytesTransferred}
  $shape|ConvertTo-Json|Add-Content C:\InstallerTrace\sample-shapes.txt
  # Hold the fixture state so the independent 500-ms read-only observer can sample it.
  Start-Sleep -Milliseconds 1600
  if($name -eq 'cancel'){Remove-BitsTransfer -BitsJob $job;continue}
  if($name -eq 'unacked'){
   if(Test-Path -LiteralPath $path){throw 'Unacknowledged destination unexpectedly available'}
   continue
  }
  $row.AckBefore=[DateTime]::UtcNow.ToString('o');Complete-BitsTransfer -BitsJob $job;$row.AckAfter=[DateTime]::UtcNow.ToString('o')
  if([IO.File]::ReadAllText($path) -ne 'inert BITS fixture bytes'){throw 'Transferred fixture bytes differ'}
  if($name -eq 'changed'){[IO.File]::WriteAllText($path,'changed length')}
 }
 Set-Content C:\InstallerTrace\download-pass.txt 'PASS fixture transfers'
}catch{$_|Out-String|Set-Content C:\InstallerTrace\download-error.txt}finally{$rows|ConvertTo-Json -Depth 4|Set-Content C:\InstallerTrace\jobs.json}
'@ | Set-Content C:\TraceFixture\download.ps1
 $child=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\TraceFixture\download.ps1' -WindowStyle Hidden -PassThru
 $birth=$child.StartTime.ToString('o')
 if(-not $child.WaitForExit(65000)){throw 'BITS fixture timed out'}
 if(-not(Test-Path C:\InstallerTrace\download-pass.txt)){throw (Get-Content C:\InstallerTrace\download-error.txt -Raw)}
 @([pscustomobject]@{ProcessId=$child.Id;CreatedAt=$birth;Name='powershell.exe'})|ConvertTo-Json|Set-Content C:\InstallerTrace\scope.json
 Set-Content C:\InstallerTrace\stop.txt 'stop'
 if(-not $worker.WaitForExit(30000)){throw 'Collector timed out'}
 Copy-Item C:\InstallerTrace\result.json C:\InstallerOutput\trace-result.json
 Copy-Item C:\InstallerTrace\jobs.json C:\InstallerOutput\fixture-stages.json
 Copy-Item C:\InstallerTrace\sample-shapes.txt C:\InstallerOutput\sample-shapes.txt
 $trace=Get-Content C:\InstallerTrace\result.json -Raw|ConvertFrom-Json
 $rows=Get-Content C:\InstallerTrace\jobs.json -Raw|ConvertFrom-Json
 # Retain only sanitized signal metadata for checking the native event's timing.
 $signals=@();$query=New-Object Diagnostics.Eventing.Reader.EventLogQuery 'C:\InstallerTrace\payload.etl',([Diagnostics.Eventing.Reader.PathType]::FilePath)
 $reader=New-Object Diagnostics.Eventing.Reader.EventLogReader $query
 try{
  for($i=0;$i -lt 100000;$i++){$event=$reader.ReadEvent();if($null -eq $event){break};try{
   if($event.ProviderName -eq 'Microsoft-Windows-Bits-Client' -and $event.Id -in @(4,16403)){$xml=[xml]$event.ToXml();$data=@{};foreach($field in $xml.Event.EventData.Data){$data[[string]$field.Name]=[string]$field.'#text'};$signals+=@([pscustomobject]@{Id=$event.Id;JobId=$data['jobId'];Time=$event.TimeCreated.ToUniversalTime().ToString('o');Bytes=$data['bytesTransferred'];FileCount=$data['fileCount'];Owner=$data['jobOwner']})}
  }finally{$event.Dispose()}}
 }finally{$reader.Dispose()}
 $signals|ConvertTo-Json -Depth 4|Set-Content C:\InstallerOutput\completion-signals.json
 foreach($name in @('good','redirect','changed')){
  $row=$rows|Where-Object {$_.Name -eq $name};$download=@($trace.BitsDownloads|Where-Object {$_.JobId -eq $row.JobId})
  if($download.Count -ne 1){throw ('Expected completion evidence absent: '+$name+'; '+($trace|ConvertTo-Json -Depth 6 -Compress))}
  if($download[0].RequestedOrigin -ne 'http://127.0.0.1:18888'){throw 'Requested origin changed to a redirect destination'}
  if([DateTimeOffset]::Parse($download[0].CompletionObservedAt) -lt [DateTimeOffset]::Parse($row.AckBefore)){throw 'Event 4 preceded explicit acknowledgment; completion semantics need revision'}
  if($name -eq 'changed'){if($download[0].Sha256 -or $download[0].FileSnapshotStatus -notlike '*length differs*'){throw 'Changed local file received a matching fingerprint'}}
  else{if($download[0].Sha256 -ne (Get-FileHash -LiteralPath $row.Path -Algorithm SHA256).Hash){throw 'Local snapshot digest mismatch'}}
 }
 foreach($name in @('cancel','unacked','failed')){$row=$rows|Where-Object {$_.Name -eq $name};if(@($trace.BitsDownloads|Where-Object {$_.JobId -eq $row.JobId}).Count){throw ('Unfinished/failed transfer falsely reported complete: '+$name)}}
 if([CompletionFixtureServer]::Redirects -lt 1 -or [CompletionFixtureServer]::FinalHits -lt 1){throw 'Redirect fixture was not exercised'}
 if((Get-Content C:\InstallerOutput\trace-result.json -Raw).Contains('fixture-secret')){throw 'URL secret leaked'}
 Set-Content C:\InstallerOutput\PASS.txt 'PASS real BITS completed direct and redirected inert downloads; acknowledgment timing and locked local digests; cancelled/unacknowledged/HTTP-failed jobs withheld; changed local file length refused; requested origin only; no payload executed.'
}catch{$_|Out-String|Set-Content C:\InstallerOutput\error.txt
 foreach($file in @('result.json','jobs.json','download-error.txt')){if(Test-Path ('C:\InstallerTrace\'+$file)){Copy-Item -LiteralPath ('C:\InstallerTrace\'+$file) -Destination ('C:\InstallerOutput\debug-'+$file)}}
}finally{
 if(Test-Path C:\InstallerTrace\jobs.json){Import-Module BitsTransfer -ErrorAction SilentlyContinue;$cleanupRows=Get-Content C:\InstallerTrace\jobs.json -Raw|ConvertFrom-Json;foreach($row in $cleanupRows){try{Get-BitsTransfer -JobId ([Guid]$row.JobId) -ErrorAction SilentlyContinue|Remove-BitsTransfer -ErrorAction SilentlyContinue}catch{}}}
 Stop-Transcript;Set-Content C:\InstallerOutput\done.txt 'done'
}
