namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string PayloadTraceEvidenceScript = """
$script:PayloadTraceWorker=$null
$script:PayloadTraceStopped=$false
function Start-PayloadTrace {
  try{
    [IO.Directory]::CreateDirectory('C:\InstallerTrace') | Out-Null
    [IO.File]::WriteAllText('C:\InstallerTrace\worker.ps1',[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__TRACE_WORKER_B64__')))
    $script:PayloadTraceWorker=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\InstallerTrace\worker.ps1' -PassThru -WindowStyle Hidden
    $until=[DateTime]::UtcNow.AddSeconds(3)
    while([DateTime]::UtcNow -lt $until -and -not (Test-Path -LiteralPath 'C:\InstallerTrace\ready.txt') -and -not $script:PayloadTraceWorker.HasExited){Start-Sleep -Milliseconds 100}
    $result['PayloadTrace']=[ordered]@{Status='Started; optional collection';Limitation='Trace limits or dropped events may omit activity. Absence is not established.';EventsRead=0;Files=@()}
  }catch{$result['PayloadTrace']=[ordered]@{Status='Unavailable';Limitation=$_.Exception.Message;EventsRead=0;Files=@()}}
}
function Stop-PayloadTrace {
  if($script:PayloadTraceStopped){return}
  $script:PayloadTraceStopped=$true
  if($null -eq $script:PayloadTraceWorker){return}
  try{
    @($result.ProcessTree) | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath 'C:\InstallerTrace\scope.json' -Encoding UTF8
    [IO.File]::WriteAllText('C:\InstallerTrace\stop.txt','stop')
    $finished=$script:PayloadTraceWorker.WaitForExit(25000)
    if(-not $finished){try{$script:PayloadTraceWorker.Kill()}catch{}}
    $result['PayloadTrace']=[ordered]@{Status='Unavailable';Limitation='Collector produced no readable summary.';EventsRead=0;Files=@()}
    if(Test-Path -LiteralPath 'C:\InstallerTrace\result.json'){
      $file=Get-Item -LiteralPath 'C:\InstallerTrace\result.json'
      if($file.Length -le 1048576){$result['PayloadTrace']=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json}
    }
    if(-not $finished){$result.PayloadTrace.Status='Collection time limit; partial'}
    foreach($file in @($result.PayloadTrace.Files)){
      $result.DiscoveredInstallerFiles=@(@($result.DiscoveredInstallerFiles)+[string]$file.Path | Select-Object -Unique | Select-Object -First 120)
    }
  }catch{$result['PayloadTrace']=[ordered]@{Status='Unavailable';Limitation=$_.Exception.Message;EventsRead=0;Files=@()}}
}
""";

    private const string PayloadTraceWorkerScript = """
$ErrorActionPreference='Stop'
$traceName='IA-Payload-'+[guid]::NewGuid().ToString('N')
$traceStarted=$false
$reducer=$null
function Invoke-TraceControl([string]$arguments){
  $info=New-Object Diagnostics.ProcessStartInfo
  $info.FileName=Join-Path $env:WINDIR 'System32\logman.exe';$info.Arguments=$arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
  $process=[Diagnostics.Process]::Start($info)
  try{if(-not $process.WaitForExit(4000)){try{$process.Kill()}catch{};throw 'Trace control timed out.'};if($process.ExitCode -ne 0){throw ('Trace control failed: '+$process.ExitCode)}}finally{$process.Dispose()}
}
function Save-TraceResult {
  $json=$reducer.Result | ConvertTo-Json -Depth 6 -Compress
  [IO.File]::WriteAllText('C:\InstallerTrace\result.tmp',$json)
  Move-Item -LiteralPath 'C:\InstallerTrace\result.tmp' -Destination 'C:\InstallerTrace\result.json' -Force
}
function Observe-BitsJobs {
  try {
    foreach($job in @(Get-BitsTransfer -ErrorAction Stop | Select-Object -First 64)){
      try {
        $files=$job.FileList
        if($files.Count -ne 1){$reducer.ObserveBits([string]$job.JobId,[string]$job.TransferType,[string]$job.JobState,'','','-1','-1',[int]$files.Count,$false,[DateTime]::UtcNow.ToString('o'));continue}
        $file=$files[0]
        # The module's per-file IsTransferComplete can remain false at Transferred on Windows.
        # For a single-file job, require the native job byte counters and FilesTransferred/FilesTotal instead.
        $completeFiles=([int]$job.FilesTransferred -eq 1 -and [int]$job.FilesTotal -eq 1)
        $reducer.ObserveBits([string]$job.JobId,[string]$job.TransferType,[string]$job.JobState,[string]$file.LocalName,[string]$file.RemoteName,[string]$job.BytesTotal,[string]$job.BytesTransferred,1,$completeFiles,[DateTime]::UtcNow.ToString('o'))
      }catch{$reducer.Result.BitsObservationStatus='Read-only job sample unavailable; partial. Short-lived/current-other-user jobs may be missed.'}
    }
  }catch{$reducer.Result.BitsObservationStatus='Read-only current-user job enumeration unavailable; completion coverage unknown.'}
}
try{
  @('Microsoft-Windows-Kernel-File 0x12c0 4','Microsoft-Windows-Kernel-Process 0x30 4','Microsoft-Windows-Bits-Client 0xffffffffffffffff 5') | Set-Content -LiteralPath 'C:\InstallerTrace\providers.txt' -Encoding ASCII
  # Capture process births before compiling the reducer; compilation may outlast the startup grace period.
  Invoke-TraceControl ('create trace '+$traceName+' -ets -pf C:\InstallerTrace\providers.txt -o C:\InstallerTrace\payload.etl -f bin -max 128 -bs 64 -nb 16 64')
  $traceStarted=$true
  [IO.File]::WriteAllText('C:\InstallerTrace\ready.txt','ready')
  $source=[IO.File]::ReadAllText('C:\InstallerInput\PayloadTraceReducer.cs').Replace('#nullable disable','')
  Add-Type -TypeDefinition $source -ReferencedAssemblies 'System.Core','System.Xml.Linq','System.Xml' -ErrorAction Stop
  Add-Type -TypeDefinition 'using System;using System.Text;using System.Runtime.InteropServices;public static class TraceDriveMap{[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]public static extern uint QueryDosDevice(string name,StringBuilder value,int size);}'
  $reducer=New-Object InstallerAnalyzer.Services.PayloadTraceReducer
  foreach($drive in [IO.DriveInfo]::GetDrives()){
    if($drive.DriveType -ne [IO.DriveType]::Fixed){continue}
    $value=New-Object Text.StringBuilder 1024
    if([TraceDriveMap]::QueryDosDevice($drive.Name.Substring(0,2),$value,1024)){$reducer.AddDrive($value.ToString(),$drive.Name.Substring(0,2))}
  }
  $bitsAvailable=$false
  try{Import-Module BitsTransfer -ErrorAction Stop;$bitsAvailable=$true;$reducer.Result.BitsObservationStatus='Read-only current-user jobs sampled every 500 ms, at most 64 jobs per poll. Short-lived and other-user jobs may be missed.'}catch{$reducer.Result.BitsObservationStatus='BITS module unavailable; no completion inference.'}
  [IO.File]::WriteAllText('C:\InstallerTrace\bits-ready.txt','ready')
  $until=[DateTime]::UtcNow.AddMinutes(15)
  while(-not (Test-Path -LiteralPath 'C:\InstallerTrace\stop.txt') -and [DateTime]::UtcNow -lt $until){if($bitsAvailable){Observe-BitsJobs};Start-Sleep -Milliseconds 500}
  try{Invoke-TraceControl ('stop '+$traceName+' -ets')}catch{$reducer.Result.Status='Trace stop unavailable; partial'}
  $traceStarted=$false
  if(Test-Path -LiteralPath 'C:\InstallerTrace\scope.json'){
    $scope=Get-Content -LiteralPath 'C:\InstallerTrace\scope.json' -Raw | ConvertFrom-Json
    foreach($process in $scope){$reducer.AddScope([int]$process.ProcessId,[string]$process.CreatedAt,[string]$process.Name)}
  }
  Save-TraceResult
  $query=New-Object Diagnostics.Eventing.Reader.EventLogQuery 'C:\InstallerTrace\payload.etl',([Diagnostics.Eventing.Reader.PathType]::FilePath)
  $reader=New-Object Diagnostics.Eventing.Reader.EventLogReader $query
  try{$reducer.Read($reader,12000,300000,[Action]{Save-TraceResult})}finally{$reader.Dispose()}
  $reducer.FinishBits()
  [InstallerAnalyzer.Services.BitsDownloadFingerprint]::Capture($reducer.Result)
  Save-TraceResult
}catch{
  if($null -ne $reducer){$reducer.Result.Status='Partial / unavailable: '+$_.Exception.Message;try{Save-TraceResult}catch{}}
}finally{
  if($traceStarted){try{Invoke-TraceControl ('stop '+$traceName+' -ets')}catch{}}
}
""";
}
