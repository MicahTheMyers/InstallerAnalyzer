namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string NetFx3ProvisioningScript = """
$script:NetFx3Terminal=$false
$script:NetFx3Attempted=$false
function Test-NetFx3RequirementText([string]$text) {
  return $text -match '(?i)(?:\.NET\s*(?:Framework\s*)?3\.5|NetFx3|NETFRAMEWORK35)' -and $text -match '(?i)\brequir(?:e[sd]?|ement)\b|\bneeds?\b|\bmust\b|\bmissing\b|\bnot installed\b' -and $text -notmatch '(?i)not required|does not require|optional|not needed'
}
function Invoke-NetFx3Command([string]$file,[string]$arguments,[string]$log,[int]$seconds) {
  $info=New-Object Diagnostics.ProcessStartInfo
  $info.FileName=$file; $info.Arguments=$arguments; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
  $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
  $process=New-Object Diagnostics.Process; $process.StartInfo=$info
  try {
    [void]$process.Start(); $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not $process.WaitForExit(1000)) {
      Set-AnalysisHeartbeat 'netfx3-prerequisite'
      if($watch.Elapsed.TotalSeconds -ge $seconds){try{$process.Kill()}catch{}; ('Timed out after '+$seconds+' seconds; no installer retry.') | Set-Content -LiteralPath ('C:\InstallerOutput\'+$log) -Encoding UTF8; return [pscustomobject]@{ExitCode=-2;Text='Timed out';TimedOut=$true}}
    }
    $text=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
    if($text.Length -gt 65536){$text=$text.Substring($text.Length-65536)}
    $text | Set-Content -LiteralPath ('C:\InstallerOutput\'+$log) -Encoding UTF8
    return [pscustomobject]@{ExitCode=$process.ExitCode;Text=$text;TimedOut=$false}
  } finally {$process.Dispose()}
}
function Get-NetFx3FeatureState {
  $query=Invoke-NetFx3Command ($env:WINDIR+'\System32\dism.exe') '/Online /Get-FeatureInfo /FeatureName:NetFx3 /English' 'netfx3-feature-query.txt' 30
  if($query.ExitCode -ne 0){return 'Unknown'}
  if($query.Text -match '(?im)^\s*State\s*:\s*(.+?)\s*$'){return $matches[1].Trim()}
  return 'Unknown'
}
function Test-NetFx3Runtime {
  $compiler=$env:WINDIR+'\Microsoft.NET\Framework\v3.5\csc.exe'
  if(-not (Test-Path -LiteralPath $compiler)){return $false}
  $source='C:\InstallerOutput\netfx3-runtime.cs'; $exe='C:\InstallerOutput\netfx3-runtime.exe'
  'using System; using System.Linq; class Probe { static int Main() { Console.WriteLine("CLR="+Environment.Version); return Environment.Version.Major==2 && Enumerable.Range(1,3).Sum()==6 ? 0 : 1; } }' | Set-Content -LiteralPath $source -Encoding UTF8
  $compile=Invoke-NetFx3Command $compiler ('/nologo /target:exe /out:"'+$exe+'" /r:System.Core.dll "'+$source+'"') 'netfx3-runtime-compile.txt' 30
  if($compile.ExitCode -ne 0){return $false}
  '<configuration><startup><supportedRuntime version="v2.0.50727"/></startup></configuration>' | Set-Content -LiteralPath ($exe+'.config')
  $run=Invoke-NetFx3Command $exe '' 'netfx3-runtime.txt' 30
  return $run.ExitCode -eq 0 -and $run.Text -match 'CLR=2\.0\.'
}
function Stop-NetFx3Provisioning([string]$status,[string]$detail,[bool]$needsVM=$false) {
  $result.NetFx3Provisioning.Status=$status; $result.NetFx3Provisioning.Detail=$detail
  $result.NetFx3Provisioning.RequiresFullWindowsVM=$false; $result.NetFx3Provisioning['Blocked']=$true; $script:NetFx3Terminal=$true
  Write-Checkpoint ('.NET 3.5: '+$status)
  if($status -eq 'Restart required'){$result.RebootRequired=$true; $result.NetFx3Provisioning.RestartNeeded=$true; throw ('REBOOT REQUIRED: .NET Framework 3.5. '+$detail)}
  throw ('PREREQUISITE REQUIRED: .NET Framework 3.5. '+$detail)
}
function Prepare-NetFx3Sandbox {
  $key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
  $policy=Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
  $au=Get-ItemProperty -LiteralPath ($key+'\AU') -ErrorAction SilentlyContinue
  # This exact malformed loopback WSUS placeholder is the Sandbox default, not a real WSUS server.
  if([int]$au.UseWUServer -ne 1 -or [string]$policy.WUServer -notin @('127.0.0.1:80','localhost:80')){return}
  Write-Checkpoint '.NET 3.5: preparing Sandbox servicing resources'
  $root='C:\InstallerInput\NetFx3RepairSource'
  $manifest=Join-Path $root 'source-manifest.json'
  $restored=0
  if(Test-Path -LiteralPath $manifest){
    $source=Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    if($source.Schema -ne 1 -or @($source.Entries).Count -gt 256 -or [long]$source.Bytes -gt 67108864){throw 'Invalid NetFx3 repair-source manifest'}
    foreach($entry in @($source.Entries)){
      $name=[string]$entry.Component
      if($name -notmatch '^(amd64|x86|wow64)_[a-z0-9._-]+_(31bf3856ad364e35|b03f5f7f11d50a3a)_[0-9.]+_[a-z0-9._-]+$' -or $name -notmatch '(?i)wcf|wwf|wpf|netfx|presentation|windowsbase|mscor|clr|system.workflow' -or $name -notmatch '(?i)resources|perf|_exe_cnf'){throw 'Invalid NetFx3 component identity'}
      $destination=Join-Path ($env:WINDIR+'\WinSxS') $name
      if(Test-Path -LiteralPath $destination){continue}
      if(-not(Test-Path -LiteralPath ($env:WINDIR+'\WinSxS\Manifests\'+$name+'.manifest'))){continue}
      if(@($entry.Files).Count -gt 32){throw 'Excessive NetFx3 component file count'}
      foreach($file in @($entry.Files)){
        if([IO.Path]::GetFileName([string]$file.Name) -ne [string]$file.Name -or [string]$file.Name -match '[\\/:]'){throw 'Invalid NetFx3 source file name'}
        $path=Join-Path (Join-Path $root $name) ([string]$file.Name)
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne [string]$file.Sha256){throw 'NetFx3 source hash mismatch'}
      }
      $copy=Invoke-NetFx3Command ($env:WINDIR+'\System32\robocopy.exe') ('"'+(Join-Path $root $name)+'" "'+$destination+'" /E /B /COPY:DAT /R:0 /W:0') ('netfx3-resource-'+$restored+'.txt') 15
      if($copy.ExitCode -lt 0 -or $copy.ExitCode -gt 7){throw 'Matching Sandbox component resources could not be restored'}
      $restored++
    }
  }
  $result.NetFx3Provisioning['RestoredComponentCount']=$restored
  Set-ItemProperty -LiteralPath ($key+'\AU') -Name UseWUServer -Value 0 -ErrorAction Stop
  Restart-Service -Name wuauserv -Force -ErrorAction Stop
  $result.NetFx3Provisioning['GuestUpdateSourceAdjusted']=$true
  Write-Checkpoint ('.NET 3.5: Sandbox source corrected; resource folders restored='+$restored)
}
function Get-NetFx3Source([int]$build) {
  if(Test-Path 'C:\InstallerInput\NetFx3Source'){return 'C:\InstallerInput\NetFx3Source'}
  if($build -notin @(26100,26200) -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64'){return ''}
  # Immutable Microsoft 24H2/25H2 FoD media, selected CAB only. No installer is downloaded/executed.
  $url='https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1.240331-1435.ge_release_amd64fre_CLIENT_LOF_PACKAGES_OEM.iso'
  $expected='DC3AF93AF5C64DC115409437D31018BAF2C3C46167806A599124BC905AE512F6'
  [long]$offset=4994539520; [long]$length=71321276; [long]$isoBytes=6251841536
  $folder=Join-Path $env:TEMP ('InstallerAnalyzer-NetFx3-'+[guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $folder | Out-Null
  $file=Join-Path $folder 'Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~~.cab'
  Write-Checkpoint '.NET 3.5: downloading verified Microsoft feature source'
  $output=[IO.File]::Create($file);$watch=[Diagnostics.Stopwatch]::StartNew()
  try {
    for([long]$position=0;$position -lt $length;$position+=4194304){
      if($watch.Elapsed.TotalSeconds -gt 150){throw 'Microsoft feature-source download timed out'}
      [long]$start=$offset+$position;[long]$end=[Math]::Min($offset+$length-1,$start+4194303)
      $request=[Net.HttpWebRequest]::Create($url);$request.AllowAutoRedirect=$false;$request.Timeout=15000;$request.ReadWriteTimeout=15000
      $request.AddRange($start,$end)
      $response=$null;$stream=$null
      try {
        $response=$request.GetResponse()
        if([int]$response.StatusCode -ne 206 -or $response.Headers['Content-Range'] -ne ('bytes '+$start+'-'+$end+'/'+$isoBytes)){throw 'Microsoft source range validation failed'}
        $stream=$response.GetResponseStream();$buffer=New-Object byte[] 65536;[long]$received=0
        while(($read=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
          if($watch.Elapsed.TotalSeconds -gt 150 -or $received+$read -gt $end-$start+1){throw 'Microsoft feature-source transfer exceeded its limit'}
          $output.Write($buffer,0,$read);$received+=$read
        }
        if($received -ne $end-$start+1){throw 'Microsoft source range length mismatch'}
      } finally {if($stream){$stream.Dispose()};if($response){$response.Dispose()};$request.Abort()}
      Set-AnalysisHeartbeat 'netfx3-feature-source-download'
    }
  } finally {$output.Dispose()}
  if((Get-Item -LiteralPath $file).Length -ne $length -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $expected){throw 'Microsoft NetFx3 source checksum mismatch'}
  [ordered]@{Source=$url;PackageBytes=$length;Sha256=$expected;WholeIsoDownloaded=$false} | ConvertTo-Json | Set-Content C:\InstallerOutput\netfx3-source.json
  return $folder
}
function Ensure-NetFx3([string]$evidence) {
  if($script:NetFx3Terminal){throw ('PREREQUISITE REQUIRED: '+$result.NetFx3Provisioning.Detail)}
  if($result.NetFx3Provisioning.RuntimeVerified){return}
  if([string]::IsNullOrWhiteSpace($evidence)){return}
  $result.NetFx3Provisioning.Evidence=$evidence
  # This helper is guest-only. Never service the host as a fallback.
  if(-not(Test-Path 'C:\InstallerInput\Record-Iss.ps1') -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine'){
    Stop-NetFx3Provisioning 'Guest context unavailable' 'Automatic provisioning is restricted to the installer test guest.'
  }
  $result.NetFx3Provisioning.Status='Checking prerequisite'
  Write-Checkpoint '.NET 3.5 prerequisite verification'
  $build=[int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
  if($build -ge 28000){
    if(Test-NetFx3Runtime){$result.NetFx3Provisioning.Status='Already available';$result.NetFx3Provisioning.RuntimeVerified=$true;return}
    Stop-NetFx3Provisioning 'Standalone installer required' 'This Windows build requires the Microsoft .NET 3.5 standalone installer. Provision it in the test environment before testing; DISM is not used on this build.'
  }
  $state=Get-NetFx3FeatureState
  if($state -eq 'Enabled'){
    if(Test-NetFx3Runtime){$result.NetFx3Provisioning.Status='Already available';$result.NetFx3Provisioning.RuntimeVerified=$true;return}
    Stop-NetFx3Provisioning 'Runtime verification failed' 'The feature is enabled but its CLR 2.0 runtime probe failed. Inspect netfx3-runtime logs before retrying.'
  }
  if($state -match 'Pending'){Stop-NetFx3Provisioning 'Restart required' 'Windows servicing is pending; restart the guest before continuing.'}
  if($state -notin @('Disabled','Disabled with Payload Removed')){Stop-NetFx3Provisioning 'State unavailable' 'Windows could not establish the feature state. Inspect netfx3-feature-query.txt before retrying.'}
  if($script:NetFx3Attempted){Stop-NetFx3Provisioning 'Provisioning failed' 'The bounded installation attempt has already been used.'}
  $script:NetFx3Attempted=$true; $result.NetFx3Provisioning.Attempted=$true
  $result.NetFx3Provisioning.Status='Preparing Sandbox'
  try {Prepare-NetFx3Sandbox} catch {Stop-NetFx3Provisioning 'Sandbox preparation failed' ('Sandbox servicing preparation failed: '+$_.Exception.Message)}
  try {$source=Get-NetFx3Source $build} catch {Stop-NetFx3Provisioning 'Source unavailable' ('Could not obtain the matching Microsoft feature source: '+$_.Exception.Message+'. Check Internet access or provide the matching CAB in NetFx3Source. No installer was retried.')}
  $args='/Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart /English'
  if(-not [string]::IsNullOrWhiteSpace($source)){$args+=' /LimitAccess /Source:"'+$source+'"'}
  $result.NetFx3Provisioning.Status='Installing'
  Write-Checkpoint '.NET 3.5 command-line installation (one attempt)'
  $install=Invoke-NetFx3Command ($env:WINDIR+'\System32\dism.exe') $args 'netfx3-install.txt' 600
  $result.NetFx3Provisioning.ExitCode=$install.ExitCode
  if($install.ExitCode -eq 3010){Stop-NetFx3Provisioning 'Restart required' 'DISM requested a restart; the installer has not been retried.'}
  if($install.ExitCode -ne 0){Stop-NetFx3Provisioning 'Provisioning failed' ('DISM failed or timed out (exit '+$install.ExitCode+'). Inspect netfx3-install.txt and the Sandbox servicing/source diagnostics. No installer retry was performed.')}
  if((Get-NetFx3FeatureState) -ne 'Enabled' -or -not(Test-NetFx3Runtime)){Stop-NetFx3Provisioning 'Verification failed' 'DISM exited successfully, but Enabled state and CLR 2.0 execution were not both verified. Inspect the feature-query and runtime logs before retrying.'}
  $result.NetFx3Provisioning.Status='Provisioned';$result.NetFx3Provisioning.Provisioned=$true;$result.NetFx3Provisioning.RuntimeVerified=$true
  Write-Checkpoint '.NET 3.5 verified; continuing installer'
}
""";
}
