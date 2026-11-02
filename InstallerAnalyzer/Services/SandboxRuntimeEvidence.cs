namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string RuntimeEnvironmentEvidenceScript = """
function Read-RuntimeRegistry([string]$hive,[string]$view,[string]$path,[string[]]$names) {
  $base=$null;$key=$null
  $answer=[PSCustomObject]@{Available=$false;Exists=$null;Values=@{}}
  try{
    $h=[Microsoft.Win32.RegistryHive][Enum]::Parse([Microsoft.Win32.RegistryHive],$hive)
    $v=[Microsoft.Win32.RegistryView][Enum]::Parse([Microsoft.Win32.RegistryView],$view)
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($h,$v);$key=$base.OpenSubKey($path,$false)
    $answer.Available=$true;$answer.Exists=($null -ne $key)
    if($null -ne $key){foreach($name in $names){$answer.Values[$name]=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}}
  }catch{}
  finally{if($null -ne $key){$key.Dispose()};if($null -ne $base){$base.Dispose()}}
  return $answer
}
function New-RuntimeObservation([string]$name,[string]$state,[string]$version,[string]$architecture,[string]$source,[string]$phase) {
  return [PSCustomObject]@{Name=$name;State=$state;Version=$version;Architecture=$architecture;Source=$source;Phase=$phase;MeasuredAt=(Get-Date).ToString('o');RequirementEstablished=$false}
}
function Get-ReadOnlyNetFxFeatureState([string]$phase) {
  $observation=New-RuntimeObservation '.NET Framework 3.5 Windows feature' 'Unknown' '' 'Windows feature' 'DISM read-only NetFx3 feature query' $phase
  $process=$null
  try {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=Join-Path $env:SystemRoot 'System32\dism.exe'
    $info.Arguments='/Online /Get-FeatureInfo /FeatureName:NetFx3 /English'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process;$process.StartInfo=$info
    [void]$process.Start()
    $output=$process.StandardOutput.ReadToEndAsync();$errorText=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(6000)){try{$process.Kill()}catch{};$observation.Source+='; query timed out';return $observation}
    if($process.ExitCode -eq 0 -and $output.Wait(500)){
      $match=[regex]::Match($output.Result,'(?im)^\s*State\s*:\s*(Enabled|Disabled|Enable Pending|Disable Pending|Disabled with Payload Removed)\s*$')
      if($match.Success){$observation.State=$match.Groups[1].Value}
    }
  }catch{}
  finally{if($null -ne $process){$process.Dispose()}}
  return $observation
}
function Get-RuntimeEnvironmentSnapshot([string]$phase) {
  $observations=@()
  foreach($view in @('Registry32','Registry64')){
    $source='LocalMachine '+$view+' SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5'
    $value=Read-RuntimeRegistry 'LocalMachine' $view 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' @('Install','Version')
    $state=if(-not $value.Available){'Unknown'}elseif($value.Values['Install'] -eq 1){'Present'}else{'Not registered as installed'}
    $observations+=@(New-RuntimeObservation '.NET Framework 3.5' $state ([string]$value.Values['Version']) $view $source $phase)
    $value=Read-RuntimeRegistry 'LocalMachine' $view 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' @('Install','Release','Version')
    $state=if(-not $value.Available){'Unknown'}elseif($value.Values['Install'] -eq 1 -or [int64]$value.Values['Release'] -ge 378389){'Present'}else{'Not registered as installed'}
    $version=if($null -ne $value.Values['Release']){'Release '+[string]$value.Values['Release']}else{[string]$value.Values['Version']}
    $observations+=@(New-RuntimeObservation '.NET Framework 4.x' $state $version $view ('LocalMachine '+$view+' NDP\v4\Full') $phase)
    foreach($arch in @('x86','x64','arm64')){
      $path='SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\'+$arch
      $value=Read-RuntimeRegistry 'LocalMachine' $view $path @('Installed','Version')
      $state=if(-not $value.Available){'Unknown'}elseif($value.Values['Installed'] -eq 1){'Registered'}else{'Not registered as installed'}
      $observations+=@(New-RuntimeObservation 'Visual C++ v14 Redistributable' $state ([string]$value.Values['Version']) $arch ('LocalMachine '+$view+' '+$path) $phase)
      $base=$null;$key=$null
      try{
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,([Microsoft.Win32.RegistryView][Enum]::Parse([Microsoft.Win32.RegistryView],$view)))
        $path='SOFTWARE\dotnet\Setup\InstalledVersions\'+$arch+'\sharedfx\Microsoft.WindowsDesktop.App'
        $key=$base.OpenSubKey($path,$false)
        $versions=if($null -ne $key){@($key.GetValueNames() | Where-Object {$_ -match '^\d+(?:\.\d+){1,3}(?:-[A-Za-z0-9.-]+)?$'} | Select-Object -First 32)}else{@()}
        $state=if($versions.Count -gt 0){'Registered'}else{'Not registered; private runtimes not searched'}
        $observations+=@(New-RuntimeObservation '.NET Desktop Runtime' $state ($versions -join ', ') $arch ('LocalMachine '+$view+' '+$path) $phase)
      }catch{$observations+=@(New-RuntimeObservation '.NET Desktop Runtime' 'Unknown' '' $arch ('Registry query unavailable: '+$view) $phase)}
      finally{if($null -ne $key){$key.Dispose()};if($null -ne $base){$base.Dispose()}}
    }
    foreach($javaKey in @('Java Runtime Environment','JRE','JDK','Java Development Kit')){
      $path='SOFTWARE\JavaSoft\'+$javaKey;$value=Read-RuntimeRegistry 'LocalMachine' $view $path @('CurrentVersion')
      $state=if(-not $value.Available){'Unknown'}elseif(-not [string]::IsNullOrWhiteSpace([string]$value.Values['CurrentVersion'])){'Registered'}else{'Not registered; other distributions not excluded'}
      $observations+=@(New-RuntimeObservation ('Java: '+$javaKey) $state ([string]$value.Values['CurrentVersion']) $view ('LocalMachine '+$view+' '+$path) $phase)
    }
  }
  $webViewPath='SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
  foreach($hive in @('LocalMachine','CurrentUser')){
    $value=Read-RuntimeRegistry $hive 'Registry32' $webViewPath @('pv')
    $version=[string]$value.Values['pv'];$parsed=$null
    $state=if(-not $value.Available){'Unknown'}elseif([version]::TryParse($version,[ref]$parsed) -and $parsed -gt [version]'0.0.0.0'){'Registered Evergreen Runtime'}else{'Evergreen Runtime not registered; fixed-version runtime not excluded'}
    $observations+=@(New-RuntimeObservation 'WebView2 Runtime' $state $version 'Registry32' ($hive+' '+$webViewPath) $phase)
  }
  if($phase -eq 'Before install'){$observations+=@(Get-ReadOnlyNetFxFeatureState $phase)}
  return $observations
}
""";
}

