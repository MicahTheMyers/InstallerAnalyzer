namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string DetailedDetectionEvidenceScript = """
$script:DetectionDirectoryBaseline=@()
function Get-DetectionDirectoryBaseline {
  $snapshots=@()
  foreach($root in @($env:ProgramFiles,([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')),$env:LOCALAPPDATA) | Where-Object {$_} | Select-Object -Unique){
    $snapshot=[PSCustomObject]@{Root=$root.TrimEnd('\');Exists=$null;Children=@{};Complete=@{}}
    try {$null=Get-Item -LiteralPath $root -ErrorAction Stop;$snapshot.Exists=$true}
    catch {if($_.CategoryInfo.Category -eq 'ObjectNotFound'){$snapshot.Exists=$false};$snapshots+=@($snapshot);continue}
    $pending=New-Object 'System.Collections.Generic.Stack[object]'
    $pending.Push([PSCustomObject]@{Path=$snapshot.Root;Depth=0})
    $deadline=(Get-Date).AddSeconds(2);$seen=0
    while($pending.Count -gt 0 -and (Get-Date) -lt $deadline -and $seen -lt 2048){
      $folder=$pending.Pop();$children=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
      $complete=$true
      try {
        foreach($child in [IO.Directory]::EnumerateDirectories($folder.Path)){
          if((Get-Date) -ge $deadline -or $seen -ge 2048){$complete=$false;break}
          $seen++
          if(([IO.File]::GetAttributes($child) -band [IO.FileAttributes]::ReparsePoint) -ne 0){$complete=$false;continue}
          [void]$children.Add($child.TrimEnd('\'))
          if($folder.Depth -lt 2){$pending.Push([PSCustomObject]@{Path=$child;Depth=($folder.Depth+1)})}
        }
      }catch{$complete=$false}
      $snapshot.Children[$folder.Path]=$children
      $snapshot.Complete[$folder.Path]=$complete
    }
    $snapshots+=@($snapshot)
  }
  return $snapshots
}
function Get-DetectionBaselinePresence([string]$path,[bool]$IsFile=$false) {
  if([string]::IsNullOrWhiteSpace($path)){return $null}
  try {$full=[IO.Path]::GetFullPath($path).TrimEnd('\')}catch{return $null}
  if($IsFile){$full=[IO.Path]::GetDirectoryName($full)}
  foreach($snapshot in @($script:DetectionDirectoryBaseline)){
    $root=[string]$snapshot.Root
    if(-not $full.StartsWith(($root+'\'),[StringComparison]::OrdinalIgnoreCase) -and -not $full.Equals($root,[StringComparison]::OrdinalIgnoreCase)){continue}
    if($snapshot.Exists -eq $false){return $false}
    if($null -eq $snapshot.Exists){return $null}
    $relative=$full.Substring($root.Length).TrimStart('\')
    $parent=$root
    foreach($segment in @($relative -split '\\')){
      if(-not $segment){continue}
      $child=Join-Path $parent $segment
      if(-not $snapshot.Children.ContainsKey($parent)){return $null}
      if(-not $snapshot.Children[$parent].Contains($child)){
        if($snapshot.Complete[$parent]){return $false}
        return $null
      }
      $parent=$child
    }
    if(-not $IsFile){return $true}
    return $null # Existing directories do not establish whether a particular file existed.
  }
  return $null
}
function Resolve-DetectionInstallLocation([string]$folder) {
  if([string]::IsNullOrWhiteSpace($folder)){return $null}
  $folder=$folder.Trim()
  # Some vendors store a quoted directory in InstallLocation, not a command line.
  if($folder.Length -ge 2 -and $folder.StartsWith('"') -and $folder.EndsWith('"')){$folder=$folder.Substring(1,$folder.Length-2)}
  try {
    if($folder.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0 -or $folder -notmatch '^[A-Za-z]:\\'){return $null}
    return [IO.Path]::GetFullPath($folder).TrimEnd('\')
  } catch {return $null}
}
function Get-InstalledExecutableCandidates([string]$folder) {
  $files=@()
  $folder=Resolve-DetectionInstallLocation $folder
  if([string]::IsNullOrWhiteSpace($folder)){return $files}
  $allowed=@($env:ProgramFiles,([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')),$env:LOCALAPPDATA) | Where-Object {$_}
  if(@($allowed|Where-Object {$folder.StartsWith(($_.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)}).Count -eq 0){return $files}
  $pending=New-Object 'System.Collections.Generic.Stack[object]';$pending.Push([PSCustomObject]@{Path=$folder;Depth=0})
  $deadline=(Get-Date).AddSeconds(3);$visited=0
  while($pending.Count -gt 0 -and (Get-Date) -lt $deadline -and $files.Count -lt 128){
    $item=$pending.Pop()
    try{
      if(([IO.File]::GetAttributes($item.Path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}
      foreach($path in [IO.Directory]::EnumerateFiles($item.Path,'*.exe')){
        if((Get-Date) -ge $deadline -or $files.Count -ge 128 -or $visited++ -ge 4096){return $files}
        if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}
        if([IO.Path]::GetFileName($path) -match '(?i)^(unins|uninstall|setup|update|crash|helper|msiexec)'){continue}
        $info=[Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        if(-not [string]::IsNullOrWhiteSpace($info.FileVersion)){$files+=@([PSCustomObject]@{Path=$path;Version=[string]$info.FileVersion;Product=[string]$info.ProductName;Company=[string]$info.CompanyName})}
      }
      if($item.Depth -lt 2){
        foreach($child in [IO.Directory]::EnumerateDirectories($item.Path)){
          if((Get-Date) -ge $deadline -or $visited++ -ge 4096){return $files}
          if(([IO.File]::GetAttributes($child) -band [IO.FileAttributes]::ReparsePoint) -eq 0){$pending.Push([PSCustomObject]@{Path=$child;Depth=($item.Depth+1)})}
        }
      }
    }catch{}
  }
  return $files
}
function Add-DetailedDetectionCandidates($entry) {
  if($null -eq $entry){return}
  Add-MsiApplicationRegistryCandidates $entry
  $location=Resolve-DetectionInstallLocation ([string]$entry.InstallLocation)
  $candidates=@(Get-InstalledExecutableCandidates $location)
  $product=([string]$entry.DisplayName -replace '[^A-Za-z0-9]','').ToLowerInvariant()
  $publisher=([string]$entry.Publisher).Trim()
  foreach($file in @($candidates|Where-Object {
    $name=([string]$_.Product -replace '[^A-Za-z0-9]','').ToLowerInvariant()
    ($product.Length -gt 2 -and $name.Length -gt 2 -and ($name.Contains($product) -or $product.Contains($name))) -or
    ($publisher.Length -gt 0 -and $_.Company -eq $publisher)
  } | Select-Object -First 3)){
    $result.DetectionStrategies+=@([PSCustomObject]@{Type='ExecutablePathAndVersion';Identity=$file.Path;RegistryPath='';ValueName='';ExecutablePath=$file.Path;Version=$file.Version;Rank=75;BeforeInstall=(Get-DetectionBaselinePresence $file.Path $true);AfterInstall=$true;AfterUninstall=$null})
  }
  foreach($component in @($result.Components | Where-Object {$_.Kind -eq 'Service'} | Select-Object -First 16)){
    $parts=Split-Command ([Environment]::ExpandEnvironmentVariables([string]$component.Path))
    if($null -eq $parts -or [string]::IsNullOrWhiteSpace($location)){continue}
    $executable=[string]$parts[0]
    if(-not $executable.StartsWith(($location.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){continue}
    if(-not (Test-Path -LiteralPath $executable)){continue}
    $result.DetectionStrategies+=@([PSCustomObject]@{Type='ServiceAndExecutable';Identity=$component.Name;RegistryPath='';ValueName='';ExecutablePath=$executable;Version=$null;Rank=70;BeforeInstall=$component.BeforeInstall;AfterInstall=$true;AfterUninstall=$null})
  }
  $result.DetectionStrategies=@($result.DetectionStrategies | Sort-Object Rank -Descending)
}
function Get-DetailedDetectionPresence($rule) {
  if($rule.Type -eq 'ExecutablePathAndVersion'){
    try {
      $null=Get-Item -LiteralPath $rule.Identity -ErrorAction Stop
      return ([Diagnostics.FileVersionInfo]::GetVersionInfo([string]$rule.Identity).FileVersion -eq [string]$rule.Version)
    }catch{if($_.CategoryInfo.Category -eq 'ObjectNotFound'){return $false};return $null}
  }
  if($rule.Type -eq 'ServiceAndExecutable'){
    try {
      $service=@(Get-Service -ErrorAction Stop | Where-Object {$_.ServiceName -eq [string]$rule.Identity})
      if($service.Count -eq 0){return $false}
      $null=Get-Item -LiteralPath $rule.ExecutablePath -ErrorAction Stop
      return $true
    }catch{if($_.CategoryInfo.Category -eq 'ObjectNotFound'){return $false};return $null}
  }
  return $null
}
""";
}

