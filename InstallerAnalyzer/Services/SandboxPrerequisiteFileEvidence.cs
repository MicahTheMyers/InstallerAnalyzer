namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string PrerequisiteFileEvidenceScript = """
function Resolve-MsiProbeDirectory([string]$signature,[string[]]$visited=@()) {
  if($visited.Count -ge 8 -or $visited -ccontains $signature){throw 'Directory locator cycle or depth limit.'}
  $rows=@($script:MsiStaticMetadata.DirectoryLocators | Where-Object {$_.Signature -ceq $signature})
  if($rows.Count -ne 1){throw 'Directory locator missing or ambiguous.'}
  $row=$rows[0]
  if([int]$row.Depth -ne 0){throw 'Recursive directory searches are not evaluated.'}
  $path=[string]$row.Path
  if($path -match '[\[\]%*?|]' -or $path.Length -gt 240){throw 'Unresolved or unsupported directory path.'}
  if([string]::IsNullOrEmpty([string]$row.Parent)){
    if($path -notmatch '^[A-Za-z]:\\' -or $path.Substring(2).Contains(':')){throw 'Only explicit local drive paths are observed.'}
    $drive=New-Object IO.DriveInfo ($path.Substring(0,3))
    if($drive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable)){throw 'Network, unknown and optical drives are not probed.'}
  }else{
    if([IO.Path]::IsPathRooted($path) -or $path.Contains(':')){throw 'Unsupported child directory path.'}
    $parent=Resolve-MsiProbeDirectory ([string]$row.Parent) (@($visited)+$signature)
    $path=[IO.Path]::Combine($parent,$path)
  }
  if(@($path.Split('\') | Where-Object {$_ -in @('.','..')}).Count){throw 'Relative traversal is not evaluated.'}
  return [IO.Path]::GetFullPath($path)
}
function Get-MsiProbeItem([string]$path) {
  # Inspect ancestors first so even a missing child cannot hide a reparse traversal.
  $ancestors=New-Object 'System.Collections.Generic.List[string]'
  $cursor=$path
  while($cursor){
    if($ancestors.Count -ge 64){throw 'Ancestor limit reached.'}
    $ancestors.Add($cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)
  }
  $item=$null
  for($i=$ancestors.Count-1;$i -ge 0;$i--){
    try{$item=Get-Item -LiteralPath $ancestors[$i] -Force -ErrorAction Stop}
    catch{
      if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound){return $null}
      throw
    }
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse paths are not followed.'}
  }
  return $item
}
function Get-MsiPrerequisiteFileEvidence {
  $deadline=[DateTime]::UtcNow.AddSeconds(3)
  foreach($search in @($script:MsiStaticMetadata.FileSearches | Select-Object -First 64)){
    $observation=[ordered]@{Property=[string]$search.Property;Signature=[string]$search.Signature;Target='';Kind='Directory';Phase='Before install';Version='';SizeBytes=$null;Present=$null;SignatureMatched=$null;ConditionDescription=[string]$search.ConditionDescription;Evidence=''}
    try{
      if([DateTime]::UtcNow -gt $deadline){throw 'File probe collection time budget reached.'}
      $path=Resolve-MsiProbeDirectory ([string]$search.Signature)
      if($null -ne $search.File){
        $observation.Kind='File';$name=[string]$search.File.FileName
        if($name.Contains('|')){
          $parts=$name.Split('|');if($parts.Count -ne 2){throw 'Ambiguous file name.'};$name=$parts[1]
        }
        if([string]::IsNullOrWhiteSpace($name) -or $name -in @('.','..') -or $name -match '[\\/:*?\[\]%|]'){throw 'Unresolved or unsupported file name.'}
        $path=[IO.Path]::Combine($path,$name)
      }
      $observation.Target=$path;$item=Get-MsiProbeItem $path
      $present=$null -ne $item -and (($observation.Kind -eq 'Directory') -eq [bool]$item.PSIsContainer)
      $observation.Present=$present;$observation.SignatureMatched=$present
      $observation.Evidence='Literal path observation; MSI launch condition not evaluated.'
      if($present -and $observation.Kind -eq 'File'){
        $observation.SizeBytes=[long]$item.Length
        try{$observation.Version=[string][Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion}catch{}
        $criteria=$search.File;$unknown=$false;$mismatch=$false
        foreach($bound in @('MinSize','MaxSize')){
          $value=[string]$criteria.$bound
          if($value.Length){
            $size=0L
            if(-not [long]::TryParse($value,[ref]$size) -or $size -lt 0){$unknown=$true}
            elseif(($bound -eq 'MinSize' -and $item.Length -lt $size) -or ($bound -eq 'MaxSize' -and $item.Length -gt $size)){$mismatch=$true}
          }
        }
        foreach($filter in @('MinVersion','MaxVersion','MinDate','MaxDate','Languages')){if([string]$criteria.$filter){$unknown=$true}}
        if($mismatch){$observation.SignatureMatched=$false}
        elseif($unknown){$observation.SignatureMatched=$null;$observation.Evidence+=' Full MSI file criteria were not evaluated.'}
      }
    }catch{$observation.SignatureMatched=$null;$observation.Evidence=$_.Exception.Message}
    [PSCustomObject]$observation
  }
}
""";
}
