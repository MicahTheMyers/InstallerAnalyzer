namespace InstallerAnalyzer.Services;
public static partial class SandboxIssRecorder
{
    private const string DllEvidenceScript = """
function Get-PeDllFileEvidence($metadata=$null) {
  if($null -eq $metadata){
    try{
      $file=Get-Item -LiteralPath 'C:\InstallerInput\pe-dependencies.json' -ErrorAction Stop
      if($file.Length -gt 262144){return}
      $metadata=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    }catch{return}
  }
  $deadline=[DateTime]::UtcNow.AddSeconds(3)
  foreach($import in @($metadata.Imports | Select-Object -First 128)){
    $module=[string]$import.Module
    if($module -notmatch '\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,246}\.dll\z' -or $module.Contains('..')){continue}
    $arch=[string]$metadata.Architecture
    $contract=$import.ApiSetContract -eq $true -or $module -match '^(?i)(api-ms-|ext-ms-)'
    $locations=@([PSCustomObject]@{Name='Staged source directory';Path=(Join-Path ([IO.Path]::GetDirectoryName($Installer)) $module)})
    $native=[string]$env:PROCESSOR_ARCHITECTURE
    $system=if($arch -eq 'x86' -and [Environment]::Is64BitOperatingSystem){Join-Path $env:WINDIR 'SysWOW64'}elseif(($arch -eq 'x86' -and -not [Environment]::Is64BitOperatingSystem) -or ($arch -eq 'x64' -and $native -eq 'AMD64') -or ($arch -eq 'arm64' -and $native -eq 'ARM64')){Join-Path $env:WINDIR 'System32'}else{''}
    $locations+=@([PSCustomObject]@{Name='Architecture-specific Windows directory';Path=if($system){Join-Path $system $module}else{''}})
    foreach($location in $locations){
      $entry=[ordered]@{Module=$module;Kind=[string]$import.Kind;Architecture=$arch;Location=[string]$location.Name;Path=[string]$location.Path;Present=$null;Version='';Evidence='Declared import; this observation does not reproduce loader resolution.'}
      try{
        if($contract){$entry.Path='';$entry.Evidence='API-set loader contract; physical DLL absence is not evaluated.'}
        elseif([DateTime]::UtcNow -gt $deadline){$entry.Evidence='DLL observation budget reached; presence unknown.'}
        elseif(-not $entry.Path){$entry.Evidence='Unsupported image/OS architecture combination; presence unknown.'}
        else{
          $item=Get-MsiProbeItem $entry.Path
          $entry.Present=($null -ne $item -and -not $item.PSIsContainer)
          if($entry.Present){try{$entry.Version=[string][Diagnostics.FileVersionInfo]::GetVersionInfo($entry.Path).FileVersion}catch{}}
          $entry.Evidence+=' Staged and system directories only; PATH, side-by-side and package graph are not searched.'
        }
      }catch{$entry.Evidence='Observation unavailable: '+$_.Exception.Message}
      [PSCustomObject]$entry
    }
  }
}
""";
}
