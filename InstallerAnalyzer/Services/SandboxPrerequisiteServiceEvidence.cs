namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string PrerequisiteServiceEvidenceScript = """
function Get-MsiPrerequisiteServiceEvidence {
  $observations=@();$seen=@{}
  foreach($probe in @($script:MsiStaticMetadata.RegistryProbes | Select-Object -First 64)){
    if([int]$probe.Root -ne 2){continue}
    $match=[regex]::Match([string]$probe.Key,'(?i)^SYSTEM\\CurrentControlSet\\Services\\(?<name>[a-z0-9_. -]{1,128})(?:\\[a-z0-9_. -]+)*$')
    if(-not $match.Success){continue}
    $name=$match.Groups['name'].Value;$id=$name.ToUpperInvariant()+'|'+[string]$probe.Property
    if($seen.ContainsKey($id)){continue};$seen[$id]=$true
    $observation=[ordered]@{Name=$name;Property=[string]$probe.Property;Present=$null;State='Unknown';ServiceType='';Phase='Before install';Evidence='Exact service named by MSI RegLocator; availability is not proof of a requirement or an MSI property value.';RequirementEstablished=$false}
    $services=@()
    try {
      # The name grammar excludes wildcard/control/path characters. No remote query or service mutation.
      $services=@(Get-Service -Name $name -ErrorAction Stop)
      if($services.Count -eq 1 -and $services[0].ServiceName -ieq $name){
        $observation.Present=$true;$observation.State=[string]$services[0].Status;$observation.ServiceType=[string]$services[0].ServiceType
      }
    }catch{
      if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound){$observation.Present=$false;$observation.State='Not found'}
      else{$observation.Evidence+=' Service query unavailable; absence remains unknown.'}
    }finally{foreach($service in $services){if($service -is [IDisposable]){$service.Dispose()}}}
    $observations+=@([PSCustomObject]$observation)
  }
  return $observations
}
""";
}
