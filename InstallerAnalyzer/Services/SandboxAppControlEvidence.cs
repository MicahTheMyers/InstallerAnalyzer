namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string AppControlEvidenceScript = """
function Convert-AppControlEvent([string]$xml,[string]$sourceImage,[string]$deviceImage,[DateTimeOffset]$start,[DateTimeOffset]$end) {
  $reader=$null
  try {
    if($xml.Length -gt 65536){return $null}
    $settings=New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing=[System.Xml.DtdProcessing]::Prohibit; $settings.XmlResolver=$null; $settings.MaxCharactersInDocument=65536
    $reader=[System.Xml.XmlReader]::Create((New-Object IO.StringReader($xml)),$settings)
    $doc=New-Object System.Xml.XmlDocument; $doc.XmlResolver=$null; $doc.Load($reader)
    $ns=New-Object System.Xml.XmlNamespaceManager($doc.NameTable); $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    if($doc.SelectSingleNode('/e:Event/e:System/e:EventID',$ns).InnerText -ne '3077'){return $null}
    if($doc.SelectSingleNode('/e:Event/e:System/e:Provider',$ns).GetAttribute('Name') -cne 'Microsoft-Windows-CodeIntegrity'){return $null}
    $at=[DateTimeOffset]::Parse($doc.SelectSingleNode('/e:Event/e:System/e:TimeCreated',$ns).GetAttribute('SystemTime'))
    if($at -lt $start -or $at -gt $end){return $null}
    $data=@{}
    foreach($node in @($doc.SelectNodes('/e:Event/e:EventData/e:Data',$ns))){
      $name=$node.GetAttribute('Name'); if($data.ContainsKey($name)){return $null}; $data[$name]=$node.InnerText
    }
    # Windows event versions use both spaced and compact field names. Never let
    # two aliases silently override one another.
    if(($data.ContainsKey('ProcessName') -and $data.ContainsKey('Process Name')) -or
       ($data.ContainsKey('FileName') -and $data.ContainsKey('File Name'))){return $null}
    $parent=if($data.ContainsKey('Process Name')){[string]$data['Process Name']}else{[string]$data['ProcessName']}
    if(-not [string]::Equals($parent,$sourceImage,[StringComparison]::OrdinalIgnoreCase) -and
       ([string]::IsNullOrWhiteSpace($deviceImage) -or -not [string]::Equals($parent,$deviceImage,[StringComparison]::OrdinalIgnoreCase))){return $null}
    $blocked=if($data.ContainsKey('File Name')){[string]$data['File Name']}else{[string]$data['FileName']}
    if([string]::IsNullOrWhiteSpace($blocked) -or $blocked.Length -gt 1024){return $null}
    $policy=if($data.ContainsKey('PolicyGUID')){[string]$data['PolicyGUID']}else{[string]$data['PolicyID']}; $guid=[guid]::Empty
    if(-not [guid]::TryParse($policy,[ref]$guid)){$policy=''}
    $policyName=[string]$data['PolicyName']; if($policyName.Length -gt 128){$policyName=$policyName.Substring(0,128)}
    return [PSCustomObject]@{EventId=3077;Provider='Microsoft-Windows-CodeIntegrity';ObservedAt=$at.ToUniversalTime().ToString('o');ParentImage=$sourceImage;BlockedFile=$blocked;PolicyId=$policy;PolicyName=$policyName;Correlation='Exact source process image'}
  }catch{return $null}finally{if($null -ne $reader){$reader.Dispose()}}
}
function Get-AppControlEvidence([string[]]$observedImages=@()) {
  $end=[DateTimeOffset]::UtcNow; $start=([DateTimeOffset]$StartedAt).ToUniversalTime()
  $capture=[ordered]@{Status='Unavailable';StartedAt=$start.ToString('o');CapturedAt=$end.ToString('o');Scope='Bounded read-only Code Integrity 3077 events for the exact source process image. Child-process blocks are not inferred; no captured event does not establish unrestricted execution.';Blocks=@()}
  $childMode=@($observedImages).Count -gt 0
  if($childMode){$capture.Scope="Bounded read-only enforced events matched to exact executable images observed in the tracked bootstrapper descendant tree. No audit or unrelated-process blocks are inferred."}
  $eventReader=$null
  try {
    if(-not ('InstallerAnalyzerPolicyPath' -as [type])){
      Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class InstallerAnalyzerPolicyPath {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint QueryDosDevice(string name,StringBuilder target,int size);
 public static string Resolve(string drive){var text=new StringBuilder(32768); return QueryDosDevice(drive,text,text.Capacity)==0 ? "" : text.ToString().Split('\0')[0];}
}
'@ -ErrorAction Stop
    }
    $images=if($childMode){@($observedImages | Select-Object -First 32)}else{@($Installer)}
    $parents=@{}
    foreach($image in $images){
      if($image -notmatch '^[a-zA-Z]:\\' -or [IO.Path]::GetExtension($image) -ine '.exe'){continue}
      $deviceRoot=[InstallerAnalyzerPolicyPath]::Resolve([IO.Path]::GetPathRoot($image).TrimEnd('\'))
      $parents[$image]=if($deviceRoot){$deviceRoot+$image.Substring(2)}else{''}
    }
    $xpath="*[System[(EventID=3077) and TimeCreated[@SystemTime >= '"+$start.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')+"']]]"
    $query=New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Microsoft-Windows-CodeIntegrity/Operational',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
    $query.ReverseDirection=$true
    $eventReader=New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    $clock=[Diagnostics.Stopwatch]::StartNew(); $capture.Status='Available'
    for($index=0;$index -lt 64;$index++){
      if($clock.Elapsed.TotalSeconds -ge 3){$capture.Status='Partial';break}
      $entry=$eventReader.ReadEvent([TimeSpan]::FromMilliseconds(100))
      if($null -eq $entry){break}
      try {
        $xml=$entry.ToXml()
        foreach($image in $parents.Keys){
          $block=Convert-AppControlEvent $xml $image $parents[$image] $start $end
          if($null -ne $block){
            if($childMode){$block.Correlation='Exact observed bootstrapper descendant image'}
            $capture.Blocks+=@($block);break
          }
        }
      }finally{$entry.Dispose()}
      if($index -eq 63){$capture.Status='Partial'}
    }
  }catch{$capture.Status='Unavailable'}finally{if($null -ne $eventReader){$eventReader.Dispose()}}
  return [PSCustomObject]$capture
}
function Complete-AppControlEvidence {
  $capture=Get-AppControlEvidence
  $result['AppControl']=$capture
  $children=@($result.BootstrapperObservedImages | Where-Object {$_ -and $_ -ine $Installer} | Select-Object -Unique -First 32)
  if($children.Count -gt 0){
    $childCapture=Get-AppControlEvidence -observedImages $children
    $result['BootstrapperChildAppControl']=$childCapture
    try {Write-JsonAtomic 'C:\InstallerOutput\bootstrapper-child-app-control.json' $childCapture}catch{}
    if($childCapture.Status -in @('Available','Partial') -and @($childCapture.Blocks).Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($result.ValidationError)){
      $result.ValidationError=('APPLICATION CONTROL BLOCKED: Windows recorded an enforced block of '+$childCapture.Blocks[0].BlockedFile+' loaded by an observed installer child. '+$result.ValidationError)
    }
  }
  try {Write-JsonAtomic 'C:\InstallerOutput\app-control-evidence.json' $capture}catch{}
  if($capture.Status -in @('Available','Partial') -and @($capture.Blocks).Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($result.ValidationError)){
    $result.ValidationError=('APPLICATION CONTROL BLOCKED: Windows recorded an enforced block of '+$capture.Blocks[0].BlockedFile+'. '+$result.ValidationError)
  }
}
""";
}
