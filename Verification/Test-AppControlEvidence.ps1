param([string]$ProjectRoot)
$ErrorActionPreference='Stop'
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxAppControlEvidence.cs'))
$body=[regex]::Match($source,'(?s)AppControlEvidenceScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
if($errors.Count){$errors|Format-List|Out-String|Write-Output;throw 'App Control collector does not parse'}
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Convert-AppControlEvent'},$true)
. ([scriptblock]::Create($node.Extent.Text))
$sourceImage='C:\InstallerInput\setup.exe';$device='\Device\HarddiskVolume2\InstallerInput\setup.exe'
$start=[DateTimeOffset]::Parse('2026-10-29T12:00:00Z');$end=$start.AddMinutes(2)
$xml=@'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-CodeIntegrity"/><EventID>3077</EventID><TimeCreated SystemTime="2026-10-29T12:01:00Z"/></System><EventData><Data Name="ProcessName">\Device\HarddiskVolume2\InstallerInput\setup.exe</Data><Data Name="FileName">\Device\HarddiskVolume2\Temp\setup.tmp</Data><Data Name="PolicyID">{0283ac0f-fff1-49ae-ada1-8a933130cad6}</Data><Data Name="PolicyName">Fixture policy</Data></EventData></Event>
'@
$cases=@(
 @{Name='exact device source';Xml=$xml;Expected=$true},
 @{Name='exact DOS source';Xml=$xml.Replace($device,$sourceImage);Expected=$true},
 @{Name='native spaced field names';Xml=$xml.Replace('Name="ProcessName"','Name="Process Name"').Replace('Name="FileName"','Name="File Name"');Expected=$true},
 @{Name='ambiguous parent aliases';Xml=$xml.Replace('</EventData>','<Data Name="Process Name">other</Data></EventData>');Expected=$false},
 @{Name='ambiguous target aliases';Xml=$xml.Replace('</EventData>','<Data Name="File Name">other</Data></EventData>');Expected=$false},
 @{Name='audit event';Xml=$xml.Replace('3077','3076');Expected=$false},
 @{Name='different provider';Xml=$xml.Replace('Microsoft-Windows-CodeIntegrity','Unrelated');Expected=$false},
 @{Name='other source directory';Xml=$xml.Replace('\InstallerInput\','\Other\');Expected=$false},
 @{Name='source basename prefix';Xml=$xml.Replace('setup.exe','setup.exe.other');Expected=$false},
 @{Name='other device volume';Xml=$xml.Replace('HarddiskVolume2','HarddiskVolume3');Expected=$false},
 @{Name='old event';Xml=$xml.Replace('12:01:00Z','11:59:59Z');Expected=$false},
 @{Name='future event';Xml=$xml.Replace('12:01:00Z','12:02:01Z');Expected=$false},
 @{Name='duplicate field';Xml=$xml.Replace('</EventData>','<Data Name="ProcessName">other</Data></EventData>');Expected=$false},
 @{Name='missing target';Xml=$xml.Replace('\Device\HarddiskVolume2\Temp\setup.tmp','');Expected=$false},
 @{Name='invalid XML';Xml='<invalid';Expected=$false},
 @{Name='oversized XML';Xml=('x'*65537);Expected=$false},
 @{Name='DTD rejected';Xml=('<!DOCTYPE Event [<!ENTITY x "value">]>'+$xml);Expected=$false}
)
$count=1;Write-Output 'PASS Windows PowerShell collector syntax'
foreach($case in $cases){$result=Convert-AppControlEvent $case.Xml $sourceImage $device $start $end;if(($null -ne $result) -ne $case.Expected){throw ('FAIL '+$case.Name)};$count++;Write-Output ('PASS '+$case.Name)}
$block=Convert-AppControlEvent $xml $sourceImage $device $start $end
if($block.ParentImage -cne $sourceImage -or $block.Correlation -cne 'Exact source process image'){throw 'Canonical source correlation missing'}
$count++;Write-Output 'PASS normalized source correlation'
$native=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Fixtures\AppControl-3077-Native.xml'))
$block=Convert-AppControlEvent $native $sourceImage $device $start $end
if($null -eq $block -or $block.PolicyId -ne '{0283ac0f-fff1-49ae-ada1-8a933130cad6}'){throw 'Native event schema or policy GUID was not retained'}
$count++;Write-Output 'PASS retained native event schema and policy GUID (version ID is distinct)'
Write-Output ('RESULT: '+$count+' App Control checks passed; no event log or policy was changed')
