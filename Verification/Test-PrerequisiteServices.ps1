param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop';$count=0
function Check([bool]$ok,[string]$name){if(-not $ok){throw ('FAIL '+$name)};$script:count++;Write-Output ('PASS '+$name)}
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxPrerequisiteServiceEvidence.cs'))
$body=[regex]::Match($source,'(?s)PrerequisiteServiceEvidenceScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
Check ($errors.Count -eq 0) 'Service helper parses in Windows PowerShell 5.1'
if($errors.Count){throw 'Cannot load service helper'}
. ([scriptblock]::Create($body))
$script:Calls=0;$script:Denied=$false
function Get-Service {param($Name,$ErrorAction)
 $script:Calls++
 if($script:Denied){throw [UnauthorizedAccessException]::new('Fixture denied')}
 if($Name -eq 'NotFoundFixture'){Write-Error -Message 'No such service' -Category ObjectNotFound -ErrorAction Stop}
 return [pscustomobject]@{ServiceName=$Name;Status='Stopped';ServiceType='Win32OwnProcess'}
}
$script:MsiStaticMetadata=[pscustomobject]@{RegistryProbes=@([pscustomobject]@{Root=2;Key='SYSTEM\CurrentControlSet\Services\FixtureSvc\Parameters';Property='FIXTURE'})}
$observed=@(Get-MsiPrerequisiteServiceEvidence)
Check ($observed.Count -eq 1 -and $observed[0].Present -eq $true -and $observed[0].State -eq 'Stopped') 'Declared exact service is measured even when stopped'
Check (-not $observed[0].RequirementEstablished -and $observed[0].Property -eq 'FIXTURE') 'Service availability is linked to declaration without fabricating an MSI property value'
$script:MsiStaticMetadata.RegistryProbes[0].Key='SYSTEM\CurrentControlSet\Services\NotFoundFixture'
$observed=@(Get-MsiPrerequisiteServiceEvidence)
Check ($observed[0].Present -eq $false -and $observed[0].State -eq 'Not found') 'Explicit SCM not-found response establishes service absence'
$script:Denied=$true;$observed=@(Get-MsiPrerequisiteServiceEvidence)
Check ($null -eq $observed[0].Present -and $observed[0].State -eq 'Unknown') 'Denied service query does not establish absence';$script:Denied=$false
foreach($key in @('SYSTEM\CurrentControlSet\Services\*','SYSTEM\CurrentControlSet\Services\[FORMATTED]','SYSTEM\ControlSet001\Services\FixtureSvc','\\remote\SYSTEM\CurrentControlSet\Services\FixtureSvc','SYSTEM\CurrentControlSet\Services\Fixture?')){
 $script:MsiStaticMetadata.RegistryProbes[0].Key=$key;$before=$script:Calls
 Check (@(Get-MsiPrerequisiteServiceEvidence).Count -eq 0 -and $script:Calls -eq $before) ('Unsupported service target is not queried: '+$key)
}
$script:MsiStaticMetadata.RegistryProbes=@([pscustomobject]@{Root=1;Key='SYSTEM\CurrentControlSet\Services\FixtureSvc';Property='FIXTURE'})
Check (@(Get-MsiPrerequisiteServiceEvidence).Count -eq 0) 'Per-user registry declaration does not become a machine service probe'
$probe=[pscustomobject]@{Root=2;Key='SYSTEM\CurrentControlSet\Services\FixtureSvc';Property='FIXTURE'}
$script:MsiStaticMetadata.RegistryProbes=@($probe,$probe)
Check (@(Get-MsiPrerequisiteServiceEvidence).Count -eq 1) 'Duplicate service/property declarations are deduplicated'
$script:MsiStaticMetadata.RegistryProbes=@(1..100 | ForEach-Object {[pscustomobject]@{Root=2;Key=('SYSTEM\CurrentControlSet\Services\Fixture'+$_);Property='FIXTURE'}})
Check (@(Get-MsiPrerequisiteServiceEvidence).Count -eq 64) 'Service query count is bounded'
Write-Output ('RESULT: '+$count+' service checks passed; SCM reads mocked, no service changed')
