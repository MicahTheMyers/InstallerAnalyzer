$ErrorActionPreference='Stop'
try {
 if($env:USERNAME -ne 'WDAGUtilityAccount'){throw 'Fresh Sandbox guest required'}
 $source=[IO.File]::ReadAllText('C:\PublishedVerifier\SandboxPrerequisiteServiceEvidence.cs')
 $body=[regex]::Match($source,'(?s)PrerequisiteServiceEvidenceScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
 if(-not $body){throw 'Production helper source missing'}
 . ([scriptblock]::Create($body))
 $script:MsiStaticMetadata=[pscustomobject]@{RegistryProbes=@(
  [pscustomobject]@{Root=2;Key='SYSTEM\CurrentControlSet\Services\BITS';Property='DECLARED_BITS'},
  [pscustomobject]@{Root=2;Key='SYSTEM\CurrentControlSet\Services\InstallerAnalyzerMissingFixture_8a9984e3';Property='DECLARED_ABSENT'},
  [pscustomobject]@{Root=2;Key='SYSTEM\CurrentControlSet\Services\*';Property='NO_WILDCARD'})}
 $before=(Get-Service -Name BITS -ErrorAction Stop).Status
 $observed=@(Get-MsiPrerequisiteServiceEvidence)
 $observed | ConvertTo-Json -Depth 4 | Set-Content C:\InstallerOutput\service-observations.json
 if($observed.Count -ne 2){throw 'Unexpected service probe count'}
 if($observed[0].Name -ne 'BITS' -or $observed[0].Present -ne $true -or $observed[0].State -ne [string]$before){throw 'Known service availability mismatch'}
 if($observed[1].Present -ne $false -or $observed[1].State -ne 'Not found'){throw 'Missing service did not remain absent'}
 if(@($observed|Where-Object {$_.RequirementEstablished}).Count){throw 'Availability fabricated a requirement'}
 if((Get-Service -Name BITS -ErrorAction Stop).Status -ne $before){throw 'Fixture service state changed'}
 Set-Content C:\InstallerOutput\PASS.txt 'PASS real read-only service observations in fresh Sandbox: known BITS state, absent service, wildcard rejected, no service state changed or requirement inferred.'
} catch {$_|Out-String|Set-Content C:\InstallerOutput\error.txt} finally {Set-Content C:\InstallerOutput\done.txt 'done'}
