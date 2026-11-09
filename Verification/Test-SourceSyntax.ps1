param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[string]$OutputFolder)
$ErrorActionPreference='Stop'
if(-not $OutputFolder){$OutputFolder=Join-Path $ProjectRoot ('verification-results\source-syntax-'+[guid]::NewGuid().ToString('N'))}
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
function Read-RawConstant([string]$file,[string]$name) {
  $text=[IO.File]::ReadAllText((Join-Path $ProjectRoot $file))
  $pattern='(?s)(?:private )?const string '+[regex]::Escape($name)+' = """\r?\n(.*?)\r?\n""";'
  $match=[regex]::Match($text,$pattern)
  if(-not $match.Success){throw ('Raw script constant not found: '+$name)}
  return $match.Groups[1].Value
}
$metadata=@{RegistryProbes=@();ApplicationRegistry=@();ProductName='Fixture';ProductCode='{11111111-1111-1111-1111-111111111111}'}
$encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($metadata | ConvertTo-Json -Depth 5 -Compress)))
$helpers=(Read-RawConstant 'InstallerAnalyzer\Services\SandboxRoadmapEvidence.cs' 'RoadmapEvidenceScript').Replace('__MSI_METADATA__',$encoded)
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxDetectionEvidence.cs' 'DetailedDetectionEvidenceScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxRuntimeEvidence.cs' 'RuntimeEnvironmentEvidenceScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxNetFx3Provisioning.cs' 'NetFx3ProvisioningScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxGintPrerequisites.cs' 'GintPrerequisiteScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxCompatibility.cs' 'SandboxCompatibilityScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxMsiIdentityEvidence.cs' 'MsiIdentityEvidenceScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxPrerequisiteFileEvidence.cs' 'PrerequisiteFileEvidenceScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxPrerequisiteServiceEvidence.cs' 'PrerequisiteServiceEvidenceScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxDllEvidence.cs' 'DllEvidenceScript')
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxAppControlEvidence.cs' 'AppControlEvidenceScript')
$traceWorker=Read-RawConstant 'InstallerAnalyzer\Services\SandboxPayloadTrace.cs' 'PayloadTraceWorkerScript'
$workerTokens=$null;$workerErrors=$null
$null=[Management.Automation.Language.Parser]::ParseInput($traceWorker,[ref]$workerTokens,[ref]$workerErrors)
if($workerErrors.Count){throw 'Payload trace worker does not parse in Windows PowerShell'}
Write-Output 'PASS payload trace worker PowerShell syntax'
$reducerSource=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\PayloadTraceReducer.cs')).Replace('#nullable disable','')
Add-Type -TypeDefinition $reducerSource -ReferencedAssemblies 'System.Core','System.Xml.Linq','System.Xml' -ErrorAction Stop
Write-Output 'PASS guest reducer compiles with the Windows PowerShell framework compiler; no tracing was started'
$helpers+=[Environment]::NewLine+(Read-RawConstant 'InstallerAnalyzer\Services\SandboxPayloadTrace.cs' 'PayloadTraceEvidenceScript').Replace('__TRACE_WORKER_B64__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($traceWorker)))
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxIssRecorder.cs'))
$match=[regex]::Match($source,'(?s)var script = """\r?\n(.*?)\r?\n""";')
if(-not $match.Success){throw 'Discovery script template not found'}
$count=0
foreach($kind in @('Unknown','Msi','Msix','InstallShield','InnoSetup','Nsis','WixBurn','Squirrel','NvidiaSfx','QSetup','Bootstrapper')){
  $values=@{'__INSTALLER__'='fixture.msi';'__KIND__'=$kind;'__BASE_ARGS__'='/qn /norestart';'__ADDITIONAL_ARGS__'='';'__BLOCK_MCAFEE__'='$true';'__SILENT_ONLY__'='$true';'__RECORD_RESPONSES__'='$false';'__ROADMAP_HELPERS__'=$helpers;'__MSI_METADATA__'=$encoded;'__NETFX_EVIDENCE__'='';'__SANDBOX_COMPATIBILITY__'='$false';'__COMPONENT_PLAN__'=''}
  $assembled=[regex]::Replace($match.Groups[1].Value,'__(?:INSTALLER|KIND|BASE_ARGS|ADDITIONAL_ARGS|BLOCK_MCAFEE|SILENT_ONLY|RECORD_RESPONSES|ROADMAP_HELPERS|MSI_METADATA|NETFX_EVIDENCE|SANDBOX_COMPATIBILITY|COMPONENT_PLAN)__',[Text.RegularExpressions.MatchEvaluator]{param($m)$values[$m.Value]})
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseInput($assembled,[ref]$tokens,[ref]$errors)
  if($errors.Count -gt 0){$errors | Format-List | Out-String | Write-Output;throw ('Parse failed: '+$kind)}
  foreach($name in @('Ensure-NetFx3','Get-MsiPrerequisiteServiceEvidence','Get-MsiPrerequisiteFileEvidence','Get-DetectionBaselinePresence','Get-RuntimeEnvironmentSnapshot','Get-NativeMsiProductEntry','Get-MsiApplicationRegistryBaseline')){
    if(-not $ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)){throw ('Missing helper '+$name)}
  }
  $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
  if(@($commands|Where-Object {$_ -in @('Enable-WindowsOptionalFeature','Install-WindowsFeature','Set-ExecutionPolicy','Restart-Computer','Stop-Computer')}).Count -gt 0){throw 'Unexpected provisioning/reboot command in discovery source'}
  [IO.File]::WriteAllText((Join-Path $OutputFolder ('Static-'+$kind+'.ps1')),$assembled)
  $count++;Write-Output ('PASS source syntax and helper wiring: '+$kind)
}
Write-Output ('RESULT: '+$count+' source assemblies parse; no discovery code or application DLL was executed')

