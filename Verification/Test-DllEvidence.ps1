param([string]$ProjectRoot)
$ErrorActionPreference='Stop'
if(-not $ProjectRoot){$ProjectRoot=Split-Path -Parent $PSScriptRoot}
foreach($file in @('SandboxPrerequisiteFileEvidence.cs','SandboxDllEvidence.cs')){
  $source=[IO.File]::ReadAllText((Join-Path $ProjectRoot ('InstallerAnalyzer\Services\'+$file)))
  $body=[regex]::Match($source,'(?s)const string \w+ = """\r?\n(.*?)\r?\n""";').Groups[1].Value
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
  if($errors.Count){throw 'DLL helper does not parse'}
  foreach($definition in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($definition.Extent.Text))}
}
$root=Join-Path $ProjectRoot ('verification-results\dll-probes-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
[IO.File]::WriteAllText((Join-Path $root 'inert.dll'),'inert bytes; never loaded')
$Installer=Join-Path $root 'source.exe';$count=0
function Check($condition,$name){if(-not $condition){throw ('FAIL '+$name)};$script:count++;Write-Output ('PASS '+$name)}
$data=[pscustomobject]@{Architecture='x64';Imports=@([pscustomobject]@{Module='inert.dll';Kind='Direct';ApiSetContract=$false})}
$r=@(Get-PeDllFileEvidence $data)
Check ($r.Count -eq 2 -and $r[0].Present -eq $true) 'Staged directory DLL bytes are observed without loading the image'
$data.Imports[0].Module='not-present-fixture.dll';$r=@(Get-PeDllFileEvidence $data)
Check ($r[0].Present -eq $false -and $r[0].Evidence -match 'does not reproduce loader') 'Absent literal DLL is not a complete loader diagnosis'
$data.Imports[0].Module='api-ms-win-fixture.dll';$r=@(Get-PeDllFileEvidence $data)
Check ($null -eq $r[0].Present -and $r[0].Path -eq '') 'API-set names are contracts rather than missing files'
$data.Imports[0].Module='..\malicious.dll';$r=@(Get-PeDllFileEvidence $data)
Check ($r.Count -eq 0) 'Traversal cannot become a DLL file probe'
$data.Architecture='x86';$data.Imports[0].Module='kernel32.dll';$r=@(Get-PeDllFileEvidence $data)
Check ($r[1].Path -like '*\SysWOW64\kernel32.dll') 'x86 probes target SysWOW64 from the x64 test process'
$data.Architecture='Managed AnyCPU';$r=@(Get-PeDllFileEvidence $data)
Check ($null -eq $r[1].Present -and $r[1].Path -eq '') 'Unknown native architecture cannot produce false system DLL absence'
$data.Architecture='x64';$data.Imports[0].Module='inert.dll';$data.Imports[0].Kind='Delay-load';$r=@(Get-PeDllFileEvidence $data)
Check ($r[0].Kind -eq 'Delay-load' -and $r[0].Present -eq $true) 'Conditional delay-load kind survives file observation'
function Get-MsiProbeItem([string]$path){throw [UnauthorizedAccessException]::new('fixture denied')}
$r=@(Get-PeDllFileEvidence $data)
Check ($null -eq $r[0].Present -and $r[0].Evidence -match 'unavailable') 'Denied DLL reads remain unknown'
Write-Output ('RESULT: '+$count+' DLL observation checks passed; no DLL was loaded')
