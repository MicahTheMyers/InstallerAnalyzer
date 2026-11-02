param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'InstallerAnalyzer\Services\SandboxPrerequisiteFileEvidence.cs'))
$body=[regex]::Match($source,'(?s)PrerequisiteFileEvidenceScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Probe source does not parse'}
foreach($definition in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($definition.Extent.Text))}
$root=Join-Path $ProjectRoot ('verification-results\file-probes-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
[IO.File]::WriteAllText((Join-Path $root 'inert.txt'),'fixture')
$script:count=0
function Check($condition,$name){if(-not $condition){throw ('FAIL '+$name)};$script:count++;Write-Output ('PASS '+$name)}
function Probe($file,$path=$root,$depth=0,$parent=''){
  $script:MsiStaticMetadata=[pscustomobject]@{DirectoryLocators=@([pscustomobject]@{Signature='test';Parent=$parent;Path=$path;Depth=$depth});FileSearches=@([pscustomobject]@{Property='RUNTIME';Signature='test';File=$file;ConditionDescription='Required runtime'})}
  return @(Get-MsiPrerequisiteFileEvidence)[0]
}
$file=[pscustomobject]@{FileName='inert.txt';MinSize='';MaxSize='';MinVersion='';MaxVersion='';MinDate='';MaxDate='';Languages=''}
$r=Probe $file
Check ($r.Present -eq $true -and $r.SignatureMatched -eq $true -and $r.SizeBytes -eq 7) 'Exact file is observed without execution'
$file.MinSize='8';$r=Probe $file
Check ($r.SignatureMatched -eq $false -and $r.Present -eq $true) 'Known size mismatch retains presence'
$file.MinSize='invalid';$r=Probe $file
Check ($null -eq $r.SignatureMatched -and $r.Present -eq $true) 'Invalid size is unknown'
$file.MinSize='';$file.MinVersion='1.0';$r=Probe $file
Check ($null -eq $r.SignatureMatched -and $r.Present -eq $true) 'Unsupported MSI version semantics remain unknown'
$file.MinVersion='';$file.FileName='missing.txt';$r=Probe $file
Check ($r.Present -eq $false) 'Missing literal file is observed absent'
$r=Probe $null
Check ($r.Present -eq $true -and $r.Kind -eq 'Directory') 'Directory search retains its kind'
$file.FileName='inert.txt';$r=Probe $file $root 1
Check ($null -eq $r.Present) 'Recursive search is not guessed'
$r=Probe $file '[ProgramFilesFolder]'
Check ($null -eq $r.Present) 'Unresolved MSI property is unknown'
$r=Probe $file '\\server\share'
Check ($null -eq $r.Present) 'UNC search is rejected without network access'
$r=Probe $file 'relative'
Check ($null -eq $r.Present) 'Implicit fixed-drive search is unknown'
$r=Probe $file '' 0 'test'
Check ($null -eq $r.Present) 'Locator cycle is bounded'
$r=Probe $file '' 0 'unavailable'
Check ($null -eq $r.Present) 'Unsupported parent source is unknown'
$file.FileName='..\inert.txt';$r=Probe $file
Check ($null -eq $r.Present) 'Filename traversal is rejected'
$file.FileName='SHORT.TXT|inert.txt';$r=Probe $file
Check ($r.Present -eq $true) 'Declared long filename is observed literally'
$script:MsiStaticMetadata.DirectoryLocators=@([pscustomobject]@{Signature='base';Parent='';Path=$root;Depth=0},[pscustomobject]@{Signature='test';Parent='base';Path='';Depth=0})
$r=@(Get-MsiPrerequisiteFileEvidence)[0]
Check ($r.Present -eq $true) 'Explicit directory parent chain resolves'
$script:MsiStaticMetadata.DirectoryLocators+= $script:MsiStaticMetadata.DirectoryLocators[1]
$r=@(Get-MsiPrerequisiteFileEvidence)[0]
Check ($null -eq $r.Present) 'Ambiguous locator remains unknown'
$link=Join-Path $root 'fixture-link'
New-Item -ItemType Junction -Path $link -Target $root | Out-Null
$file.FileName='inert.txt';$r=Probe $file $link
Check ($null -eq $r.Present) 'Existing file behind a reparse directory is not followed'
$file.FileName='missing.txt';$r=Probe $file $link
Check ($null -eq $r.Present) 'Missing child behind a reparse directory is not declared absent'
# Simulate an access failure at the filesystem boundary, never convert it to absence.
function Get-MsiProbeItem([string]$path){throw [UnauthorizedAccessException]::new('fixture denied')}
$r=@(Get-MsiPrerequisiteFileEvidence)[0]
Check ($null -eq $r.Present -and $null -eq $r.SignatureMatched) 'Access failure remains unknown'
Write-Output ('RESULT: '+$script:count+' file probe checks passed; only inert fixture files were created')
