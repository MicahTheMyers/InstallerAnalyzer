param([string]$Repository=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
$source=Get-Content -LiteralPath (Join-Path $Repository 'InstallerAnalyzer\Services\SandboxDetectionEvidence.cs') -Raw
$scriptText=[regex]::Match($source,'(?s)DetailedDetectionEvidenceScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
if(-not $scriptText){throw 'Production detection helper not found'}
. ([scriptblock]::Create($scriptText))
$count=0
function Check($ok,[string]$name){if(-not $ok){throw $name};$script:count++;Write-Output "PASS $name"}
$path=Join-Path $env:LOCALAPPDATA 'InstallerAnalyzer-DetectionFixture'
Check ((Resolve-DetectionInstallLocation ('"'+$path+'"')) -eq $path) 'Quoted vendor installation directory is normalized'
Check ((Resolve-DetectionInstallLocation ('  '+$path+'  ')) -eq $path) 'Outer whitespace is normalized'
foreach($invalid in @('', 'relative\folder', '\root-relative', 'C:drive-relative', '"C:\unclosed', 'C:\bad"path', ('C:\bad'+[char]0+'path'), 'C:\a" /switch')) {
  Check ($null -eq (Resolve-DetectionInstallLocation $invalid)) 'Malformed or relative location is ignored without aborting analysis'
  Check (@(Get-InstalledExecutableCandidates $invalid).Count -eq 0) 'Malformed location yields no executable candidates'
}
Check (@(Get-InstalledExecutableCandidates 'C:\Windows').Count -eq 0) 'Directories outside permitted application roots are not scanned'
Write-Output "RESULT: $count passed, 0 failed"
