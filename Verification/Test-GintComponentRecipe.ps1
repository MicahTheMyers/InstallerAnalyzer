param([string]$ComponentPath)
$ErrorActionPreference='Stop'
Import-Module Microsoft.PowerShell.Utility
if($ComponentPath){
 $componentTokens=$null;$componentErrors=$null
 $null=[Management.Automation.Language.Parser]::ParseFile($ComponentPath,[ref]$componentTokens,[ref]$componentErrors)
 if($componentErrors.Count){throw ($componentErrors|Out-String)}
 Write-Output 'PASS exported Datto component parses under Windows PowerShell'
}
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\InstallerAnalyzer\Services\GintDeploymentRecipe.cs'))
$raw=[regex]::Match($source,'(?s)RecipeScript = """\r?\n(.*?)\r?\n""";').Groups[1].Value
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseInput($raw,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
. ([scriptblock]::Create($raw))
$features=${function:Initialize-IAGintFeatures}
$script:IAGintPlan=[pscustomobject]@{Files=[pscustomobject]@{'fixture.exe'='ABC'}}
$InstallerFolder='C:\InertFixture'
function Get-FileHash {[pscustomobject]@{Hash='ABC'}}
function Initialize-IAGintFeatures {}
function Test-IAGintMsi {param($code); if($code -like '{710F*'){return [bool]$script:installed.VC2005};if($code -like '{9014*'){return [bool]$script:installed.Access2010};return [bool]$script:installed.gINT}
function Test-IAGintV9 {return [bool]$script:installed.VC2008}
function Test-IAGintV14 {return [bool]$script:installed.VC14}
function Test-IAGintConnection {return [bool]$script:installed.ConnectionClient}
function Invoke-IAGintNative {
 param($label,$file,$arguments,$seconds)
 $script:calls+=@($label)
 if(-not $script:falseWrapper){$script:installed[$label]=$true}
 return 0
}
$script:installed=@{};$script:calls=@();$script:falseWrapper=$true;$failed=$false
try{Invoke-IAGintPrerequisites}catch{$failed=$_.Exception.Message -match 'VC2005 prerequisite was not installed despite wrapper exit 0'}
if(-not $failed -or $calls.Count -ne 1 -or $installed.gINT){throw 'Wrapper success was mistaken for a prerequisite install'}
Write-Output 'PASS wrapper exit zero without product registration stops the recipe before gINT'
$script:falseWrapper=$false;$script:installed=@{};$script:calls=@()
Invoke-IAGintPrerequisites
if(($calls -join ',') -ne 'VC2005,VC2008,VC14,Access2010,ConnectionClient'){throw 'Prerequisites were not ordered or verified'}
Write-Output 'PASS all five prerequisites install in order and meet their postconditions'
$script:calls=@();Invoke-IAGintPrerequisites
if($calls.Count){throw 'Existing shared prerequisites were needlessly reinstalled'}
Write-Output 'PASS repeated prerequisite preparation preserves compatible shared runtimes'
function Get-WindowsOptionalFeature {[pscustomobject]@{State=$script:featureState}}
function Test-Path {$true}
function Invoke-IAGintNative {param($label,$file,$arguments,$seconds);$script:calls+=@($label);$script:featureState=$script:afterFeature;return 3010}
foreach($case in @('enabled','enable-success','enable-pending')){
 $script:calls=@();$script:featureState=if($case -eq 'enabled'){'Enabled'}else{'Disabled'}
 $script:afterFeature=if($case -eq 'enable-pending'){'EnablePending'}else{'Enabled'}
 $failed=$false;try{& $features}catch{$failed=$true}
 if($case -eq 'enable-pending'){if(-not $failed){throw 'Pending feature was treated as usable'}}else{if($failed){throw 'Usable feature was rejected'}}
 if($case -eq 'enabled' -and $calls.Count){throw 'Enabled feature triggered servicing'}
 Write-Output ('PASS mocked target Windows-feature state: '+$case)
}
Write-Output 'RESULT: 6 recipe checks passed; all native, registry and feature boundaries were mocked'
