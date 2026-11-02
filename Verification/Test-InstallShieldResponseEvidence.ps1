param([Parameter(Mandatory=$true)][string]$GeneratedScript,[string]$OutputFolder)
$ErrorActionPreference='Stop'
if(-not $OutputFolder){$OutputFolder=Join-Path (Split-Path -Parent $PSScriptRoot) ('verification-results\iss-evidence-'+[guid]::NewGuid().ToString('N'))}
New-Item -ItemType Directory -Path $OutputFolder | Out-Null
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($GeneratedScript,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Recorder script failed Windows PowerShell syntax validation'}
foreach($name in @('Test-InstallShieldResponse','Test-InstallShieldReplayLog')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(-not $node){throw ('Missing production helper: '+$name)}
 . ([scriptblock]::Create($node.Extent.Text))
}
$path=Join-Path $OutputFolder 'response[fixture].iss'
$valid="[InstallShield Silent]`r`nVersion=v7.00`r`nFile=Response File`r`n[Product-DlgOrder]`r`nCount=5`r`n"
$cases=@(
 @{Name='valid response';Text=$valid;Response=$true;Expected=$true},
 @{Name='empty response';Text='';Response=$true;Expected=$false},
 @{Name='arbitrary response';Text='not a response';Response=$true;Expected=$false},
 @{Name='no dialogs';Text=$valid.Replace('Count=5','Count=0');Response=$true;Expected=$false},
 @{Name='wrong file type';Text=$valid.Replace('Response File','Log File');Response=$true;Expected=$false},
 @{Name='success log';Text="[ResponseResult]`r`nResultCode=0`r`n";Expected=$true},
 @{Name='failed log';Text='ResultCode=-3';Expected=$false},
 @{Name='duplicate success';Text="ResultCode=0`r`nResultCode=0";Expected=$false},
 @{Name='conflicting log';Text="ResultCode=0`r`nResultCode=-3";Expected=$false},
 @{Name='absent result';Text='[ResponseResult]';Expected=$false},
 @{Name='padded success is not canonical';Text='ResultCode=00';Expected=$false}
)
$count=0
foreach($case in $cases){
 [IO.File]::WriteAllText($path,$case.Text)
 $actual=if($case.Response){Test-InstallShieldResponse $path}else{Test-InstallShieldReplayLog $path}
 if($actual -ne $case.Expected){throw ('FAIL '+$case.Name)}
 $count++;Write-Output ('PASS '+$case.Name)
}
$missing=Join-Path $OutputFolder 'missing.iss'
if((Test-InstallShieldResponse $missing) -or (Test-InstallShieldReplayLog $missing)){throw 'Missing files were accepted'}
$count++;Write-Output 'PASS missing evidence withheld'
[IO.File]::WriteAllText($path,('x'*1048577))
if((Test-InstallShieldResponse $path) -or (Test-InstallShieldReplayLog $path)){throw 'Oversized files were accepted'}
$count++;Write-Output 'PASS oversized evidence withheld'
Write-Output ('RESULT: '+$count+' checks passed; no installer executed')
