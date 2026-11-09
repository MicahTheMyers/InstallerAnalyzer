$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\InstallerAnalyzer\Services\DattoRmmDeploymentService.cs'))
$raw=[regex]::Match($source,'(?s)ComponentTemplate = """\r?\n(.*?)\r?\n""";').Groups[1].Value
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($raw,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$function=$ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-IAAttachments'},$true)|Select-Object -First 1
if(-not $function){throw 'Attachment preflight not found'}
Invoke-Expression $function.Extent.Text
$folder=Join-Path (Split-Path $PSScriptRoot) ('verification-results\datto-attachments-'+[guid]::NewGuid().ToString('N')+'#\payload folder')
New-Item -ItemType Directory -Path $folder -Force|Out-Null
$files=[pscustomobject]@{'gINT.msi'='inert';'vc8redist_x86.exe'='inert'}
$message='';try{Assert-IAAttachments $folder $files}catch{$message=$_.Exception.Message}
if(-not $message.Contains('gINT.msi, vc8redist_x86.exe') -or -not $message.Contains('confirm upload success')){throw 'Missing attachment list is incomplete'}
Write-Output 'PASS missing attachments are listed together with recovery instructions'
Set-Content -LiteralPath (Join-Path $folder 'gINT.msi') -Value 'inert fixture; never execute'
$message='';try{Assert-IAAttachments $folder $files}catch{$message=$_.Exception.Message}
if(-not $message.StartsWith('Missing component attachments: vc8redist_x86.exe.')){throw 'Present attachment was reported missing'}
Write-Output 'PASS present files are excluded from the missing list'
Set-Content -LiteralPath (Join-Path $folder 'vc8redist_x86.exe') -Value 'inert fixture; never execute'
Assert-IAAttachments $folder $files
Write-Output 'PASS complete attachments are accepted in a folder containing spaces and #'
Write-Output 'RESULT: 3 attachment checks passed; no installer or native command executed'
