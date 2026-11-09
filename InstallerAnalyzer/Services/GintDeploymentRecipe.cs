namespace InstallerAnalyzer.Services;

public static partial class GintDeploymentPlanService
{
    public const string RecipeScript = """
$script:IAGintReboot=$false
$script:IAGintClock=[Diagnostics.Stopwatch]::StartNew()
$script:IAGintLog=Join-Path $env:WINDIR ('Temp\InstallerAnalyzer-gINT-'+[guid]::NewGuid().ToString('N'))
function Get-IAGintEntries {
    @(Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue)
}
function Test-IAGintMsi([string]$code) {
    $engine=$null
    try {$engine=New-Object -ComObject WindowsInstaller.Installer;return $engine.ProductState($code) -eq 5}
    finally {if($engine){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine)}}
}
function Test-IAGintV14 {
    $entries=@(Get-IAGintEntries | Where-Object {$_.DisplayName -match '^Microsoft Visual C\+\+ (?:2015|2017|2019|2022|v14).*\(x86\)' -and $_.Publisher -like 'Microsoft*'})
    foreach($entry in $entries){try{if([version]$entry.DisplayVersion -ge [version]'14.0.24212.0'){return $true}}catch{}}
    return $false
}
function Test-IAGintV9 {
    foreach($entry in @(Get-IAGintEntries|Where-Object {$_.DisplayName -match '^Microsoft Visual C\+\+ 2008.*x86' -and $_.Publisher -like 'Microsoft*'})){
        try{if([version]$entry.DisplayVersion -ge [version]'9.0.30729.5570'){return $true}}catch{}
    }
    return $false
}
function Test-IAGintConnection {
    foreach($entry in @(Get-IAGintEntries|Where-Object {$_.DisplayName -eq 'CONNECTION Client' -and $_.Publisher -like 'Bentley*'})){
        try{if([version]$entry.DisplayVersion -ge [version]'10.0.17.10'){return $true}}catch{}
    }
    return $false
}
function Invoke-IAGintNative([string]$label,[string]$file,[string]$arguments,[int]$seconds=600) {
    Write-Host ('IA_STEP='+$label)
    if($script:IAGintClock.Elapsed.TotalSeconds -ge 1800){throw 'gINT deployment exceeded its thirty-minute execution budget.'}
    New-Item -ItemType Directory -Path $script:IAGintLog -Force|Out-Null
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$file;$info.Arguments=$arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.WorkingDirectory=$InstallerFolder
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($info)
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try {
        while(-not $process.WaitForExit(1000)){
            if($clock.Elapsed.TotalSeconds -gt $seconds -or $script:IAGintClock.Elapsed.TotalSeconds -gt 1800){throw ($label+' timed out; inspect any still-running installer before retrying.')}
            if(Get-Command Set-AnalysisHeartbeat -ErrorAction SilentlyContinue){Set-AnalysisHeartbeat ('component-'+$label)}
        }
        [IO.File]::WriteAllText((Join-Path $script:IAGintLog ($label+'.txt')),($stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()))
        $code=$process.ExitCode
        if($code -in @(3010,1641)){$script:IAGintReboot=$true;Write-Host 'IA_REBOOT_REQUIRED=1'}
        if($code -notin @(0,3010,1641,1638)){throw ($label+' failed with exit '+$code+'. Logs: '+$script:IAGintLog)}
        return $code
    }finally{$process.Dispose()}
}
function Test-IAGintAttachment([string]$name) {
    $property=$script:IAGintPlan.Files.PSObject.Properties[$name]
    if($null -eq $property -or (Get-FileHash -LiteralPath (Join-Path $InstallerFolder $name)).Hash -ne $property.Value){throw ('gINT attachment checksum mismatch: '+$name)}
}
function Initialize-IAGintFeatures {
    $feature=Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop
    if([string]$feature.State -ne 'Enabled'){
        $null=Invoke-IAGintNative 'NetFx3' ($env:WINDIR+'\System32\dism.exe') '/Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart /English' 600
        $feature=Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop
        if([string]$feature.State -ne 'Enabled'){throw '.NET 3.5 is not enabled. Supply matching Windows feature media or resolve Windows Update policy; reboot if requested, then retry. No application install was attempted.'}
    }
    $vb=Join-Path $env:WINDIR 'SysWOW64\vbscript.dll'
    $clsid='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{B54F3741-5B07-11CF-A4B0-00AA004A55E8}\InprocServer32'
    if(-not(Test-Path -LiteralPath $vb) -or -not(Test-Path -LiteralPath $clsid)){
        $null=Invoke-IAGintNative 'VBScript' ($env:WINDIR+'\System32\dism.exe') '/Online /Add-Capability /CapabilityName:VBSCRIPT /NoRestart /English' 600
        if(-not(Test-Path -LiteralPath $vb) -or -not(Test-Path -LiteralPath $clsid)){throw '32-bit VBScript is unavailable. Resolve Windows optional-feature provisioning, then retry.'}
    }
}
function Invoke-IAGintPrerequisites {
    if(-not [Environment]::Is64BitProcess){throw 'gINT component deployment requires 64-bit Windows PowerShell.'}
    foreach($item in $script:IAGintPlan.Files.PSObject.Properties){Test-IAGintAttachment $item.Name}
    Initialize-IAGintFeatures
    $steps=@(
      @{Name='VC2005';File='vc8redist_x86.exe';Args='/q:a /c:"msiexec /i vcredist.msi /qn /norestart"';Check={Test-IAGintMsi '{710F4C1C-CC18-4C49-8CBF-51240C89A1A2}'}},
      @{Name='VC2008';File='vc9redist_x86.exe';Args='/q:a /c:"msiexec /i vcredist.msi /qn /norestart"';Check={Test-IAGintV9}},
      @{Name='VC14';File='vc14redist_x86.exe';Args='/install /quiet /norestart';Check={Test-IAGintV14}},
      @{Name='Access2010';File='AccessDatabaseEngine.exe';Args='/quiet /norestart';Check={Test-IAGintMsi '{90140000-00D1-0409-0000-0000000FF1CE}'}},
      @{Name='ConnectionClient';File='Setup_CONNECTIONclientx64_10_00_17_010.exe';Args='/q NoStartPostInstall=1 InstallDesktopShortcut=0';Check={Test-IAGintConnection}}
    )
    foreach($step in $steps){
        if(-not(& $step.Check)){
            $code=Invoke-IAGintNative $step.Name (Join-Path $InstallerFolder $step.File) $step.Args
            if(-not(& $step.Check)){throw ($step.Name+' prerequisite was not installed despite wrapper exit '+$code+'. Check installer logs and target application-control policy. Security policies were not changed. Logs: '+$script:IAGintLog)}
        }
        Write-Host ('IA_PREREQUISITE_VERIFIED='+$step.Name)
    }
}
function Invoke-IAGintInstall {
    Invoke-IAGintPrerequisites
    $log=Join-Path $script:IAGintLog 'gINT-install.log'
    $code=Invoke-IAGintNative 'gINT' ($env:WINDIR+'\System32\msiexec.exe') ('/i "'+(Join-Path $InstallerFolder 'gINT.msi')+'" /qn /norestart /L*v "'+$log+'"')
    if($code -eq 1638){throw 'A different gINT version is installed; this recipe does not downgrade or replace it.'}
    if(-not(Test-IAGintMsi '{192AEB44-6992-44B8-B66D-D0781DC50768}')){throw 'gINT MSI product registration was not established.'}
}
""";
}
