using System.Diagnostics;
using System.Security;
using System.Text;
using System.IO;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed class SandboxIssSession
{
    public required string SessionFolder { get; init; }
    public required string OutputFolder { get; init; }
    public required string IssPath { get; init; }
    public required string WsbPath { get; init; }
    public string AnalysisPath => Path.Combine(OutputFolder, "install-analysis.json");
    public bool RequiresIss { get; init; }
}

public static class SandboxIssRecorder
{
    public static bool IsSandboxAvailable()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return File.Exists(Path.Combine(windows, "System32", "WindowsSandbox.exe"));
    }

    public static SandboxIssSession Start(string installerPath, InstallerKind kind, bool requiresIss, string baseSilentArguments, string additionalPackageArguments)
    {
        if (!File.Exists(installerPath)) throw new FileNotFoundException("Installer not found.", installerPath);
        if (!IsSandboxAvailable()) throw new InvalidOperationException("Windows Sandbox was not found. Enable 'Windows Sandbox' in Windows Features, then restart Windows.");

        var root = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer", "ISS-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        var input = Path.Combine(root, "Input");
        var output = Path.Combine(root, "Output");
        Directory.CreateDirectory(input);
        Directory.CreateDirectory(output);

        var installerName = Path.GetFileName(installerPath);
        var copiedInstaller = Path.Combine(input, installerName);
        File.Copy(installerPath, copiedInstaller, true);

        var ps1 = Path.Combine(input, "Record-Iss.ps1");
        File.WriteAllText(ps1, requiresIss ? BuildRecorderScript(installerName) : BuildDiscoveryScript(installerName, kind, baseSilentArguments, additionalPackageArguments), new UTF8Encoding(false));

        var wsb = Path.Combine(root, "Record-setup-iss.wsb");
        File.WriteAllText(wsb, BuildWsb(input, output), new UTF8Encoding(false));

        Process.Start(new ProcessStartInfo { FileName = wsb, UseShellExecute = true });

        return new SandboxIssSession
        {
            SessionFolder = root,
            OutputFolder = output,
            IssPath = Path.Combine(output, "setup.iss"),
            WsbPath = wsb,
            RequiresIss = requiresIss
        };
    }


    public static SandboxIssSession StartLocal(string installerPath)
    {
        if (!File.Exists(installerPath)) throw new FileNotFoundException("Installer not found.", installerPath);

        var root = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer", "ISS-Local-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        var output = Path.Combine(root, "Output");
        Directory.CreateDirectory(output);
        var issPath = Path.Combine(output, "setup.iss");
        var arguments = $"/r /f1\"{issPath}\"";

        Process.Start(new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = arguments,
            UseShellExecute = true
        });

        return new SandboxIssSession
        {
            SessionFolder = root,
            OutputFolder = output,
            IssPath = issPath,
            WsbPath = string.Empty,
            RequiresIss = true
        };
    }

    private static string BuildDiscoveryScript(string installerName, InstallerKind kind, string baseSilentArguments, string additionalPackageArguments)
    {
        var escaped = installerName.Replace("'", "''");
        var kindName = kind.ToString().Replace("'", "''");
        var baseSilent = (baseSilentArguments ?? string.Empty).Replace("'", "''");
        var additional = (additionalPackageArguments ?? string.Empty).Replace("'", "''");
        var script = """
$ErrorActionPreference = 'Stop'
$Installer = 'C:\InstallerInput\__INSTALLER__'
$Analysis = 'C:\InstallerOutput\install-analysis.json'
$BaseSilentArguments = '__BASE_ARGS__'
$AdditionalPackageArguments = '__ADDITIONAL_ARGS__'
$SilentInstallArguments = (@($BaseSilentArguments,$AdditionalPackageArguments) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
$InstallerKind = '__KIND__'
$StartedAt = Get-Date

function Get-UninstallSnapshot {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
    Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        [PSCustomObject]@{ Key=$_.PSPath; DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion; Publisher=$_.Publisher; InstallLocation=$_.InstallLocation; UninstallString=$_.UninstallString; QuietUninstallString=$_.QuietUninstallString; WindowsInstaller=$_.WindowsInstaller; ProductCode=if ($_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {$_.PSChildName}else{$null} }
    }
}
function Select-Primary($entries) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($Installer).ToLowerInvariant() -replace '(setup|installer|install)','' -replace '[^a-z0-9]',''
    $best=$null; $bestScore=[int]::MinValue
    foreach($e in $entries){
        $name=([string]$e.DisplayName).ToLowerInvariant() -replace '[^a-z0-9]',''; $score=0
        if($stem -and ($name.Contains($stem) -or $stem.Contains($name))){$score+=70}
        if($e.InstallLocation){$score+=15}; if($e.UninstallString){$score+=10}; if($e.QuietUninstallString){$score+=15}; if($e.DisplayVersion){$score+=5}
        if($name -match 'microsoftvisualc|redistributable|runtime'){$score-=50}
        if($score -gt $bestScore){$best=$e;$bestScore=$score}
    }
    return $best
}
function Split-Command([string]$command) {
    if([string]::IsNullOrWhiteSpace($command)){return $null}
    $command=$command.Trim()
    # Registry uninstall strings are not consistently quoted. Prefer the executable
    # boundary so paths containing spaces (for example Program Files (x86)) stay intact.
    if($command -match '^\s*"?(.+?\.exe)"?\s*(.*)$'){ return @($matches[1].Trim('"'),$matches[2]) }
    if($command -match '^\s*"([^"]+)"\s*(.*)$'){ return @($matches[1],$matches[2]) }
    if($command -match '^\s*(\S+)\s*(.*)$'){ return @($matches[1],$matches[2]) }
    return $null
}
function Test-Detected($primary) {
    if($primary.Key -like 'FILE::*'){ return Test-Path $primary.InstallLocation }
    return (@(Get-UninstallSnapshot | Where-Object { $_.Key -eq $primary.Key -or $_.DisplayName -eq $primary.DisplayName }).Count -gt 0)
}
function Find-Reinstalled($primary) {
    if($primary.Key -like 'FILE::*') { return Find-SquirrelApplication }
    $same=@(Get-UninstallSnapshot | Where-Object { $_.DisplayName -eq $primary.DisplayName })
    if($same.Count -gt 0){ return $same[0] }; return $null
}
function Find-SquirrelApplication {
    $roots=@($env:LOCALAPPDATA)
    foreach($root in $roots){
      $updates=Get-ChildItem -Path $root -Filter Update.exe -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notmatch '\\SquirrelTemp\\'} | Sort-Object LastWriteTime -Descending
      foreach($u in $updates){
        $dir=$u.Directory.FullName
        $apps=@(Get-ChildItem -Path $dir -Directory -Filter 'app-*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if($apps.Count -gt 0){
          $exe=Get-ChildItem -Path $apps[0].FullName -Filter '*.exe' -File -ErrorAction SilentlyContinue | Where-Object {$_.Name -notmatch 'Update|Squirrel'} | Select-Object -First 1
          $name=if($exe){$exe.VersionInfo.ProductName}else{$u.Directory.Name}; if([string]::IsNullOrWhiteSpace($name)){$name=$u.Directory.Name}
          $ver=if($exe){$exe.VersionInfo.ProductVersion}else{$null}
          return [PSCustomObject]@{Key=('FILE::'+$dir);DisplayName=$name;DisplayVersion=$ver;Publisher=if($exe){$exe.VersionInfo.CompanyName}else{$null};InstallLocation=$dir;UninstallString=('"'+$u.FullName+'" --uninstall');QuietUninstallString=$null;WindowsInstaller=$null;ProductCode=$null}
        }
      }
    }
    return $null
}
function Invoke-NativeProcess([string]$file,[string]$arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $file
    $psi.Arguments = $arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return [PSCustomObject]@{ ExitCode=$proc.ExitCode; StdOut=$stdout; StdErr=$stderr }
}
function Write-Result($r) { $r.CapturedAt=(Get-Date).ToString('o'); [PSCustomObject]$r | ConvertTo-Json -Depth 8 | Set-Content $Analysis -Encoding UTF8 }

Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("Installer Analyzer v0.10.9 detected __KIND__. Complete the installer normally. Discovery may wait briefly for bootstrapper child processes. Silent lifecycle validation only passes when both the process result and application detection pass.","Installer Analyzer v0.10.9",'OK','Information') | Out-Null
$result=[ordered]@{ Installer=[IO.Path]::GetFileName($Installer); InstallerExitCode=-1; CapturedAt=(Get-Date).ToString('o'); NewUninstallEntries=@(); PrimaryKey=$null; UninstallValidationMethod='Discovery only'; UninstallRecordingAttempted=$false; UninstallResponseFileCreated=$false; RecordedUninstallExitCode=$null; BaseSilentArguments=$BaseSilentArguments; AdditionalPackageArguments=$AdditionalPackageArguments; CombinedSilentArguments=$SilentInstallArguments; SilentInstallCommand=('"'+$Installer+'" '+$SilentInstallArguments).Trim(); SilentInstallStdOut=$null; SilentInstallStdErr=$null; SilentReinstallExitCode=$null; SilentReinstallValidated=$false; SilentUninstallExitCode=$null; PostUninstallDetected=$null; SilentUninstallValidated=$false; DiscoverySucceeded=$false; DiscoveryMethod=$null; UninstallCandidate=$null; ValidationError=$null }
try {
    $before=@(Get-UninstallSnapshot); $beforeKeys=@($before | ForEach-Object {$_.Key})
    $p=Start-Process -FilePath $Installer -PassThru; $finished=$p.WaitForExit(300000); $result.InstallerExitCode=if($finished){$p.ExitCode}else{-2}
    $primary=$null; $new=@()
    for($i=0;$i -lt 12 -and -not $primary;$i++){
      Start-Sleep 3
      $after=@(Get-UninstallSnapshot); $new=@($after | Where-Object {$_.Key -notin $beforeKeys})
      $primary=Select-Primary $new
      if(-not $primary -and $InstallerKind -eq 'Squirrel'){$primary=Find-SquirrelApplication}
    }
    $result.NewUninstallEntries=$new
    if(-not $primary){ throw 'Installer completed, but no primary application could be identified after registry and installer-specific discovery.' }
    if($primary.Key -like 'FILE::*' -and @($result.NewUninstallEntries).Count -eq 0){$result.NewUninstallEntries=@($primary)}
    $result.PrimaryKey=$primary.Key; $result.DiscoverySucceeded=$true; $result.DiscoveryMethod=if($primary.Key -like 'FILE::*'){'Squirrel LocalAppData filesystem'}else{'Uninstall registry'}

    $uninstallCommand=$primary.QuietUninstallString
    if([string]::IsNullOrWhiteSpace($uninstallCommand) -and $InstallerKind -eq 'Nsis' -and $primary.UninstallString){$uninstallCommand=$primary.UninstallString + ' /S'; $result.UninstallCandidate=$uninstallCommand; $result.UninstallValidationMethod='NSIS /S candidate'}
    elseif([string]::IsNullOrWhiteSpace($uninstallCommand) -and $InstallerKind -eq 'Squirrel' -and $primary.UninstallString){$uninstallCommand=$primary.UninstallString; $result.UninstallCandidate=$uninstallCommand; $result.UninstallValidationMethod='Squirrel Update.exe --uninstall candidate'}
    elseif(-not [string]::IsNullOrWhiteSpace($uninstallCommand)){$result.UninstallValidationMethod='QuietUninstallString + detected silent install strategy'}

    if([string]::IsNullOrWhiteSpace($uninstallCommand)) {$result.ValidationError='Discovery succeeded, but no safe silent uninstall method or installer-family candidate is available. Lifecycle validation was not attempted.'}
    elseif([string]::IsNullOrWhiteSpace($SilentInstallArguments)) {$result.ValidationError='Discovery succeeded, but no silent-install arguments are configured. Add package-specific arguments if required, then rerun validation.'}
    else {
      [System.Windows.MessageBox]::Show("Discovery complete for $($primary.DisplayName). Installer Analyzer will now validate the candidate silent uninstall, silent reinstall, detection, and final removal.","Validate silent lifecycle",'OK','Information')|Out-Null
      $parts=Split-Command $uninstallCommand; if(-not $parts){throw 'Could not parse silent uninstall command.'}
      $u1=Start-Process -FilePath $parts[0] -ArgumentList $parts[1] -Wait -PassThru; Start-Sleep 5
      if($u1.ExitCode -notin @(0,1605,3010)){throw "Initial silent uninstall returned exit code $($u1.ExitCode)."}
      if(Test-Detected $primary){throw 'Application remained detected after the initial silent uninstall.'}

      Write-Result $result
      $ri=Invoke-NativeProcess $Installer $SilentInstallArguments
      $result.SilentReinstallExitCode=$ri.ExitCode; $result.SilentInstallStdOut=$ri.StdOut; $result.SilentInstallStdErr=$ri.StdErr
      $current=$null
      for($i=0;$i -lt 12 -and -not $current;$i++){Start-Sleep 3;$current=Find-Reinstalled $primary}
      $result.SilentReinstallValidated=($ri.ExitCode -in @(0,3010) -and $null -ne $current)
      if(-not $result.SilentReinstallValidated){
        if($ri.ExitCode -in @(0,3010) -and $null -eq $current){throw "Installer returned success (exit $($ri.ExitCode)) but the application was not installed/detected. Exact command: $($result.SilentInstallCommand)"}
        throw "Silent reinstall was not validated. Process exit code: $($ri.ExitCode). Application detected after reinstall: $($null -ne $current). Exact command: $($result.SilentInstallCommand)"
      }

      $finalCommand=$current.QuietUninstallString
      if([string]::IsNullOrWhiteSpace($finalCommand) -and $InstallerKind -eq 'Nsis' -and $current.UninstallString){$finalCommand=$current.UninstallString+' /S'}
      if([string]::IsNullOrWhiteSpace($finalCommand) -and $InstallerKind -eq 'Squirrel' -and $current.UninstallString){$finalCommand=$current.UninstallString}
      if([string]::IsNullOrWhiteSpace($finalCommand)){throw 'Reinstalled application was detected, but no silent uninstall command could be produced.'}
      $parts2=Split-Command $finalCommand; if(-not $parts2){throw 'Could not parse final silent uninstall command.'}
      $u2=Start-Process -FilePath $parts2[0] -ArgumentList $parts2[1] -Wait -PassThru; $result.SilentUninstallExitCode=$u2.ExitCode; Start-Sleep 6
      $result.PostUninstallDetected=Test-Detected $current
      $result.SilentUninstallValidated=($u2.ExitCode -in @(0,1605,3010) -and -not $result.PostUninstallDetected)
      if(-not $result.SilentUninstallValidated){$result.ValidationError='Final silent uninstall completed, but removal verification did not pass.'}
    }
} catch {$result.ValidationError=$_.Exception.Message}
Write-Result $result
if($result.SilentUninstallValidated){$msg='Silent lifecycle validation completed successfully: uninstall, reinstall, detection, final uninstall, and removal verification all passed.'}else{$msg='Installation discovery completed, but the silent lifecycle was not fully validated. Review the Validation tab for details.'}
[System.Windows.MessageBox]::Show($msg + "`n`nReturn to Installer Analyzer for the results.","Installer Analyzer v0.10.9",'OK',$(if($result.SilentUninstallValidated){'Information'}else{'Warning'}))|Out-Null
""";
        return script.Replace("__INSTALLER__", escaped).Replace("__KIND__", kindName).Replace("__BASE_ARGS__", baseSilent).Replace("__ADDITIONAL_ARGS__", additional);
    }

    private static string BuildWsb(string input, string output)
    {
        string X(string value) => SecurityElement.Escape(value) ?? value;
        return "<Configuration>\r\n" +
               "  <MappedFolders>\r\n" +
               "    <MappedFolder>\r\n" +
               $"      <HostFolder>{X(input)}</HostFolder>\r\n" +
               "      <SandboxFolder>C:\\InstallerInput</SandboxFolder>\r\n" +
               "      <ReadOnly>true</ReadOnly>\r\n" +
               "    </MappedFolder>\r\n" +
               "    <MappedFolder>\r\n" +
               $"      <HostFolder>{X(output)}</HostFolder>\r\n" +
               "      <SandboxFolder>C:\\InstallerOutput</SandboxFolder>\r\n" +
               "      <ReadOnly>false</ReadOnly>\r\n" +
               "    </MappedFolder>\r\n" +
               "  </MappedFolders>\r\n" +
               "  <ClipboardRedirection>Enable</ClipboardRedirection>\r\n" +
               "  <Networking>Default</Networking>\r\n" +
               "  <LogonCommand>\r\n" +
               "    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\InstallerInput\\Record-Iss.ps1</Command>\r\n" +
               "  </LogonCommand>\r\n" +
               "</Configuration>\r\n";
    }

    private static string BuildRecorderScript(string installerName)
    {
        var escaped = installerName.Replace("'", "''");
        var script = @"$ErrorActionPreference = 'Stop'
$Installer = 'C:\InstallerInput\__INSTALLER__'
$SetupIss = 'C:\InstallerOutput\setup.iss'
$UninstallIss = 'C:\InstallerOutput\uninstall.iss'
$Analysis = 'C:\InstallerOutput\install-analysis.json'

function Get-UninstallSnapshot {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        [PSCustomObject]@{ Key=$_.PSPath; DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion; Publisher=$_.Publisher; InstallLocation=$_.InstallLocation; UninstallString=$_.UninstallString; QuietUninstallString=$_.QuietUninstallString; WindowsInstaller=$_.WindowsInstaller; ProductCode=if ($_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {$_.PSChildName}else{$null} }
    }
}
function Select-Primary($entries) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($Installer).ToLowerInvariant() -replace '[^a-z0-9]',''
    $best=$null; $bestScore=[int]::MinValue
    foreach($e in $entries){
        $name=([string]$e.DisplayName).ToLowerInvariant() -replace '[^a-z0-9]',''; $score=0
        if($name -eq $stem){$score+=100}elseif($name.Contains($stem) -or $stem.Contains($name)){$score+=60}
        if($e.InstallLocation){$score+=10}; if($e.UninstallString){$score+=10}
        if($name -match 'microsoftvisualc|redistributable|runtime'){$score-=45}
        if($score -gt $bestScore){$best=$e;$bestScore=$score}
    }
    return $best
}
function Split-Command([string]$command) {
    if([string]::IsNullOrWhiteSpace($command)){return $null}
    $command=$command.Trim()
    if($command -match '^\s*""?(.+?\.exe)""?\s*(.*)$'){ return @($matches[1].Trim('""'),$matches[2]) }
    if($command -match '^\s*""([^""]+)""\s*(.*)$'){ return @($matches[1],$matches[2]) }
    if($command -match '^\s*(\S+)\s*(.*)$'){ return @($matches[1],$matches[2]) }
    return $null
}
function Test-KeyGone([string]$key) { return -not (@(Get-UninstallSnapshot | Where-Object { $_.Key -eq $key }).Count -gt 0) }

Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show(""Installer Analyzer v0.10.9 will record setup.iss, discover the installed application, then attempt to record and validate a silent uninstall. You may see the installer/uninstaller several times. Follow the prompts and do not close Sandbox until the final completion message appears."",""Installer Analyzer v0.10.9"",'OK','Information') | Out-Null

$result=[ordered]@{ Installer=[IO.Path]::GetFileName($Installer); InstallerExitCode=-1; CapturedAt=(Get-Date).ToString('o'); NewUninstallEntries=@(); PrimaryKey=$null; UninstallValidationMethod=$null; UninstallRecordingAttempted=$false; UninstallResponseFileCreated=$false; RecordedUninstallExitCode=$null; SilentReinstallExitCode=$null; SilentUninstallExitCode=$null; PostUninstallDetected=$null; SilentUninstallValidated=$false; ValidationError=$null }
try {
    $before=@(Get-UninstallSnapshot)
    $p=Start-Process -FilePath $Installer -ArgumentList ""/r /f1`""$SetupIss`"""" -Wait -PassThru
    $result.InstallerExitCode=$p.ExitCode
    Start-Sleep 3
    $after=@(Get-UninstallSnapshot); $beforeKeys=@($before|%{$_.Key}); $new=@($after|?{$_.Key -notin $beforeKeys}); $result.NewUninstallEntries=$new
    $primary=Select-Primary $new
    if($primary){
        $result.PrimaryKey=$primary.Key
        if($primary.WindowsInstaller -eq 1 -and $primary.ProductCode){
            $result.UninstallValidationMethod='MSI /qn'
            $u=Start-Process msiexec.exe -ArgumentList ""/x $($primary.ProductCode) /qn /norestart"" -Wait -PassThru
            $result.SilentUninstallExitCode=$u.ExitCode; Start-Sleep 3
            $result.PostUninstallDetected=-not (Test-KeyGone $primary.Key)
            $result.SilentUninstallValidated=($u.ExitCode -in @(0,1605,3010) -and -not $result.PostUninstallDetected)
        } elseif($primary.QuietUninstallString) {
            $result.UninstallValidationMethod='QuietUninstallString'
            $parts=Split-Command $primary.QuietUninstallString
            if($parts){$u=Start-Process -FilePath $parts[0] -ArgumentList $parts[1] -Wait -PassThru; $result.SilentUninstallExitCode=$u.ExitCode; Start-Sleep 3; $result.PostUninstallDetected=-not (Test-KeyGone $primary.Key); $result.SilentUninstallValidated=($u.ExitCode -in @(0,1605,3010) -and -not $result.PostUninstallDetected)}
        } elseif($primary.UninstallString) {
            $result.UninstallValidationMethod='InstallShield response file'
            $result.UninstallRecordingAttempted=$true
            $parts=Split-Command $primary.UninstallString
            if($parts){
                [System.Windows.MessageBox]::Show(""Installer Analyzer found the uninstall entry for $($primary.DisplayName). The uninstaller will open now in RECORD mode. Complete the uninstall normally so uninstall.iss can be created."",""Record uninstall response"",'OK','Information')|Out-Null
                $recordArgs=(($parts[1] + "" /r /f1`""$UninstallIss`"""").Trim())
                $ur=Start-Process -FilePath $parts[0] -ArgumentList $recordArgs -Wait -PassThru
                $result.RecordedUninstallExitCode=$ur.ExitCode; Start-Sleep 3; $result.UninstallResponseFileCreated=Test-Path $UninstallIss
                if($result.UninstallResponseFileCreated -and (Test-KeyGone $primary.Key)){
                    [System.Windows.MessageBox]::Show(""uninstall.iss was recorded. Installer Analyzer will now silently reinstall the application, then silently uninstall it to validate the response files. No interaction should be required for these two passes."",""Validate silent uninstall"",'OK','Information')|Out-Null
                    $ri=Start-Process -FilePath $Installer -ArgumentList ""/s /f1`""$SetupIss`"""" -Wait -PassThru; $result.SilentReinstallExitCode=$ri.ExitCode; Start-Sleep 4
                    $current=@(Get-UninstallSnapshot|?{$_.DisplayName -eq $primary.DisplayName}); $cur=if($current.Count){$current[0]}else{$null}
                    if($cur -and $cur.UninstallString){
                        $p2=Split-Command $cur.UninstallString
                        $silentArgs=(($p2[1] + "" /s /f1`""$UninstallIss`"""").Trim())
                        $su=Start-Process -FilePath $p2[0] -ArgumentList $silentArgs -Wait -PassThru; $result.SilentUninstallExitCode=$su.ExitCode; Start-Sleep 4
                        $result.PostUninstallDetected=-not (Test-KeyGone $cur.Key)
                        $result.SilentUninstallValidated=($su.ExitCode -in @(0,1605,3010) -and -not $result.PostUninstallDetected)
                    } else {$result.ValidationError='Application was not detected after the silent reinstall.'}
                } else {$result.ValidationError='The recorded uninstall did not create uninstall.iss or the application remained detected.'}
            }
        }
    } else {$result.ValidationError='No primary installed application could be identified.'}
} catch {$result.ValidationError=$_.Exception.Message}
$result.CapturedAt=(Get-Date).ToString('o')
[PSCustomObject]$result | ConvertTo-Json -Depth 8 | Set-Content $Analysis -Encoding UTF8
if($result.SilentUninstallValidated){$msg='Install, detection, and silent uninstall validation completed successfully.'}else{$msg='Analysis completed, but silent uninstall was not fully validated. Review the Validation tab.'}
[System.Windows.MessageBox]::Show($msg + ""`n`nReturn to Installer Analyzer for the results."",""Installer Analyzer v0.10.9"",'OK',$(if($result.SilentUninstallValidated){'Information'}else{'Warning'}))|Out-Null
";
        return script.Replace("__INSTALLER__", escaped);
    }
}
