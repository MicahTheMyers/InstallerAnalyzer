using System.Diagnostics;
using System.Security;
using System.Text;
using System.IO;

namespace InstallerAnalyzer.Services;

public sealed class SandboxIssSession
{
    public required string SessionFolder { get; init; }
    public required string OutputFolder { get; init; }
    public required string IssPath { get; init; }
    public required string WsbPath { get; init; }
    public string AnalysisPath => Path.Combine(OutputFolder, "install-analysis.json");
}

public static class SandboxIssRecorder
{
    public static bool IsSandboxAvailable()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return File.Exists(Path.Combine(windows, "System32", "WindowsSandbox.exe"));
    }

    public static SandboxIssSession Start(string installerPath)
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
        File.WriteAllText(ps1, BuildRecorderScript(installerName), new UTF8Encoding(false));

        var wsb = Path.Combine(root, "Record-setup-iss.wsb");
        File.WriteAllText(wsb, BuildWsb(input, output), new UTF8Encoding(false));

        Process.Start(new ProcessStartInfo { FileName = wsb, UseShellExecute = true });

        return new SandboxIssSession
        {
            SessionFolder = root,
            OutputFolder = output,
            IssPath = Path.Combine(output, "setup.iss"),
            WsbPath = wsb
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
            WsbPath = string.Empty
        };
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
    if($command -match '^\s*""([^""]+)""\s*(.*)$'){ return @($matches[1],$matches[2]) }
    if($command -match '^\s*(\S+)\s*(.*)$'){ return @($matches[1],$matches[2]) }
    return $null
}
function Test-KeyGone([string]$key) { return -not (@(Get-UninstallSnapshot | Where-Object { $_.Key -eq $key }).Count -gt 0) }

Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show(""Installer Analyzer v0.8.2 will record setup.iss, discover the installed application, then attempt to record and validate a silent uninstall. You may see the installer/uninstaller several times. Follow the prompts and do not close Sandbox until the final completion message appears."",""Installer Analyzer v0.8.2"",'OK','Information') | Out-Null

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
[System.Windows.MessageBox]::Show($msg + ""`n`nReturn to Installer Analyzer for the results."",""Installer Analyzer v0.8.2"",'OK',$(if($result.SilentUninstallValidated){'Information'}else{'Warning'}))|Out-Null
";
        return script.Replace("__INSTALLER__", escaped);
    }
}
