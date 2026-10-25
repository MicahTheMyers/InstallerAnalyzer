using System.IO;
using InstallerAnalyzer.Models;
namespace InstallerAnalyzer.Services;
public static class ImmyBotScriptGenerator
{
    public static string Generate(AnalysisResult r, string arguments, string appName)
    {
        appName = string.IsNullOrWhiteSpace(appName) ? Path.GetFileNameWithoutExtension(r.FilePath) : appName.Trim();
        if (r.Kind == InstallerKind.Msi)
        {
            return $$"""
$Installer = $InstallerFile

Write-Host "Installer: $Installer"

if (-not (Test-Path $Installer)) {
    throw "Installer was not found at: $Installer"
}

$Arguments = "/i `"$Installer`" {{arguments}}"
Write-Host "Starting {{appName}} installation..."
$Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -PassThru
Write-Host "{{appName}} installer exited with code $($Process.ExitCode)"

switch ($Process.ExitCode) {
    0 { Write-Host "Installation completed successfully." }
    3010 { Write-Host "Installation completed successfully. A reboot is required." }
    default { throw "{{appName}} installation failed with exit code $($Process.ExitCode)" }
}
""";
        }

        var argumentLine = r.NeedsIss
            ? "$Arguments = '/s /f1\"{0}\"' -f $ResponseFile"
            : "$Arguments = '" + arguments.Replace("'", "''") + "'";

        var response = r.NeedsIss ? """
$ResponseFile = Join-Path $InstallerFolder "setup.iss"
Write-Host "Response file: $ResponseFile"
if (-not (Test-Path $ResponseFile)) {
    throw "setup.iss was not found at: $ResponseFile"
}
""" : "";

        return $$"""
$Installer = $InstallerFile
{{response}}
Write-Host "Installer: $Installer"

if (-not (Test-Path $Installer)) {
    throw "Installer was not found at: $Installer"
}

{{argumentLine}}
Write-Host "Starting {{appName}} installation..."

$Process = Start-Process `
    -FilePath $Installer `
    -ArgumentList $Arguments `
    -Wait `
    -PassThru

Write-Host "{{appName}} installer exited with code $($Process.ExitCode)"

switch ($Process.ExitCode) {
    0 { Write-Host "Installation completed successfully." }
    3010 { Write-Host "Installation completed successfully. A reboot is required." }
    default { throw "{{appName}} installation failed with exit code $($Process.ExitCode)" }
}
""";
    }

    public static string GenerateDetection(UninstallEntry? e, string appName)
    {
        if (e is null) return "# Run the Sandbox installation analysis to generate a detection script.";
        var name = (e.DisplayName ?? appName).Replace("'", "''");
        var version = (e.DisplayVersion ?? "").Replace("'", "''");
        if (!string.IsNullOrWhiteSpace(e.ProductCode))
            return $"$ProductCode = '{e.ProductCode}'\n$Installed = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object {{ $_.PSChildName -eq $ProductCode }}\nreturn [bool]$Installed";
        return $"$Installed = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object {{ $_.DisplayName -eq '{name}'{(version.Length>0 ? $" -and $_.DisplayVersion -eq '{version}'" : "")} }}\nreturn [bool]$Installed";
    }

    public static string GenerateUninstall(UninstallEntry? e, string appName, InstallAnalysis? analysis = null)
    {
        if (e is null) return "# Run the Sandbox installation analysis to generate an uninstall script.";
        if (IsWindowsInstallerEntry(e) && !string.IsNullOrWhiteSpace(e.ProductCode))
            return $"$Arguments = '/x {e.ProductCode} /qn /norestart'\n$Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $Arguments -Wait -PassThru\nif ($Process.ExitCode -notin @(0, 1605, 3010)) {{ throw '{appName} uninstall failed with exit code ' + $Process.ExitCode }}";
        if (analysis?.SilentUninstallValidated == true && analysis.UninstallResponseFileCreated && !string.IsNullOrWhiteSpace(e.UninstallString))
        {
            var validatedUninstallCommand = e.UninstallString.Replace("'", "''");
            return $$"""
$ErrorActionPreference = 'Stop'

# ImmyBot does not guarantee $InstallerFolder in uninstall scripts. Search the staged script/package locations instead.
$SearchRoots = @($PSScriptRoot, (Get-Location).Path)
if ($InstallerFile) { $SearchRoots += (Split-Path -Parent $InstallerFile) }
$SearchRoots = $SearchRoots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

$UninstallResponseFile = $null
foreach ($Root in $SearchRoots) {
    $Candidate = Join-Path $Root 'uninstall.iss'
    if (Test-Path -LiteralPath $Candidate) { $UninstallResponseFile = $Candidate; break }
    $Found = Get-ChildItem -LiteralPath $Root -Filter 'uninstall.iss' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Found) { $UninstallResponseFile = $Found.FullName; break }
}

if ([string]::IsNullOrWhiteSpace($UninstallResponseFile) -or -not (Test-Path -LiteralPath $UninstallResponseFile)) {
    throw 'Unable to locate uninstall.iss in the ImmyBot staged files.'
}
Write-Host "Uninstall response file: $UninstallResponseFile"

$BaseCommand = @'
{{validatedUninstallCommand}}
'@
$Command = '{0} /s /f1"{1}"' -f $BaseCommand.Trim(), $UninstallResponseFile
Write-Host "Starting validated silent uninstall for {{appName}}..."
$Process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $Command -Wait -PassThru
if ($Process.ExitCode -notin @(0, 1605, 3010)) { throw "{{appName}} uninstall failed with exit code $($Process.ExitCode)" }
""";
        }
        var cmd = e.QuietUninstallString ?? e.UninstallString;
        if (string.IsNullOrWhiteSpace(cmd)) return "# No uninstall command was exposed by the installed application.";
        return $"# Discovered uninstall command from the Sandbox\n$UninstallCommand = @'\n{cmd}\n'@\nWrite-Host 'Discovered uninstall command:' $UninstallCommand\n# Review vendor silent-uninstall switches before deployment.\nStart-Process -FilePath 'cmd.exe' -ArgumentList '/c', $UninstallCommand -Wait -PassThru";
    }

    private static bool IsWindowsInstallerEntry(UninstallEntry e)
    {
        if (e.WindowsInstaller is null) return false;
        if (e.WindowsInstaller is int i) return i == 1;
        if (e.WindowsInstaller is long l) return l == 1;
        if (e.WindowsInstaller is System.Text.Json.JsonElement j)
        {
            if (j.ValueKind == System.Text.Json.JsonValueKind.Number && j.TryGetInt32(out var n)) return n == 1;
            if (j.ValueKind == System.Text.Json.JsonValueKind.True) return true;
        }
        return string.Equals(e.WindowsInstaller.ToString(), "1", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(e.WindowsInstaller.ToString(), "true", StringComparison.OrdinalIgnoreCase);
    }
}
