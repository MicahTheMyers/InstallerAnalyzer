using System.IO;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;
namespace InstallerAnalyzer.Services;
public static class ImmyBotScriptGenerator
{
    public static string Generate(AnalysisResult r, string arguments, string appName, InstallAnalysis? proof = null)
    {
        appName = string.IsNullOrWhiteSpace(appName) ? Path.GetFileNameWithoutExtension(r.FilePath) : appName.Trim();
        arguments ??= "";
        if (r.Kind == InstallerKind.Msix)
        {
            var dependencySetup = "";
            var dependencyArgument = "";
            if (proof?.MsixDependencies is { Count: > 0 } dependencies)
            {
                var evidence = string.Join(Environment.NewLine, dependencies.Select(dependency =>
                    $"    @{{ FileName = '{dependency.FileName.Replace("'", "''")}'; Sha256 = '{dependency.Sha256.Replace("'", "''")}' }}"));
                dependencySetup = $$"""
$DependencyPath = foreach ($Dependency in @(
{{evidence}}
)) {
    $Path = Join-Path ($Installer + '{{MsixDependencyService.Suffix}}') $Dependency.FileName
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash -ne $Dependency.Sha256) {
        throw "MSIX dependency changed since validation: $($Dependency.FileName)"
    }
    $Path
}
"""+Environment.NewLine;
                dependencyArgument = " -DependencyPath @($DependencyPath)";
            }
            return $$"""
$Installer = $InstallerFile
if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) { throw "Installer was not found at: $Installer" }
Write-Host "Installing {{appName}} MSIX/AppX package..."
{{dependencySetup}}Add-AppxPackage -Path $Installer{{dependencyArgument}} -ErrorAction Stop
Write-Host "{{appName}} package installation completed successfully."
""";
        }

        if (r.Kind == InstallerKind.Msi)
        {
            return $$"""
$Installer = $InstallerFile

Write-Host "Installer: $Installer"

if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    throw "Installer was not found at: $Installer"
}

$Arguments = '/i "' + $Installer + '" ' + '{{arguments.Replace("'", "''")}}'
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

        // Preserve the tested launcher's switches, while rebinding response files to
        // the exported package instead of retaining disposable Sandbox paths.
        var responseArguments = Regex.Replace(arguments, @"(?i)(?<!\S)/f[12](?:""[^""]*""|\S+)", "").Trim();
        responseArguments = Regex.Replace(responseArguments, @"(?i)(?<!\S)/r(?=\s|$)", "").Trim();
        if (!Regex.IsMatch(responseArguments, @"(?i)(?<!\S)/s(?=\s|$)")) responseArguments = ("/s " + responseArguments).Trim();
        var argumentLine = r.NeedsIss
            ? "$Arguments = '" + responseArguments.Replace("'", "''") + "' + ' /f1\"' + $ResponseFile + '\"'"
            : "$Arguments = '" + arguments.Replace("'", "''") + "'";

        var response = r.NeedsIss ? """
$ResponseFile = Join-Path $InstallerFolder "setup.iss"
Write-Host "Response file: $ResponseFile"
if (-not (Test-Path -LiteralPath $ResponseFile -PathType Leaf)) {
    throw "setup.iss was not found at: $ResponseFile"
}
""" : "";

        return $$"""
$Installer = $InstallerFile
{{response}}
Write-Host "Installer: $Installer"

if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
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
        if ((e.Key ?? "").StartsWith("APPX::", StringComparison.OrdinalIgnoreCase))
        {
            var packageName = (e.DisplayName ?? appName).Replace("'", "''");
            return $"$Installed = Get-AppxPackage -Name '{packageName}' -ErrorAction SilentlyContinue\nreturn [bool]$Installed";
        }
        if (!string.IsNullOrWhiteSpace(e.ProductCode))
            return $"$ProductCode = '{e.ProductCode}'\n$Installed = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object {{ $_.PSChildName -eq $ProductCode }}\nreturn [bool]$Installed";
        return $"$Installed = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object {{ $_.DisplayName -eq '{name}'{(version.Length>0 ? $" -and $_.DisplayVersion -eq '{version}'" : "")} }}\nreturn [bool]$Installed";
    }

    public static string GenerateUninstall(UninstallEntry? e, string appName, InstallAnalysis? analysis = null)
    {
        if (e is null) return "# Run the Sandbox installation analysis to generate an uninstall script.";
        if ((e.Key ?? "").StartsWith("APPX::", StringComparison.OrdinalIgnoreCase))
        {
            var packageName = (e.DisplayName ?? appName).Replace("'", "''");
            return $"$Package = Get-AppxPackage -Name '{packageName}' -ErrorAction SilentlyContinue\nif ($Package) {{ Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction Stop }}";
        }
        if (IsWindowsInstallerEntry(e) && !string.IsNullOrWhiteSpace(e.ProductCode))
        {
            var arguments = $"/x {e.ProductCode} /qn /norestart";
            var prefix = "msiexec.exe " + arguments;
            var command = analysis?.UninstallCandidate;
            if (analysis?.SilentUninstallValidated == true &&
                command?.StartsWith(prefix + " ", StringComparison.OrdinalIgnoreCase) == true)
                arguments = command["msiexec.exe ".Length..];
            return $"$Arguments = '{arguments.Replace("'", "''")}'\n$Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $Arguments -Wait -PassThru\nif ($Process.ExitCode -notin @(0, 1605, 3010)) {{ throw '{appName} uninstall failed with exit code ' + $Process.ExitCode }}";
        }
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

$BaseCommand = '{{validatedUninstallCommand}}'
if ($BaseCommand -match '^\s*"([^"]+)"\s*(.*)$' -or $BaseCommand -match '^\s*([^\s"]+)\s*(.*)$') {
    $UninstallExecutable = $Matches[1]
    $UninstallArguments = $Matches[2]
} else {
    throw 'Unable to separate the recorded uninstall executable and arguments.'
}
$Arguments = $UninstallArguments + ' /s /f1"' + $UninstallResponseFile + '"'
Write-Host "Starting validated silent uninstall for {{appName}}..."
$Process = Start-Process -FilePath $UninstallExecutable -ArgumentList $Arguments -Wait -PassThru
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
