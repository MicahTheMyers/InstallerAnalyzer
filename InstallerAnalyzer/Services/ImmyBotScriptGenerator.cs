using System.IO;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;
namespace InstallerAnalyzer.Services;
public static class ImmyBotScriptGenerator
{
    public static string Generate(AnalysisResult r, string arguments, string appName, InstallAnalysis? proof = null)
    {
        if (r.Archive is null) return GenerateInstall(r, arguments, appName, proof);
        if (r.Archive.DeploymentBlockReason(proof) is { } reason)
            return "# " + reason;
        if (Project2007Deployment.Matches(r.Archive, proof))
            return Project2007Deployment.Generate(r.Archive, proof!, uninstall: false);
        var validatedArguments = proof!.CombinedSilentArguments ?? proof.BaseSilentArguments ?? "";
        return r.Archive.WrapInstallScript(GenerateInstall(r, validatedArguments, "Validated application", proof));
    }

    private static string GenerateInstall(AnalysisResult r, string arguments, string appName, InstallAnalysis? proof)
    {
        appName = string.IsNullOrWhiteSpace(appName) ? Path.GetFileNameWithoutExtension(r.FilePath) : appName.Trim();
        arguments ??= "";
        var workingDirectory = r.Archive is null ? "" : " -WorkingDirectory (Split-Path -Parent $Installer)";
        if (r.Archive is null && r.Kind == InstallerKind.Msix)
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

        if (r.Archive is null ? r.Kind == InstallerKind.Msi : r.Archive.Entry.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
        {
            var shortcut = ActDesktopShortcut(proof, remove: false);
            return $$"""
$Installer = $InstallerFile

Write-Host "Installer: $Installer"

if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    throw "Installer was not found at: $Installer"
}

$Arguments = '/i "' + $Installer + '" ' + '{{arguments.Replace("'", "''")}}'
Write-Host "Starting {{appName}} installation..."
$Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -PassThru{{workingDirectory}}
Write-Host "{{appName}} installer exited with code $($Process.ExitCode)"

switch ($Process.ExitCode) {
    0 { Write-Host "Installation completed successfully." }
    3010 { Write-Host "Installation completed successfully. A reboot is required." }
    default { throw "{{appName}} installation failed with exit code $($Process.ExitCode)" }
}
{{shortcut}}
""";
        }

        // Preserve the tested launcher's switches, while rebinding response files to
        // the exported package instead of retaining disposable Sandbox paths.
        var responseArguments = Regex.Replace(arguments, @"(?i)(?<!\S)/f[12](?:""[^""]*""|\S+)", "").Trim();
        responseArguments = Regex.Replace(responseArguments, @"(?i)(?<!\S)/r(?=\s|$)", "").Trim();
        if (!Regex.IsMatch(responseArguments, @"(?i)(?<!\S)/s(?=\s|$)")) responseArguments = ("/s " + responseArguments).Trim();
        var needsResponse = r.Archive is null ? r.NeedsIss :
            proof?.SelectedSilentStrategy?.StartsWith("Recorded InstallShield", StringComparison.OrdinalIgnoreCase) == true;
        var argumentLine = needsResponse
            ? "$Arguments = '" + responseArguments.Replace("'", "''") + "' + ' /f1\"' + $ResponseFile + '\"'"
            : "$Arguments = '" + arguments.Replace("'", "''") + "'";

        var response = needsResponse ? """
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
    -PassThru{{workingDirectory}}

Write-Host "{{appName}} installer exited with code $($Process.ExitCode)"

switch ($Process.ExitCode) {
    0 { Write-Host "Installation completed successfully." }
    3010 { Write-Host "Installation completed successfully. A reboot is required." }
    default { throw "{{appName}} installation failed with exit code $($Process.ExitCode)" }
}
""";
    }

    internal static string ActDesktopShortcut(InstallAnalysis? proof, bool remove)
    {
        if (proof is null || string.IsNullOrWhiteSpace(proof.PrimaryKey) ||
            !proof.NewUninstallEntries.Any(entry => entry.Key == proof.PrimaryKey &&
                string.Equals(entry.ProductCode, "{38FE5475-B2E9-44C9-A93B-FD0D942D1FF3}", StringComparison.OrdinalIgnoreCase)) ||
            !proof.DetectionStrategies.Any(rule => rule.Validated && rule.Type == "ExecutablePathAndVersion" &&
                string.Equals(rule.Identity, @"C:\Program Files\ACT\ActInstallDir\Act!.exe", StringComparison.OrdinalIgnoreCase)))
            return "";

        var operation = remove ? """
if (Test-Path -LiteralPath $actShortcutPath -PathType Leaf -ErrorAction Stop) {
    $actShortcut = (New-Object -ComObject WScript.Shell -ErrorAction Stop).CreateShortcut($actShortcutPath)
    if ($actShortcut.Description -eq 'ACT! shortcut created by Installer Analyzer' -and $actShortcut.TargetPath -eq $actExe) {
        Remove-Item -LiteralPath $actShortcutPath -ErrorAction Stop
    }
}
""" : """
if ((Test-Path -LiteralPath $actExe -PathType Leaf -ErrorAction Stop) -and
    !(Test-Path -LiteralPath $actShortcutPath -ErrorAction Stop)) {
    $actShortcut = (New-Object -ComObject WScript.Shell -ErrorAction Stop).CreateShortcut($actShortcutPath)
    $actShortcut.TargetPath = $actExe
    $actShortcut.WorkingDirectory = Split-Path -Parent $actExe
    $actShortcut.Description = 'ACT! shortcut created by Installer Analyzer'
    $actShortcut.Save()
}
""";
        return """
$actExe = 'C:\Program Files\ACT\ActInstallDir\Act!.exe'
$actShortcutPath = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'ACT!.lnk'
""" + Environment.NewLine + operation;
    }

    public static string GenerateVersionDetection(UninstallEntry? entry)
    {
        if (entry is null) return "# Run Sandbox analysis and select the installed application to generate version detection.";
        if ((entry.Key ?? "").StartsWith("APPX::", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(entry.DisplayName))
            return "$package = Get-AppxPackage -Name " + Quote(entry.DisplayName) +
                " -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1\n" +
                "if ($null -ne $package) { [string]$package.Version }";

        string predicate;
        if (Guid.TryParse(entry.ProductCode, out var productCode))
            predicate = "$_.PSChildName -eq " + Quote(productCode.ToString("B"));
        else if (!string.IsNullOrWhiteSpace(entry.DisplayName))
            predicate = "$_.DisplayName -eq " + Quote(entry.DisplayName);
        else
            return "# The selected application needs a product code or display name for version detection.";

        return $$"""
# ImmyBot software detection returns the installed version or no output.
$roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
$installed = foreach ($root in $roots) {
    if (Test-Path -LiteralPath $root -ErrorAction Stop) {
        Get-ChildItem -LiteralPath $root -ErrorAction Stop |
            Get-ItemProperty -ErrorAction Stop |
            Where-Object { {{predicate}} }
    }
}
$versions = @($installed | ForEach-Object {
    $version = ([string]$_.DisplayVersion).Trim()
    if ($version -match '^([0-9]+\.[0-9]+\.[0-9]+)\.0$') { $version = $Matches[1] }
    if ($version) { $version }
} | Select-Object -Unique)
if ($versions.Count -gt 1) { throw 'Multiple installed versions match this software detection rule.' }
if ($versions.Count -eq 1) { $versions[0] }
""";

        static string Quote(string value) => "'" + value.Replace("'", "''") + "'";
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

    public static string GenerateUninstall(UninstallEntry? e, string appName, InstallAnalysis? analysis = null, InstallerArchive? archive = null)
    {
        if (archive?.DeploymentBlockReason(analysis) is { } reason) return "# " + reason;
        if (archive is not null && Project2007Deployment.Matches(archive, analysis))
            return string.Equals(e?.Key, analysis!.PrimaryKey, StringComparison.OrdinalIgnoreCase)
                ? Project2007Deployment.Generate(archive, analysis, uninstall: true)
                : "# Select the application that passed the recorded lifecycle.";
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
            return $"$Arguments = '{arguments.Replace("'", "''")}'\n$Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $Arguments -Wait -PassThru\nif ($Process.ExitCode -notin @(0, 1605, 3010)) {{ throw '{appName} uninstall failed with exit code ' + $Process.ExitCode }}\n" +
                ActDesktopShortcut(analysis, remove: true);
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
