using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed record DetectionCandidate(string Name, int Score, string Detail);
public sealed record ScriptInspection(int Errors, int Warnings, IReadOnlyList<string> Checks)
{
    public bool Passed => Errors == 0;
}

public static class DeploymentIntelligenceService
{
    public static IReadOnlyList<DetectionCandidate> RankDetection(UninstallEntry? entry)
    {
        var list = new List<DetectionCandidate>();
        if (entry is null) return list;
        if (!string.IsNullOrWhiteSpace(entry.ProductCode)) list.Add(new("MSI ProductCode", 100, entry.ProductCode!));
        if (entry.WindowsInstaller is not null && !string.IsNullOrWhiteSpace(entry.Key)) list.Add(new("Windows Installer registry", 95, entry.Key!));
        if (!string.IsNullOrWhiteSpace(entry.Key)) list.Add(new("Uninstall registry entry", 90, entry.Key!));
        if (!string.IsNullOrWhiteSpace(entry.DisplayVersion)) list.Add(new("DisplayVersion", 82, entry.DisplayVersion!));
        if (!string.IsNullOrWhiteSpace(entry.InstallLocation)) list.Add(new("Install location", 65, entry.InstallLocation!));
        return list.OrderByDescending(x => x.Score).ToList();
    }

    public static ScriptInspection Inspect(string install, string detection, string uninstall, bool needsIss, bool sandboxValidated)
    {
        var checks = new List<string>(); var errors = 0; var warnings = 0;
        void Check(bool ok, string good, string bad, bool error = false)
        { checks.Add((ok ? "✓ " : error ? "✕ " : "! ") + (ok ? good : bad)); if (!ok) { if (error) errors++; else warnings++; } }

        Check(!string.IsNullOrWhiteSpace(install), "Install script generated", "Install script is empty", true);
        Check(!string.IsNullOrWhiteSpace(detection), "Detection script generated", "Detection script is empty", true);
        Check(!string.IsNullOrWhiteSpace(uninstall), "Uninstall script generated", "Uninstall script is empty", true);
        var all = install + "\n" + detection + "\n" + uninstall;
        Check(!Regex.IsMatch(all, @"\$InstallerFolder\b", RegexOptions.IgnoreCase), "No dependency on $InstallerFolder", "Generated script references $InstallerFolder, which may not exist in ImmyBot", true);
        Check(!Regex.IsMatch(all, @"(?<!`)\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*['""]?[A-Z]:\\Users\\", RegexOptions.IgnoreCase), "No user-specific absolute paths", "A generated variable contains a user-specific absolute path");
        Check(!needsIss || install.Contains("setup.iss", StringComparison.OrdinalIgnoreCase), "Install response-file requirement satisfied", "Installer requires setup.iss but install script does not reference it", true);
        Check(!needsIss || uninstall.Contains("uninstall.iss", StringComparison.OrdinalIgnoreCase), "Uninstall response-file strategy present", "InstallShield package may require uninstall.iss");
        Check(install.Contains("ExitCode", StringComparison.OrdinalIgnoreCase) || install.Contains("Start-Process", StringComparison.OrdinalIgnoreCase), "Install execution/exit handling present", "Install script has no obvious process/exit handling");
        Check(sandboxValidated, "Sandbox lifecycle validated", "Sandbox lifecycle has not been validated");
        return new(errors, warnings, checks);
    }
}
