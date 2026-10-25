using InstallerAnalyzer.Models;
using System.Text;

namespace InstallerAnalyzer.Services;

public static class ValidationReportGenerator
{
    public static string Generate(InstallAnalysis? analysis, UninstallEntry? primary, string appName)
    {
        if (analysis is null)
            return "VALIDATION\n==========\n[WAIT] Run the Sandbox installation analysis to validate the generated deployment.";

        var sb = new StringBuilder();
        sb.AppendLine("VALIDATION");
        sb.AppendLine("==========");
        sb.AppendLine($"Installer: {analysis.Installer ?? "Unknown"}");
        sb.AppendLine($"Captured: {analysis.CapturedAt ?? "Unknown"}");
        sb.AppendLine();
        if (!string.IsNullOrWhiteSpace(analysis.SilentInstallCommand))
        {
            sb.AppendLine($"Silent install command: {analysis.SilentInstallCommand}");
            sb.AppendLine($"Base silent arguments: {analysis.BaseSilentArguments ?? ""}");
            sb.AppendLine($"Additional package arguments: {analysis.AdditionalPackageArguments ?? ""}");
            sb.AppendLine($"Combined silent arguments: {analysis.CombinedSilentArguments ?? ""}");
            if (!string.IsNullOrWhiteSpace(analysis.SilentInstallStdOut)) sb.AppendLine($"Silent install stdout: {analysis.SilentInstallStdOut.Trim()}");
            if (!string.IsNullOrWhiteSpace(analysis.SilentInstallStdErr)) sb.AppendLine($"Silent install stderr: {analysis.SilentInstallStdErr.Trim()}");
            sb.AppendLine();
        }

        if (analysis.InstallerExitCode == 0 || analysis.InstallerExitCode == 3010)
            sb.AppendLine($"[PASS] Install exit code: {analysis.InstallerExitCode}" + (analysis.InstallerExitCode == 3010 ? " (success, reboot required)" : ""));
        else
            sb.AppendLine($"[FAIL] Installer returned exit code {analysis.InstallerExitCode}.");

        if (primary is null)
        {
            sb.AppendLine("[FAIL] No primary installed application could be identified.");
            sb.AppendLine("[FAIL] Detection script cannot be validated.");
            sb.AppendLine("[FAIL] Uninstall script cannot be validated.");
        }
        else
        {
            sb.AppendLine($"[PASS] Primary application identified: {primary.DisplayName ?? appName} {primary.DisplayVersion}".TrimEnd());
            sb.AppendLine("[PASS] Detection basis exists in the post-install uninstall registry snapshot.");
            if (!string.IsNullOrWhiteSpace(primary.DisplayVersion))
                sb.AppendLine($"[PASS] Installed version captured: {primary.DisplayVersion}");
            else
                sb.AppendLine("[WARN] Installed version was not exposed by the uninstall registry entry.");

            if (IsWindowsInstallerEntry(primary) && !string.IsNullOrWhiteSpace(primary.ProductCode))
                sb.AppendLine($"[PASS] Silent MSI uninstall can be generated from product code {primary.ProductCode}.");
            else if (!string.IsNullOrWhiteSpace(primary.QuietUninstallString))
                sb.AppendLine("[PASS] Vendor supplied a QuietUninstallString.");
            else if (!string.IsNullOrWhiteSpace(primary.UninstallString))
            {
                sb.AppendLine("[PASS] Registry uninstall command captured.");
                if (analysis.SilentUninstallValidated)
                    sb.AppendLine("[INFO] Registry does not provide a native quiet uninstall command; a separate silent uninstall method was successfully validated.");
                else
                    sb.AppendLine("[WARN] Registry does not provide a native quiet uninstall command. Review or validate silent switches before deployment.");
            }
            else
                sb.AppendLine("[FAIL] No uninstall command was discovered.");

            if (analysis.UninstallRecordingAttempted)
                sb.AppendLine(analysis.UninstallResponseFileCreated ? "[PASS] InstallShield uninstall response file recorded (uninstall.iss)." : "[FAIL] uninstall.iss response file was not created.");
            if (analysis.SilentReinstallExitCode.HasValue)
                sb.AppendLine(analysis.SilentReinstallValidated ? $"[PASS] Silent reinstall validated (exit code {analysis.SilentReinstallExitCode} + application detected)." : $"[FAIL] Silent reinstall was not validated (exit code {analysis.SilentReinstallExitCode}; application detection failed or was incomplete).");
            if (analysis.SilentUninstallExitCode.HasValue)
                sb.AppendLine(analysis.SilentUninstallExitCode is 0 or 1605 or 3010 ? $"[PASS] Silent uninstall exit code: {analysis.SilentUninstallExitCode}" : $"[FAIL] Silent uninstall exit code: {analysis.SilentUninstallExitCode}");
            if (analysis.PostUninstallDetected.HasValue)
                sb.AppendLine(analysis.PostUninstallDetected == false ? "[PASS] Application no longer detected after uninstall." : "[FAIL] Application is still detected after uninstall.");
            sb.AppendLine(analysis.SilentUninstallValidated ? $"[PASS] Silent uninstall validated using {analysis.UninstallValidationMethod ?? "validated method"}." : "[WARN] Silent uninstall was not fully validated.");
            if (!string.IsNullOrWhiteSpace(analysis.ValidationError)) sb.AppendLine($"[WARN] Validation detail: {analysis.ValidationError}");
        }

        sb.AppendLine();
        sb.AppendLine("SANDBOX ANALYSIS");
        sb.AppendLine("================");
        if (primary is not null)
        {
            sb.AppendLine($"Primary: {primary.DisplayName ?? "Unknown"}");
            sb.AppendLine($"Version: {primary.DisplayVersion ?? "Unknown"}");
            sb.AppendLine($"Publisher: {primary.Publisher ?? "Unknown"}");
            sb.AppendLine($"Install location: {primary.InstallLocation ?? "Unknown"}");
            sb.AppendLine($"Uninstall: {primary.UninstallString ?? "Not found"}");
            sb.AppendLine($"Quiet uninstall: {primary.QuietUninstallString ?? "Not found"}");
        }

        var deps = analysis.NewUninstallEntries.Where(e => !ReferenceEquals(e, primary) && !SameEntry(e, primary)).ToList();
        sb.AppendLine();
        sb.AppendLine($"Additional new uninstall entries / dependencies: {deps.Count}");
        foreach (var d in deps)
            sb.AppendLine($"  - {d.DisplayName ?? "Unknown"} {d.DisplayVersion}".TrimEnd());

        return sb.ToString().TrimEnd();
    }

    private static bool SameEntry(UninstallEntry a, UninstallEntry? b)
        => b is not null && !string.IsNullOrWhiteSpace(a.Key) && string.Equals(a.Key, b.Key, StringComparison.OrdinalIgnoreCase);

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
