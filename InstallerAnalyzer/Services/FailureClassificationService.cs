using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class FailureClassificationService
{
    public static FailureDetail Classify(string outcome, string reason, InstallAnalysis? proof, string hostStage)
    {
        if (outcome == "PASS") return new() { Category = FailureCategory.None, Explanation = "Complete lifecycle validated." };
        var stage = proof?.WorkflowStage ?? hostStage;
        var lower = reason.ToLowerInvariant();
        var removal = stage.Contains("uninstall", StringComparison.OrdinalIgnoreCase) ||
                      stage.Contains("removal", StringComparison.OrdinalIgnoreCase) || lower.Contains("uninstall") || proof?.SilentUninstallExitCode is not null;
        var visibleWindows = proof is null ? "" : string.Join("\n", proof.SilentReinstallVisibleWindows.Concat(proof.SilentUninstallVisibleWindows)
            .Concat(proof.SilentStrategyAttempts.Where(a => a.UiDetected).SelectMany(a => a.VisibleWindows)).Concat(proof.UiTextEvidence.SelectMany(w => w.Labels)));
        bool Matches(string text, string pattern) => System.Text.RegularExpressions.Regex.IsMatch(text, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        var rebootText = (lower + "\n" + visibleWindows).Split('\n').Any(line =>
            Matches(line, @"(?:reboot|restart) (?:is )?required|must (?:reboot|restart)") &&
            !Matches(line, @"no (?:reboot|restart)|not required|does not require"));
        FailureCategory category;
        string owner = "Installer";
        if (outcome == "STOPPED") { category = FailureCategory.Cancelled; owner = "User"; }
        else if (outcome == "NOT TESTED") { category = FailureCategory.NotTested; owner = "Unknown"; }
        else if (hostStage == "Static analysis") { category = FailureCategory.AnalyzerInfrastructureFailure; owner = "Analyzer"; }
        else if (proof?.SandboxCompatibility.Status == "Failed")
        { category = FailureCategory.SandboxStartupFailure; owner = "Sandbox"; }
        else if (AppControlEvidenceService.HasConfirmedBlock(proof))
        { category = FailureCategory.ApplicationControlBlocked; owner = "Environment"; }
        else if (proof?.NetFx3Provisioning.RestartNeeded == true)
        { category = FailureCategory.RebootRequired; owner = "Environment"; }
        else if (proof?.NetFx3Provisioning.RequiresFullWindowsVM == true || proof?.NetFx3Provisioning.Blocked == true)
        { category = FailureCategory.PrerequisiteMissing; owner = "Environment"; }
        else if (lower.Contains("sandbox environment") || hostStage == "Sandbox startup")
        { category = FailureCategory.SandboxStartupFailure; owner = "Sandbox"; }
        else if (lower.Contains("heartbeat") || lower.Contains("final analysis result"))
        { category = outcome == "TIMEOUT" ? FailureCategory.Timeout : FailureCategory.SandboxHandoffFailure; owner = "Sandbox"; }
        else if (outcome == "TIMEOUT" || lower.Contains("timed out") || lower.Contains("timeout"))
        { category = FailureCategory.Timeout; owner = "Unknown"; }
        else if (proof?.SilentUninstallUiDetected == true ||
                 lower.Contains("uninstall") && (System.Text.RegularExpressions.Regex.IsMatch(lower, @"\bui\b|interactive|window")))
            category = FailureCategory.UninstallerUiDetected;
        else if (Matches(lower + "\n" + visibleWindows, @"authentication required|sign[ -]?in (?:to|is required)|log[ -]?in (?:to|is required)|credentials required")) category = FailureCategory.AuthenticationRequired;
        else if (proof?.InstallerExitCode == 1641 || proof?.SilentReinstallExitCode == 1641 || proof?.SilentUninstallExitCode == 1641 ||
                 rebootText) category = FailureCategory.RebootRequired;
        else if (lower.StartsWith("prerequisite required") || lower.Contains("0xc0000135") ||
                 proof?.Intelligence.Prerequisites.Any(p => p.Status is "Missing" or "Required / missing evidence") == true) category = FailureCategory.PrerequisiteMissing;
        else if (lower.StartsWith("package configuration required") || lower.StartsWith("interaction or prerequisite required"))
            category = FailureCategory.UserInteractionRequired;
        else if (lower.StartsWith("no silent strategy") || lower.Contains("no candidate silent-install strategy passed")) category = FailureCategory.NoSilentStrategy;
        else if (proof?.SilentReinstallUiDetected == true) category = FailureCategory.InstallerUiDetected;
        else if (Matches(lower, @"(?:download|network download) (?:failed|failure)|(?:unable|failed) to download|could not download"))
            category = FailureCategory.NetworkDownloadFailure;
        else if (proof is not null && !proof.DiscoverySucceeded && proof.Components.Any(c => c.Kind == "Driver" && c.AfterInstall == true) &&
                 Matches(lower, @"no primary|not.*identified|unsupported driver"))
        { category = FailureCategory.UnsupportedDriverInstallation; owner = "Environment"; }
        else if (Matches(lower, @"payload (?:was )?(?:not found|discovery failed|could not be|missing)|no .*payload.*(?:found|discovered)")) category = FailureCategory.PayloadDiscoveryFailure;
        else if (Matches(lower, @"no primary application|without an identifiable installed application|no primary.*identified|application (?:identity )?(?:was )?not detected|detection (?:failed|failure)")) category = FailureCategory.DetectionFailure;
        else if (removal && (proof?.SilentUninstallExitCode ?? proof?.InitialUninstallExitCode) is int uninstallExit && uninstallExit is not (0 or 3010))
            category = FailureCategory.UninstallerExitCodeFailure;
        else if (!removal && proof is not null && (proof.SilentReinstallExitCode ?? proof.InstallerExitCode) is not (0 or 3010 or 1641))
            category = FailureCategory.InstallerExitCodeFailure;
        else if (proof?.PostUninstallDetected == true) category = FailureCategory.RemovalFailure;
        else if (proof?.RebootRequired == true) category = FailureCategory.RebootRequired;
        else category = FailureCategory.StrategyFailure;

        var explanation = category switch
        {
            FailureCategory.ApplicationControlBlocked => "Windows Application Control blocked execution by the source installer during this run. Other lifecycle failures may also be present.",
            FailureCategory.UninstallerUiDetected => "The uninstaller displayed a window during unattended validation.",
            FailureCategory.InstallerUiDetected => "The installer displayed a window during unattended validation.",
            FailureCategory.PrerequisiteMissing => proof?.NetFx3Provisioning.RequiresFullWindowsVM == true || proof?.NetFx3Provisioning.Blocked == true ? proof.NetFx3Provisioning.Detail : "Evidence indicates an unresolved prerequisite. Inspect the prerequisite evidence and provisioning result.",
            FailureCategory.RebootRequired => "A reboot is required. Validation after reboot has not been performed.",
            FailureCategory.SandboxStartupFailure => "Windows Sandbox could not start or ended unexpectedly.",
            FailureCategory.SandboxHandoffFailure => "Windows Sandbox did not return a complete analysis.",
            FailureCategory.AnalyzerInfrastructureFailure => "Installer Analyzer could not prepare the analysis.",
            FailureCategory.Timeout => "The operation exceeded its time or activity limit. Its cause may require investigation.",
            FailureCategory.Cancelled => "The run was stopped. An incomplete lifecycle is not a pass.",
            FailureCategory.NotTested => "This installer was queued but not tested.",
            FailureCategory.NoSilentStrategy => "No tested unattended strategy completed a validated lifecycle.",
            FailureCategory.AuthenticationRequired => "An authentication prompt blocked unattended validation.",
            FailureCategory.NetworkDownloadFailure => "Available evidence reports a failed installer download.",
            FailureCategory.PayloadDiscoveryFailure => "The required deployment payload could not be discovered.",
            FailureCategory.DetectionFailure => "Installation did not produce a reliable detected application identity.",
            FailureCategory.UnsupportedDriverInstallation => "Driver changes were observed, but this Sandbox analysis could not prove their complete deployment and removal lifecycle.",
            FailureCategory.InstallerExitCodeFailure => "The install command returned a failure exit code.",
            FailureCategory.UninstallerExitCodeFailure => "The removal command returned a failure exit code.",
            FailureCategory.RemovalFailure => "The application remained present after the uninstall command.",
            _ => "The lifecycle did not meet the validation requirements."
        };
        return new()
        {
            Category = category, Owner = owner, Explanation = proof?.SandboxCompatibility.Status == "Failed" ? proof.SandboxCompatibility.Detail : explanation, TechnicalReason = reason,
            Stage = stage, ExitCode = proof?.NetFx3Provisioning.RequiresFullWindowsVM == true || proof?.NetFx3Provisioning.Blocked == true ? proof.NetFx3Provisioning.ExitCode : removal ? proof?.SilentUninstallExitCode ?? proof?.InitialUninstallExitCode :
                proof?.SilentReinstallExitCode ?? proof?.InstallerExitCode,
            Candidate = proof?.SelectedSilentStrategy, Process = RelevantProcess(proof),
            NextInvestigation = proof?.SandboxCompatibility.Status == "Failed" ? "Inspect sandbox-compatibility.json and sandbox-compatibility-refresh.txt. Retry in a fresh Sandbox or turn off legacy installer compatibility in Settings." :
                category == FailureCategory.ApplicationControlBlocked ? "Inspect the blocked file and enforcing policy in app-control-evidence.json; check vendor-supported packages and administrator-reviewed policy decisions." :
                proof?.NetFx3Provisioning.Blocked == true ? "Inspect netfx3-install.txt, netfx3-source.json and netfx3-provisioning.json; verify access to the matching Microsoft feature source before retrying." :
                owner is "Sandbox" or "Analyzer" ? "Inspect Sandbox startup, heartbeat and host diagnostics before changing installer strategies." :
                category == FailureCategory.UninstallerUiDetected ? "Inspect uninstall strategy attempts and MSI custom actions." :
                category == FailureCategory.PrerequisiteMissing ? "Inspect installer UI and logs to identify the required runtime or Windows feature." :
                "Inspect strategy attempts and lifecycle evidence at the recorded workflow stage."
        };
    }

    private static string? RelevantProcess(InstallAnalysis? proof)
    {
        if (proof is null) return null;
        var window = (proof.SilentUninstallUiDetected ? proof.SilentUninstallVisibleWindows : proof.SilentReinstallVisibleWindows).FirstOrDefault();
        var match = System.Text.RegularExpressions.Regex.Match(window ?? "", @"^(\d+)\s*::");
        return match.Success && int.TryParse(match.Groups[1].Value, out var id)
            ? proof.ProcessTree.FirstOrDefault(p => p.ProcessId == id)?.Name : null;
    }

    public static string Explain(RegressionTestRecord? item)
    {
        if (item is null) return "Not tested in this run.";
        var f = item.Failure;
        var attempts = string.Join("\n", item.Attempts.Select((a, n) =>
            $"{n + 1}. {a.Name}: {a.Outcome}; exit {a.ExitCode?.ToString() ?? "unknown"}; UI {a.UiDetected}; detected {a.ApplicationDetected}\n{a.Source}\n{a.StartedAt ?? "unknown"} → {a.CompletedAt ?? "unknown"}\n{a.Command}"));
        var prerequisites = string.Join("\n", item.Intelligence.Prerequisites.Select(p => $"{p.Name}: {p.Status}\n{p.Source}: {p.Evidence}"));
        var detection = string.Join("\n", item.DetectionStrategies.OrderByDescending(d => d.Rank).Select(d =>
            $"{d.Type}: {d.Identity} • presence {d.BeforeInstall?.ToString() ?? "unknown"} / {d.AfterInstall?.ToString() ?? "unknown"} / {d.AfterUninstall?.ToString() ?? "unknown"} • validated {d.Validated}"));
        return $"{item.Installer}\nSHA-256: {item.InstallerSha256}\nProduct: {item.ProductName} • {item.Publisher}\n" +
            $"Result: {item.Result}\nInstall: {item.Install}; Uninstall: {item.Uninstall}; Removal: {item.Removal}\n" +
            $"Classification: {f.Category}\nOwner: {f.Owner}\nStage: {f.Stage}\n{f.Explanation}\n" +
            $"Evidence: {f.TechnicalReason}\nExit: {f.ExitCode?.ToString() ?? "unknown"}\nCandidate: {f.Candidate ?? "unknown"}\n" +
            $"Next investigation: {f.NextInvestigation}\nReboot required: {item.RebootRequired}; post-reboot validation not performed.\n\n" +
            $"Prerequisites:\n{(prerequisites.Length == 0 ? "No prerequisite established." : prerequisites)}\n\nDetection:\n{(detection.Length == 0 ? "No independent detection evidence recorded." : detection)}\n\n" +
            $"Strategy attempts:\n{(attempts.Length == 0 ? "No attempts recorded." : attempts)}";
    }
}
