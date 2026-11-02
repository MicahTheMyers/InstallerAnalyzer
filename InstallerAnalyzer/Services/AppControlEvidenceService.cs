using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class AppControlEvidenceService
{
    public static bool HasConfirmedBlock(InstallAnalysis? proof)
    {
        if (proof is null || proof.AppControl is null || proof.AppControl.Blocks is null || proof.AppControl.Status is not ("Available" or "Partial") ||
            string.IsNullOrWhiteSpace(proof.Installer) || proof.Installer.IndexOfAny(['\\', '/']) >= 0 ||
            !DateTimeOffset.TryParse(proof.AppControl.StartedAt, out var start) ||
            !DateTimeOffset.TryParse(proof.AppControl.CapturedAt, out var end) || end < start) return false;
        var parent = @"C:\InstallerInput\" + proof.Installer;
        return proof.AppControl.Blocks.Take(64).Any(b => b.EventId == 3077 &&
            b.Provider == "Microsoft-Windows-CodeIntegrity" && b.Correlation == "Exact source process image" &&
            string.Equals(b.ParentImage, parent, StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(b.BlockedFile) && b.BlockedFile.Length <= 1024 &&
            DateTimeOffset.TryParse(b.ObservedAt, out var at) && at >= start && at <= end);
    }
}
