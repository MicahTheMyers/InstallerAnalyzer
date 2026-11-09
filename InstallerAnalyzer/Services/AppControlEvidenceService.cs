using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class AppControlEvidenceService
{
    public static bool HasConfirmedBlock(InstallAnalysis? proof) => HasConfirmedSourceBlock(proof) || HasConfirmedChildBlock(proof);

    private static bool HasConfirmedSourceBlock(InstallAnalysis? proof)
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

    private static bool HasConfirmedChildBlock(InstallAnalysis? proof)
    {
        if (string.IsNullOrWhiteSpace(proof?.Installer) || proof.Installer.IndexOfAny(['\\', '/']) >= 0) return false;
        var capture = proof.BootstrapperChildAppControl;
        if (capture?.Status is not ("Available" or "Partial") || capture.Blocks is null || proof?.BootstrapperObservedImages is null ||
            !DateTimeOffset.TryParse(capture.StartedAt, out var start) || !DateTimeOffset.TryParse(capture.CapturedAt, out var end) || end < start) return false;
        var images = proof.BootstrapperObservedImages.Take(32).Where(p => !string.IsNullOrWhiteSpace(p) && !string.Equals(p, @"C:\InstallerInput\" + proof.Installer, StringComparison.OrdinalIgnoreCase) && p.Length >= 4 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\' &&
            p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !p.Split('\\').Contains("..")).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return capture.Blocks.Take(64).Any(b => b.EventId == 3077 && b.Provider == "Microsoft-Windows-CodeIntegrity" &&
            b.Correlation == "Exact observed bootstrapper descendant image" && images.Contains(b.ParentImage) &&
            !string.IsNullOrWhiteSpace(b.BlockedFile) && b.BlockedFile.Length <= 1024 &&
            DateTimeOffset.TryParse(b.ObservedAt, out var at) && at >= start && at <= end);
    }
}
