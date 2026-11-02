using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class LifecycleValidationService
{
    public static bool InstallPassed(InstallAnalysis? proof) => proof is not null &&
        proof.SilentReinstallValidated && proof.SilentReinstallExitCode is 0 or 3010 && !proof.SilentReinstallUiDetected &&
        (proof.ValidationSchemaVersion < 2 || (proof.InitialInstallValidated && proof.CleanBaselineVerified && proof.InitialUninstallValidated && proof.InitialUninstallExitCode is 0 or 3010));

    public static bool UninstallPassed(InstallAnalysis? proof) => UninstallEvidence(proof) && proof!.SilentUninstallValidated;

    private static bool UninstallEvidence(InstallAnalysis? proof) => proof is not null &&
        proof.SilentUninstallExitCode is 0 or 3010 && !proof.SilentUninstallUiDetected && proof.PostUninstallDetected == false;

    private static bool IdentityPassed(InstallAnalysis proof) => proof.DiscoverySucceeded &&
        !string.IsNullOrWhiteSpace(proof.PrimaryKey) && proof.NewUninstallEntries.Any(e =>
            string.Equals(e.Key, proof.PrimaryKey, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(e.DisplayName));

    public static bool IsComplete(InstallAnalysis? proof) => InstallPassed(proof) && UninstallPassed(proof) &&
        (proof!.ValidationSchemaVersion < 3 || proof.EvidenceCollectionComplete) &&
        IdentityPassed(proof!) && string.IsNullOrWhiteSpace(proof!.ValidationError) &&
        DateTimeOffset.TryParse(proof.CapturedAt, out _);

    public static bool CanPromoteCheckpoint(InstallAnalysis? proof) => proof is not null &&
        proof.ValidationSchemaVersion >= 2 && proof.InitialUninstallValidated && proof.CleanBaselineVerified &&
        (proof.ValidationSchemaVersion < 3 || proof.EvidenceCollectionComplete) &&
        InstallPassed(proof) && UninstallEvidence(proof) && IdentityPassed(proof) &&
        string.IsNullOrWhiteSpace(proof.ValidationError) &&
        proof.WorkflowStage?.StartsWith("Final absence verification", StringComparison.Ordinal) == true &&
        DateTimeOffset.TryParse(proof.CapturedAt, out _);
}
