using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed record DeploymentConfidenceResult(int Score, string Status, IReadOnlyList<string> Checks);

public static class DeploymentConfidenceService
{
    public static DeploymentConfidenceResult Calculate(
        AnalysisResult? result,
        InstallAnalysis? analysis,
        UninstallEntry? primaryApplication)
    {
        var score = 0;
        var checks = new List<string>();

        // A completely validated lifecycle is stronger evidence than static signature matching.
        // Give the technology/delivery-strategy points when either static identity is strong or
        // Sandbox proved both install and uninstall behavior.
        if ((result is not null && result.Kind != InstallerKind.Unknown && result.Confidence >= 70) ||
            LifecycleValidationService.IsComplete(analysis))
        {
            score += 15;
            checks.Add("✓ Installer/deployment strategy identified with strong confidence");
        }
        else checks.Add("○ Installer technology is not strongly identified");

        if (primaryApplication is not null)
        {
            score += 15;
            checks.Add("✓ Primary installed application identified");
        }
        else checks.Add("○ Primary installed application not identified");

        if (analysis?.DiscoverySucceeded == true)
        {
            score += 15;
            checks.Add("✓ Post-install application detection validated");
        }
        else checks.Add("○ Post-install detection not validated");

        if (LifecycleValidationService.InstallPassed(analysis))
        {
            score += 25;
            checks.Add("✓ Silent installation validated");
        }
        else checks.Add("○ Silent installation not validated");

        if (LifecycleValidationService.UninstallPassed(analysis))
        {
            score += 25;
            checks.Add("✓ Silent uninstall validated");
        }
        else checks.Add("○ Silent uninstall not validated");

        if (analysis?.PostUninstallDetected == false)
        {
            score += 5;
            checks.Add("✓ Post-uninstall absence verified");
        }
        else checks.Add("○ Post-uninstall absence not verified");

        score = Math.Clamp(score, 0, 100);
        if (score == 100 && !LifecycleValidationService.IsComplete(analysis))
        {
            score = 95;
            checks.Add("! Full lifecycle proof is incomplete or contains a validation failure");
        }
        var status = score switch
        {
            100 => "READY FOR IMMYBOT",
            >= 75 => "REVIEW RECOMMENDED",
            >= 50 => "PARTIALLY VALIDATED",
            _ => "VALIDATION REQUIRED"
        };
        return new(score, status, checks);
    }
}
