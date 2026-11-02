using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class BundledProductClassificationService
{
    public static List<BundledProductAssessment> Classify(AnalysisResult? source, InstallAnalysis proof)
    {
        var declared = source?.Identity.Msi.LaunchConditions ?? new();
        var windows = proof.SilentReinstallVisibleWindows.Concat(proof.SilentUninstallVisibleWindows)
            .Concat(proof.SilentStrategyAttempts.SelectMany(a => a.VisibleWindows)).Concat(proof.UiTextEvidence.SelectMany(w => w.Labels)).ToArray();
        var assessments = new List<BundledProductAssessment>();
        foreach (var entry in proof.NewUninstallEntries)
        {
            var assessment = new BundledProductAssessment { Identity = entry.Key ?? "", Name = entry.DisplayName ?? "Unknown product" };
            if (!string.IsNullOrWhiteSpace(proof.PrimaryKey) && entry.Key == proof.PrimaryKey)
            {
                assessment.Role = InstalledProductRole.PrimaryApplication; assessment.EvidenceStrength = "Observed identity";
                assessment.Reasons.Add("This identity was selected as the primary application during analysis.");
            }
            else if (assessment.Name.Contains("McAfee", StringComparison.OrdinalIgnoreCase) &&
                !(source?.ProductName.Contains("McAfee", StringComparison.OrdinalIgnoreCase) ?? false) &&
                !(source?.FileName.Contains("McAfee", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                assessment.Role = InstalledProductRole.PotentiallyUnwantedBundledSoftware; assessment.EvidenceStrength = "Existing protection policy";
                assessment.Reasons.Add("McAfee is a secondary product rather than the selected primary installer. Existing McAfee bundle prevention remains applicable.");
            }
            else
            {
                var product = Normalize(assessment.Name);
                var offer = product.Length >= 6 ? windows.FirstOrDefault(w => Normalize(w).Contains(product, StringComparison.Ordinal) &&
                    Regex.IsMatch(w, @"(?i)optional|additional software|also install|bundled offer") && !Regex.IsMatch(w, @"(?i)not optional|mandatory")) : null;
                var requirement = product.Length >= 8 ? declared.FirstOrDefault(c => Normalize(c.Description).Contains(product, StringComparison.Ordinal) &&
                    Regex.IsMatch(c.Description, @"(?i)requires?|required|dependency|must.*install") && !Regex.IsMatch(c.Description, @"(?i)not required|does not require|not needed")) : null;
                if (offer is not null)
                {
                    assessment.Role = InstalledProductRole.OptionalBundledSoftware; assessment.EvidenceStrength = "Explicit installer-window text";
                    assessment.Reasons.Add(AiDiagnosticContext.Redact(offer[..Math.Min(offer.Length, 600)]));
                }
                else if (Regex.IsMatch(assessment.Name, @"(?i)Microsoft Visual C\+\+|\.NET (?:Framework|Runtime|Desktop)|WebView2 Runtime|Java (?:Runtime|Development)|DirectX"))
                {
                    assessment.Role = InstalledProductRole.Prerequisite; assessment.EvidenceStrength = requirement is null ? "Runtime name; requirement unverified" : "Declared conditional requirement";
                    assessment.Reasons.Add(requirement is null ? "The product resembles a runtime. Its necessity for the primary application has not been established." : AiDiagnosticContext.Redact(requirement.Description));
                }
                else if (requirement is not null)
                {
                    assessment.Role = InstalledProductRole.LegitimateDependency; assessment.EvidenceStrength = "Declared conditional requirement";
                    assessment.Reasons.Add("The installer declares a relationship; necessity in every deployment configuration is not established.");
                    assessment.Reasons.Add(AiDiagnosticContext.Redact(requirement.Description[..Math.Min(requirement.Description.Length, 600)]));
                }
                else assessment.Reasons.Add("No reliable declared dependency or explicit optional-offer relationship was found. Matching publishers alone do not establish a dependency.");
            }
            assessments.Add(assessment);
        }
        return assessments;
    }
    private static string Normalize(string text) => Regex.Replace(text, "[^A-Za-z0-9]", "").ToLowerInvariant();
}
