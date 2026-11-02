using System.Text.Json.Serialization;

namespace InstallerAnalyzer.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum InstalledProductRole { PrimaryApplication, Prerequisite, LegitimateDependency, OptionalBundledSoftware, PotentiallyUnwantedBundledSoftware, UnknownSecondaryProduct }

public sealed class BundledProductAssessment
{
    public string Identity { get; set; } = "";
    public string Name { get; set; } = "";
    public InstalledProductRole Role { get; set; } = InstalledProductRole.UnknownSecondaryProduct;
    public string EvidenceStrength { get; set; } = "Unknown";
    public List<string> Reasons { get; set; } = new();
    public string DisplayRole => Role switch
    {
        InstalledProductRole.PrimaryApplication => "Primary application",
        InstalledProductRole.Prerequisite => "Prerequisite candidate",
        InstalledProductRole.LegitimateDependency => "Declared dependency candidate",
        InstalledProductRole.OptionalBundledSoftware => "Optional bundled software",
        InstalledProductRole.PotentiallyUnwantedBundledSoftware => "Potentially unwanted bundled software",
        _ => "Unknown secondary product"
    };
}
