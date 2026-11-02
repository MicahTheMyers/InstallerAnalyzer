namespace InstallerAnalyzer.Models;

public sealed class CatalogValidation
{
    public string ProofId { get; set; } = "";
    public string TimestampUtc { get; set; } = "";
    public string AnalyzerVersion { get; set; } = "";
    public string InstallerSha256 { get; set; } = "";
    public string Source { get; set; } = "Analyze";
    public string StrategyType { get; set; } = "";
    public string InstallArguments { get; set; } = "";
    public bool InstallPassed { get; set; }
    public bool DetectionPassed { get; set; }
    public bool UninstallPassed { get; set; }
    public bool RemovalPassed { get; set; }
    public double? DurationSeconds { get; set; }
    public int Confidence { get; set; }
}

public sealed class CatalogRecord
{
    public string Sha256 { get; set; } = "";
    public string Product { get; set; } = "";
    public string ProductFamily { get; set; } = "";
    public string Version { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string Architecture { get; set; } = "";
    public string Family { get; set; } = "Unknown";
    public string InstallArguments { get; set; } = "";
    public string DeploymentSource { get; set; } = "";
    public string DeploymentMechanism { get; set; } = "";
    public string ApplicationIdentity { get; set; } = "";
    public string LocalInstallerPath { get; set; } = "";
    public InstallerIdentity SigningIdentity { get; set; } = new();
    public DetectionStrategy? Detection { get; set; }
    public string UninstallType { get; set; } = "Unknown";
    public string UninstallIdentity { get; set; } = "";
    public string FirstValidatedUtc { get; set; } = "";
    public string LastValidatedUtc { get; set; } = "";
    public int Validations { get; set; }
    public int Failures { get; set; }
    public bool RebootRequired { get; set; }
    public bool PostRebootValidated { get; set; }
    public string Origin { get; set; } = "Local validated";
    public List<CatalogValidation> History { get; set; } = new();
    public string Display => $"{Product} • {Version} • {Family} • {Validations} local validations • {Origin}";
}

public sealed class CatalogTransfer
{
    public int SchemaVersion { get; set; } = 1;
    public DateTimeOffset ExportedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<CatalogRecord> Entries { get; set; } = new();
}
public sealed record CatalogImportResult(int Imported, int Preserved);
