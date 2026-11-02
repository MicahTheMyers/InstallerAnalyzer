namespace InstallerAnalyzer.Models;

public sealed class MsiPropertySnapshot
{
    public string Source { get; set; } = "msi-install.log";
    public string Scope { get; set; } = "Terminal server property dump; not launch-time state or an action-sequence simulation";
    public string Status { get; set; } = "Unavailable";
    public List<MsiPropertyObservation> Properties { get; set; } = new();
    public List<MsiConditionObservation> Conditions { get; set; } = new();
}

public sealed class MsiPropertyObservation
{
    public string Property { get; set; } = "";
    public bool? IsSet { get; set; }
    public string Evidence { get; set; } = "";
    // Raw values are used transiently for evaluation and are never serialized here.
}

public sealed class PrerequisiteServiceObservation
{
    public string Name { get; set; } = "";
    public string Property { get; set; } = "";
    public bool? Present { get; set; }
    public string State { get; set; } = "Unknown";
    public string ServiceType { get; set; } = "";
    public string Phase { get; set; } = "Before install";
    public string Evidence { get; set; } = "";
    public bool RequirementEstablished { get; set; }
}
