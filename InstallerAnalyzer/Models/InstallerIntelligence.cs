namespace InstallerAnalyzer.Models;

public sealed class InstallerIdentity
{
    public string Sha256 { get; set; } = "";
    public string SignatureStatus { get; set; } = "Not checked";
    public string SignerThumbprint { get; set; } = "";
    public string SignerSubject { get; set; } = "";
    public MsiMetadata Msi { get; set; } = new();
    public PeDependencies Pe { get; set; } = new();
    public bool SignatureValid => SignatureStatus == "Valid";
}

public sealed class DetectionStrategy
{
    public string RegistryPath { get; set; } = "";
    public string ValueName { get; set; } = "";
    public string ExecutablePath { get; set; } = "";
    public string Provider { get; set; } = "";
    public string RegistryHive { get; set; } = "";
    public string RegistrySubKey { get; set; } = "";
    public string RegistryView { get; set; } = "";
    public string Type { get; set; } = "";
    public string Identity { get; set; } = "";
    public string? Version { get; set; }
    public int Rank { get; set; }
    public bool? BeforeInstall { get; set; }
    public bool? AfterInstall { get; set; }
    public bool? AfterUninstall { get; set; }
    public bool Validated => BeforeInstall == false && AfterInstall == true && AfterUninstall == false;
}

public sealed class PrerequisiteEvidence
{
    public string Name { get; set; } = "";
    public string Status { get; set; } = "Unknown";
    public string Evidence { get; set; } = "";
    public string Source { get; set; } = "";
    public string? Capability { get; set; }
    public bool Provisioned { get; set; }
}

public sealed class RuntimeEnvironmentObservation
{
    public string Name { get; set; } = "";
    public string State { get; set; } = "Unknown";
    public string Version { get; set; } = "";
    public string Architecture { get; set; } = "";
    public string Source { get; set; } = "";
    public string Phase { get; set; } = "";
    public string MeasuredAt { get; set; } = "";
    public bool RequirementEstablished { get; set; }
}

public sealed class ComponentEvidence
{
    public string Kind { get; set; } = "";
    public string Name { get; set; } = "";
    public string? DisplayName { get; set; }
    public string? Path { get; set; }
    public string? StartupType { get; set; }
    public bool? BeforeInstall { get; set; }
    public bool? AfterInstall { get; set; }
    public bool? AfterUninstall { get; set; }
}

public sealed class ProcessEvidence
{
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public string? CommandLine { get; set; }
    public string? CreatedAt { get; set; }
}
public sealed class InstallerUiTextEvidence
{
    public int ProcessId { get; set; }
    public string Process { get; set; } = "";
    public string WindowTitle { get; set; } = "";
    public string Phase { get; set; } = "";
    public List<string> Labels { get; set; } = new();
}

public sealed class NetworkEvidence
{
    public int ProcessId { get; set; }
    public string? ProcessCreatedAt { get; set; }
    public string? ObservedAt { get; set; }
    public string Process { get; set; } = "";
    public string Evidence { get; set; } = "";
    // A connection is not proof of a download or an Internet requirement.
    public string Attribution { get; set; } = "Installer process tree";
}

public sealed class PayloadEvidence
{
    public List<BitsDownloadEvidence> Downloads { get; set; } = new();
    public List<PayloadFileActivity> Writes { get; set; } = new();
    public List<int> NetworkActiveWriterProcessIds { get; set; } = new();
    public string Path { get; set; } = "";
    public string Type { get; set; } = "";
    public string Role { get; set; } = "Unknown";
    public string Evidence { get; set; } = "";
    public int? ProcessId { get; set; }
    public bool? Executed { get; set; }
    public int? DownloadReferenceProcessId { get; set; }
    public string? DownloadEvidence { get; set; }
}

public sealed class RelationshipNode
{
    public string Id { get; set; } = "";
    public string Role { get; set; } = "";
    public string Label { get; set; } = "";
    public string Evidence { get; set; } = "";
}
public sealed class RelationshipEdge
{
    public string From { get; set; } = "";
    public string To { get; set; } = "";
    public string Relationship { get; set; } = "";
}
public sealed class InstallerIntelligence
{
    public int SchemaVersion { get; set; } = 1;
    public List<PrerequisiteEvidence> Prerequisites { get; set; } = new();
    public List<PayloadEvidence> Payloads { get; set; } = new();
    public List<RelationshipNode> Nodes { get; set; } = new();
    public List<RelationshipEdge> Edges { get; set; } = new();
    public List<string> Limitations { get; set; } = new();
    public List<BundledProductAssessment> InstalledProducts { get; set; } = new();
}
