namespace InstallerAnalyzer.Models;

public sealed class MsiMetadata
{
    public string Status { get; set; } = "Not read";
    public string ProductName { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string ProductVersion { get; set; } = "";
    public string ProductCode { get; set; } = "";
    public string UpgradeCode { get; set; } = "";
    public string Platform { get; set; } = "";
    public List<MsiLaunchCondition> LaunchConditions { get; set; } = new();
    public List<string> HiddenProperties { get; set; } = new();
    public bool HiddenPropertiesTruncated { get; set; }
    public List<MsiRegistryProbe> RegistryProbes { get; set; } = new();
    public List<MsiDirectoryLocator> DirectoryLocators { get; set; } = new();
    public List<MsiFileSearchDefinition> FileSearches { get; set; } = new();
    public List<MsiApplicationRegistryDefinition> ApplicationRegistry { get; set; } = new();
    public List<string> Limitations { get; set; } = new();
}
public sealed class MsiDirectoryLocator
{
    public string Signature { get; set; } = "";
    public string Parent { get; set; } = "";
    public string Path { get; set; } = "";
    public int Depth { get; set; }
}
public sealed class MsiFileSearchDefinition
{
    public string Property { get; set; } = "";
    public string Signature { get; set; } = "";
    public string ConditionDescription { get; set; } = "";
    public MsiFileSignature? File { get; set; }
}
public sealed class MsiFileSignature
{
    public string FileName { get; set; } = "";
    public string MinVersion { get; set; } = "";
    public string MaxVersion { get; set; } = "";
    public string MinSize { get; set; } = "";
    public string MaxSize { get; set; } = "";
    public string MinDate { get; set; } = "";
    public string MaxDate { get; set; } = "";
    public string Languages { get; set; } = "";
}
public sealed class PrerequisiteFileObservation
{
    public string Property { get; set; } = "";
    public string Signature { get; set; } = "";
    public string Target { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Phase { get; set; } = "Before install";
    public string Version { get; set; } = "";
    public long? SizeBytes { get; set; }
    public bool? Present { get; set; }
    public bool? SignatureMatched { get; set; }
    public string ConditionDescription { get; set; } = "";
    public string Evidence { get; set; } = "";
}
public sealed class MsiApplicationRegistryDefinition
{
    public string Id { get; set; } = "";
    public int Root { get; set; }
    public string Key { get; set; } = "";
    public string Name { get; set; } = "";
    public string RegistryView { get; set; } = "Registry32";
}
public sealed class MsiLaunchCondition
{
    public string Condition { get; set; } = "";
    public string Description { get; set; } = "";
}
public sealed class MsiRegistryProbe
{
    public string Property { get; set; } = "";
    public string Signature { get; set; } = "";
    public int Root { get; set; }
    public string Key { get; set; } = "";
    public string Name { get; set; } = "";
    public int Type { get; set; }
    public bool DefaultConfigured { get; set; }
    public string ConditionDescription { get; set; } = "";
}
public sealed class PrerequisiteProbeObservation
{
    public string Property { get; set; } = "";
    public string Target { get; set; } = "";
    public string RegistryView { get; set; } = "";
    public bool? ValuePresent { get; set; }
    public string Evidence { get; set; } = "";
    public string ConditionDescription { get; set; } = "";
}
