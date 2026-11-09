namespace InstallerAnalyzer.Models;

public sealed class ComponentDeploymentPlan
{
    public string Recipe { get; set; } = "";
    public string SourceSha256 { get; set; } = "";
    public Dictionary<string, string> Files { get; set; } = new();
}
