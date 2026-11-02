namespace InstallerAnalyzer.Models;
public sealed class PeDependencies
{
    public string Status { get; set; } = "Not a PE image";
    public string Architecture { get; set; } = "Unknown";
    public List<PeImport> Imports { get; set; } = new();
    public List<string> Limitations { get; set; } = new();
}
public sealed class PeImport
{
    public string Module { get; set; } = "";
    public string Kind { get; set; } = "Direct";
    public bool ApiSetContract { get; set; }
}
public sealed class DllFileObservation
{
    public string Module { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Architecture { get; set; } = "";
    public string Location { get; set; } = "";
    public string Path { get; set; } = "";
    public bool? Present { get; set; }
    public string Version { get; set; } = "";
    public string Evidence { get; set; } = "";
}
