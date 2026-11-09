namespace InstallerAnalyzer.Models;

public sealed class SandboxCompatibilityEvidence
{
    public bool Requested { get; set; }
    public string Status { get; set; } = "Not requested";
    public int? BeforeState { get; set; }
    public int? AfterState { get; set; }
    public int? RefreshExitCode { get; set; }
    public bool Prepared { get; set; }
    public string Detail { get; set; } = "";
}
