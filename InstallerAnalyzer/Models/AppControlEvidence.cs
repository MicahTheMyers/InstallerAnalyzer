namespace InstallerAnalyzer.Models;

public sealed class AppControlEvidence
{
    public string Status { get; set; } = "Not captured";
    public string StartedAt { get; set; } = "";
    public string CapturedAt { get; set; } = "";
    public string Scope { get; set; } = "Direct source process only; child-process policy blocks are not inferred.";
    public List<AppControlBlock> Blocks { get; set; } = new();
}
public sealed class AppControlBlock
{
    public int EventId { get; set; }
    public string Provider { get; set; } = "";
    public string ObservedAt { get; set; } = "";
    public string ParentImage { get; set; } = "";
    public string BlockedFile { get; set; } = "";
    public string PolicyId { get; set; } = "";
    public string PolicyName { get; set; } = "";
    public string Correlation { get; set; } = "";
}
