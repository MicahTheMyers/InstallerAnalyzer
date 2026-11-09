namespace InstallerAnalyzer.Models;

public sealed class BootstrapperMainMsiEvidence
{
    public int ProcessId { get; set; }
    public string StartedAt { get; set; } = "";
    public string Deadline { get; set; } = "";
    public string Product { get; set; } = "";
}

public sealed class BootstrapperLogSnapshot
{
    public string Source { get; set; } = "";
    public string File { get; set; } = "";
    public bool Truncated { get; set; }
}
