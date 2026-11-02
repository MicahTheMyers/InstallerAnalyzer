namespace InstallerAnalyzer.Models;
public sealed class NetFx3Provisioning
{
    public string Status { get; set; } = "Not required";
    public string Evidence { get; set; } = "";
    public string Detail { get; set; } = "";
    public bool Attempted { get; set; }
    public bool Provisioned { get; set; }
    public bool RuntimeVerified { get; set; }
    public bool RequiresFullWindowsVM { get; set; }
    public bool RestartNeeded { get; set; }
    public bool Blocked { get; set; }
    public int? ExitCode { get; set; }
    public bool GuestUpdateSourceAdjusted { get; set; }
    public int RestoredComponentCount { get; set; }
}
