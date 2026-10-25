namespace InstallerAnalyzer.Models;
public sealed class InstallAnalysis
{
    public string? Installer { get; set; }
    public int InstallerExitCode { get; set; }
    public string? CapturedAt { get; set; }
    public List<UninstallEntry> NewUninstallEntries { get; set; } = new();
    public string? PrimaryKey { get; set; }
    public string? UninstallValidationMethod { get; set; }
    public bool UninstallRecordingAttempted { get; set; }
    public bool UninstallResponseFileCreated { get; set; }
    public int? RecordedUninstallExitCode { get; set; }
    public string? BaseSilentArguments { get; set; }
    public string? AdditionalPackageArguments { get; set; }
    public string? CombinedSilentArguments { get; set; }
    public string? SilentInstallCommand { get; set; }
    public string? SilentInstallStdOut { get; set; }
    public string? SilentInstallStdErr { get; set; }
    public int? SilentReinstallExitCode { get; set; }
    public bool SilentReinstallValidated { get; set; }
    public bool DiscoverySucceeded { get; set; }
    public string? DiscoveryMethod { get; set; }
    public string? UninstallCandidate { get; set; }
    public int? SilentUninstallExitCode { get; set; }
    public bool? PostUninstallDetected { get; set; }
    public bool SilentUninstallValidated { get; set; }
    public string? ValidationError { get; set; }
}
public sealed class UninstallEntry
{
    public string? Key { get; set; }
    public string? DisplayName { get; set; }
    public string? DisplayVersion { get; set; }
    public string? Publisher { get; set; }
    public string? InstallLocation { get; set; }
    public string? UninstallString { get; set; }
    public string? QuietUninstallString { get; set; }
    public object? WindowsInstaller { get; set; }
    public string? ProductCode { get; set; }
}
