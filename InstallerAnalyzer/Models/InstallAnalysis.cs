namespace InstallerAnalyzer.Models;
public sealed class InstallAnalysis
{
    public NetFx3Provisioning NetFx3Provisioning { get; set; } = new();
    public AppControlEvidence AppControl { get; set; } = new();
    public bool PayloadScanIncomplete { get; set; }
    public PayloadTraceCapture PayloadTrace { get; set; } = new();
    public List<DetectionStrategy> DetectionStrategies { get; set; } = new();
    public List<ComponentEvidence> Components { get; set; } = new();
    public List<ProcessEvidence> ProcessTree { get; set; } = new();
    public List<NetworkEvidence> NetworkActivity { get; set; } = new();
    public List<string> NewRebootIndicators { get; set; } = new();
    public List<PrerequisiteProbeObservation> PrerequisiteProbes { get; set; } = new();
    public List<PrerequisiteFileObservation> PrerequisiteFiles { get; set; } = new();
    public List<DllFileObservation> DllFiles { get; set; } = new();
    public int? MsiProductStateBefore { get; set; }
    public List<MsiConditionObservation> MsiConditions { get; set; } = new();
    public List<MsiPropertySnapshot> MsiPropertySnapshots { get; set; } = new();
    public List<PrerequisiteServiceObservation> PrerequisiteServices { get; set; } = new();
    public List<RuntimeEnvironmentObservation> RuntimeEnvironment { get; set; } = new();
    public List<InstallerUiTextEvidence> UiTextEvidence { get; set; } = new();
    public bool PostRebootValidated { get; set; }
    public InstallerIntelligence Intelligence { get; set; } = new();
    public string? HostTermination { get; set; }
    public int ValidationSchemaVersion { get; set; }
    public bool EvidenceCollectionComplete { get; set; }
    public bool InitialInstallValidated { get; set; }
    public bool InitialUninstallValidated { get; set; }
    public int? InitialUninstallExitCode { get; set; }
    public bool CleanBaselineVerified { get; set; }
    public bool RebootRequired { get; set; }
    public List<MsiRemovalUiAction> MsiRemovalUiActions { get; set; } = new();
    public string? SessionId { get; set; }
    public string? InstallerSha256 { get; set; }
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
    public bool SilentReinstallUiDetected { get; set; }
    public List<string> SilentReinstallVisibleWindows { get; set; } = new();
    public bool DiscoverySucceeded { get; set; }
    public string? DiscoveryMethod { get; set; }
    public string? DeploymentMechanism { get; set; }
    public string? DeploymentSource { get; set; }
    public string? IdentitySource { get; set; }
    public string? UninstallCandidate { get; set; }
    public int? SilentUninstallExitCode { get; set; }
    public int? SilentUninstallRawExitCode { get; set; }
    public bool? PostUninstallDetected { get; set; }
    public bool SilentUninstallValidated { get; set; }
    public bool SilentUninstallUiDetected { get; set; }
    public List<string> SilentUninstallVisibleWindows { get; set; } = new();
    public List<SilentStrategyCandidate> SilentStrategyCandidates { get; set; } = new();
    public List<SilentStrategyAttempt> SilentStrategyAttempts { get; set; } = new();
    public string? SelectedSilentStrategy { get; set; }
    public string? ValidationError { get; set; }
    public List<string> BootstrapperProcesses { get; set; } = new();
    public List<string> DiscoveredInstallerFiles { get; set; } = new();
    public string? WorkflowStage { get; set; }
    public string? WorkflowStageUpdatedAt { get; set; }
    public List<WorkflowStageEvent> WorkflowStageHistory { get; set; } = new();
}
public sealed class MsiRemovalUiAction
{
    public string? Action { get; set; }
    public string? Condition { get; set; }
}
public sealed class WorkflowStageEvent
{
    public string? Stage { get; set; }
    public string? At { get; set; }
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

public sealed class SilentStrategyCandidate
{
    public string? Name { get; set; }
    public int Score { get; set; }
    public string? File { get; set; }
    public string? Arguments { get; set; }
    public string? Reason { get; set; }
}
public sealed class SilentStrategyAttempt
{
    public string? Source { get; set; }
    public string? StartedAt { get; set; }
    public string? CompletedAt { get; set; }
    public string? Name { get; set; }
    public int Score { get; set; }
    public string? Command { get; set; }
    public string? Outcome { get; set; }
    public int? ExitCode { get; set; }
    public bool UiDetected { get; set; }
    public List<string> VisibleWindows { get; set; } = new();
    public bool ApplicationDetected { get; set; }
}
