using System.Text.Json.Serialization;

namespace InstallerAnalyzer.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FailureCategory
{
    None, StrategyFailure, NoSilentStrategy, PrerequisiteMissing, UserInteractionRequired,
    InstallerUiDetected, UninstallerUiDetected, RebootRequired, NetworkDownloadFailure,
    InstallerExitCodeFailure, UninstallerExitCodeFailure, DetectionFailure, RemovalFailure,
    PayloadDiscoveryFailure, SandboxStartupFailure, SandboxHandoffFailure,
    AnalyzerInfrastructureFailure, AuthenticationRequired, UnsupportedDriverInstallation, Timeout,
    Cancelled, NotTested, ApplicationControlBlocked
}

public sealed class FailureDetail
{
    public FailureCategory Category { get; set; }
    public string Owner { get; set; } = "";
    public string Explanation { get; set; } = "";
    public string TechnicalReason { get; set; } = "";
    public string Stage { get; set; } = "";
    public string? Process { get; set; }
    public int? ExitCode { get; set; }
    public string? Candidate { get; set; }
    public string NextInvestigation { get; set; } = "";
    public bool Infrastructure => Owner is "Sandbox" or "Analyzer" || Category is FailureCategory.UnsupportedDriverInstallation or FailureCategory.ApplicationControlBlocked && Owner == "Environment";
}

public sealed class RegressionTestRecord
{
    public string Installer { get; set; } = "";
    public string InstallerPath { get; set; } = "";
    public string InstallerSha256 { get; set; } = "";
    public string ProductName { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string InstallerType { get; set; } = "Unknown";
    public string Result { get; set; } = "NOT TESTED";
    public string Install { get; set; } = "NOT TESTED";
    public string Uninstall { get; set; } = "NOT TESTED";
    public string Removal { get; set; } = "NOT TESTED";
    public string ArtifactFolder { get; set; } = "";
    public double DurationSeconds { get; set; }
    public bool RebootRequired { get; set; }
    public InstallerIntelligence Intelligence { get; set; } = new();
    public List<DetectionStrategy> DetectionStrategies { get; set; } = new();
    public FailureDetail Failure { get; set; } = new() { Category = FailureCategory.NotTested };
    public List<SilentStrategyAttempt> Attempts { get; set; } = new();
    public bool Passed => Result == "PASS";
    public bool Tested => Result is "PASS" or "FAIL" or "TIMEOUT";
}

public sealed class RegressionRun
{
    public string Provenance { get; set; } = "Recorded by Installer Analyzer";
    public int SchemaVersion { get; set; } = 1;
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Version { get; set; } = "";
    public string Mode { get; set; } = "";
    public bool SandboxInstallerCompatibility { get; set; }
    public DateTimeOffset Started { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset? Completed { get; set; }
    public bool Stopped { get; set; }
    public string ArtifactFolder { get; set; } = "";
    public List<RegressionTestRecord> Tests { get; set; } = new();
    public string Display => $"{Started:yyyy-MM-dd HH:mm:ss} • v{Version} • {Mode} • {Tests.Count(t => t.Passed)}/{Tests.Count(t => t.Tested)} pass" +
        (Completed is null ? " • incomplete" : Stopped ? " • stopped" : "") +
        (Provenance.StartsWith("Legacy", StringComparison.Ordinal) ? " • legacy summary" : "");
}

public sealed class RegressionComparison
{
    public string Classification { get; init; } = "";
    public RegressionTestRecord? Previous { get; init; }
    public RegressionTestRecord? Current { get; init; }
    public string Note { get; init; } = "";
    public string Display => $"{Classification} • {(Current ?? Previous)?.Installer} • {Previous?.Result ?? "—"} → {Current?.Result ?? "NOT TESTED"}" +
        (string.IsNullOrEmpty(Note) ? "" : $" • {Note}");
}
