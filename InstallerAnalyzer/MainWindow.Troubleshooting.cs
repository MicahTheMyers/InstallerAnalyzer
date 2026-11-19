using System.IO;
using System.Text.Json;
using System.Windows;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;
using Microsoft.Win32;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private bool _exportingSandboxDiagnostics;

    private RegressionTestRecord CreateSandboxDiagnosticRecord()
    {
        var session = _issSession ?? throw new InvalidOperationException("Start a Sandbox analysis first.");
        var proof = _installAnalysis ?? _liveLifecycleProof;
        var running = _sandboxElapsed.IsRunning || _sandboxStarting;
        var outcome = running ? "RUNNING" : LifecycleValidationService.IsComplete(proof) ? "PASS" :
            SandboxRunStatus.Text.Contains("stopped", StringComparison.OrdinalIgnoreCase) ? "STOPPED" :
            SandboxRunStatus.Text.Contains("timed out", StringComparison.OrdinalIgnoreCase) ? "TIMEOUT" : "FAIL";
        var detail = string.IsNullOrWhiteSpace(proof?.ValidationError) ? SandboxRunDetails.Text : proof.ValidationError;
        return new()
        {
            Installer = _result?.Archive is { } archive ? Path.GetFileName(archive.Path) + " → " + archive.Entry : Path.GetFileName(_installerPath ?? "Installer"),
            InstallerSha256 = _result?.Archive?.Sha256 ?? _result?.Identity.Sha256 ?? "",
            ProductName = ProductBox.Text,
            Publisher = _result?.CompanyName ?? "",
            InstallerType = _result?.Kind.ToString() ?? "Unknown",
            ArtifactFolder = session.OutputFolder,
            Result = outcome,
            Install = proof is null ? "NOT TESTED" : LifecycleValidationService.InstallPassed(proof) ? "PASS" : "FAIL",
            Uninstall = proof is null ? "NOT TESTED" : LifecycleValidationService.UninstallPassed(proof) ? "PASS" : "FAIL",
            Removal = proof?.PostUninstallDetected is null ? "NOT TESTED" : proof.PostUninstallDetected == false ? "PASS" : "FAIL",
            DurationSeconds = _sandboxElapsed.Elapsed.TotalSeconds,
            RebootRequired = proof?.RebootRequired == true,
            Attempts = proof?.SilentStrategyAttempts ?? new(),
            Failure = running ? new() { Category = FailureCategory.NotTested, Explanation = "Analysis is running. This bundle captures its current state.", TechnicalReason = detail, Stage = _liveWorkflowStage ?? "" }
                : FailureClassificationService.Classify(outcome, detail, proof, _liveWorkflowStage ?? "Sandbox analysis")
        };
    }

    private string CreateSandboxDiagnosticContext() => JsonSerializer.Serialize(new
    {
        ApplicationVersion = UpdateService.CurrentDisplayVersion,
        CapturedAt = DateTimeOffset.UtcNow,
        Status = SandboxRunStatus.Text,
        Detail = SandboxRunDetails.Text,
        WorkflowStage = _liveWorkflowStage,
        SandboxScript = new { CustomScript = _issSession?.UsesCustomScript, Sha256 = _issSession?.ScriptSha256 },
        InstallerOptions = new
        {
            BaseArguments = AiDiagnosticContext.Redact(ArgumentsBox.Text),
            AdditionalArguments = AiDiagnosticContext.Redact(AdditionalArgumentsBox.Text),
            ResponseFileMode = IssCheck.IsChecked == true
        },
        Settings = new
        {
            DisplayMode = UseIntegratedViewer ? "Integrated" : "Separate",
            PrepareNetFx3 = PrepareNetFx3Check.IsChecked == true,
            LegacyCompatibility = SandboxCompatibilityCheck.IsChecked == true,
            BlockBundledMcAfee = BlockBundledMcAfeeToggle.IsChecked == true,
            AutoCloseSandbox = AutoCloseSandboxToggle.IsChecked == true,
            CurrentTimeouts = ReadTimeoutSettings(),
            RunTimeouts = _issSession?.Timeouts
        }
    }, new JsonSerializerOptions { WriteIndented = true });

    private async void ExportSandboxDiagnostics_Click(object sender, RoutedEventArgs e)
    {
        if (_issSession is null || _exportingSandboxDiagnostics) return;
        var dialog = new SaveFileDialog
        {
            Filter = "Troubleshooting ZIP (*.zip)|*.zip",
            FileName = "InstallerAnalyzer-troubleshooting-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".zip"
        };
        if (dialog.ShowDialog(this) != true) return;
        _exportingSandboxDiagnostics = true;
        try
        {
            var record = CreateSandboxDiagnosticRecord();
            var context = CreateSandboxDiagnosticContext();
            StatusText.Text = "Exporting troubleshooting ZIP…";
            var result = await Task.Run(() => DiagnosticBundleService.Export(dialog.FileName, new[] { record }, contextJson: context));
            StatusText.Text = $"Troubleshooting ZIP saved. {result.Included} files included; {result.Omitted} unavailable or over size limits.";
        }
        catch (Exception ex) { StatusText.Text = "Troubleshooting export failed. " + ex.Message; }
        finally { _exportingSandboxDiagnostics = false; }
    }
}
