using System.IO;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class AppControlChecks
{
    public static void Run(string root, Action<bool, string> check)
    {
        var proof = new InstallAnalysis { Installer = "setup.exe", InstallerExitCode = 1, AppControl = new()
        {
            Status = "Available", StartedAt = "2026-10-29T12:00:00Z", CapturedAt = "2026-10-29T12:02:00Z",
            Blocks = [new() { EventId = 3077, Provider = "Microsoft-Windows-CodeIntegrity", ObservedAt = "2026-10-29T12:01:00Z",
                ParentImage = @"C:\InstallerInput\setup.exe", BlockedFile = @"C:\Temp\setup.tmp", PolicyId = Guid.NewGuid().ToString(), Correlation = "Exact source process image" }]
        } };
        check(AppControlEvidenceService.HasConfirmedBlock(proof), "App Control evidence requires a scoped enforced block for the exact source image");
        var failure = FailureClassificationService.Classify("FAIL", "No primary application identified", proof, "Sandbox lifecycle");
        check(failure.Category == FailureCategory.ApplicationControlBlocked && failure.Infrastructure && failure.Owner == "Environment",
            "Policy blocks are explained as environment failures before generic detection failure");
        check(failure.NextInvestigation.Contains("app-control-evidence.json"), "Policy failure points to the retained policy evidence");
        check(FailureClassificationService.Classify("STOPPED", "Stopped", proof, "Sandbox lifecycle").Category == FailureCategory.Cancelled,
            "Cancellation retains precedence over earlier policy events");
        check(FailureClassificationService.Classify("PASS", "", proof, "Sandbox lifecycle").Category == FailureCategory.None,
            "A completed lifecycle is not relabelled by an earlier rejected policy-blocked attempt");
        void Reject(Action<InstallAnalysis> change, string name)
        {
            var copy = JsonSerializer.Deserialize<InstallAnalysis>(JsonSerializer.Serialize(proof))!; change(copy);
            check(!AppControlEvidenceService.HasConfirmedBlock(copy), name);
        }
        Reject(p => p.AppControl.Blocks[0].EventId = 3076, "Audit-only policy events cannot establish an enforced block");
        Reject(p => p.AppControl.Blocks[0].Provider = "Unrelated", "An unrelated provider cannot establish an App Control block");
        Reject(p => p.AppControl.Blocks[0].ParentImage = @"C:\Other\setup.exe", "Same basename outside the staged source path is not correlated");
        Reject(p => p.AppControl.Blocks[0].ObservedAt = "2026-10-29T11:59:59Z", "Stale policy events before this run are excluded");
        Reject(p => p.AppControl.Blocks[0].ObservedAt = "2026-10-29T12:03:00Z", "Events after the capture window are excluded");
        Reject(p => p.AppControl.Status = "Unavailable", "Unavailable policy collection cannot establish a block");
        Reject(p => p.AppControl.Blocks[0].Correlation = "basename only", "Unscoped event hints cannot establish a block");
        Reject(p => p.AppControl.Blocks[0].BlockedFile = "", "A block without a target file is incomplete evidence");
        Reject(p => p.AppControl.CapturedAt = "invalid", "Invalid policy capture times are not accepted");
        Reject(p => p.AppControl = null!, "Legacy or explicit-null policy evidence remains unknown");
        proof.AppControl.Status = "Partial";
        check(AppControlEvidenceService.HasConfirmedBlock(proof), "A bounded partial read can retain an individually correlated enforced block");
        File.WriteAllText(Path.Combine(root, "app-control-fixture.json"), JsonSerializer.Serialize(proof));
        var config = (string)typeof(SandboxIssRecorder).GetMethod("BuildWsb", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(null, [@"C:\Fixture\Input", @"C:\Fixture\Output"])!;
        var doc = System.Xml.Linq.XDocument.Parse(config);
        check(doc.Root!.Element("vGPU")?.Value == "Disable" && config.Contains("<ReadOnly>true</ReadOnly>") && config.Contains("Start-Analysis.ps1"),
            "Installer Sandbox uses software guest graphics with read-only input and the production bootstrap");
    }
}
