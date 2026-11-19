using System.Text;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private static readonly Lazy<string> EditorTemplate = new(() =>
        "# Sandbox analysis script. Values marked __NAME__ are supplied from Analyze and Settings at launch.\n" +
        "# Keep the heartbeat and result-handling sections to retain analysis and progress reporting.\n" +
        BuildDiscoveryScriptWithTimeouts("", InstallerKind.Unknown, "", "", false, false, new MsiMetadata(), editableTemplate: true));

    internal static string GetEditableScriptTemplate() => EditorTemplate.Value;

    private static string BuildRoadmapHelpers(string encodedMsiMetadata) =>
        LiveProgressScript + Environment.NewLine + RoadmapEvidenceScript.Replace("__MSI_METADATA__", encodedMsiMetadata) + Environment.NewLine + DetailedDetectionEvidenceScript + Environment.NewLine + RuntimeEnvironmentEvidenceScript + Environment.NewLine + NetFx3ProvisioningScript + Environment.NewLine + GintPrerequisiteScript + Environment.NewLine + SandboxCompatibilityScript + Environment.NewLine + MsiIdentityEvidenceScript + Environment.NewLine + PrerequisiteFileEvidenceScript + Environment.NewLine + PrerequisiteServiceEvidenceScript + Environment.NewLine + DllEvidenceScript + Environment.NewLine + AppControlEvidenceScript + Environment.NewLine + PayloadTraceEvidenceScript.Replace("__TRACE_WORKER_B64__", Convert.ToBase64String(Encoding.UTF8.GetBytes(PayloadTraceWorkerScript)));
}
