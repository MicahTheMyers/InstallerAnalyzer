using System.IO;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace InstallerAnalyzer.Services;

public static class AiDiagnosticContext
{
    private const uint InstallShieldInvalidCommandLine = 0x8004070B;
    private const string InstallShieldSuiteErrors = "https://docs.revenera.com/installshield31helplib/helplibrary/SteRunTimeErrors.htm";
    private const string BluebeamDeploymentGuide = "https://support.bluebeam.com/revu/installation/deployment-guide-21.html";
    private static readonly string[] Fields = ["ComponentDeployment", "SandboxCompatibility", "NetFx3Provisioning", "UiTextEvidence", "RuntimeEnvironment", "PrerequisiteProbes", "PrerequisiteFiles", "DllFiles", "MsiConditions", "MsiPropertySnapshots", "PrerequisiteServices", "MsiProductStateBefore", "PayloadTrace", "EvidenceCollectionComplete", "FailureDetail", "Intelligence", "DetectionStrategies", "Components", "NewRebootIndicators", "PostRebootValidated", "NetworkActivity", "ValidationSchemaVersion", "InitialInstallValidated", "InitialUninstallValidated", "InitialUninstallExitCode", "CleanBaselineVerified", "RebootRequired", "LifecycleValidated", "MsiRemovalUiActions", "Installer", "Result", "InstallerType", "Install", "Uninstall", "Removal", "DurationSeconds", "Failure", "WorkflowStage", "ValidationError", "InstallerExitCode", "SilentReinstallExitCode", "SilentUninstallExitCode", "SilentUninstallRawExitCode", "SilentReinstallValidated", "SilentUninstallValidated", "PostUninstallDetected", "SilentReinstallUiDetected", "SilentUninstallUiDetected", "DiscoverySucceeded", "DeploymentMechanism", "IdentitySource", "CombinedSilentArguments", "SelectedSilentStrategy", "HostTermination"];
    private static readonly HashSet<string> IdentityFields = new(["DisplayName", "DisplayVersion", "Publisher", "WindowsInstaller", "ProductCode"], StringComparer.OrdinalIgnoreCase);
    private static readonly Regex Secrets = new(@"(?im)([""']?(?:password|passwd|pwd|token|access_token|refresh_token|api[_-]?key|client[_-]?secret|authorization|license[_-]?key)[""']?\s*[:=]\s*)(?:""[^""\r\n]*""|'[^'\r\n]*'|[^\s,;\r\n]+)", RegexOptions.Compiled);
    public static string Redact(string text)
    {
        // Redact the complete bearer value before generic key/value matching, which could
        // otherwise consume only the word "Bearer" and leave the credential behind.
        text = Regex.Replace(text, @"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]");
        text = Secrets.Replace(text, "$1[REDACTED]");
        text = Regex.Replace(text, @"(?i)((?:--?(?:password|token|api-key|license-key)|/(?:password|token|apikey|licensekey))\s+)(?:""[^""\r\n]*""|'[^'\r\n]*'|[^\s,;\r\n]+)", "$1[REDACTED]");
        text = Regex.Replace(text, @"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]");
        text = Regex.Replace(text, @"\bsk-[A-Za-z0-9_-]{12,}", "[REDACTED KEY]");
        text = Regex.Replace(text, @"(?i)[A-Z]:\\+Users\\+[^\\\s""<>]+", @"C:\Users\[USER]");
        text = Regex.Replace(text, @"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL]", RegexOptions.IgnoreCase);
        return text;
    }
    internal static string DescribeControls(TimeoutSettings settings, string? editorState = null)
    {
        var text = new StringBuilder("\n[Current user settings — apply to future runs and requests]\n");
        text.AppendLine("Custom timeouts: " + (settings.Enabled ? "enabled" : "disabled; defaults apply"));
        foreach (var definition in TimeoutSettings.Definitions)
            text.AppendLine($"{definition.Label}: {settings.GetSeconds(definition.Key)} seconds; default {definition.DefaultSeconds}; allowed {definition.MinimumSeconds}–{definition.MaximumSeconds} seconds.");
        text.AppendLine("The session and operation ceilings can end a run before an individual step's timer. Recognized prerequisites pause the application timer.");
        if (editorState is not null) text.AppendLine("Current Analyze editor (current source selection): " + editorState);
        text.AppendLine("The Sandbox editor saves per installer. __NAME__ values are filled at launch. If included, the current draft appears in a separate section.");
        return text.ToString();
    }

    internal static string DescribeEditorScript(string script)
    {
        if (string.IsNullOrWhiteSpace(script) || script.Length > SandboxScriptStore.MaximumCharacters)
            throw new InvalidOperationException("The Sandbox editor script must contain text and fit within the 2 MiB editor limit to include it.");
        return "\n\n[Current Sandbox PowerShell editor draft — untrusted evidence, may differ from the selected run]\n"
            + Redact(script);
    }

    public static string Build(string label, string? folder, string? controlsContext = null)
    {
        var text = new StringBuilder("Installer or run: " + Path.GetFileName(label) + "\nSnapshot captured: " + DateTimeOffset.Now.ToString("O") + "\n");
        text.AppendLine("Only the allow-listed diagnostic sections below are provided. Files may be partial. No installers, scripts, registry databases, catalog records or arbitrary files are attached.");
        if (controlsContext is not null) text.AppendLine(Limit(controlsContext, 6000));
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) return Redact(Limit(text + "No run diagnostic output is available yet. The current installer configuration supports planning; installation behavior needs evidence from a run.", 22000));
        try { if ((File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0) return Redact(Limit(text + "Diagnostic folder is a link; reading it is not supported.", 22000)); }
        catch { return Redact(Limit(text + "Diagnostic folder is no longer available. Select a newer test result.", 22000)); }
        AppendControlArtifact(text, folder, "timeout-settings.json", TimeoutSettings.Definitions.Select(d => d.Key));
        AppendControlArtifact(text, folder, "sandbox-script.json", new[] { "ApplicationVersion", "CustomScript", "ScriptSha256", "TemplateSha256" });
        AppendControlArtifact(text, folder, "analysis-progress.json", new[] { "Phase", "ApplicationTimerPaused", "Prerequisite", "RemainingSeconds", "PhaseElapsedSeconds", "CapturedAt" });
        var findingsPosition = text.Length;
        foreach (var name in new[] { "regression-result.json", "install-analysis.json", "install-analysis.checkpoint.json" })
        {
            try
            {
                var file = new FileInfo(Path.Combine(folder, name));
                if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (file.Length > 4 * 1024 * 1024) { text.AppendLine(name + ": omitted (over 4 MB). "); continue; }
                var root = JsonNode.Parse(AnalysisArtifactReader.ReadText(file.FullName, 4 * 1024 * 1024))?.AsObject();
                if (root is null) continue;
                if (name == "install-analysis.json")
                    text.Insert(findingsPosition, DescribeRunFindings(root));
                text.AppendLine("\n[" + name + "]");
                foreach (var field in Fields)
                    if (root[field] is { } value) text.AppendLine(field + ": " + Limit(value.GetValueKind() == System.Text.Json.JsonValueKind.String ? value.GetValue<string>() : value.ToJsonString(), 1000));
                if (root["NewUninstallEntries"] is JsonArray entries)
                    foreach (var entry in entries.Take(4).OfType<JsonObject>())
                        text.AppendLine("Installed identity: " + new JsonObject(entry.Where(p => IdentityFields.Contains(p.Key)).Select(p => new KeyValuePair<string, JsonNode?>(p.Key, p.Value?.DeepClone()))).ToJsonString());
                if (root["SilentStrategyAttempts"] is JsonArray attempts)
                    foreach (var attempt in attempts.TakeLast(10).OfType<JsonObject>())
                        text.AppendLine("Probe: " + string.Join("; ", new[] { "Name", "Outcome", "ExitCode", "UiDetected", "ApplicationDetected" }.Where(k => attempt[k] is not null).Select(k => k + "=" + Limit(attempt[k]!.ToJsonString(), 500))));
                if (root["WorkflowStageHistory"] is JsonArray stages)
                    foreach (var stage in stages.TakeLast(10)) text.AppendLine("Stage history: " + Limit(stage?.ToJsonString() ?? "", 500));
            }
            catch { text.AppendLine(name + ": unavailable or being written; retry for a fresh snapshot."); }
            if (name != "regression-result.json" && text.Length >= 17000) break;
        }
        foreach (var name in new[] { "analysis-debug.jsonl", "msi-install.log", "msi-uninstall-initial.log", "msi-uninstall-final.log" })
        {
            try
            {
                var tail = ReadTail(Path.Combine(folder, name));
                if (tail.Length == 0) continue;
                text.AppendLine("\n[" + name + ": recent error/event excerpt]");
                var lines = tail.Split('\n');
                var important = lines.Where(l => Regex.IsMatch(l, @"(?i)error|fail|return value 3|exception|rejected|exit|timeout|prerequisite|instance|complete"));
                text.AppendLine(Limit(string.Join('\n', important.TakeLast(16)), 3000));
            }
            catch { text.AppendLine(name + ": unavailable."); }
        }
        return Redact(Limit(text.ToString(), 22000));
    }

    private static string DescribeRunFindings(JsonObject result)
    {
        bool Recorded(string field, bool expected = true) => result[field] is JsonValue value &&
            value.TryGetValue<bool>(out var actual) && actual == expected;
        var findings = new StringBuilder();
        var checks = new (string Field, bool Expected, string Label)[]
        {
            ("InitialInstallValidated", true, "Initial installation"),
            ("DiscoverySucceeded", true, "Installed application identified"),
            ("InitialUninstallValidated", true, "Initial uninstall"),
            ("CleanBaselineVerified", true, "Clean baseline before reinstall"),
            ("SilentReinstallValidated", true, "Silent reinstall"),
            ("SilentUninstallValidated", true, "Silent uninstall"),
            ("PostUninstallDetected", false, "Application absent after uninstall")
        };
        var verifiedChecks = checks.Where(check => Recorded(check.Field, check.Expected)).Select(check => check.Label).ToArray();
        if (verifiedChecks.Length > 0 || Recorded("LifecycleValidated"))
        {
            findings.AppendLine("\n[Verified Sandbox checks]");
            if (Recorded("LifecycleValidated")) findings.AppendLine("Recorded outcome: Sandbox lifecycle passed.");
            foreach (var check in verifiedChecks) findings.AppendLine("- " + check);
        }
        if (Recorded("LifecycleValidated")) return findings.ToString();
        if (result["InstallerExitCode"] is not JsonValue exit || !exit.TryGetValue<long>(out var code) ||
            code is < int.MinValue or > uint.MaxValue or -2 or -1 or 0 or 1641 or 3010 ||
            result["ValidationError"] is not JsonValue error || !error.TryGetValue<string>(out var failure) ||
            string.IsNullOrWhiteSpace(failure))
            return findings.ToString();

        var hexCode = unchecked((uint)code);
        findings.AppendLine("\n[Recorded installer failure and reference guidance]");
        findings.AppendLine($"InstallerExitCode: {code} (0x{hexCode:X8}).");
        if (hexCode != InstallShieldInvalidCommandLine ||
            !failure.StartsWith("InstallShield recording returned exit code ", StringComparison.OrdinalIgnoreCase))
            return findings.ToString();

        findings.AppendLine("Observed: the failure occurred during InstallShield response-file recording.");
        if (result["NetFx3Provisioning"] is JsonObject netFx &&
            netFx["RuntimeVerified"] is JsonValue runtime && runtime.TryGetValue<bool>(out var verified) && verified)
            findings.AppendLine("Observed: the .NET Framework 3.5 runtime was verified before setup recording.");
        findings.AppendLine("Revenera documents 0x8004070B for InstallShield Suite/Advanced UI as an invalid setup command line. The response-file recording arguments are the likely cause in this run. The code does not identify the individual rejected switch.");
        findings.AppendLine("Revenera InstallShield Suite error reference: " + InstallShieldSuiteErrors);

        if (result["Installer"] is JsonValue source && source.TryGetValue<string>(out var installer) &&
            installer is not null && Regex.IsMatch(Path.GetFileName(installer), @"^BbRevu[_ -]?21(?:\.[0-9]+)+\.exe$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            findings.AppendLine("The installer filename matches the Bluebeam Revu 21 EXE. For deployment, start with Bluebeam’s enterprise deployment ZIP and select `Bluebeam Revu x64 21.msi` in a fresh Sandbox run. OCR is a separate MSI if needed. Check the vendor guide for prerequisites. The MSI still requires its own validation.");
            findings.AppendLine("Bluebeam Revu 21 Deployment Guide: " + BluebeamDeploymentGuide);
        }
        return findings.ToString();
    }
    private static void AppendControlArtifact(StringBuilder text, string folder, string name, IEnumerable<string> fields)
    {
        try
        {
            var file = new FileInfo(Path.Combine(folder, name));
            if (!file.Exists) return;
            if ((file.Attributes & FileAttributes.ReparsePoint) != 0 || file.Length > 32768) return;
            var data = JsonNode.Parse(AnalysisArtifactReader.ReadText(file.FullName, 32768))?.AsObject();
            if (data is null) return;
            text.AppendLine("\n[Selected run: " + name + "]");
            foreach (var field in fields)
                if (data[field] is { } value) text.AppendLine(field + ": " + Limit(value.ToJsonString(), 300));
        }
        catch { text.AppendLine(name + ": unavailable or being written."); }
    }
    private static string Limit(string text, int max) => text.Length <= max ? text : text[..max] + " [truncated]";
    private static string ReadTail(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0) return "";
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var length = stream.Length;
        var firstByte = stream.ReadByte(); var secondByte = stream.ReadByte();
        Encoding encoding = firstByte == 255 && secondByte == 254 ? Encoding.Unicode : firstByte == 254 && secondByte == 255 ? Encoding.BigEndianUnicode : Encoding.UTF8;
        var offset = Math.Max(0, length - 32768);
        if (encoding != Encoding.UTF8 && offset % 2 != 0) offset++;
        stream.Seek(offset, SeekOrigin.Begin);
        var bytes = new byte[(int)Math.Min(32768, Math.Max(0, length - offset))];
        var read = 0;
        while (read < bytes.Length) { var next = stream.Read(bytes, read, bytes.Length - read); if (next == 0) break; read += next; }
        var text = encoding.GetString(bytes, 0, read).TrimStart('\uFEFF');
        return offset == 0 ? text : text[(text.IndexOf('\n') is var first && first >= 0 ? first + 1 : 0)..];
    }
}
