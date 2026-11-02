using System.IO;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace InstallerAnalyzer.Services;

public static class AiDiagnosticContext
{
    private static readonly string[] Fields = ["NetFx3Provisioning", "UiTextEvidence", "RuntimeEnvironment", "PrerequisiteProbes", "PrerequisiteFiles", "DllFiles", "MsiConditions", "MsiPropertySnapshots", "PrerequisiteServices", "MsiProductStateBefore", "PayloadTrace", "EvidenceCollectionComplete", "FailureDetail", "Intelligence", "DetectionStrategies", "Components", "NewRebootIndicators", "PostRebootValidated", "NetworkActivity", "ValidationSchemaVersion", "InitialInstallValidated", "InitialUninstallValidated", "InitialUninstallExitCode", "CleanBaselineVerified", "RebootRequired", "LifecycleValidated", "MsiRemovalUiActions", "Installer", "Result", "InstallerType", "Install", "Uninstall", "Removal", "DurationSeconds", "Failure", "WorkflowStage", "ValidationError", "InstallerExitCode", "SilentReinstallExitCode", "SilentUninstallExitCode", "SilentUninstallRawExitCode", "SilentReinstallValidated", "SilentUninstallValidated", "PostUninstallDetected", "SilentReinstallUiDetected", "SilentUninstallUiDetected", "DiscoverySucceeded", "DeploymentMechanism", "IdentitySource", "CombinedSilentArguments", "SelectedSilentStrategy", "HostTermination"];
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
    public static string Build(string label, string? folder)
    {
        var text = new StringBuilder("Test: " + Path.GetFileName(label) + "\nSnapshot captured: " + DateTimeOffset.Now.ToString("O") + "\n");
        text.AppendLine("Only the allow-listed diagnostic sections below are provided. Files may be partial. No installers, scripts, registry databases, catalog records or arbitrary files are attached.");
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) return text + "No diagnostic output is available yet. Run or select a test first.";
        try { if ((File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0) return text + "Diagnostic folder is a link; reading it is not supported."; }
        catch { return text + "Diagnostic folder is no longer available. Select a newer test result."; }
        foreach (var name in new[] { "regression-result.json", "install-analysis.json", "install-analysis.checkpoint.json" })
        {
            try
            {
                var file = new FileInfo(Path.Combine(folder, name));
                if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (file.Length > 4 * 1024 * 1024) { text.AppendLine(name + ": omitted (over 4 MB). "); continue; }
                var root = JsonNode.Parse(File.ReadAllText(file.FullName))?.AsObject();
                if (root is null) continue;
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
            if (text.Length >= 17000) break;
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
