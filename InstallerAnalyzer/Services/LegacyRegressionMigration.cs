using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed record LegacyRunImportResult(int Imported, int Preserved, IReadOnlyList<string> Warnings);

public sealed partial class RegressionHistoryService
{
    public LegacyRunImportResult ImportLegacyRuns(string resultsRoot)
    {
        int imported = 0, preserved = 0; var warnings = new List<string>();
        if (!Directory.Exists(resultsRoot) || IsLink(resultsRoot)) return new(0, 0, warnings);
        foreach (var summary in LegacyFiles(resultsRoot, "Summary.json", 2048))
        {
            try
            {
                var info = new FileInfo(summary);
                if (info.Length > 8 * 1024 * 1024) throw new InvalidDataException("Summary exceeds the migration size limit.");
                var bytes = File.ReadAllBytes(summary);
                using var json = JsonDocument.Parse(bytes);
                var node = json.RootElement; var folder = Path.GetDirectoryName(summary)!;
                var previousId = Text(node, "RunId");
                if (!Guid.TryParseExact(previousId, "N", out _)) previousId = Path.GetFileName(folder).Split('_').Last();
                if (Guid.TryParseExact(previousId, "N", out _) && File.Exists(Path.Combine(root, previousId + ".json"))) { preserved++; continue; }
                var id = Convert.ToHexString(SHA256.HashData(bytes))[..32].ToLowerInvariant();
                if (File.Exists(Path.Combine(root, id + ".json"))) { preserved++; continue; }
                if (!DateTimeOffset.TryParse(Text(node, "Started"), out var started) || !DateTimeOffset.TryParse(Text(node, "Completed"), out var completed) || completed < started)
                    throw new InvalidDataException("Completed legacy run timestamps are missing or invalid.");
                if (!Property(node, "Tests", out var tests) || tests.ValueKind != JsonValueKind.Array || tests.GetArrayLength() > 5000)
                    throw new InvalidDataException("Legacy summary has no supported test list.");
                var run = new RegressionRun { Id = id, Version = Text(node, "Version"), Mode = Text(node, "Mode"),
                    Started = started, Completed = completed, ArtifactFolder = folder, Stopped = Boolean(node, "Stopped"),
                    Provenance = "Legacy summary; outcomes imported without fresh validation" };
                var artifacts = ReadLegacyArtifacts(folder);
                foreach (var item in tests.EnumerateArray())
                {
                    var name = Text(item, "Installer");
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    var result = Text(item, "Result").ToUpperInvariant();
                    if (result is not ("PASS" or "FAIL" or "TIMEOUT" or "STOPPED")) result = "NOT TESTED";
                    var matches = artifacts.Where(a => a.Installer.Equals(name, StringComparison.OrdinalIgnoreCase)).ToArray();
                    var artifact = matches.Length == 1 ? matches[0] : null;
                    var hash = Text(item, "InstallerSha256");
                    if (!ValidHash(hash)) hash = artifact?.Hash ?? "";
                    // Never hash today's installer to invent the identity of an older result.
                    var record = new RegressionTestRecord { Installer = Path.GetFileName(name), Result = result,
                        InstallerSha256 = ValidHash(hash) ? hash.ToUpperInvariant() : "",
                        ProductName = Text(item, "ProductName"), Publisher = Text(item, "Publisher"), InstallerType = Text(item, "InstallerType"),
                        Install = Text(item, "Install"), Uninstall = Text(item, "Uninstall"), Removal = Text(item, "Removal"),
                        ArtifactFolder = artifact?.Folder ?? "", DurationSeconds = Number(item, "DurationSeconds"),
                        Failure = FailureClassificationService.Classify(result, Text(item, "Failure"), null, Text(item, "WorkflowStage")) };
                    if (record.ProductName.Length == 0) record.ProductName = artifact?.Product ?? "";
                    if (record.Publisher.Length == 0) record.Publisher = artifact?.Publisher ?? "";
                    run.Tests.Add(record);
                }
                if (run.Tests.Count == 0) throw new InvalidDataException("Legacy summary contains no recognizable installer results.");
                Save(run); imported++;
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
            { warnings.Add(Path.GetFileName(Path.GetDirectoryName(summary)) + ": " + ex.Message); }
        }
        return new(imported, preserved, warnings);
    }

    private sealed record LegacyArtifact(string Installer, string Folder, string Hash, string Product, string Publisher);
    private static List<LegacyArtifact> ReadLegacyArtifacts(string folder)
    {
        var artifacts = new List<LegacyArtifact>();
        foreach (var path in LegacyFiles(folder, "regression-result.json", 5000))
            try
            {
                if (new FileInfo(path).Length > 1024 * 1024) continue;
                using var json = JsonDocument.Parse(File.ReadAllText(path)); var row = json.RootElement;
                var installer = Text(row, "Installer"); var hash = Text(row, "InstallerSha256"); var product = Text(row, "ProductName"); var publisher = Text(row, "Publisher");
                var parent = Path.GetDirectoryName(path)!; var proofPath = Path.Combine(parent, "install-analysis.json");
                if (!ValidHash(hash) && File.Exists(proofPath) && !IsLink(proofPath) && new FileInfo(proofPath).Length <= 4 * 1024 * 1024)
                {
                    using var proofJson = JsonDocument.Parse(File.ReadAllText(proofPath)); var proof = proofJson.RootElement;
                    if (Text(proof, "Installer").Equals(installer, StringComparison.OrdinalIgnoreCase)) hash = Text(proof, "InstallerSha256");
                    if (Property(proof, "NewUninstallEntries", out var entries) && entries.ValueKind == JsonValueKind.Array)
                    {
                        var primary = entries.EnumerateArray().FirstOrDefault(e => Text(e, "Key") == Text(proof, "PrimaryKey"));
                        if (product.Length == 0) product = Text(primary, "DisplayName");
                        if (publisher.Length == 0) publisher = Text(primary, "Publisher");
                    }
                }
                artifacts.Add(new(installer, parent, ValidHash(hash) ? hash : "", product, publisher));
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { }
        return artifacts;
    }
    private static bool ValidHash(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);
    private static bool IsLink(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    private static IEnumerable<string> LegacyFiles(string rootFolder, string fileName, int limit)
    {
        var pending = new Stack<string>(); pending.Push(rootFolder); int visited = 0, count = 0;
        while (pending.Count > 0 && visited++ < 10000 && count < limit)
        {
            var folder = pending.Pop(); string[] entries;
            try { entries = Directory.GetFileSystemEntries(folder); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            foreach (var path in entries)
            {
                FileAttributes attributes;
                try { attributes = File.GetAttributes(path); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
                if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(path);
                else if (Path.GetFileName(path).Equals(fileName, StringComparison.OrdinalIgnoreCase)) { yield return path; if (++count == limit) yield break; }
            }
        }
    }
    private static bool Property(JsonElement node, string name, out JsonElement value)
    {
        if (node.ValueKind == JsonValueKind.Object)
            foreach (var property in node.EnumerateObject()) if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) { value = property.Value; return true; }
        value = default; return false;
    }
    private static string Text(JsonElement node, string name) => Property(node, name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
    private static bool Boolean(JsonElement node, string name) => Property(node, name, out var value) && value.ValueKind == JsonValueKind.True;
    private static double Number(JsonElement node, string name) => Property(node, name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number) ? number : 0;
}
