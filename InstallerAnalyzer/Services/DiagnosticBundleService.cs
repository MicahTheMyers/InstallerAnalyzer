using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed record DiagnosticBundleResult(int Included, int Omitted);

public static class DiagnosticBundleService
{
    private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase)
    {
        "install-analysis.json", "install-analysis.checkpoint.json", "regression-result.json",
        "analysis-debug.jsonl", "analysis-heartbeat.txt", "msi-install.log", "msi-uninstall-initial.log", "msi-uninstall-final.log",
        "iss-install-replay.log", "iss-uninstall-replay.log",
        "component-deployment.json", "sandbox-compatibility.json", "sandbox-compatibility-refresh.txt", "sandbox-host-startup.json", "sandbox-guest-startup.json", "sandbox-guest-startup-error.txt",
        "app-control-evidence.json",
        "installer-intelligence.json", "installer-intelligence.txt", "process-snapshot.json", "registry-snapshot.json",
        "strategy-attempts.json", "prerequisite-results.json", "relationship-graph.json", "detection-strategies.json",
        "component-evidence.json", "network-evidence.json", "payload-file-activity.json", "bits-file-mappings.json", "bits-download-evidence.json", "analysis-summary.json", "prerequisite-probes.json", "prerequisite-files.json", "dll-file-observations.json", "msi-condition-observations.json", "msi-property-observations.json", "prerequisite-services.json", "runtime-environment.json", "bundled-products.json", "installer-ui-text.json"
    };
    public static DiagnosticBundleResult Export(string destination, IEnumerable<RegressionTestRecord> selected, bool includeScreenshots = false)
    {
        var records = selected.ToArray();
        int included = 0, omitted = 0; long bytes = 0;
        var manifest = new List<object>();
        using var stream = new FileStream(destination, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create);
        for (int index = 0; index < records.Length; index++)
        {
            var record = records[index]; var prefix = (index + 1).ToString("D3");
            Write(archive, prefix + "/result-summary.txt", AiDiagnosticContext.Redact(FailureClassificationService.Explain(record)));
            var paths = new List<string>(); var warnings = new List<string>();
            if (!Directory.Exists(record.ArtifactFolder)) { warnings.Add("Original diagnostic folder is unavailable; normalized summary only."); omitted++; }
            else if ((File.GetAttributes(record.ArtifactFolder) & FileAttributes.ReparsePoint) != 0) { warnings.Add("Linked diagnostic folder omitted."); omitted++; }
            else
                foreach (var file in Walk(record.ArtifactFolder))
                {
                    var name = Path.GetFileName(file);
                    var screenshot = includeScreenshots && Path.GetExtension(name).Equals(".png", StringComparison.OrdinalIgnoreCase) &&
                        Path.GetRelativePath(record.ArtifactFolder, file).Split(Path.DirectorySeparatorChar).Any(p => p.Equals("screenshots", StringComparison.OrdinalIgnoreCase));
                    if (!Allowed.Contains(name) && !screenshot) continue;
                    try
                    {
                        var info = new FileInfo(file);
                        if (info.Length > 2 * 1024 * 1024 || bytes + info.Length > 20 * 1024 * 1024)
                        { warnings.Add(name + " omitted: bundle size limit."); omitted++; continue; }
                        var entryName = prefix + "/" + (paths.Count + 1).ToString("D3") + "_" + name;
                        if (screenshot)
                        {
                            var entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
                            using var output = entry.Open(); using var input = File.OpenRead(file); input.CopyTo(output);
                        }
                        else Write(archive, entryName, AiDiagnosticContext.Redact(File.ReadAllText(file)));
                        paths.Add(entryName); included++; bytes += info.Length;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    { warnings.Add(name + " could not be read."); omitted++; }
                }
            manifest.Add(new { Test = record.Installer, record.Result, Files = paths, Warnings = warnings });
        }
        Write(archive, "manifest.json", JsonSerializer.Serialize(new
        {
            SchemaVersion = 1, Created = DateTimeOffset.UtcNow, Included = included, Omitted = omitted,
            ScreenshotsIncluded = includeScreenshots, InstallerBinariesIncluded = false,
            Note = "Text credentials, emails and user-profile paths are redacted on a best-effort basis. Screenshots are opt-in and are not redacted.",
            Tests = manifest
        }, new JsonSerializerOptions { WriteIndented = true }));
        return new(included, omitted);
    }
    private static IEnumerable<string> Walk(string root)
    {
        var pending = new Stack<string>(); pending.Push(root);
        while (pending.Count > 0)
        {
            var folder = pending.Pop();
            foreach (var path in Directory.EnumerateFileSystemEntries(folder))
            {
                var flags = File.GetAttributes(path);
                if ((flags & FileAttributes.ReparsePoint) != 0) continue;
                if ((flags & FileAttributes.Directory) != 0) pending.Push(path); else yield return path;
            }
        }
    }
    private static void Write(ZipArchive archive, string name, string text)
    {
        using var writer = new StreamWriter(archive.CreateEntry(name, CompressionLevel.Optimal).Open(), new UTF8Encoding(false));
        writer.Write(text);
    }
}
