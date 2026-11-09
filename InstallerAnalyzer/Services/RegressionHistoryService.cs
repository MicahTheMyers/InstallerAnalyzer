using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

// Summaries and baseline live outside the disposable Sandbox and TestResults folders.
public sealed partial class RegressionHistoryService
{
    private readonly string root;
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    public RegressionHistoryService(string root) => this.root = root;
    public List<string> Warnings { get; } = new();

    public static string HashFile(string path)
    {
        using var input = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(input));
    }

    public void Save(RegressionRun run)
    {
        Validate(run);
        Directory.CreateDirectory(root);
        AtomicWrite(Path.Combine(root, run.Id + ".json"), JsonSerializer.Serialize(run, Options));
    }

    public List<RegressionRun> Load()
    {
        Warnings.Clear();
        var runs = new List<RegressionRun>();
        if (!Directory.Exists(root)) return runs;
        foreach (var file in Directory.EnumerateFiles(root, "*.json").Where(f => Path.GetFileName(f) != "baseline.json"))
        {
            try
            {
                if (new FileInfo(file).Length > 32 * 1024 * 1024) throw new InvalidDataException("Run summary exceeds the supported size limit.");
                var run = JsonSerializer.Deserialize<RegressionRun>(File.ReadAllText(file), Options)
                    ?? throw new InvalidDataException("Empty run.");
                Validate(run);
                if (!string.Equals(Path.GetFileNameWithoutExtension(file), run.Id, StringComparison.Ordinal))
                    throw new InvalidDataException("Run filename and identity differ.");
                runs.Add(run);
            }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
            { Warnings.Add(Path.GetFileName(file) + ": " + ex.Message); }
        }
        return runs.OrderByDescending(r => r.Started).ToList();
    }

    public string? BaselineId()
    {
        var path = Path.Combine(root, "baseline.json");
        if (!File.Exists(path)) return null;
        try
        {
            var id = JsonSerializer.Deserialize<BaselinePointer>(File.ReadAllText(path))?.RunId;
            if (id is not null && Guid.TryParseExact(id, "N", out _)) return id;
            Warnings.Add("Baseline pointer is invalid.");
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        { Warnings.Add("Baseline: " + ex.Message); }
        return null;
    }

    public void SetBaseline(RegressionRun run)
    {
        if (run.Completed is null || run.Stopped || !run.Tests.Any(t => t.Tested))
            throw new InvalidOperationException("Choose a completed, uninterrupted run as the baseline.");
        Save(run);
        AtomicWrite(Path.Combine(root, "baseline.json"), JsonSerializer.Serialize(new BaselinePointer(run.Id), Options));
    }

    public void ClearBaseline()
    {
        var path = Path.Combine(root, "baseline.json");
        if (File.Exists(path)) File.Delete(path);
    }

    private sealed record BaselinePointer(string RunId);
    private static void Validate(RegressionRun run)
    {
        run.Provenance ??= "Unknown provenance";
        if (run.SchemaVersion != 1 || !Guid.TryParseExact(run.Id, "N", out _) || run.Tests is null ||
            run.Tests.Any(t => t is null || t.Failure is null || t.Attempts is null || t.Intelligence is null || t.DetectionStrategies is null))
            throw new InvalidDataException("Unsupported or malformed regression summary.");
    }

    private static void AtomicWrite(string path, string contents)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temporary, contents); File.Move(temporary, path, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static bool SameInstaller(RegressionTestRecord left, RegressionTestRecord right)
    {
        if (!string.IsNullOrWhiteSpace(left.InstallerSha256) || !string.IsNullOrWhiteSpace(right.InstallerSha256))
            return !string.IsNullOrWhiteSpace(left.InstallerSha256) &&
                string.Equals(left.InstallerSha256, right.InstallerSha256, StringComparison.OrdinalIgnoreCase);
        // Legacy data may lack hashes. Never fall back to filename alone.
        return !string.IsNullOrWhiteSpace(left.ProductName) && !string.IsNullOrWhiteSpace(left.Publisher) &&
            string.Equals(left.ProductName.Trim(), right.ProductName.Trim(), StringComparison.OrdinalIgnoreCase) &&
            string.Equals(left.Publisher.Trim(), right.Publisher.Trim(), StringComparison.OrdinalIgnoreCase) &&
            string.Equals(left.InstallerType, right.InstallerType, StringComparison.OrdinalIgnoreCase);
    }

    public static List<RegressionComparison> Compare(RegressionRun current, RegressionRun baseline)
    {
        var remaining = baseline.Tests.ToList();
        var result = new List<RegressionComparison>();
        foreach (var item in current.Tests)
        {
            var candidates = remaining.Where(old => SameInstaller(item, old)).ToList();
            // Ambiguous legacy matches are not evidence of a regression.
            var old = candidates.Count == 1 ? candidates[0] : null;
            if (old is not null) remaining.Remove(old);
            string classification;
            string note = "";
            if (old is null) classification = "NEW";
            else if (!old.Tested || !item.Tested) classification = "REMOVED / NOT TESTED";
            else if (current.Mode != baseline.Mode) { classification = "NOT COMPARABLE"; note = "Different test modes"; }
            else if (current.SandboxInstallerCompatibility != baseline.SandboxInstallerCompatibility) { classification = "NOT COMPARABLE"; note = "Different Sandbox security settings"; }
            else if ((!item.Passed && item.Failure.Category == FailureCategory.Timeout && item.Failure.Owner == "Unknown") ||
                     (!old.Passed && old.Failure.Category == FailureCategory.Timeout && old.Failure.Owner == "Unknown"))
            { classification = "INCONCLUSIVE"; note = "Timeout cause is unknown; inspect evidence"; }
            else if (old.Failure.Infrastructure || item.Failure.Infrastructure)
            { classification = "INFRASTRUCTURE"; note = "Analyzer/Sandbox failure; installer change not established"; }
            else classification = (old.Passed, item.Passed) switch
            {
                (true, true) => "UNCHANGED PASS", (false, true) => "IMPROVED",
                (true, false) => "REGRESSION", _ => "UNCHANGED FAIL"
            };
            result.Add(new() { Classification = classification, Previous = old, Current = item, Note = note });
        }
        result.AddRange(remaining.Select(old => new RegressionComparison
            { Classification = "REMOVED / NOT TESTED", Previous = old, Note = "Not in this run" }));
        return result;
    }
}
