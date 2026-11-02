using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class LiveCampaignChecks
{
    private sealed class Outcome
    {
        public string Installer { get; set; } = "";
        public string Sha256Before { get; set; } = "";
        public string Sha256After { get; set; } = "";
        public string Result { get; set; } = "Not tested";
        public string Reason { get; set; } = "";
        public string Category { get; set; } = "";
        public string Folder { get; set; } = "";
        public int FileWriterObservations { get; set; }
        public string TraceStatus { get; set; } = "";
    }
    public static int Run(string root, string directory)
    {
        if (SandboxIssRecorder.IsEnvironmentRunning() != false) throw new InvalidOperationException("Campaign requires confirmed empty Sandbox state.");
        Directory.CreateDirectory(root);
        string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
        var paths = Directory.GetFiles(directory).Where(p => Path.GetExtension(p).ToLowerInvariant() is ".exe" or ".msi")
            .OrderBy(p => Path.GetFileName(p).Equals("ccsetup630.exe", StringComparison.OrdinalIgnoreCase) ? 0 : Path.GetFileName(p).Equals("WinDirStat-x64.msi", StringComparison.OrdinalIgnoreCase) ? 1 : 2)
            .ThenBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase).ToArray();
        if (paths.Length == 0) throw new InvalidOperationException("No source installers found.");
        var records = paths.Select((p, i) => new Outcome { Installer = Path.GetFileName(p), Sha256Before = Hash(p), Folder = Path.Combine(root, (i + 1).ToString("D2") + "-" + Path.GetFileNameWithoutExtension(p)) }).ToList();
        void Save() => File.WriteAllText(Path.Combine(root, "campaign-summary.json"), JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true }));
        Save();
        for (var i = 0; i < paths.Length; i++)
        {
            var record = records[i]; record.Result = "Running"; Save();
            Console.WriteLine($"CAMPAIGN {i + 1}/{paths.Length}: {record.Installer}");
            try
            {
                var result = LiveSandboxChecks.Run(record.Folder, paths[i], TimeSpan.FromMinutes(8));
                record.Result = result == 0 ? "PASS" : "FAIL / INCONCLUSIVE";
                var analysis = Path.Combine(record.Folder, "enriched-analysis.json");
                if (!File.Exists(analysis)) analysis = Path.Combine(record.Folder, "install-analysis.json");
                if (!File.Exists(analysis)) analysis = Path.Combine(record.Folder, "install-analysis.checkpoint.json");
                if (File.Exists(analysis))
                {
                    var proof = JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(analysis), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (proof is not null)
                    {
                        record.Reason = proof.ValidationError ?? (result == 0 ? "Complete measured lifecycle" : "Incomplete lifecycle within campaign time budget");
                        record.Category = result == 0 ? "None" : FailureClassificationService.Classify("FAIL", record.Reason, proof, "USB Sandbox campaign").Category.ToString();
                        record.FileWriterObservations = proof.PayloadTrace.Files.Count; record.TraceStatus = proof.PayloadTrace.Status;
                    }
                }
                else { record.Reason = "No analysis returned within eight-minute case budget"; record.Category = "Timeout"; }
                var errorPath = Path.Combine(record.Folder, "verification-error.json");
                if (File.Exists(errorPath))
                {
                    using var error = JsonDocument.Parse(File.ReadAllText(errorPath));
                    var type = error.RootElement.GetProperty("Type").GetString();
                    if (type is "IOException" or "TimeoutException")
                    {
                        record.Result = "INFRASTRUCTURE / INCONCLUSIVE";
                        record.Category = type == "TimeoutException" ? "Timeout" : "AnalyzerInfrastructureFailure";
                        record.Reason = error.RootElement.GetProperty("Message").GetString() ?? type;
                    }
                }
            }
            catch (Exception ex) { record.Result = "INFRASTRUCTURE / INCONCLUSIVE"; record.Reason = ex.Message; }
            finally { record.Sha256After = Hash(paths[i]); Save(); }
            if (record.Sha256After != record.Sha256Before) throw new InvalidOperationException("Source installer bytes changed: " + record.Installer);
            if (SandboxIssRecorder.IsEnvironmentRunning() != false) throw new InvalidOperationException("Sandbox teardown not confirmed; campaign stopped before the next installer.");
            Console.WriteLine($"CAMPAIGN RESULT: {record.Installer}: {record.Result}; {record.Category}; writers={record.FileWriterObservations}; {record.Reason}");
        }
        Console.WriteLine($"CAMPAIGN COMPLETE: {records.Count(r => r.Result == "PASS")}/{records.Count} full lifecycles passed; source hashes preserved.");
        return records.All(r => r.Result == "PASS") ? 0 : 1;
    }
}
