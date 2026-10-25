using System.Text.Json;
using System.IO;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed class AnalysisHistoryItem
{
    public DateTime AnalyzedAt { get; set; }
    public string InstallerPath { get; set; } = "";
    public string ProductName { get; set; } = "";
    public string Version { get; set; } = "";
    public string InstallerType { get; set; } = "";
    public int Confidence { get; set; }
    public bool SandboxValidated { get; set; }
    public string DetectionMethod { get; set; } = "";
    public string Display => $"{ProductName} {Version}".Trim();
    public string Summary => $"{AnalyzedAt:g}  •  {InstallerType}  •  {Confidence}%  •  {(SandboxValidated ? "Sandbox Validated" : "Static Analysis")}";
}

public static class AnalysisHistoryService
{
    private static string Folder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer");
    private static string FilePath => Path.Combine(Folder, "history.json");
    public static List<AnalysisHistoryItem> Load()
    {
        try { return File.Exists(FilePath) ? JsonSerializer.Deserialize<List<AnalysisHistoryItem>>(File.ReadAllText(FilePath)) ?? new() : new(); }
        catch { return new(); }
    }
    public static void Save(AnalysisHistoryItem item)
    {
        try
        {
            Directory.CreateDirectory(Folder); var items = Load();
            items.RemoveAll(x => string.Equals(x.InstallerPath, item.InstallerPath, StringComparison.OrdinalIgnoreCase));
            items.Insert(0, item); if (items.Count > 50) items.RemoveRange(50, items.Count - 50);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }
    public static void Clear() { try { if (File.Exists(FilePath)) File.Delete(FilePath); } catch { } }
}
