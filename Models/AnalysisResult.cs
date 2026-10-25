using System.IO;
namespace InstallerAnalyzer.Models;
public enum InstallerKind { Unknown, Msi, InstallShield, InnoSetup, Nsis, WixBurn, Squirrel, NvidiaSfx, QSetup, Bootstrapper }
public sealed class AnalysisResult
{
    public string FilePath { get; set; } = "";
    public string FileName => Path.GetFileName(FilePath);
    public string ProductName { get; set; } = "";
    public string CompanyName { get; set; } = "";
    public string FileVersion { get; set; } = "";
    public string Architecture { get; set; } = "Unknown";
    public InstallerKind Kind { get; set; } = InstallerKind.Unknown;
    public int Confidence { get; set; }
    public string SuggestedArguments { get; set; } = "";
    public List<string> Evidence { get; } = new();
    public bool NeedsIss { get; set; }
    public bool IsPerUser { get; set; }
    public string ExpectedInstallRoot { get; set; } = "";
}
