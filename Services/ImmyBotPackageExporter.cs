using System.IO;
using System.IO.Compression;

namespace InstallerAnalyzer.Services;

public static class ImmyBotPackageExporter
{
    public static void Export(string zipPath, string installerPath, string? outputFolder, string? logoPath)
    {
        var temp = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer-ImmyBot-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            File.Copy(installerPath, Path.Combine(temp, Path.GetFileName(installerPath)), true);
            if (!string.IsNullOrWhiteSpace(outputFolder))
            {
                foreach (var name in new[] { "setup.iss", "uninstall.iss" })
                {
                    var source = Path.Combine(outputFolder, name);
                    if (File.Exists(source)) File.Copy(source, Path.Combine(temp, name), true);
                }
            }
            if (!string.IsNullOrWhiteSpace(logoPath) && File.Exists(logoPath))
                File.Copy(logoPath, Path.Combine(temp, "Logo.png"), true);
            if (File.Exists(zipPath)) File.Delete(zipPath);
            ZipFile.CreateFromDirectory(temp, zipPath, CompressionLevel.Optimal, false);
        }
        finally { try { Directory.Delete(temp, true); } catch { } }
    }
}
