using System.IO;
using System.IO.Compression;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class ImmyBotPackageExporter
{
    public static void Export(string zipPath, string installerPath, string? outputFolder, string? logoPath, IReadOnlyList<MsixDependency>? dependencies = null, InstallerArchive? archive = null, InstallAnalysis? proof = null)
    {
        if (archive?.DeploymentBlockReason(proof) is { } reason)
            throw new InvalidOperationException(reason);
        if (archive is not null && string.Equals(Path.GetFullPath(zipPath), Path.GetFullPath(archive.Path), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Export cannot replace the original installer ZIP.");
        var temp = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer-ImmyBot-" + Guid.NewGuid().ToString("N"));
        var pendingZip = zipPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        Directory.CreateDirectory(temp);
        try
        {
            var targetInstaller = Path.Combine(temp, Path.GetFileName(installerPath));
            if (archive is null) File.Copy(installerPath, targetInstaller, true);
            if (dependencies is { Count: > 0 })
                MsixDependencyService.CopyValidated(installerPath, targetInstaller, dependencies);
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
            using (var zip = ZipFile.Open(pendingZip, ZipArchiveMode.Create))
            {
                foreach (var file in Directory.EnumerateFiles(temp, "*", SearchOption.AllDirectories))
                    zip.CreateEntryFromFile(file, Path.GetRelativePath(temp, file).Replace('\\', '/'), CompressionLevel.Optimal);
                if (archive is not null)
                {
                    using var source = archive.OpenVerified();
                    using var attachment = zip.CreateEntry(InstallerArchive.AttachmentName, CompressionLevel.NoCompression).Open();
                    source.CopyTo(attachment);
                }
            }
            File.Move(pendingZip, zipPath, overwrite: true);
        }
        finally
        {
            try { Directory.Delete(temp, true); } catch { }
            if (File.Exists(pendingZip)) File.Delete(pendingZip);
        }
    }
}
