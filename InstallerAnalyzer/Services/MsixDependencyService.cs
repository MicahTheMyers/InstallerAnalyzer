using System.IO;
using System.Security.Cryptography;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

internal static class MsixDependencyService
{
    internal const string Suffix = ".dependencies";

    internal static bool IsPackage(string path) => Path.GetExtension(path).ToLowerInvariant()
        is ".appx" or ".msix" or ".appxbundle" or ".msixbundle";

    internal static string[] Find(string installerPath)
    {
        var directory = installerPath + Suffix;
        if (!Directory.Exists(directory)) return [];
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Use a local MSIX dependency folder.");
        return Directory.EnumerateFiles(directory).Where(IsPackage)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    internal static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    internal static bool Matches(string installerPath, IReadOnlyList<MsixDependency> dependencies)
    {
        var files = Find(installerPath);
        return files.Length == dependencies.Count && files.All(path => dependencies.Any(dependency =>
            dependency.FileName.Equals(Path.GetFileName(path), StringComparison.OrdinalIgnoreCase) &&
            dependency.Sha256.Equals(Hash(path), StringComparison.OrdinalIgnoreCase)));
    }

    internal static void CopyValidated(string installerPath, string targetInstaller, IReadOnlyList<MsixDependency> dependencies)
    {
        if (dependencies.Count == 0) return;
        var target = Directory.CreateDirectory(targetInstaller + Suffix).FullName;
        foreach (var dependency in dependencies)
        {
            if (dependency.FileName != Path.GetFileName(dependency.FileName) || !IsPackage(dependency.FileName))
                throw new InvalidOperationException("Invalid MSIX dependency file name.");
            var destination = Path.Combine(target, dependency.FileName);
            var source = Path.Combine(installerPath + Suffix, dependency.FileName);
            if (!File.Exists(destination)) File.Copy(source, destination);
            if (!Hash(destination).Equals(dependency.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"MSIX dependency changed since validation: {dependency.FileName}");
        }
    }
}
