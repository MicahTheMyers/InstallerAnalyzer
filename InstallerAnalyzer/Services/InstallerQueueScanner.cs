using System.IO;

namespace InstallerAnalyzer.Services;

public static class InstallerQueueScanner
{
    public static string[] Scan(string folder, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var extensions = new HashSet<string>([".exe", ".msi", ".msix", ".appx", ".msixbundle", ".appxbundle"], StringComparer.OrdinalIgnoreCase);
        var files = new List<string>();
        foreach (var path in Directory.EnumerateFiles(folder, "*", new EnumerationOptions
                 { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true }))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (extensions.Contains(Path.GetExtension(path))) files.Add(path);
        }
        files.Sort((left, right) =>
        {
            var name = StringComparer.OrdinalIgnoreCase.Compare(Path.GetFileName(left), Path.GetFileName(right));
            return name != 0 ? name : StringComparer.OrdinalIgnoreCase.Compare(left, right);
        });
        cancellationToken.ThrowIfCancellationRequested();
        return files.ToArray();
    }
}
