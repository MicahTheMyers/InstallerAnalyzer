using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

internal static class AdobeReaderInstaller
{
    internal const string DesktopProduct = "Adobe Acrobat";

    internal static bool IsOfflinePackage(string path, FileVersionInfo version) =>
        string.Equals(version.OriginalFilename, "AdobeSelfExtractor.exe", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(version.ProductName, "Adobe Self Extractor", StringComparison.OrdinalIgnoreCase) &&
        (version.CompanyName?.StartsWith("Adobe ", StringComparison.OrdinalIgnoreCase) ?? false) &&
        Regex.IsMatch(Path.GetFileName(path), @"^AcroRdr(?:DC)?(?:x64)?\d+(?:_[a-zA-Z]+)?\.exe$", RegexOptions.IgnoreCase);

    internal static bool IsDesktopEntry(UninstallEntry entry) =>
        entry.WindowsInstaller?.ToString() == "1" &&
        Regex.IsMatch(entry.ProductCode ?? "", @"^\{AC76BA86-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$", RegexOptions.IgnoreCase) &&
        Regex.IsMatch(entry.DisplayName ?? "", @"^Adobe Acrobat(?:\s|$)", RegexOptions.IgnoreCase) &&
        Regex.IsMatch(entry.Publisher ?? "", @"^Adobe(?:\s|$)", RegexOptions.IgnoreCase);
}
