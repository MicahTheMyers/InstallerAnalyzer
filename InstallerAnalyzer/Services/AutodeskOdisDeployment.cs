using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

internal static class AutodeskOdisDeployment
{
    internal const string ImageInstructions = "For unattended Autodesk ODIS installation, select image\\Installer.exe from a complete Autodesk Account Custom Install ZIP. Enter the installed product name and use the silent install arguments from Autodesk's generated batch file.";

    internal static bool IsOdis(string path, FileVersionInfo version) =>
        Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
        Regex.IsMatch(version.CompanyName?.Trim() ?? "", @"^Autodesk(?:,? Inc\.?)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) &&
        (version.ProductName?.Trim() is { } product &&
         (product.Equals("Autodesk Installation Services", StringComparison.OrdinalIgnoreCase) ||
          product.Equals("Autodesk On-Demand Install Service", StringComparison.OrdinalIgnoreCase) ||
          product.Equals("Autodesk ODIS", StringComparison.OrdinalIgnoreCase)));

    internal static string GetImageManifest(InstallerArchive? archive, string arguments, string? product)
    {
        if (archive is null || !Path.GetFileName(archive.Entry).Equals("Installer.exe", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(Path.GetDirectoryName(archive.Entry)), "image", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(ImageInstructions);
        if (string.IsNullOrWhiteSpace(product) || product.StartsWith("Autodesk ODIS", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Enter the intended application's installed name in the Analyze page's Product field, such as Autodesk Civil 3D 2027.");
        var match = Regex.Match(arguments.Trim(),
            """^-i\s+deploy\s+--offline_mode\s+(?:-q|--silent|--ui_mode\s+silent)\s+-o\s+(?:"(?<xml>[\w .-]+\.xml)"|(?<xml>[\w.-]+\.xml))\s+--installer_version\s+(?:"[0-9]+(?:\.[0-9]+)+"|[0-9]+(?:\.[0-9]+)+)$""",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success)
            throw new InvalidOperationException("Use the generated Autodesk offline silent command's arguments, for example -i deploy --offline_mode -q -o \"Collection.xml\" --installer_version \"<version from batch>\". Use the XML filename next to Installer.exe.");
        return match.Groups["xml"].Value;
    }
}
