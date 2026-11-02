using System.IO;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class NetFx3RequirementService
{
    public static string Detect(string path, MsiMetadata metadata)
    {
        foreach (var condition in metadata.LaunchConditions)
            if (IsExplicitRequirement(condition.Description)) return "MSI LaunchCondition: " + condition.Description;
        try
        {
            using var stream = File.OpenRead(path); using var pe = new PEReader(stream);
            if (!pe.HasMetadata || !pe.GetMetadataReader().MetadataVersion.StartsWith("v2.0.", StringComparison.Ordinal)) return "";
            if (File.Exists(path + ".config"))
            {
                var info = new FileInfo(path + ".config"); if (info.Length > 65536) return "";
                var config = XDocument.Load(path + ".config");
                var runtimes = config.Descendants("supportedRuntime").Select(e => (string?)e.Attribute("version")).ToArray();
                if (runtimes.Length != 0 && runtimes[0] != "v2.0.50727") return "";
            }
            return "Managed installer metadata requires CLR v2.0; supplied runtime configuration does not select CLR v4.";
        }
        catch { return ""; }
    }
    public static bool IsExplicitRequirement(string text) => Regex.IsMatch(text ?? "", @"(?i)(?:\.NET\s*(?:Framework\s*)?3\.5|NetFx3|NETFRAMEWORK35)") &&
        Regex.IsMatch(text ?? "", @"(?i)\brequir(?:e[sd]?|ement)\b|\bneeds?\b|\bmust\b|\bmissing\b|\bnot installed\b") &&
        !Regex.IsMatch(text ?? "", @"(?i)not required|does not require|no .{0,20}required|optional|not needed");
}
