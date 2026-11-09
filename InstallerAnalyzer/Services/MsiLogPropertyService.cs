using System.IO;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

// Consumes existing logs as untrusted evidence. Opens no MSI session and runs no actions.
// Raw property values remain local variables; only presence and scoped condition results leave this class.
public static class MsiLogPropertyService
{
    private const int Limit = 4 * 1024 * 1024;
    private static readonly Regex PropertyLine = new(@"\AProperty\(S\): (?<name>[A-Za-z_][A-Za-z0-9_.]*) = (?<value>[^\r\n]*)\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex SensitiveName = new(@"password|passwd|secret|token|credential|api.?key|customactiondata", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly string[] Standard = ["VersionNT", "VersionNT64", "WindowsBuild", "ServicePackLevel", "ServicePackLevelMinor", "MsiNTProductType", "Privileged", "AdminUser", "Installed"];

    public static List<MsiPropertySnapshot> Read(string path, MsiMetadata metadata)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return Unavailable("Reparse log path not read.");
            return Parse(AnalysisArtifactReader.ReadText(path, Limit), metadata);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException or RegexMatchTimeoutException)
        { return Unavailable("Log unavailable or exceeds bounded read limits; properties remain unknown."); }
    }

    private static List<MsiPropertySnapshot> Unavailable(string reason) => [new() { Status = reason }];

    public static List<MsiPropertySnapshot> Parse(string text, MsiMetadata metadata)
    {
        if (text.Length > Limit) return Unavailable("Log exceeds bounded read limits.");
        if (!Guid.TryParse(metadata.ProductCode, out var expected) || expected == Guid.Empty) return Unavailable("Known package ProductCode required for property attribution.");
        var requested = metadata.LaunchConditions.Take(64).SelectMany(c => MsiConditionEvaluator.Evaluate(c.Condition,
            new Dictionary<string,string?>()).UnresolvedSymbols).Where(p => p.Length > 0 && !"%$?!&".Contains(p[0])).Concat(Standard).Distinct(StringComparer.Ordinal).Take(128).ToHashSet(StringComparer.Ordinal);
        var hidden = metadata.HiddenProperties.Take(256).ToHashSet(StringComparer.Ordinal);
        var snapshots = new List<MsiPropertySnapshot>();
        var block = new Dictionary<string,string>(StringComparer.Ordinal);
        var duplicates = new HashSet<string>(StringComparer.Ordinal);
        var invalid = false;
        void Finish(bool terminated)
        {
            if (block.Count == 0) return;
            if (snapshots.Count >= 4) { invalid = true; return; }
            var snapshot = new MsiPropertySnapshot(); snapshots.Add(snapshot);
            var ownPackage = !duplicates.Contains("ProductCode") && block.TryGetValue("ProductCode",out var code) && Guid.TryParse(code,out var actual) && actual == expected;
            if (!terminated || invalid || !ownPackage)
            { snapshot.Status = "Incomplete, ambiguous or different-product server dump; no properties bound."; }
            else
            {
                snapshot.Status = "Observed terminal server property block " + snapshots.Count;
                var blockHidden = block.GetValueOrDefault("MsiHiddenProperties", "");
                var hideAll = metadata.HiddenPropertiesTruncated || duplicates.Contains("MsiHiddenProperties") || blockHidden.Contains('*') || blockHidden.Length > 4096;
                var allHidden = hidden.Concat(blockHidden.Split(';', StringSplitOptions.RemoveEmptyEntries)).ToHashSet(StringComparer.Ordinal);
                var values = new Dictionary<string,string?>(StringComparer.Ordinal);
                foreach (var name in requested.Order(StringComparer.Ordinal))
                {
                    var observation = new MsiPropertyObservation { Property = name, Evidence = "Not reported in this server dump; missing is not unset." };
                    if (block.TryGetValue(name,out var value))
                    {
                        if (hideAll || allHidden.Contains(name) || SensitiveName.IsMatch(name) || duplicates.Contains(name) || value.Length > 4096 || value.Contains('\0') || value.Contains('*'))
                            observation.Evidence = "Hidden, sensitive, masked, duplicated or unsupported value; not retained or bound.";
                        else
                        {
                            observation.IsSet = value.Length > 0; values[name] = value;
                            observation.Evidence = "Reported by the matching package's terminal server dump. Raw value not retained; not evidence of launch-time state.";
                        }
                    }
                    snapshot.Properties.Add(observation);
                }
                foreach (var condition in metadata.LaunchConditions.Take(64))
                {
                    var evaluated = MsiConditionEvaluator.Evaluate(condition.Condition,values);
                    evaluated.Description = condition.Description; evaluated.Scope = snapshot.Scope;
                    evaluated.Explanation += " Log-reported evidence only; not a substitute for actual LaunchConditions action results.";
                    snapshot.Conditions.Add(evaluated);
                }
            }
            block.Clear(); duplicates.Clear(); invalid = false;
        }
        using var reader = new StringReader(text); string? line; var lines = 0;
        while ((line = reader.ReadLine()) is not null)
        {
            if (++lines > 100000) return Unavailable("Log line limit reached; no property bindings retained.");
            var match = PropertyLine.Match(line);
            if (match.Success)
            {
                var name = match.Groups["name"].Value;
                if (block.Count >= 4096 || line.Length > 16384) { invalid = true; continue; }
                if (!block.TryAdd(name,match.Groups["value"].Value)) duplicates.Add(name);
            }
            else if (block.Count > 0)
            {
                // A known log boundary closes a dump. Arbitrary continuation text invalidates it.
                var boundary = line.StartsWith("MSI (",StringComparison.Ordinal) || line.StartsWith("Property(C): ",StringComparison.Ordinal) || line.StartsWith("=== ",StringComparison.Ordinal);
                Finish(boundary);
            }
        }
        Finish(false); // A truncated property block is not a complete snapshot.
        return snapshots.Count == 0 ? Unavailable("No supported terminal server property dump found.") : snapshots;
    }
}
