using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

// Reads data tables only. No MSI session/actions, AppSearch execution, repair, install, or commit.
// https://learn.microsoft.com/windows/win32/api/msiquery/nf-msiquery-msiopendatabasew
public static class MsiMetadataService
{
    public static MsiMetadata Read(string path)
    {
        var data = new MsiMetadata();
        if (!Path.GetExtension(path).Equals(".msi", StringComparison.OrdinalIgnoreCase)) return data;
        uint database = 0;
        try
        {
            var opened = MsiOpenDatabase(path, IntPtr.Zero, out database); // MSIDBOPEN_READONLY
            if (opened != 0) { data.Status = "Read unavailable (MSI error " + opened + ")"; return data; }
            var properties = Query(database, "SELECT `Property`,`Value` FROM `Property`", 2, 4096)
                .ToDictionary(r => r[0], r => r[1], StringComparer.Ordinal);
            data.ProductName = properties.GetValueOrDefault("ProductName", ""); data.Manufacturer = properties.GetValueOrDefault("Manufacturer", "");
            data.ProductVersion = properties.GetValueOrDefault("ProductVersion", ""); data.ProductCode = properties.GetValueOrDefault("ProductCode", "");
            data.UpgradeCode = properties.GetValueOrDefault("UpgradeCode", ""); data.Platform = ReadPlatform(database);
            var hidden = properties.GetValueOrDefault("MsiHiddenProperties", "").Split(';', StringSplitOptions.RemoveEmptyEntries);
            data.HiddenProperties = hidden.Take(256).ToList(); data.HiddenPropertiesTruncated = hidden.Length > 256;
            data.LaunchConditions = Query(database, "SELECT `Condition`,`Description` FROM `LaunchCondition`", 2, 64)
                .Select(r => new MsiLaunchCondition { Condition = r[0], Description = r[1] }).ToList();
            var locators = Query(database, "SELECT `Signature_`,`Root`,`Key`,`Name`,`Type` FROM `RegLocator`", 5, 128)
                .GroupBy(r => r[0]).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
            var searches = Query(database, "SELECT `Property`,`Signature_` FROM `AppSearch`", 2, 128);
            data.DirectoryLocators = Query(database, "SELECT `Signature_`,`Parent`,`Path`,`Depth` FROM `DrLocator`", 4, 256)
                .Select(r => new MsiDirectoryLocator { Signature = r[0], Parent = r[1], Path = r[2], Depth = r[3].Length == 0 ? 0 : int.TryParse(r[3], out var depth) ? depth : -1 }).ToList();
            var signatures = Query(database, "SELECT `Signature`,`FileName`,`MinVersion`,`MaxVersion`,`MinSize`,`MaxSize`,`MinDate`,`MaxDate`,`Languages` FROM `Signature`", 9, 256)
                .GroupBy(r => r[0]).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
            foreach (var search in searches.Where(s => data.DirectoryLocators.Any(d => d.Signature == s[1])).Take(64))
            {
                var definition = new MsiFileSearchDefinition { Property = search[0], Signature = search[1], ConditionDescription = ConditionDescriptions(data, search[0]) };
                if (signatures.TryGetValue(search[1], out var row)) definition.File = new() { FileName = row[1], MinVersion = row[2], MaxVersion = row[3], MinSize = row[4], MaxSize = row[5], MinDate = row[6], MaxDate = row[7], Languages = row[8] };
                data.FileSearches.Add(definition);
            }
            foreach (var appSearch in searches)
                if (locators.TryGetValue(appSearch[1], out var locator) && int.TryParse(locator[1], out var root) && int.TryParse(locator[4], out var type))
                    data.RegistryProbes.Add(new() { Property = appSearch[0], Signature = appSearch[1], Root = root, Key = locator[2], Name = locator[3], Type = type,
                        DefaultConfigured = properties.TryGetValue(appSearch[0], out var value) && value.Length > 0,
                        ConditionDescription = ConditionDescriptions(data, appSearch[0]) });
            data.Status = "Read-only metadata";
            var keyPaths = Query(database, "SELECT `Component`,`Attributes`,`KeyPath` FROM `Component`", 3, 4096)
                .Where(r => int.TryParse(r[1], out var flags) && (flags & 4) != 0 && !string.IsNullOrWhiteSpace(r[2]))
                .GroupBy(r => r[2]).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
            foreach (var row in Query(database, "SELECT `Registry`,`Root`,`Key`,`Name`,`Component_` FROM `Registry`", 5, 4096))
            {
                if (data.ApplicationRegistry.Count >= 64) break;
                if (!keyPaths.TryGetValue(row[0], out var component) || row[4] != component[0] || !int.TryParse(row[1], out var registryRoot) || row[3] is "+" or "-" or "*") continue;
                var attributes = int.Parse(component[1]);
                data.ApplicationRegistry.Add(new() { Id = row[0], Root = registryRoot, Key = row[2], Name = row[3], RegistryView = (attributes & 256) != 0 ? "Registry64" : "Registry32" });
            }
            data.Limitations.Add("Launch conditions are declarations, not proof that a prerequisite is absent. Formatted registry paths and complex MSI conditions require evaluation in Sandbox.");
            if (data.FileSearches.Count > 0) data.Limitations.Add("Declared directory/file searches are observed read-only in Sandbox. Recursive, ambiguous, reparse, unresolved and full MSI version/date/language matching may remain unknown.");
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or InvalidDataException or ArgumentException)
        { data.Status = "Read unavailable: " + ex.Message; }
        finally { if (database != 0) MsiCloseHandle(database); }
        return data;
    }

    private static string ConditionDescriptions(MsiMetadata data, string property) => string.Join("; ", data.LaunchConditions
        .Where(c => System.Text.RegularExpressions.Regex.IsMatch(c.Condition, @"\b" + System.Text.RegularExpressions.Regex.Escape(property) + @"\b"))
        .Select(c => c.Description));

    private static List<string[]> Query(uint database, string sql, int columns, int limit)
    {
        var rows = new List<string[]>();
        if (MsiDatabaseOpenView(database, sql, out var view) != 0) return rows; // Optional table may not exist.
        try
        {
            if (MsiViewExecute(view, 0) != 0) return rows;
            while (rows.Count < limit && MsiViewFetch(view, out var record) == 0)
                try { rows.Add(Enumerable.Range(1, columns).Select(field => RecordString(record, (uint)field)).ToArray()); }
                finally { MsiCloseHandle(record); }
        }
        finally { MsiViewClose(view); MsiCloseHandle(view); }
        return rows;
    }
    private static string RecordString(uint record, uint field)
    {
        uint length = 512; var value = new StringBuilder((int)length);
        var status = MsiRecordGetString(record, field, value, ref length);
        if (status == 234)
        {
            if (length > 65536) throw new InvalidDataException("MSI metadata field exceeds the read limit.");
            length++; value = new StringBuilder((int)length); status = MsiRecordGetString(record, field, value, ref length);
        }
        return status == 0 ? value.ToString() : "";
    }
    private static string ReadPlatform(uint database)
    {
        if (MsiGetSummaryInformation(database, null, 0, out var summary) != 0) return "";
        try
        {
            uint length = 512; var value = new StringBuilder((int)length);
            var status = MsiSummaryInfoGetProperty(summary, 7, out _, out _, out _, value, ref length); // PID_TEMPLATE
            if (status != 0) return "";
            return value.ToString().Split(';')[0] switch { "Intel" => "x86", "x64" => "x64", "Arm64" => "ARM64", var other => other };
        }
        finally { MsiCloseHandle(summary); }
    }
    [DllImport("msi.dll", EntryPoint = "MsiOpenDatabaseW", CharSet = CharSet.Unicode)] private static extern uint MsiOpenDatabase(string path, IntPtr mode, out uint database);
    [DllImport("msi.dll", EntryPoint = "MsiDatabaseOpenViewW", CharSet = CharSet.Unicode)] private static extern uint MsiDatabaseOpenView(uint database, string sql, out uint view);
    [DllImport("msi.dll")] private static extern uint MsiViewExecute(uint view, uint record);
    [DllImport("msi.dll")] private static extern uint MsiViewFetch(uint view, out uint record);
    [DllImport("msi.dll")] private static extern uint MsiViewClose(uint view);
    [DllImport("msi.dll")] private static extern uint MsiCloseHandle(uint handle);
    [DllImport("msi.dll", EntryPoint = "MsiRecordGetStringW", CharSet = CharSet.Unicode)] private static extern uint MsiRecordGetString(uint record, uint field, StringBuilder value, ref uint length);
    [DllImport("msi.dll", EntryPoint = "MsiGetSummaryInformationW", CharSet = CharSet.Unicode)] private static extern uint MsiGetSummaryInformation(uint database, string? path, uint updateCount, out uint summary);
    [DllImport("msi.dll", EntryPoint = "MsiSummaryInfoGetPropertyW", CharSet = CharSet.Unicode)] private static extern uint MsiSummaryInfoGetProperty(uint summary, uint property, out uint type, out int integer, out FILETIME filetime, StringBuilder value, ref uint length);
}
