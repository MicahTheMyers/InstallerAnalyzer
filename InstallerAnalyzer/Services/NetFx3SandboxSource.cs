using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace InstallerAnalyzer.Services;

// Only local Windows component resources are staged. No host feature/policy is changed.
public static class NetFx3SandboxSource
{
    internal static string? TestWindowsFolder;
    internal static bool IsResourceComponent(string name) =>
        Regex.IsMatch(name, @"^(?:amd64|x86|wow64)_[a-z0-9._-]+_(?:31bf3856ad364e35|b03f5f7f11d50a3a)_[0-9.]+_[a-z0-9._-]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) &&
        Regex.IsMatch(name, @"wcf|wwf|wpf|netfx|presentation|windowsbase|mscor|clr|system.workflow", RegexOptions.IgnoreCase) &&
        Regex.IsMatch(name, @"resources|perf|_exe_cnf", RegexOptions.IgnoreCase);

    public static void Stage(string input)
    {
        var root = Path.Combine(TestWindowsFolder ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS");
        var target = Path.Combine(input, "NetFx3RepairSource");
        var entries = new List<object>(); long total = 0; int count = 0;
        try
        {
            foreach (var directory in new DirectoryInfo(root).EnumerateDirectories().Where(d => IsResourceComponent(d.Name)).OrderBy(d => d.Name).Take(256))
            {
                if (directory.LinkTarget is not null || !File.Exists(Path.Combine(root,"Manifests",directory.Name+".manifest"))) continue;
                var files = directory.EnumerateFiles().ToArray();
                if (files.Length == 0 || files.Length > 32 || files.Any(f => f.LinkTarget is not null) || count + files.Length > 512 || total + files.Sum(f => f.Length) > 64L*1024*1024) continue;
                var destination = Path.Combine(target,directory.Name); Directory.CreateDirectory(destination);
                var hashes = new List<object>();
                foreach (var file in files)
                {
                    var copy = Path.Combine(destination,file.Name); File.Copy(file.FullName,copy);
                    using var stream = File.OpenRead(copy);
                    hashes.Add(new { Name=file.Name, Sha256=Convert.ToHexString(SHA256.HashData(stream)), Bytes=file.Length });
                }
                entries.Add(new { Component=directory.Name, Files=hashes }); total += files.Sum(f => f.Length); count += files.Length;
            }
            Directory.CreateDirectory(target);
            File.WriteAllText(Path.Combine(target,"source-manifest.json"), JsonSerializer.Serialize(new { Schema=1, Bytes=total, Entries=entries }));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Provisioning still reports a bounded guest failure if this optional source is unavailable.
            File.WriteAllText(Path.Combine(input,"netfx3-source-unavailable.txt"), "Matching Windows .NET resource files could not be staged.");
        }
    }
}
