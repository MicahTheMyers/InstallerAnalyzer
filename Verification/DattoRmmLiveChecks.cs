using System.IO;
using System.IO.Compression;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class DattoRmmLiveChecks
{
    public static int Prepare(string root,string installer,string evidence)
    {
        var proof=JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(Path.Combine(evidence,"install-analysis.json")),new JsonSerializerOptions{PropertyNameCaseInsensitive=true})!;
        var source=new InstallerDetector().Analyze(installer);
        var entry=proof.NewUninstallEntries.Single(e=>e.Key==proof.PrimaryKey);
        var input=Path.Combine(root,"Input");Directory.CreateDirectory(input);
        var kit=Path.Combine(input,"kit.zip");DattoRmmDeploymentService.Export(kit,source,entry,proof,evidence);
        using var zip=ZipFile.OpenRead(kit);
        var guard=Path.Combine(input,"guard");Directory.CreateDirectory(guard);
        foreach(var name in new[]{"Component.cmd","DattoComponent.ps1"})zip.GetEntry(name)!.ExtractToFile(Path.Combine(guard,name));
        Console.WriteLine("Prepared Datto RMM kit from real completed recording proof; no installer executed.");return 0;
    }
}
