using System.Diagnostics;
using System.IO;
using System.Text.Json;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

// Initial component recipe is deliberately bound to the actual tested vendor package.
// Inspecting/extracting a cabinet does not execute any vendor code on the host.
public static partial class GintDeploymentPlanService
{
    public const string Recipe = "Bentley.gINT.10.02.00.04";
    public const string SourceHash = "CAF6D9BC30E98501F1B0F7277549A6498630885F743647F6D54462D83E80A365";
    public const string ProductCode = "{192AEB44-6992-44B8-B66D-D0781DC50768}";
    private static readonly object Gate = new();
    public static ComponentDeploymentPlan Canonical() => new() { Recipe = Recipe, SourceSha256 = SourceHash, Files = new()
    {
        ["gINT.msi"]="DC12B37DB3A1100E3D8F65D61EEE14F25C79CA7E10B0ADB27474F4B6A9A4C2BC",
        ["vc8redist_x86.exe"]="4EE4DA0FE62D5FA1B5E80C6E6D88A4A2F8B3B140C35DA51053D0D7B72A381D29",
        ["vc9redist_x86.exe"]="75E39A5224977F69E0A3A62A46E57DB1F8EC72AAFE11C76CEE7F130713935CFC",
        ["vc14redist_x86.exe"]="DAFB8B5F4B46BFAF7FAA1D0AD05211F5C9855F0005CD603F8B5037B6A708D6B6",
        ["AccessDatabaseEngine.exe"]="2B94903A1B87EA55F4BC28457BE5C602C6194DE7E79B8E22D7B723D5EF351587",
        ["Setup_CONNECTIONclientx64_10_00_17_010.exe"]="AD134FDF567D3A336E1F26991274205D8747889308FCD688E3A30818A43848B2"
    }};
    public static bool IsCanonical(ComponentDeploymentPlan? plan) => plan is not null && plan.Recipe == Recipe &&
        string.Equals(plan.SourceSha256, SourceHash, StringComparison.OrdinalIgnoreCase) && plan.Files is not null && plan.Files.Count == 6 &&
        Canonical().Files.All(f => plan.Files.TryGetValue(f.Key, out var hash) && string.Equals(hash, f.Value, StringComparison.OrdinalIgnoreCase));

    public static ComponentDeploymentPlan? TryStage(string source, string destination)
    {
        var version = FileVersionInfo.GetVersionInfo(source);
        if (!(version.ProductName ?? "").Equals("gINT", StringComparison.OrdinalIgnoreCase) ||
            !(version.CompanyName ?? "").StartsWith("Bentley Systems", StringComparison.OrdinalIgnoreCase)) return null;
        if (!RegressionHistoryService.HashFile(source).Equals(SourceHash, StringComparison.OrdinalIgnoreCase)) return null;
        Stage(source, destination);
        return Canonical();
    }

    public static Dictionary<string, string> ExportSources(string source, ComponentDeploymentPlan plan)
    {
        if (!IsCanonical(plan)) throw new InvalidOperationException("Unsupported or changed component recipe. Run fresh validation.");
        var cache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer", "ComponentPayloads", SourceHash);
        lock (Gate) Stage(source, cache);
        return plan.Files.ToDictionary(f => f.Key, f => Path.Combine(cache, f.Key));
    }

    private static void Stage(string source, string destination)
    {
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(input)).Equals(SourceHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The original gINT source changed. Run fresh validation.");
        Directory.CreateDirectory(destination);
        bool Ready() => Canonical().Files.All(f => File.Exists(Path.Combine(destination, f.Key)) && RegressionHistoryService.HashFile(Path.Combine(destination, f.Key)).Equals(f.Value, StringComparison.OrdinalIgnoreCase));
        if (Ready()) return;
        var cab = BentleyBootstrapperService.Inspect(source, "Bentley Systems") ?? throw new InvalidDataException("The expected gINT cabinet was not found.");
        var scratch = Path.Combine(destination, ".extract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        try
        {
            var cabinet = Path.Combine(scratch, "payload.cab");
            input.Position = cab.CabinetOffset;
            using (var output = File.Create(cabinet))
            {
                var buffer = new byte[1024 * 1024]; long remaining = cab.CabinetBytes;
                while (remaining > 0) { int count = input.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining)); if (count == 0) throw new EndOfStreamException(); output.Write(buffer, 0, count); remaining -= count; }
            }
            var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "expand.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in new[] { "-F:*", cabinet, scratch }) info.ArgumentList.Add(argument);
            using var process = Process.Start(info)!;
            var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(120000)) { try { process.Kill(); } catch { } throw new IOException("gINT cabinet extraction timed out."); }
            if (process.ExitCode != 0) throw new IOException("gINT cabinet extraction failed.");
            foreach (var file in Canonical().Files)
            {
                var path = Path.Combine(scratch, file.Key);
                if (!File.Exists(path) || !RegressionHistoryService.HashFile(path).Equals(file.Value, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("gINT attachment checksum mismatch: " + file.Key);
                File.Copy(path, Path.Combine(destination, file.Key), true);
            }
        }
        finally
        {
            var parent = Path.GetFullPath(destination) + Path.DirectorySeparatorChar;
            if (Path.GetFullPath(scratch).StartsWith(parent, StringComparison.OrdinalIgnoreCase))
            {
                // CAB members can retain their vendor read-only attribute.
                foreach (var file in Directory.EnumerateFiles(scratch, "*", SearchOption.AllDirectories))
                    File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.ReadOnly);
                Directory.Delete(scratch, true);
            }
        }
    }

    private static string PlanPrefix => "$script:IAGintPlan=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(Canonical())) + "'))|ConvertFrom-Json\n";
    public static string InstallScript => PlanPrefix + RecipeScript + "\nInvoke-IAGintInstall\n$Process=[pscustomobject]@{ExitCode=if($script:IAGintReboot){3010}else{0}}\n";
    public static string SandboxScript(ComponentDeploymentPlan plan) =>
        "$script:IAGintPlan=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(plan)) + "'))|ConvertFrom-Json\n" +
        "if($env:USERNAME -ne 'WDAGUtilityAccount' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine'){throw 'Sandbox guest required'}\n" + RecipeScript + "\n$InstallerFolder='C:\\InstallerInput\\Payload'\nInvoke-IAGintPrerequisites\n";
}
