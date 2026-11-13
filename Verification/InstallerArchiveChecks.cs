using System.IO;
using System.IO.Compression;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class InstallerArchiveChecks
{
    public static void Run(string root, Action<bool, string> check)
    {
        var folder = Directory.CreateDirectory(Path.Combine(root, "ArchiveChecks")).FullName;
        var path = Path.Combine(folder, "installer.zip");
        const string entry = @"Setup Files\O'Brien.msi";
        WriteZip(path, "Setup Files/O'Brien.msi", "Data/package.cab", "Data/Empty/");
        check(InstallerArchive.ListInstallers(path).SequenceEqual(new[] { entry }), "ZIP selection shows nested installers by relative path");
        var archive = InstallerArchive.Inspect(path, entry, Path.Combine(folder, "Inspection"), out var installer);
        var stage = Path.Combine(folder, "Staged");
        var stagedInstaller = archive.Stage(stage);
        check(File.Exists(installer) && stagedInstaller == Path.Combine(stage, entry) &&
            File.Exists(Path.Combine(stage, "Data", "package.cab")) && Directory.Exists(Path.Combine(stage, "Data", "Empty")),
            "ZIP staging preserves nested setup, companion files and empty directories");
        var proof = new InstallAnalysis
        {
            InstallerArchiveEntry = entry,
            InstallerArchiveSha256 = archive.Sha256,
            DeploymentSource = @"C:\InstallerArchive\" + entry
        };
        check(archive.SupportsDeployment(proof) && !(archive with { Entry = "Another.msi" }).SupportsDeployment(proof),
            "ZIP proof identifies the exact selected setup");
        proof.DeploymentSource = @"C:\Other\O'Brien.msi";
        check(!archive.SupportsDeployment(proof), "ZIP proof refuses a substituted deployment source with the same name");
        proof.DeploymentSource = @"C:\InstallerArchive\" + entry;
        proof.UninstallCandidate = @"C:\InstallerArchive\Uninstall.exe /S";
        check(!archive.SupportsDeployment(proof), "ZIP exports refuse uninstall commands tied to the Sandbox staging path");
        var app = new UninstallEntry { Key = @"HKLM:\SOFTWARE\IAZipFixture", DisplayName = "ZIP fixture" };
        proof.PrimaryKey = app.Key;
        proof.NewUninstallEntries.Add(app);
        proof.CapturedAt = DateTimeOffset.UtcNow.ToString("o");
        proof.DiscoverySucceeded = proof.SilentReinstallValidated = proof.SilentUninstallValidated = true;
        proof.SilentReinstallExitCode = proof.SilentUninstallExitCode = 0;
        proof.PostUninstallDetected = false;
        proof.InstallerSha256 = RegressionHistoryService.HashFile(installer);
        proof.CombinedSilentArguments = "/qn /norestart";
        proof.UninstallCandidate = "msiexec.exe /x {11111111-1111-1111-1111-111111111111} /qn";
        proof.DetectionStrategies.Add(new() { Type = "UninstallRegistryKey", RegistryPath = app.Key, BeforeInstall = false, AfterInstall = true, AfterUninstall = false, Rank = 90 });
        var source = new AnalysisResult { FilePath = installer, Kind = InstallerKind.Msi, Archive = archive };
        var immy = Path.Combine(folder, "ImmyBot.zip");
        var datto = Path.Combine(folder, "Datto.zip");
        ImmyBotPackageExporter.Export(immy, installer, null, null, archive: archive, proof: proof);
        DattoRmmDeploymentService.Export(datto, source, app, proof, null);
        check(ContainsOriginalZip(immy, archive) && ContainsOriginalZip(datto, archive), "Both deployment kits include the entire validated ZIP");
        var script = ImmyBotScriptGenerator.Generate(source, "/unchecked", "ZIP fixture", proof);
        check(script.Contains("-WorkingDirectory (Split-Path -Parent $Installer)") &&
            script.Contains(proof.CombinedSilentArguments) && !script.Contains("/unchecked"),
            "ZIP deployment uses the validated arguments and the setup directory");
        File.WriteAllText(Path.Combine(folder, "Install.ps1"), script);
        WriteZip(path, "Setup Files/O'Brien.msi", "Data/changed.cab");
        check(Rejects(() => archive.Stage(Path.Combine(folder, "Changed"))), "Changed companion files invalidate ZIP staging even when the MSI is unchanged");
        check(Rejects(() => ImmyBotPackageExporter.Export(immy, installer, null, null, archive: archive, proof: proof)) &&
            Rejects(() => DattoRmmDeploymentService.Export(datto, source, app, proof, null)) &&
            ContainsOriginalZip(immy, archive) && ContainsOriginalZip(datto, archive),
            "Both exports reject changed archives and preserve existing kits");
        var bad = Path.Combine(folder, "unsafe.zip");
        foreach (var names in new[]
        {
            new[] { "setup.exe", "../outside" }, new[] { "setup.exe", "Data/aux.txt" },
            new[] { "setup.exe", "SETUP.EXE" }, new[] { "setup.exe", "Data", "data/x" },
            new[] { "setup.exe", "C:/outside" }, new[] { "setup.exe", "Data/name:stream" }
        })
        {
            WriteZip(bad, names);
            check(Rejects(() => InstallerArchive.ListInstallers(bad)), "ZIP rejects unsafe or ambiguous path " + names[1]);
        }

        var large = Path.Combine(folder, "large.zip");
        WriteZip(large, Enumerable.Range(0, 65_536).Select(i => $"Data/{i}.bin").Append("setup.exe").ToArray());
        check(InstallerArchive.ListInstallers(large).SequenceEqual(new[] { "setup.exe" }),
            "Installer selection supports a ZIP64 installer with over 65,535 entries");
        InstallerArchive.Inspect(large, "setup.exe", Path.Combine(folder, "LargeInspection"), out var largeInstaller);
        check(File.Exists(largeInstaller), "Installer inspection extracts the selected setup from a large ZIP");
    }

    private static bool ContainsOriginalZip(string path, InstallerArchive archive)
    {
        using var zip = ZipFile.OpenRead(path);
        using var payload = zip.GetEntry(InstallerArchive.AttachmentName)!.Open();
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload)) == archive.Sha256;
    }

    private static bool Rejects(Action action)
    {
        try { action(); return false; }
        catch (InvalidDataException) { return true; }
    }

    private static void WriteZip(string path, params string[] entries)
    {
        using var stream = File.Create(path);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Create);
        foreach (var name in entries)
        {
            using var writer = new StreamWriter(zip.CreateEntry(name).Open());
            if (!name.EndsWith('/')) writer.Write("fixture");
        }
    }
}
