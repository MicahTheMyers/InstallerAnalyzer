using System.IO;
using System.IO.Compression;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class ResponseFileChecks
{
    public static void Run(string root,Action<bool,string> check)
    {
        var folder=Path.Combine(root,"response files [fixture] O'Brien"); Directory.CreateDirectory(folder);
        var installer=Path.Combine(folder,"setup.exe");File.WriteAllText(installer,"inert fixture; never executed");
        var analysis=new AnalysisResult {FilePath=installer,Kind=InstallerKind.InstallShield,NeedsIss=true};
        File.WriteAllText(Path.Combine(folder,"Install.ps1"),ImmyBotScriptGenerator.Generate(analysis,"/s","Fixture"));
        File.WriteAllText(Path.Combine(folder,"Wrapped-Install.ps1"),ImmyBotScriptGenerator.Generate(analysis,
            "/s /a /s /f1\"C:\\InstallerOutput\\setup.iss\" /f2\"C:\\InstallerOutput\\replay.log\" /tag=O'Brien{fixture}","Fixture"));
        var entry=new UninstallEntry {DisplayName="Fixture",UninstallString="\"C:\\Program Files\\Fixture\\uninstall.exe\""};
        var proof=new InstallAnalysis {SilentUninstallValidated=true,UninstallResponseFileCreated=true};
        File.WriteAllText(Path.Combine(folder,"Uninstall.ps1"),ImmyBotScriptGenerator.GenerateUninstall(entry,"Fixture",proof));
        check(File.ReadAllText(Path.Combine(folder,"Install.ps1")).Contains("-LiteralPath $ResponseFile -PathType Leaf"),"Response script requires a literal existing response file");
        var setup=Path.Combine(folder,"setup.iss");var uninstall=Path.Combine(folder,"uninstall.iss");
        File.WriteAllText(setup,"[InstallShield Silent]\r\nVersion=v7.00\r\n"); File.WriteAllText(uninstall,"[InstallShield Silent]\r\nVersion=v7.00\r\nUninstall=yes\r\n");
        File.WriteAllText(Path.Combine(folder,"unrelated.txt"),"not packaged");
        var zip=Path.Combine(root,"response-package.zip");ImmyBotPackageExporter.Export(zip,installer,folder,null);
        using(var archive=ZipFile.OpenRead(zip))
        {
            check(archive.Entries.Select(e=>e.FullName).Order().SequenceEqual(new[]{"setup.exe","setup.iss","uninstall.iss"}),"Response package contains both response files and the selected installer only");
            foreach(var name in new[]{"setup.iss","uninstall.iss"})
            { using var reader=new StreamReader(archive.GetEntry(name)!.Open());check(reader.ReadToEnd()==File.ReadAllText(Path.Combine(folder,name)),"Response package preserves exact "+name+" contents"); }
        }
        const string productKey = @"Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Fixture";
        var media = new InstallerArchive("installer.zip", @"Product\setup.exe", new string('A', 64));
        var recorded = new InstallAnalysis
        {
            InstallerSha256 = RegressionHistoryService.HashFile(installer),
            InstallerArchiveSha256 = media.Sha256,
            InstallerArchiveEntry = media.Entry,
            PrimaryKey = "prerequisite",
            InitialInstallValidated = true,
            InitialUninstallValidated = true,
            InitialUninstallExitCode = 0,
            CleanBaselineVerified = true,
            UninstallResponseFileCreated = true,
            UninstallCandidate = entry.UninstallString,
            DetectionStrategies = [new() { Type = "UninstallRegistryKey", RegistryPath = productKey, BeforeInstall = false, AfterInstall = true }]
        };
        var report = Path.Combine(root, "recorded-output.zip");
        using (var output = ZipFile.Open(report, ZipArchiveMode.Create))
        {
            output.CreateEntryFromFile(setup, "Output/setup.iss");
            output.CreateEntryFromFile(uninstall, "Output/uninstall.iss");
            using var stream = output.CreateEntry("Output/install-analysis.json").Open();
            JsonSerializer.Serialize(stream, recorded);
        }
        var replay = RecordedSandboxReplay.FromZip(report);
        replay.VerifySource(installer, media);
        check(replay.RegistryKey == productKey && replay.Setup.SequenceEqual(File.ReadAllBytes(setup)) &&
            replay.Uninstall.SequenceEqual(File.ReadAllBytes(uninstall)), "Replay loads exact response bytes and uses the original installed product identity");
        bool rejected = false;
        try { replay.VerifySource(installer, media with { Entry = @"Other\setup.exe" }); }
        catch (InvalidDataException) { rejected = true; }
        check(rejected, "Replay rejects a different setup entry from the same installer ZIP");
    }
}
