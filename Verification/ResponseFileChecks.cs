using System.IO;
using System.IO.Compression;
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
    }
}
