using System.IO;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class RecordedDeploymentChecks
{
    public static int Prepare(string root, string installer, string evidenceFolder)
    {
        var proof=JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(Path.Combine(evidenceFolder,"install-analysis.json")),
            new JsonSerializerOptions{PropertyNameCaseInsensitive=true}) ?? throw new InvalidDataException("Missing analysis");
        if(!proof.InitialInstallValidated || !proof.InitialUninstallValidated || !proof.CleanBaselineVerified ||
           !proof.SilentReinstallValidated || !proof.SilentUninstallValidated || proof.PostUninstallDetected!=false)
            throw new InvalidDataException("A complete recorded lifecycle is required before deployment replay");
        if(!File.Exists(Path.Combine(evidenceFolder,"setup.iss")))throw new FileNotFoundException("Recorded setup.iss is required");
        var primary=proof.NewUninstallEntries.Single(e=>e.Key==proof.PrimaryKey);
        var input=Path.Combine(root,"Input");Directory.CreateDirectory(input);
        var analysis=new InstallerDetector().Analyze(installer);
        if(!analysis.NeedsIss)throw new InvalidDataException("This verifier requires an InstallShield response-file package");
        var arguments=proof.CombinedSilentArguments ?? proof.BaseSilentArguments;
        if(string.IsNullOrWhiteSpace(arguments))throw new InvalidDataException("Validated arguments are required");
        File.WriteAllText(Path.Combine(input,"Install.ps1"),ImmyBotScriptGenerator.Generate(analysis,arguments,primary.DisplayName ?? "Recorded application"));
        File.WriteAllText(Path.Combine(input,"Detect.ps1"),ValidatedDetectionScriptService.Generate(proof) ?? ImmyBotScriptGenerator.GenerateDetection(primary,primary.DisplayName ?? "Recorded application"));
        File.WriteAllText(Path.Combine(input,"Uninstall.ps1"),ImmyBotScriptGenerator.GenerateUninstall(primary,primary.DisplayName ?? "Recorded application",proof));
        ImmyBotPackageExporter.Export(Path.Combine(input,"package.zip"),installer,evidenceFolder,null);
        File.WriteAllText(Path.Combine(input,"deployment-config.json"),JsonSerializer.Serialize(new{InstallerFile=Path.GetFileName(installer),Sha256=RegressionHistoryService.HashFile(installer)}));
        Console.WriteLine("Prepared actual generated deployment scripts/package from completed recording evidence; no installer executed.");
        return 0;
    }
}
