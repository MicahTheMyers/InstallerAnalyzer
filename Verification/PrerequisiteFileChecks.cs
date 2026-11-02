using System.IO;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class PrerequisiteFileChecks
{
    public static void Run(string root, Action<bool, string> check)
    {
        // Create only MSI database tables; no installation session or custom action is run.
        var msiPath = Path.Combine(root, "metadata-only-fixture.msi");
        object? engine = null, database = null;
        try
        {
            engine = Activator.CreateInstance(Type.GetTypeFromProgID("WindowsInstaller.Installer")!);
            database = ((dynamic)engine!).OpenDatabase(msiPath, 3);
            foreach (var sql in new[] {
                "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) PRIMARY KEY `Property`)",
                "CREATE TABLE `AppSearch` (`Property` CHAR(72) NOT NULL, `Signature_` CHAR(72) PRIMARY KEY `Property`)",
                "CREATE TABLE `DrLocator` (`Signature_` CHAR(72) NOT NULL, `Parent` CHAR(72), `Path` CHAR(255), `Depth` SHORT PRIMARY KEY `Signature_`)",
                "CREATE TABLE `Signature` (`Signature` CHAR(72) NOT NULL, `FileName` CHAR(255), `MinVersion` CHAR(20), `MaxVersion` CHAR(20), `MinSize` LONG, `MaxSize` LONG, `MinDate` LONG, `MaxDate` LONG, `Languages` CHAR(255) PRIMARY KEY `Signature`)",
                "INSERT INTO `AppSearch` (`Property`,`Signature_`) VALUES ('RUNTIME','RuntimeFile')",
                "INSERT INTO `DrLocator` (`Signature_`,`Path`,`Depth`) VALUES ('RuntimeFile','C:\\Fixture',0)",
                "INSERT INTO `Signature` (`Signature`,`FileName`,`MinSize`,`MinVersion`) VALUES ('RuntimeFile','runtime.dll',7,'1.2.3')" })
            {
                object? view = null;
                try { view = ((dynamic)database).OpenView(sql); ((dynamic)view).Execute(); }
                finally { if (view is not null) Marshal.FinalReleaseComObject(view); }
            }
            ((dynamic)database).Commit();
        }
        finally
        {
            if (database is not null) Marshal.FinalReleaseComObject(database);
            if (engine is not null) Marshal.FinalReleaseComObject(engine);
        }
        var before = SHA256.HashData(File.ReadAllBytes(msiPath));
        var metadata = MsiMetadataService.Read(msiPath);
        check(metadata.Status == "Read-only metadata" && metadata.FileSearches.Single().File?.MinSize == "7" && metadata.FileSearches[0].File?.MinVersion == "1.2.3", "Real MSI table reader preserves declared file search criteria");
        check(metadata.DirectoryLocators.Single().Path == @"C:\Fixture" && before.SequenceEqual(SHA256.HashData(File.ReadAllBytes(msiPath))), "MSI metadata collection leaves fixture database bytes unchanged");
        var proof = new InstallAnalysis { PrerequisiteFiles = [
            new() { Property = "ABSENT_RUNTIME", Present = false, SignatureMatched = false, Target = @"C:\Fixture\missing.dll" },
            new() { Property = "UNKNOWN_CRITERIA", Present = true, SignatureMatched = null, Version = "1.2.3", SizeBytes = 7 },
            new() { Property = "DENIED", Present = null, Evidence = "Access denied" }] };
        IntelligenceReportService.Enrich(proof, null, null);
        check(proof.Intelligence.Prerequisites.Count == 3 && proof.Intelligence.Prerequisites.All(p => !p.Status.Contains("Required / missing")), "File absence alone never establishes a missing prerequisite");
        check(proof.Intelligence.Prerequisites[1].Status.Contains("not evaluated") && proof.Intelligence.Prerequisites[1].Evidence.Contains("1.2.3"), "Unknown file criteria preserve observed metadata without declaring a match");
        check(proof.Intelligence.Prerequisites[2].Status == "Observation unavailable", "Denied file observation is not absence");
        var folder = Path.Combine(root, "file-prerequisites"); Directory.CreateDirectory(folder);
        IntelligenceReportService.WriteArtifacts(proof, null, folder);
        var roundtrip = JsonSerializer.Deserialize<List<PrerequisiteFileObservation>>(File.ReadAllText(Path.Combine(folder, "prerequisite-files.json")))!;
        check(roundtrip[0].Present == false && roundtrip[1].SignatureMatched is null && roundtrip[2].Present is null, "Diagnostic file evidence preserves false and unknown separately");
    }
}
