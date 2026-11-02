using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;
using Microsoft.Data.Sqlite;

internal static class RoadmapChecks
{
    public static void Run(string root, Action<bool,string> check)
    {
        var folder = Path.Combine(root, "roadmap"); Directory.CreateDirectory(folder);
        var field = typeof(InstallerCatalogService).GetField("TestDatabasePath", BindingFlags.NonPublic | BindingFlags.Static)!;
        var originalDb = field.GetValue(null);
        field.SetValue(null, Path.Combine(folder, "catalog.db"));
        try
        {
            using (var sqlite = new SqliteConnection("Data Source=:memory:"))
            {
                sqlite.Open();
                using var versionQuery = sqlite.CreateCommand(); versionQuery.CommandText = "SELECT sqlite_version()";
                var nativeVersion = versionQuery.ExecuteScalar()?.ToString();
                check(Version.TryParse(nativeVersion, out var version) && version >= new Version(3, 50, 2),
                    "Loaded native SQLite engine meets the CVE-2025-6965 security baseline (3.50.2 or later)");
            }
            var installerFile = Path.Combine(folder, "package.exe"); File.WriteAllText(installerFile, "package one");
            var installer = new AnalysisResult { FilePath = installerFile, ProductName = "Example Product", CompanyName = "Example",
                Architecture = "x64", Kind = InstallerKind.Nsis, Confidence = 95,
                Identity = new() { Sha256 = RegressionHistoryService.HashFile(installerFile), SignatureStatus = "Valid", SignerThumbprint = "FIXTURE-CERT" } };
            var proof = new InstallAnalysis { ValidationSchemaVersion = 2, SessionId = "first", CapturedAt = DateTimeOffset.UtcNow.ToString("O"),
                InitialInstallValidated = true, InitialUninstallValidated = true, InitialUninstallExitCode = 0, CleanBaselineVerified = true,
                SilentReinstallValidated = true, SilentReinstallExitCode = 0, SilentUninstallValidated = true, SilentUninstallExitCode = 0,
                PostUninstallDetected = false, DiscoverySucceeded = true, PrimaryKey = @"HKLM:\SOFTWARE\Example", DeploymentSource = installerFile,
                CombinedSilentArguments = "/S", UninstallCandidate = "uninstall.exe /S", SelectedSilentStrategy = "NSIS",
                NewUninstallEntries = new() { new() { Key = @"HKLM:\SOFTWARE\Example", DisplayName = "Example Product", DisplayVersion = "1.0", Publisher = "Example" } },
                DetectionStrategies = new() { new() { Type = "RegistryAndVersion", Identity = @"HKLM:\SOFTWARE\Example", RegistryPath = @"HKLM:\SOFTWARE\Example", Version = "1.0",
                    BeforeInstall = false, AfterInstall = true, AfterUninstall = false, Rank = 90 } } };
            check(InstallerCatalogService.Remember(installer, proof, "Test Mode"), "Catalog records complete lifecycle with structured evidence");
            var record = InstallerCatalogService.ReadCatalog().Single();
            check(record.History.Count == 1 && record.History[0].Source == "Test Mode" && record.History[0].DetectionPassed, "Catalog retains per-proof source and detection history");
            check(record.Detection?.Validated == true && record.LocalInstallerPath == installerFile, "Catalog retains validated detection and local source");
            var recovery = JsonSerializer.Deserialize<InstallAnalysis>(JsonSerializer.Serialize(proof))!;
            recovery.ValidationSchemaVersion = 3; recovery.WorkflowStage = "Final absence verification 1/20: detected=False";
            check(!LifecycleValidationService.CanPromoteCheckpoint(recovery) && !LifecycleValidationService.IsComplete(recovery), "Host cannot promote a schema-3 lifecycle before evidence collection completes");
            recovery.EvidenceCollectionComplete = true;
            check(LifecycleValidationService.CanPromoteCheckpoint(recovery) && LifecycleValidationService.IsComplete(recovery), "Host recovery remains available after final evidence has been written");
            var clone = JsonSerializer.Deserialize<InstallAnalysis>(JsonSerializer.Serialize(proof))!; clone.SessionId = "second";
            check(InstallerCatalogService.Remember(installer, clone, "Retest"), "Independent proof adds history");
            var replay = JsonSerializer.Deserialize<InstallAnalysis>(JsonSerializer.Serialize(proof))!;
            check(!InstallerCatalogService.Remember(installer, replay), "Older proof replay after newer proof does not increase count");
            check(InstallerCatalogService.ReadCatalog().Single().Validations == 2, "Validation count agrees with unique proof history");
            InstallerCatalogService.RecordFailure(installer.Identity.Sha256);
            check(InstallerCatalogService.ReadCatalog().Single().Failures == 1, "Failed retest increments failure count without losing strategy");

            var secondFile = Path.Combine(folder, "package-new.exe"); File.WriteAllText(secondFile, "package two");
            AnalysisResult NewVersion(string signer, string status = "Valid") => new() { FilePath = secondFile, ProductName = installer.ProductName, CompanyName = installer.CompanyName,
                Architecture = "x64", Kind = InstallerKind.Nsis, Identity = new() { Sha256 = RegressionHistoryService.HashFile(secondFile), SignatureStatus = status, SignerThumbprint = signer } };
            var related = NewVersion("FIXTURE-CERT");
            check(InstallerCatalogService.ApplyBestMatch(related) && related.CatalogMatch.StartsWith("Related signed") && related.SuggestedArguments == "/S", "Same signed product receives candidate from older version");
            check(!InstallerCatalogService.ApplyBestMatch(NewVersion("OTHER-CERT")), "Different signer cannot inherit a product strategy");
            check(!InstallerCatalogService.ApplyBestMatch(NewVersion("FIXTURE-CERT", "NotSigned")), "Invalid signature cannot inherit a product strategy");
            var wrongProduct = NewVersion("FIXTURE-CERT"); wrongProduct.ProductName = "Other Product";
            check(!InstallerCatalogService.ApplyBestMatch(wrongProduct), "Matching signer alone is insufficient for inheritance");
            check(InstallerCatalogService.ReadCatalog().Single().Validations == 2, "Inheritance never records validation for the new version");
            var exported = Path.Combine(folder, "catalog.json"); InstallerCatalogService.ExportCatalog(exported);
            var transfer = JsonSerializer.Deserialize<CatalogTransfer>(File.ReadAllText(exported))!;
            check(transfer.Entries.Single().LocalInstallerPath.Length == 0, "Catalog export excludes private local installer paths");
            check(InstallerCatalogService.ImportCatalog(exported).Preserved == 1 && InstallerCatalogService.ReadCatalog().Single().Validations == 2, "Import preserves stronger local proof");
            var backup = Path.Combine(folder, "backup.db"); InstallerCatalogService.BackupCatalog(backup);
            check(new FileInfo(backup).Length > 0, "SQLite online backup creates a nonempty consistent snapshot");

            field.SetValue(null, Path.Combine(folder, "fresh.db"));
            var imported = InstallerCatalogService.ImportCatalog(exported);
            check(imported.Imported == 1 && InstallerCatalogService.ReadEntries().Count == 0, "Imported entries do not enter the trusted local catalog");
            check(InstallerCatalogService.ReadCatalog().Single().Validations == 0 && InstallerCatalogService.ReadCatalog().Single().Origin == "Imported candidate", "Imported validation claims remain untrusted");
            var importedCandidate = new AnalysisResult { FilePath = installerFile, Identity = installer.Identity };
            check(InstallerCatalogService.ApplyBestMatch(importedCandidate) && importedCandidate.CatalogMatch.StartsWith("Imported candidate"), "Imported exact hash supplies only a fresh-validation candidate");
            var malformed = Path.Combine(folder, "malformed.json");
            transfer.SchemaVersion = 99; File.WriteAllText(malformed, JsonSerializer.Serialize(transfer));
            try { InstallerCatalogService.ImportCatalog(malformed); check(false, "Unsupported import rejected"); } catch (InvalidDataException) { check(true, "Unsupported import rejected"); }
            transfer.SchemaVersion = 1; transfer.Entries[0].InstallArguments = "/S\nInvoke-Expression test"; File.WriteAllText(malformed, JsonSerializer.Serialize(transfer));
            try { InstallerCatalogService.ImportCatalog(malformed); check(false, "Script-shaped import rejected"); } catch (InvalidDataException) { check(true, "Script-shaped import rejected"); }
            check(InstallerCatalogService.ReadCatalog().Count == 1, "Rejected import leaves prior candidates intact");
            field.SetValue(null, Path.Combine(folder, "restored.db"));
            check(InstallerCatalogService.RestoreCatalog(backup).Imported == 1 && InstallerCatalogService.ReadEntries().Count == 0, "Backup restore safely merges candidates without asserting fresh local proof");
            InstallerCatalogService.RemoveEntry(installer.Identity.Sha256);
            check(InstallerCatalogService.ReadCatalog().Count == 0, "Catalog removal removes its metadata and candidate");

            var msiFixture = Path.Combine(folder, "family-fixture.msi"); File.WriteAllText(msiFixture, "Catalog identity fixture; not an installable MSI");
            var familyInstaller = new AnalysisResult { FilePath = msiFixture, ProductName = "Original MSI Name", Architecture = "x64", Kind = InstallerKind.Msi,
                Identity = new() { SignatureStatus = "Valid", SignerThumbprint = "SAME-SIGNER", Msi = new() { UpgradeCode = "{11111111-2222-3333-4444-555555555555}" } } };
            var familyProof = JsonSerializer.Deserialize<InstallAnalysis>(JsonSerializer.Serialize(proof))!;
            familyProof.DeploymentSource = msiFixture; familyProof.SessionId = "msi-family-proof"; familyProof.CombinedSilentArguments = "/qn /norestart";
            check(InstallerCatalogService.Remember(familyInstaller, familyProof), "MSI family fixture records a known strategy");
            var sameUpgrade = new AnalysisResult { FilePath = secondFile, ProductName = "Renamed MSI Product", Architecture = "x64", Kind = InstallerKind.Msi,
                Identity = new() { SignatureStatus = "Valid", SignerThumbprint = "SAME-SIGNER", Msi = new() { UpgradeCode = familyInstaller.Identity.Msi.UpgradeCode } } };
            check(InstallerCatalogService.ApplyBestMatch(sameUpgrade) && sameUpgrade.SuggestedArguments == "/qn /norestart", "Matching signed MSI UpgradeCode supports renamed-product strategy candidates");
            var conflictingUpgrade = new AnalysisResult { FilePath = secondFile, ProductName = "Original MSI Name", Architecture = "x64", Kind = InstallerKind.Msi,
                Identity = new() { SignatureStatus = "Valid", SignerThumbprint = "SAME-SIGNER", Msi = new() { UpgradeCode = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}" } } };
            check(!InstallerCatalogService.ApplyBestMatch(conflictingUpgrade), "Conflicting MSI UpgradeCode defeats an identical display name");
            check(MsiMetadataService.Read(msiFixture).Status.StartsWith("Read unavailable"), "Malformed MSI metadata fails without installing or repairing anything");
            if (File.Exists(@"D:\WinDirStat-x64.msi"))
            {
                var initialHash = RegressionHistoryService.HashFile(@"D:\WinDirStat-x64.msi");
                var metadata = MsiMetadataService.Read(@"D:\WinDirStat-x64.msi");
                check(metadata.Status == "Read-only metadata" && metadata.ProductName.Contains("WinDirStat") && Guid.TryParse(metadata.ProductCode, out _) && Guid.TryParse(metadata.UpgradeCode, out _),
                    "Real USB MSI exposes product and upgrade identity without executing actions");
                check(metadata.Platform == "x64" && initialHash == RegressionHistoryService.HashFile(@"D:\WinDirStat-x64.msi"), "Read-only MSI inspection preserves source bytes and reads package architecture");
                File.WriteAllText(Path.Combine(folder, "MSI-Metadata-WinDirStat.json"), JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }));
            }

            var diagnosticFolder = Path.Combine(folder, "diagnostic"); Directory.CreateDirectory(diagnosticFolder);
            File.WriteAllText(Path.Combine(diagnosticFolder, "msi-install.log"), "Error: requires .NET Framework 3.5; password=example-secret\nVisual C++ feature action succeeded");
            File.WriteAllText(Path.Combine(diagnosticFolder, "installer.exe"), "DO NOT EXPORT");
            File.WriteAllText(Path.Combine(diagnosticFolder, "unrelated.json"), "{\"private\":\"do not export\"}");
            File.WriteAllText(Path.Combine(diagnosticFolder, "install-analysis.json"), "{\"UiDiagnostics\":[\"raw proof\"],\"BlockedBundledSoftwareVerifiedAbsent\":true}");
            proof.ValidationError = "PREREQUISITE REQUIRED: runtime";
            proof.DiscoveredInstallerFiles.Add(@"C:\Temp\payload.msi");
            proof.ProcessTree.Add(new() { ProcessId = 42, ParentProcessId = 1, Name = "setup.exe", Path = @"C:\Temp\payload.msi" });
            IntelligenceReportService.Enrich(proof, installer, diagnosticFolder);
            check(proof.Intelligence.Prerequisites.Any(p => p.Name == ".NET Framework 3.5" && p.Capability == "NetFx3" && p.Status == "Required / missing evidence" && !p.Provisioned), "Missing NetFx3 is recognized without provisioning");
            check(proof.Intelligence.Prerequisites.Any(p => p.Name == "Visual C++ Redistributable" && p.Status.StartsWith("Observed")), "Runtime mentions do not automatically imply a missing prerequisite");
            installer.Identity.Msi.LaunchConditions.Add(new() { Condition = "NETFRAMEWORK35 OR Installed", Description = ".NET Framework 3.5 is required" });
            proof.PrerequisiteProbes.Add(new() { Property = "NETFRAMEWORK35", ConditionDescription = ".NET Framework 3.5 is required", RegistryView = "Registry32", ValuePresent = false, Evidence = "Registry value absent; condition evaluation unavailable." });
            IntelligenceReportService.Enrich(proof, installer, diagnosticFolder);
            check(proof.Intelligence.Prerequisites.Any(p => p.Name == ".NET Framework 3.5" && p.Status == "Declared; not evaluated") &&
                proof.Intelligence.Prerequisites.Any(p => p.Name.Contains("MSI probe") && p.Status.StartsWith("Registry value absent")),
                "Declared launch conditions and absent registry probes are distinguished from evaluated missing prerequisites");
            check(proof.Intelligence.Payloads.Single().Executed == true && proof.DeploymentSource == installerFile, "Payload execution evidence preserves original deployment source");
            proof.ProcessTree.Clear();
            proof.ProcessTree.Add(new() { ProcessId = 43, ParentProcessId = 1, Name = "msiexec.exe", Path = @"C:\Windows\System32\msiexec.exe", CommandLine = "msiexec.exe /i \"C:\\Temp\\payload.msi\" /qn" });
            proof.ProcessTree.Add(new() { ProcessId = 44, ParentProcessId = 1, Name = "powershell.exe", CommandLine = "powershell Invoke-WebRequest https://example.invalid/file -OutFile 'C:\\Temp\\payload.msi'" });
            IntelligenceReportService.Enrich(proof, installer, diagnosticFolder);
            check(proof.Intelligence.Payloads.Single().ProcessId == 43 && proof.Intelligence.Payloads.Single().Executed == true,
                "MSI payload execution is correlated with exact system msiexec installation arguments");
            check(proof.Intelligence.Payloads.Single().DownloadReferenceProcessId == 44 && proof.Intelligence.Payloads.Single().DownloadEvidence!.Contains("not independently established"),
                "Download-output references retain process identity without claiming successful downloads");
            proof.ProcessTree[0].CommandLine = "msiexec.exe /i C:\\Temp\\payload.msi.other /qn";
            IntelligenceReportService.Enrich(proof, installer, diagnosticFolder);
            check(proof.Intelligence.Payloads.Single().Executed is null, "Payload path prefixes do not fabricate MSI execution evidence");
            check(proof.Intelligence.Nodes.Any(n => n.Role == "Deployment Source") && proof.Intelligence.Edges.Count > 0, "Relationship graph preserves distinct source and mechanism roles");
            IntelligenceReportService.WriteArtifacts(proof, installer, diagnosticFolder);
            check(File.Exists(Path.Combine(diagnosticFolder, "installer-intelligence.json")), "Intelligence report artifacts are written");
            check(File.Exists(Path.Combine(diagnosticFolder, "analysis-summary.json")) && File.Exists(Path.Combine(diagnosticFolder, "relationship-graph.json")) &&
                File.Exists(Path.Combine(diagnosticFolder, "prerequisite-results.json")), "Normalized explanations, prerequisite and graph artifacts are retained for diagnostics");
            var rawEnriched = File.ReadAllText(Path.Combine(diagnosticFolder, "install-analysis.json"));
            check(rawEnriched.Contains("raw proof") && rawEnriched.Contains("BlockedBundledSoftwareVerifiedAbsent"), "Intelligence enrichment preserves unknown raw diagnostics and bundle protection evidence");
            var recordForExport = new RegressionTestRecord { Installer = "Example.exe", Result = "FAIL", ArtifactFolder = diagnosticFolder };
            File.WriteAllText(Path.Combine(diagnosticFolder, "iss-install-replay.log"), "[ResponseResult]\nResultCode=0");
            File.WriteAllText(Path.Combine(diagnosticFolder, "iss-uninstall-replay.log"), "[ResponseResult]\nResultCode=-3");
            File.WriteAllText(Path.Combine(diagnosticFolder, "sandbox-host-startup.json"), "{\"Outcome\":\"Startup failed\"}");
            File.WriteAllText(Path.Combine(diagnosticFolder, "sandbox-guest-startup.json"), "{\"Stage\":\"Guest bootstrap started\"}");
            File.WriteAllText(Path.Combine(diagnosticFolder, "sandbox-guest-startup-error.txt"), "inert bootstrap error");
            File.WriteAllText(Path.Combine(diagnosticFolder, "app-control-evidence.json"), "{\"Status\":\"Available\",\"Blocks\":[]}");
            var zip = Path.Combine(folder, "diagnostics.zip"); var bundle = DiagnosticBundleService.Export(zip, new[] { recordForExport });
            using (var archive = ZipFile.OpenRead(zip))
            {
                check(bundle.Included >= 3 && archive.Entries.All(e => !e.FullName.EndsWith(".exe") && !e.FullName.EndsWith("unrelated.json")), "Diagnostic export includes evidence and excludes installer binaries and arbitrary files");
                var log = archive.Entries.Single(e => e.FullName.EndsWith("msi-install.log"));
                using var reader = new StreamReader(log.Open());
                check(!reader.ReadToEnd().Contains("example-secret"), "Diagnostic logs redact credential values");
                check(archive.Entries.Any(e => e.FullName == "manifest.json"), "Diagnostic bundle records included and omitted evidence");
                check(archive.Entries.Count(e => e.FullName.EndsWith("iss-install-replay.log") || e.FullName.EndsWith("iss-uninstall-replay.log")) == 2,
                    "Diagnostic export preserves successful and failed InstallShield replay logs");
                check(archive.Entries.Count(e => Path.GetFileName(e.FullName).Contains("_sandbox-", StringComparison.Ordinal)) == 3,
                    "Diagnostic export preserves host startup, guest bootstrap and guest script failure evidence");
                check(archive.Entries.Any(e => e.FullName.EndsWith("app-control-evidence.json")), "Diagnostic export retains normalized App Control evidence");
            }
            var missing = new RegressionTestRecord { ArtifactFolder = Path.Combine(folder, "missing") };
            check(DiagnosticBundleService.Export(Path.Combine(folder, "missing.zip"), new[] { missing }).Omitted == 1, "Unavailable source diagnostics are explained without losing normalized result");

            var detectionScript = ValidatedDetectionScriptService.Generate(proof);
            check(detectionScript is not null && detectionScript.Contains("DisplayVersion") && detectionScript.Contains("Lifecycle-tested"), "Detection output uses the selected lifecycle-tested rule");
            proof.DetectionStrategies[0].BeforeInstall = null;
            check(ValidatedDetectionScriptService.Generate(proof) is null, "Unknown before-install state cannot become a validated detection rule");
            proof.DetectionStrategies[0].BeforeInstall = false;
            proof.DetectionStrategies[0].RegistryPath = @"C:\untrusted";
            check(ValidatedDetectionScriptService.Generate(proof) is null, "Registry detection rejects non-registry paths");

            var active = 0; var peak = 0; var executed = new List<int>();
            using var cts = new CancellationTokenSource();
            RegressionQueueExecutor.ExecuteAsync(new[] { 1, 2, 3 }, async (item, token) =>
            {
                peak = Math.Max(peak, ++active); await Task.Delay(1); executed.Add(item); active--;
                if (item == 2) cts.Cancel();
            }, cts.Token).GetAwaiter().GetResult();
            check(peak == 1 && executed.SequenceEqual(new[] { 1, 2 }), "Queue executor is sequential and stops before the next item on cancellation");

            foreach (var kind in Enum.GetValues<InstallerKind>())
            {
                var script = (string)typeof(SandboxIssRecorder).GetMethod("BuildDiscoveryScript", BindingFlags.NonPublic | BindingFlags.Static)!
                    .Invoke(null, new object[] { "fixture'package.exe", kind, "/quiet", "", true, true })!;
                File.WriteAllText(Path.Combine(folder, "Generated-" + kind + ".ps1"), script);
                check(!script.Contains("__ROADMAP_HELPERS__") && !script.Contains("__MSI_METADATA__") && script.Contains("Initialize-DetectionEvidence"), kind + " discovery includes roadmap evidence functions");
            }
            var tokenScript = (string)typeof(SandboxIssRecorder).GetMethod("BuildDiscoveryScript", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, new object[] { "__KIND__.exe", InstallerKind.Nsis, "__ROADMAP_HELPERS__", "", true, true })!;
            check(tokenScript.Contains("C:\\InstallerInput\\__KIND__.exe") && tokenScript.Contains("$BaseSilentArguments = '__ROADMAP_HELPERS__'"),
                "Token-shaped installer names and arguments remain literal data");
            var recordedScript = (string)typeof(SandboxIssRecorder).GetMethod("BuildRecorderScript", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, new object[] { "fixture'package.exe", true, "EXAMPLE='value'" })!;
            File.WriteAllText(Path.Combine(folder, "Generated-InstallShield-Recorder.ps1"), recordedScript);
            File.WriteAllText(Path.Combine(folder, "Generated-RSPile-Recorder.ps1"),
                (string)typeof(SandboxIssRecorder).GetMethod("BuildRecorderScript", BindingFlags.NonPublic | BindingFlags.Static)!
                    .Invoke(null, new object[] { "rsp3033j11s.exe", true, "" })!);
            check(recordedScript.Contains("$RecordResponses = $true") && recordedScript.Contains("ValidationSchemaVersion=3") &&
                recordedScript.Contains("Stop-PayloadTrace") && recordedScript.Contains("$BlockBundledMcAfee = $true"),
                "InstallShield recorder uses the shared schema-3 evidence and protection engine");
            check(recordedScript.Contains("$AdditionalPackageArguments = 'EXAMPLE=''value'''"),
                "InstallShield recording preserves package arguments as literal data");
            check(recordedScript.Contains("Test-InstallShieldResponse $SetupIss") && recordedScript.Contains("Test-InstallShieldReplayLog $replayLog") &&
                recordedScript.Contains("Wait-ApplicationAbsent $primary 'Initial'"),
                "Recorded response creation and both replay logs are checked alongside lifecycle identity");
        }
        finally { field.SetValue(null, originalDb); }
    }
}

