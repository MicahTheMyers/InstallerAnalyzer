using System.IO;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class FullRoadmapChecks
{
    public static void Run(string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "full-roadmap"); Directory.CreateDirectory(folder);
        var results = Path.Combine(folder, "legacy-results"); var legacy = Path.Combine(results, "2026-10-27_Regression-Test");
        var app = Path.Combine(legacy, "Example"); Directory.CreateDirectory(app);
        var recordedHash = new string('A', 64);
        var summary = new { Version = "0.12.7", Mode = "SilentOnlyUnattended", Started = "2026-10-27T19:00:00-07:00", Completed = "2026-10-27T19:10:00-07:00", Stopped = false,
            Tests = new[] { new { Installer = "Example.exe", Result = "PASS", ProductName = "Example", Publisher = "Publisher", InstallerType = "Nsis", Install = "PASS", Uninstall = "PASS", Removal = "PASS", DurationSeconds = 60.0 } } };
        var summaryPath = Path.Combine(legacy, "Summary.json"); File.WriteAllText(summaryPath, JsonSerializer.Serialize(summary));
        var sourceBytes = File.ReadAllBytes(summaryPath);
        File.WriteAllText(Path.Combine(app, "regression-result.json"), JsonSerializer.Serialize(summary.Tests[0]));
        File.WriteAllText(Path.Combine(app, "install-analysis.json"), JsonSerializer.Serialize(new { Installer = "Example.exe", InstallerSha256 = recordedHash }));
        var history = new RegressionHistoryService(Path.Combine(folder, "history"));
        var imported = history.ImportLegacyRuns(results);
        check(imported.Imported == 1 && imported.Warnings.Count == 0, "Completed historical summaries migrate into persistent run history");
        var migrated = history.Load().Single();
        check(migrated.Tests.Single().InstallerSha256 == recordedHash && migrated.Tests.Single().ArtifactFolder == app, "Migration recovers only a recorded matching installer hash and diagnostics folder");
        check(migrated.Provenance.StartsWith("Legacy") && migrated.Tests.Single().Result == "PASS", "Legacy outcomes retain their source provenance rather than claiming new validation");
        check(history.BaselineId() is null && sourceBytes.SequenceEqual(File.ReadAllBytes(summaryPath)), "Migration leaves the saved baseline and source summary unchanged");
        check(history.ImportLegacyRuns(results).Preserved == 1 && history.Load().Count == 1, "Repeated migration is idempotent");
        var duplicateFolder = Path.Combine(results, "Copied legacy run"); Directory.CreateDirectory(duplicateFolder);
        File.WriteAllBytes(Path.Combine(duplicateFolder, "Summary.json"), sourceBytes);
        check(history.ImportLegacyRuns(results).Imported == 0 && history.Load().Count == 1, "Copied identical summaries do not duplicate history");
        var ambiguous = Path.Combine(results, "Unknown recorded identity"); Directory.CreateDirectory(ambiguous);
        File.WriteAllText(Path.Combine(ambiguous, "Summary.json"), JsonSerializer.Serialize(new { summary.Version, summary.Mode, summary.Started, Completed = "2026-10-27T19:15:00-07:00", summary.Tests }));
        var today = Path.Combine(folder, "TestInstallers"); Directory.CreateDirectory(today); File.WriteAllText(Path.Combine(today, "Example.exe"), "Different installer bytes today");
        history.ImportLegacyRuns(results);
        var identityUnknown = history.Load().Single(r => r.ArtifactFolder == ambiguous).Tests.Single();
        check(identityUnknown.InstallerSha256.Length == 0, "Migration never backfills old hashes from today's same-named installer");
        var modern = new RegressionRun { Completed = DateTimeOffset.UtcNow, Tests = new() { new() { Installer = "Modern.exe", Result = "PASS" } } };
        history.Save(modern);
        var modernFolder = Path.Combine(results, "Modern_" + modern.Id); Directory.CreateDirectory(modernFolder);
        File.WriteAllText(Path.Combine(modernFolder, "Summary.json"), JsonSerializer.Serialize(new { RunId = modern.Id }));
        check(history.ImportLegacyRuns(results).Imported == 0, "Modern runs already present in history are not remigrated");
        var corrupt = Path.Combine(results, "Corrupt"); Directory.CreateDirectory(corrupt); File.WriteAllText(Path.Combine(corrupt, "Summary.json"), "{bad");
        check(history.ImportLegacyRuns(results).Warnings.Count == 1 && history.Load().Count == 3, "Malformed historical summaries are reported without hiding valid history");

        var proof = new InstallAnalysis { DetectionStrategies = new()
        {
            new() { Type = "ExecutablePathAndVersion", Identity = @"C:\Program Files\Example\Example.exe", Version = "1.2.3", Rank = 75, BeforeInstall = false, AfterInstall = true, AfterUninstall = false },
            new() { Type = "UninstallRegistryKey", Identity = @"HKLM:\SOFTWARE\Example", RegistryPath = @"HKLM:\SOFTWARE\Example", Rank = 90, BeforeInstall = false, AfterInstall = true, AfterUninstall = false }
        } };
        check(ValidatedDetectionScriptService.Generate(proof)!.Contains("UninstallRegistryKey"), "Validated registry identity outranks an executable-version fallback");
        proof.DetectionStrategies.RemoveAt(1);
        var fileScript = ValidatedDetectionScriptService.Generate(proof)!;
        check(fileScript.Contains("FileVersionInfo") && fileScript.Contains("1.2.3") && fileScript.Contains("ObjectNotFound"), "Executable-version detection tests the recorded version and distinguishes access failures from absence");
        proof.DetectionStrategies[0].BeforeInstall = null;
        check(ValidatedDetectionScriptService.Generate(proof) is null, "An incomplete file baseline cannot validate executable detection");
        proof.DetectionStrategies = new() { new() { Type = "ServiceAndExecutable", Identity = "ExampleSvc", ExecutablePath = @"C:\Program Files\Example\service.exe", Rank = 70,
            BeforeInstall = false, AfterInstall = true, AfterUninstall = false } };
        var combination = ValidatedDetectionScriptService.Generate(proof)!;
        check(combination.Contains("ServiceName -eq") && combination.Contains("service.exe") && !combination.Contains("Get-Service -Name"), "Service/executable detection uses exact service identity and the recorded executable");
        proof.DetectionStrategies = new() { new() { Type = "InstallationDirectory", Identity = @"C:\Program Files\Example", Rank = 40, BeforeInstall = false, AfterInstall = true, AfterUninstall = false } };
        check(ValidatedDetectionScriptService.Generate(proof)!.Contains("PSIsContainer"), "Lifecycle-tested directory fallback requires a directory rather than any same-named file");
        var missingRuntime = new InstallAnalysis { SilentReinstallUiDetected = true, Intelligence = new() { Prerequisites = new() { new() { Status = "Missing", Name = ".NET Framework 3.5" } } } };
        check(FailureClassificationService.Classify("FAIL", "Installer needs a runtime", missingRuntime, "Install").Category == FailureCategory.PrerequisiteMissing,
            "A known missing prerequisite is more informative than generic installer UI");
        var signIn = new InstallAnalysis { SilentReinstallUiDetected = true, SilentReinstallVisibleWindows = new() { "12 :: Sign in to install Example" } };
        check(FailureClassificationService.Classify("FAIL", "UI blocked", signIn, "Install").Category == FailureCategory.AuthenticationRequired,
            "Installer sign-in UI is classified as an authentication requirement");
        var rebootAndFailure = new InstallAnalysis { RebootRequired = true, SilentUninstallExitCode = 1603, WorkflowStage = "Final uninstall" };
        check(FailureClassificationService.Classify("FAIL", "Uninstall failed", rebootAndFailure, "Sandbox lifecycle").Category == FailureCategory.UninstallerExitCodeFailure,
            "An earlier reboot flag does not hide a concrete uninstall failure");
        var driverOnly = new InstallAnalysis { Components = new() { new() { Kind = "Driver", Name = "ExampleDriver", AfterInstall = true } } };
        var driverFailure = FailureClassificationService.Classify("FAIL", "No primary application could be identified", driverOnly, "Discovery");
        check(driverFailure.Category == FailureCategory.UnsupportedDriverInstallation && driverFailure.Infrastructure,
            "Observed driver changes with unsupported lifecycle proof are distinguished from installer regressions");
        check(FailureClassificationService.Classify("FAIL", "No candidate silent-install strategy passed unattended validation", null, "Install").Category == FailureCategory.NoSilentStrategy,
            "Exhausted candidate discovery receives the structured no-strategy category");

        proof.DetectionStrategies = new() { new() { Type = "MsiProductCode", Provider = "WindowsInstallerProductState", Identity = "{11111111-1111-1111-1111-111111111111}", Rank = 100,
            BeforeInstall = false, AfterInstall = true, AfterUninstall = false } };
        var native = ValidatedDetectionScriptService.Generate(proof)!;
        check(native.Contains("ProductState") && native.Contains("state -eq -1") && native.Contains("FinalReleaseComObject") && !native.Contains("Win32_Product"),
            "MSI detection without an uninstall key uses read-only product state and releases its COM object");
        proof.DetectionStrategies[0].Identity = "invalid product code";
        check(ValidatedDetectionScriptService.Generate(proof) is null, "Malformed native MSI identities cannot generate detection code");
        proof.DetectionStrategies = new() { new() { Type = "ApplicationRegistryValue", RegistryHive = "LocalMachine", RegistryView = "Registry64", RegistrySubKey = @"Software\Example's App", ValueName = "Installed",
            BeforeInstall = false, AfterInstall = true, AfterUninstall = false } };
        var registry = ValidatedDetectionScriptService.Generate(proof)!;
        check(registry.Contains("Registry64") && registry.Contains("Example''s App") && registry.Contains("GetValueNames") && !registry.Contains(".GetValue("),
            "Application registry detection preserves the measured view and escapes data without reading raw values");
        proof.DetectionStrategies[0].RegistryHive = "ClassesRoot";
        check(ValidatedDetectionScriptService.Generate(proof) is null, "Unsupported application registry roots cannot generate a weaker substituted rule");

        var source = new AnalysisResult { FilePath = "Example.exe", ProductName = "Example", CompanyName = "Publisher" };
        source.Identity.Msi.LaunchConditions.Add(new() { Condition = "SUPPORT_PRESENT", Description = "Example requires Support Component to be installed" });
        var products = new InstallAnalysis { PrimaryKey = "primary", NewUninstallEntries = new()
        {
            new() { Key = "primary", DisplayName = "Example", Publisher = "Publisher" },
            new() { Key = "runtime", DisplayName = "Microsoft Visual C++ 2022 Redistributable" },
            new() { Key = "dependency", DisplayName = "Support Component" },
            new() { Key = "optional", DisplayName = "Additional Toolbar" },
            new() { Key = "unwanted", DisplayName = "McAfee WebAdvisor" },
            new() { Key = "unknown", DisplayName = "Unrelated Tool", Publisher = "Publisher" }
        }, UiTextEvidence = new() { new() { Labels = new() { "Also install Additional Toolbar (optional)" } } } };
        var roles = BundledProductClassificationService.Classify(source, products);
        check(roles.Select(r => r.Role).SequenceEqual(Enum.GetValues<InstalledProductRole>()),
            "Observed product relationships distinguish primary, runtime, declared dependency, explicit offer, policy bundle and unknown roles");
        check(roles[1].DisplayRole.Contains("candidate") && roles[1].EvidenceStrength.Contains("unverified") && roles[5].Reasons.Single().Contains("Matching publishers alone"),
            "A runtime name or matching publisher does not assert a proven requirement");
        IntelligenceReportService.Enrich(products, source, null);
        check(products.Intelligence.Nodes.Any(n => n.Role == "Optional bundled software") && products.Intelligence.InstalledProducts.Count == 6,
            "The persisted relationship graph uses evidence-backed bundle classifications");
        var unscoped = new InstallAnalysis { Components = new() { new() { Kind = "Service", Name = "UnrelatedService", BeforeInstall = false, AfterInstall = true, AfterUninstall = false } },
            DiscoveredInstallerFiles = new() { @"C:\Temp\setup.iss", @"C:\Temp\settings.config", @"C:\Temp\archive.cab" }, PayloadScanIncomplete = true };
        IntelligenceReportService.Enrich(unscoped, source, null);
        check(unscoped.DetectionStrategies.Count == 0, "A machine-wide service delta cannot silently become product detection evidence");
        check(unscoped.Intelligence.Payloads.Select(p => p.Role).SequenceEqual(new[] { "Response file candidate", "Configuration file candidate", "Archive candidate" }) &&
            unscoped.Intelligence.Limitations.Any(l => l.Contains("boundary")), "Payload inspection classifies supporting files and exposes incomplete scanning");
        var labelFailure = new InstallAnalysis { SilentReinstallUiDetected = true, UiTextEvidence = new() { new() { Labels = new() { "Sign in to install Example" } } } };
        check(FailureClassificationService.Classify("FAIL", "UI blocked", labelFailure, "Install").Category == FailureCategory.AuthenticationRequired,
            "Installer-owned static labels can explain an otherwise generic UI failure");
        var negative = new InstallAnalysis { InstallerExitCode = 0, ValidationError = ".NET Framework 3.5 is not required", UiTextEvidence = new() { new() { Labels = new() { "No restart required" } } } };
        IntelligenceReportService.Enrich(negative, null, null);
        check(negative.Intelligence.Prerequisites.All(p => p.Status == "Observed; requirement not established") &&
            FailureClassificationService.Classify("FAIL", "Incomplete evidence", negative, "Install").Category != FailureCategory.RebootRequired,
            "Negated prerequisite and reboot messages cannot manufacture requirements");
        check(FailureClassificationService.Classify("FAIL", "Bootstrapper became idle without an identifiable installed application", new(), "Discovery").Category == FailureCategory.DetectionFailure,
            "An explicit identity-discovery failure is not hidden by an unset default process exit");
    }
}
