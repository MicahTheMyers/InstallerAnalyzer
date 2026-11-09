using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows.Controls;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class ComponentCatalogChecks
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };
    public static void Ui(MainWindow window, Action<bool,string> check)
    {
        var row = new CatalogRecord { Product = "gINT", ComponentDeployment = GintDeploymentPlanService.Canonical(), SandboxCompatibility = new() { Requested = true, Status = "Prepared", Detail = "Guest-only legacy compatibility was used." } };
        var list = (ListBox)window.FindName("CatalogList"); var previous = list.ItemsSource;
        try
        {
            list.ItemsSource = new[] { row }; list.SelectedIndex = 0;
            var text = ((TextBox)window.FindName("CatalogDetailsText")).Text;
            check(row.Display.Contains("Component recipe") && row.ComponentDeployment.Files.Keys.All(text.Contains), "Catalog UI identifies component recipes and lists all six required attachments");
            check(text.Contains(GintDeploymentPlanService.SourceHash) && text.Contains(row.SandboxCompatibility.Detail), "Catalog UI retains source hash and guest security context");
        }
        finally { list.ItemsSource = previous; }
    }

    public static int SavedProof(string root, string installer, string evidence, bool recover)
    {
        var field = typeof(InstallerCatalogService).GetField("TestDatabasePath", BindingFlags.Static | BindingFlags.NonPublic)!;
        var original = field.GetValue(null);
        var source = new InstallerDetector().Analyze(installer);
        InstallAnalysis Proof() => JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(Path.Combine(evidence, "install-analysis.json")), Json)!;
        int checks = 0;
        void Check(bool value, string name) { if (!value) throw new InvalidDataException(name); checks++; Console.WriteLine("PASS " + name); }
        try
        {
            if (!recover) field.SetValue(null, Path.Combine(root, "component-catalog.db"));
            else if (File.Exists(InstallerCatalogService.DatabasePath)) InstallerCatalogService.BackupCatalog(Path.Combine(root, "catalog-before-recovery.db"));
            var proof = Proof();
            Check(LifecycleValidationService.IsComplete(proof), "Saved evidence contains a complete actual gINT lifecycle");
            bool added = InstallerCatalogService.Remember(source, proof, recover ? "Recovered Sandbox validation" : "Component catalog verification");
            var record = InstallerCatalogService.ReadCatalog().Single(r => r.Sha256 == GintDeploymentPlanService.SourceHash);
            Check(added || record.ComponentDeployment is not null, "Complete component proof is recorded in the catalog");
            Check(GintDeploymentPlanService.IsCanonical(record.ComponentDeployment) && record.ComponentDeployment!.Files.Count == 6, "Catalog round trip preserves the complete attachment manifest");
            Check(record.InstallArguments == "" && record.History.Any(h => h.ProofId == proof.SessionId && h.InstallArguments == ""), "Component history never stores MSI switches as outer-EXE arguments");
            Check(record.History.Any(h => GintDeploymentPlanService.IsCanonical(h.ComponentDeployment) && h.SandboxCompatibility.Prepared), "Per-proof history retains recipe and guest compatibility evidence");
            var exact = new InstallerDetector().Analyze(installer); exact.SuggestedArguments = "/old-fixture-arguments";
            Check(InstallerCatalogService.ApplyExactMatch(exact) && exact.SuggestedArguments == "" && exact.CatalogMatch == "Exact validated component recipe", "Exact catalog match selects a recipe without replaying child arguments");
            if (recover)
            {
                record.LocalInstallerPath = "";
                File.WriteAllText(Path.Combine(root, "gINT-Component-Catalog.json"), JsonSerializer.Serialize(new CatalogTransfer { Entries = new() { record } }, Json));
                File.WriteAllText(Path.Combine(root, "acceptance.json"), JsonSerializer.Serialize(new { Passed = true, Checks = checks, LocalCatalog = InstallerCatalogService.DatabasePath, record.Product, Recipe = record.ComponentDeployment }, Json));
                return 0;
            }
            Check(!InstallerCatalogService.Remember(source, Proof()), "Replaying the same saved proof cannot increment catalog counts");
            var changed = Proof(); changed.ComponentDeployment!.Files["gINT.msi"] = new string('0',64);
            Check(!InstallerCatalogService.Remember(source, changed), "Altered attachment manifest is refused");
            changed = Proof(); changed.SilentReinstallValidated = false;
            Check(!InstallerCatalogService.Remember(source, changed), "Incomplete lifecycle cannot create a component entry");
            changed = Proof(); changed.NewUninstallEntries.First(e => e.Key == changed.PrimaryKey).ProductCode = "{00000000-0000-0000-0000-000000000001}";
            Check(!InstallerCatalogService.Remember(source, changed), "A prerequisite identity cannot be recorded as gINT");
            changed = Proof(); changed.ComponentDeployment = null; changed.DeploymentMechanism = "Bootstrapper";
            Check(!InstallerCatalogService.Remember(source, changed), "Generic extracted payloads remain refused without a supported recipe");
            var otherFile = Path.Combine(root, "different-package.exe"); File.WriteAllText(otherFile, "Inert changed-source fixture; never execute.");
            var otherSource = new AnalysisResult { FilePath = otherFile, ProductName = source.ProductName, CompanyName = source.CompanyName, Kind = InstallerKind.Bootstrapper, Architecture = source.Architecture,
                Identity = new() { Sha256 = RegressionHistoryService.HashFile(otherFile), SignatureStatus = "Valid", SignerThumbprint = source.Identity.SignerThumbprint } };
            Check(!InstallerCatalogService.Remember(otherSource, Proof()), "Different source bytes cannot inherit the saved component validation");
            Check(!InstallerCatalogService.ApplyBestMatch(otherSource), "Component recipes are never reused as related-version command-line candidates");
            var transfer = Path.Combine(root, "component-catalog.json"); InstallerCatalogService.ExportCatalog(transfer);
            var shared = JsonSerializer.Deserialize<CatalogTransfer>(File.ReadAllText(transfer), Json)!;
            Check(shared.Entries.Single().LocalInstallerPath == "" && GintDeploymentPlanService.IsCanonical(shared.Entries.Single().ComponentDeployment), "Portable catalog preserves recipe data without a local path");
            var backup = Path.Combine(root, "component-backup.db"); InstallerCatalogService.BackupCatalog(backup);
            field.SetValue(null, Path.Combine(root, "imported-catalog.db"));
            Check(InstallerCatalogService.ImportCatalog(transfer).Imported == 1, "Component recipe catalog imports successfully");
            var imported = InstallerCatalogService.ReadCatalog().Single();
            Check(imported.Origin == "Imported candidate" && imported.Validations == 0 && imported.History.All(h => h.Source == "Imported / unverified") && GintDeploymentPlanService.IsCanonical(imported.ComponentDeployment), "Imported recipe retains attachments without claiming local validation");
            var candidate = new InstallerDetector().Analyze(installer);
            Check(!InstallerCatalogService.ApplyExactMatch(candidate) && InstallerCatalogService.ApplyBestMatch(candidate) && candidate.SuggestedArguments == "" && candidate.CatalogMatch.StartsWith("Imported component recipe"), "Imported recipe remains a fresh-validation candidate with no executable arguments");
            shared.Entries.Single().ComponentDeployment!.Files["gINT.msi"] = new string('0',64);
            var invalid = Path.Combine(root, "invalid-catalog.json"); File.WriteAllText(invalid, JsonSerializer.Serialize(shared, Json));
            bool rejected = false; try { InstallerCatalogService.ImportCatalog(invalid); } catch (InvalidDataException) { rejected = true; }
            Check(rejected && InstallerCatalogService.ReadCatalog().Count == 1, "Altered imported recipe is rejected without changing existing entries");
            field.SetValue(null, Path.Combine(root, "restored-catalog.db"));
            Check(InstallerCatalogService.RestoreCatalog(backup).Imported == 1 && GintDeploymentPlanService.IsCanonical(InstallerCatalogService.ReadCatalog().Single().ComponentDeployment), "Backup restore preserves the recipe as an unverified candidate");
            File.WriteAllText(Path.Combine(root, "acceptance.json"), JsonSerializer.Serialize(new { Passed = true, Checks = checks, Source = evidence }, Json));
            return 0;
        }
        finally { field.SetValue(null, original); }
    }
}
