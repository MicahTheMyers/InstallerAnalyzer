using System.IO;
using System.Reflection;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class RecordingCatalogChecks
{
    public static void Ui(InstallerAnalyzer.MainWindow window, Action<bool,string> check)
    {
        var list = (System.Windows.Controls.ListBox)window.FindName("CatalogList");
        var previous = list.ItemsSource;
        try
        {
            var row = new CatalogRecord { Product="Settle3", Recording=new() { Setup=new() { Sha256="setup-hash" }, Uninstall=new() { Sha256="uninstall-hash" } } };
            list.ItemsSource = new[] { row }; list.SelectedIndex=0;
            var text=((System.Windows.Controls.TextBox)window.FindName("CatalogDetailsText")).Text;
            check(row.Display.Contains("Recorded InstallShield") && text.Contains("setup-hash") && text.Contains("uninstall-hash"),"Catalog UI identifies recordings and both response file hashes");
            check(text.Contains("Fresh Sandbox recording and validation") && text.Contains("export and backup"),"Catalog UI explains retained attachments and fresh validation");
        }
        finally { list.ItemsSource=previous; }
    }

    public static int Run(string root, string installer, string evidence, bool recover)
    {
        var field = typeof(InstallerCatalogService).GetField("TestDatabasePath", BindingFlags.Static | BindingFlags.NonPublic)!;
        var previous = field.GetValue(null);
        var json = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, WriteIndented = true };
        InstallAnalysis Proof() => JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(Path.Combine(evidence,"install-analysis.json")), json)!;
        var source = new InstallerDetector().Analyze(installer);
        var checks = 0;
        void Check(bool value, string name) { if (!value) throw new InvalidDataException(name); checks++; Console.WriteLine("PASS " + name); }
        try
        {
            if (!recover) field.SetValue(null, Path.Combine(root,"recordings.db"));
            else if (File.Exists(InstallerCatalogService.DatabasePath)) InstallerCatalogService.BackupCatalog(Path.Combine(root,"before-recovery.db"));
            Check(source.NeedsIss && LifecycleValidationService.IsComplete(Proof()), "Actual Settle3 proof is a complete recorded InstallShield lifecycle");
            if (!recover)
            {
                Check(!InstallerCatalogService.Remember(source, Proof()), "Missing response files cannot create a catalog entry");
                var incomplete = Proof(); incomplete.SilentReinstallValidated = false;
                Check(!InstallerCatalogService.Remember(source,incomplete,responseFolder:evidence), "Incomplete lifecycle is rejected");
                var mismatched = Proof(); mismatched.InstallerSha256 = new string('0',64);
                Check(!InstallerCatalogService.Remember(source,mismatched,responseFolder:evidence), "Different source hash cannot inherit a recording");
                var bad = Path.Combine(root,"bad-files"); Directory.CreateDirectory(bad);
                File.WriteAllText(Path.Combine(bad,"setup.iss"),"Not an InstallShield response");
                File.Copy(Path.Combine(evidence,"uninstall.iss"),Path.Combine(bad,"uninstall.iss"));
                Check(!InstallerCatalogService.Remember(source,Proof(),responseFolder:bad), "Malformed response files are rejected");
            }
            var added = InstallerCatalogService.Remember(source,Proof(),"Recovered recorded Sandbox validation",evidence);
            var row = InstallerCatalogService.ReadCatalog().Single(r=>r.Sha256==source.Identity.Sha256);
            Check(added || row.Recording is not null,"Actual Settle3 result added with recordings");
            Check(row.InstallArguments=="" && row.Recording is not null && row.History.Any(h=>h.Recording is not null && h.InstallPassed && h.UninstallPassed && h.RemovalPassed), "Structured recording and validation history survive database round trip");
            Check(Convert.FromBase64String(row.Recording!.Setup.Base64).SequenceEqual(File.ReadAllBytes(Path.Combine(evidence,"setup.iss"))) &&
                  Convert.FromBase64String(row.Recording.Uninstall.Base64).SequenceEqual(File.ReadAllBytes(Path.Combine(evidence,"uninstall.iss"))), "Both response files preserve exact original bytes");
            var match = new InstallerDetector().Analyze(installer);
            Check(InstallerCatalogService.ApplyExactMatch(match) && match.NeedsIss && match.SuggestedArguments=="" && match.CatalogMatch.Contains("recording"), "Exact catalog match requires fresh recording and never replays Sandbox paths");
            Check(!InstallerCatalogService.Remember(source,Proof(),responseFolder:evidence), "Saved proof replay cannot increment validations");
            var transfer = Path.Combine(root,"Settle3-Catalog.json");
            if (recover)
            {
                row.LocalInstallerPath="";
                File.WriteAllText(transfer,JsonSerializer.Serialize(new CatalogTransfer { Entries = new() { row } },json));
            }
            else
            {
                InstallerCatalogService.ExportCatalog(transfer);
                var backup = Path.Combine(root,"backup.db"); InstallerCatalogService.BackupCatalog(backup);
                field.SetValue(null,Path.Combine(root,"imported.db"));
                Check(InstallerCatalogService.ImportCatalog(transfer).Imported==1,"Recording catalog exports and imports");
                var imported = InstallerCatalogService.ReadCatalog().Single();
                Check(imported.Validations==0 && imported.Origin=="Imported candidate" && imported.History.All(h=>h.Source=="Imported / unverified") && imported.Recording!.Setup.Base64==row.Recording.Setup.Base64,"Imported recordings preserve bytes without claiming local validation");
                match=new InstallerDetector().Analyze(installer);
                Check(!InstallerCatalogService.ApplyExactMatch(match) && InstallerCatalogService.ApplyBestMatch(match) && match.NeedsIss && match.SuggestedArguments=="", "Imported recording remains an unvalidated candidate");
                var shared=JsonSerializer.Deserialize<CatalogTransfer>(File.ReadAllText(transfer),json)!;
                shared.Entries[0].Recording!.Setup.Sha256=new string('0',64);
                var invalid=Path.Combine(root,"invalid.json"); File.WriteAllText(invalid,JsonSerializer.Serialize(shared,json));
                bool rejected=false; try { InstallerCatalogService.ImportCatalog(invalid); } catch(InvalidDataException) { rejected=true; }
                Check(rejected && InstallerCatalogService.ReadCatalog().Count==1,"Corrupt attachment hash import is rejected atomically");
                field.SetValue(null,Path.Combine(root,"restored.db"));
                Check(InstallerCatalogService.RestoreCatalog(backup).Imported==1 && InstallerCatalogService.ReadCatalog().Single().Recording!.Uninstall.Base64==row.Recording.Uninstall.Base64,"Backup restore preserves recorded response files as candidates");
            }
            File.WriteAllText(Path.Combine(root,"acceptance.json"),JsonSerializer.Serialize(new { Passed=true, Checks=checks, Product=row.Product, row.Sha256, Evidence=evidence },json));
            return 0;
        }
        finally { field.SetValue(null,previous); }
    }
}
