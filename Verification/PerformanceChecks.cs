using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;
using Microsoft.Data.Sqlite;

internal static class PerformanceChecks
{
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "performance"); Directory.CreateDirectory(folder);
        var flags = BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance;
        FieldInfo Field(string name) => typeof(MainWindow).GetField(name, flags)!;
        T Get<T>(string name) => (T)Field(name).GetValue(window)!;
        void Set(string name, object? value) => Field(name).SetValue(window, value);
        object? Invoke(string name, params object[] args) => typeof(MainWindow).GetMethod(name, flags)!.Invoke(window, args);
        var saved = new[] { "_result", "_installerPath", "_installAnalysis", "_selectedUninstallEntry", "_logoPath", "_analysisLoaded", "_testQueue" }
            .ToDictionary(name => name, name => Field(name).GetValue(window));
        var oldProduct = Get<TextBox>("ProductBox").Text;
        var oldArguments = Get<TextBox>("ArgumentsBox").Text;
        var testRoot = typeof(MainWindow).GetProperty("TestModeDirectoryOverride", BindingFlags.Static | BindingFlags.NonPublic)!;
        var previousRoot = testRoot.GetValue(null);
        try
        {
            var installer = Path.Combine(folder, "inert.exe"); File.WriteAllText(installer, "inert bytes, never executed");
            Set("_result", new AnalysisResult { FilePath = installer, Kind = InstallerKind.Nsis, Confidence = 80 });
            Set("_installerPath", installer); Set("_installAnalysis", null); Set("_selectedUninstallEntry", null); Set("_analysisLoaded", false);
            Get<TextBox>("ProductBox").Text = "Performance fixture";
            Get<TextBox>("ArgumentsBox").Text = "/S";
            var logo = Path.Combine(folder, "logo.png"); File.Copy(Path.Combine(root, "logos", "native-logo.png"), logo);
            Set("_logoPath", logo); Invoke("UpdateSandboxDashboard"); Invoke("SaveHistorySnapshot");
            var document = Get<RichTextBox>("ImmyInstallBox").Document;
            var image = Get<Image>("ImmyLogoImage").Source;
            var historyPath = Path.Combine(root, "analysis-history", "history.json");
            var historyBefore = File.ReadAllText(historyPath);
            var clock = Stopwatch.StartNew();
            for (var i = 0; i < 100; i++) Invoke("UpdateSandboxDashboard");
            var unchangedMs = clock.Elapsed.TotalMilliseconds;
            check(ReferenceEquals(document, Get<RichTextBox>("ImmyInstallBox").Document), "Unchanged dashboard refreshes retain the highlighted script document");
            check(ReferenceEquals(image, Get<Image>("ImmyLogoImage").Source), "Unchanged dashboard refreshes retain the decoded logo");
            check(File.ReadAllText(historyPath) == historyBefore, "One hundred presentation refreshes do not rewrite analysis history");
            Invoke("UpdateImmyBotPage");
            check(ReferenceEquals(document, Get<RichTextBox>("ImmyInstallBox").Document), "Explicit script refresh also reuses unchanged highlighting");
            Get<TextBox>("ArgumentsBox").Text = "/S /changed"; Invoke("UpdateImmyBotPage");
            check(!ReferenceEquals(document, Get<RichTextBox>("ImmyInstallBox").Document), "Changed script arguments invalidate highlighting");
            var changedDocument = Get<RichTextBox>("ImmyInstallBox").Document;
            var brush = window.Resources["Text"];
            window.Resources["Text"] = new SolidColorBrush(Colors.Magenta); Invoke("UpdateImmyBotPage");
            check(!ReferenceEquals(changedDocument, Get<RichTextBox>("ImmyInstallBox").Document), "Theme text color changes invalidate cached highlighting");
            window.Resources["Text"] = brush;
            WritePng(logo, 64); Invoke("LoadLogoPreview");
            check(Get<Image>("ImmyLogoImage").Source is BitmapSource { PixelWidth: 64 } && !ReferenceEquals(image, Get<Image>("ImmyLogoImage").Source),
                "Replacing a same-path logo reloads its actual pixels");
            check(Get<TextBlock>("ImmyLogoStatus").Text.Contains("64 × 64"), "Changed logo dimensions remain visible in the preview");
            Get<TextBox>("ProductBox").Text = "Saved transition"; Invoke("SaveHistorySnapshot");
            check(AnalysisHistoryService.Load().Any(item => item.ProductName == "Saved transition"), "Explicit analysis transitions still persist history");
            clock.Restart();
            for (var i = 0; i < 100; i++)
            {
                ((IDictionary)Field("_highlightedScripts").GetValue(window)!).Clear();
                Set("_logoPreviewStamp", null); Set("_dashboardImmyInitialized", false);
                Invoke("UpdateSandboxDashboard"); Invoke("SaveHistorySnapshot");
            }
            var forcedFullMs = clock.Elapsed.TotalMilliseconds;

            testRoot.SetValue(null, Path.Combine(folder, "queue"));
            var queueFolder = Path.Combine(folder, "queue", "TestInstallers"); Directory.CreateDirectory(queueFolder);
            for (var i = 0; i < 512; i++) File.WriteAllText(Path.Combine(queueFolder, $"fixture-{i:000}.exe"), "inert");
            File.WriteAllText(Path.Combine(queueFolder, "ignore.txt"), "not an installer");
            var refreshing = (Task<bool>)Invoke("RefreshTestQueue")!;
            var dispatcherResponsive = false;
            window.Dispatcher.BeginInvoke(new Action(() => dispatcherResponsive = true));
            PumpUntil(() => refreshing.IsCompleted && dispatcherResponsive);
            check(refreshing.Result && dispatcherResponsive && Get<IList>("_testQueue").Count == 512,
                "Background queue refresh completes while the UI dispatcher remains responsive");
            var item = Get<IList>("_testQueue")[0]!;
            item.GetType().GetProperty("Selected")!.SetValue(item, false);
            var again = (Task<bool>)Invoke("RefreshTestQueue")!; PumpUntil(() => again.IsCompleted);
            check(again.Result && ReferenceEquals(item, Get<IList>("_testQueue")[0]) && !(bool)item.GetType().GetProperty("Selected")!.GetValue(item)!,
                "Queue replacement preserves existing item identity and selection");
            var obsolete = (Task<bool>)Invoke("RefreshTestQueue")!;
            var newest = (Task<bool>)Invoke("RefreshTestQueue")!;
            PumpUntil(() => obsolete.IsCompleted && newest.IsCompleted);
            check(!obsolete.Result && newest.Result, "A superseded queue scan cannot replace the newest queue");
            var active = (Task<bool>)Invoke("RefreshTestQueue")!;
            Set("_testModeRunning", true); PumpUntil(() => active.IsCompleted); Set("_testModeRunning", false);
            check(!active.Result && Get<IList>("_testQueue").Count == 512, "An active test run prevents a pending scan from replacing its queue");
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            var refused = false;
            try { InstallerQueueScanner.Scan(queueFolder, cancelled.Token); } catch (OperationCanceledException) { refused = true; }
            check(refused, "Queue scanning respects cancellation before disk enumeration");
            File.WriteAllText(Path.Combine(folder, "performance-measurement.json"), JsonSerializer.Serialize(new
            {
                Refreshes = 100, UnchangedDashboardMilliseconds = unchangedMs, ForcedFullRefreshMilliseconds = forcedFullMs,
                QueueEntries = 512,
                Scope = "Inert local WPF fixture. Forced comparison explicitly rebuilds documents/reloads logo/saves history as the old presentation path did; not an old-binary or Sandbox startup benchmark."
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        finally
        {
            foreach (var value in saved) Set(value.Key, value.Value);
            Get<ListBox>("TestQueueList").ItemsSource = (IEnumerable)saved["_testQueue"]!;
            var itemChanged = (System.ComponentModel.PropertyChangedEventHandler)typeof(MainWindow).GetMethod("TestQueueItem_Changed", flags)!
                .CreateDelegate(typeof(System.ComponentModel.PropertyChangedEventHandler), window);
            foreach (System.ComponentModel.INotifyPropertyChanged item in (IEnumerable)saved["_testQueue"]!)
            {
                item.PropertyChanged -= itemChanged; item.PropertyChanged += itemChanged;
            }
            Set("_testModeRunning", false); testRoot.SetValue(null, previousRoot);
            Get<TextBox>("ProductBox").Text = oldProduct; Get<TextBox>("ArgumentsBox").Text = oldArguments;
            Set("_dashboardImmyInitialized", false); Invoke("UpdateSandboxDashboard");
        }
        CheckStableHash(folder, check);
    }

    private static void CheckStableHash(string folder, Action<bool, string> check)
    {
        var databaseField = typeof(InstallerCatalogService).GetField("TestDatabasePath", BindingFlags.NonPublic | BindingFlags.Static)!;
        var previous = databaseField.GetValue(null);
        var database = Path.Combine(folder, "snapshot-catalog.db"); databaseField.SetValue(null, database);
        try
        {
            var path = Path.Combine(folder, "snapshot.exe"); File.WriteAllText(path, "stable inert snapshot");
            var hash = RegressionHistoryService.HashFile(path);
            InstallerCatalogService.ReadEntries();
            using (var connection = new SqliteConnection($"Data Source={database}"))
            {
                connection.Open(); using var command = connection.CreateCommand();
                command.CommandText = "INSERT INTO ValidatedInstallers (Sha256,Product,Version,Publisher,Architecture,Family,Arguments,LastValidatedUtc,LastProof) VALUES ($hash,'Fixture','1','Fixture','x64','Nsis','/S','fixture','fixture')";
                command.Parameters.AddWithValue("$hash", hash); command.ExecuteNonQuery();
            }
            var writeRefused = false; var replaceRefused = false; var inspections = 0;
            Func<string, AnalysisResult> inspect = file =>
            {
                inspections++;
                try { using var writer = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); } catch (IOException) { writeRefused = true; }
                try { File.Delete(file); } catch (IOException) { replaceRefused = true; }
                return new AnalysisResult { FilePath = file, Identity = new() { Sha256 = RegressionHistoryService.HashFile(file) } };
            };
            var method = typeof(InstallerCatalogService).GetMethod("AnalyzeWithCatalogSnapshot", BindingFlags.NonPublic | BindingFlags.Static)!;
            var result = (AnalysisResult)method.Invoke(null, new object[] { path, inspect })!;
            check(inspections == 1 && result.CatalogMatch == "Exact validated installer" && result.SuggestedArguments == "/S",
                "Catalog selection reuses the inspection identity within one stable snapshot");
            check(writeRefused && replaceRefused, "Stable catalog inspection refuses concurrent writes and file replacement");
            File.AppendAllText(path, " changed");
            check(!InstallerCatalogService.ApplyExactMatch(new() { FilePath = path, Identity = new() { Sha256 = hash } }),
                "Independent catalog lookup rehashes a replaced file instead of trusting its stale identity");
            var executable = Path.Combine(AppContext.BaseDirectory, "InstallerAnalyzer.exe");
            var inspection = Task.Run(() => InstallerCatalogService.AnalyzeWithCatalog(executable, new InstallerDetector()));
            PumpUntil(() => inspection.IsCompleted);
            var real = inspection.GetAwaiter().GetResult();
            File.WriteAllText(Path.Combine(folder, "native-snapshot-identity.json"), JsonSerializer.Serialize(real.Identity, new JsonSerializerOptions { WriteIndented = true }));
            check(real.Identity.Sha256 == RegressionHistoryService.HashFile(executable) &&
                  real.Identity.SignatureStatus is "NotSigned" or "Valid",
                "Real static identity and Authenticode inspection work while the installer snapshot is read-locked");
            var msiPath = Path.Combine(Path.GetDirectoryName(folder)!, "metadata-only-fixture.msi");
            var msiInspection = Task.Run(() => InstallerCatalogService.AnalyzeWithCatalog(msiPath, new InstallerDetector()));
            PumpUntil(() => msiInspection.IsCompleted);
            var msi = msiInspection.GetAwaiter().GetResult();
            check(msi.Identity.Msi.Status == "Read-only metadata" && msi.Identity.Msi.FileSearches.Count == 1,
                "Real MSI metadata inspection remains available within the stable read-locked snapshot");
        }
        finally { databaseField.SetValue(null, previous); }
    }

    private static void WritePng(string path, int size)
    {
        var image = BitmapSource.Create(size, size, 96, 96, PixelFormats.Bgra32, null, new byte[size * size * 4], size * 4);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
        using var file = File.Create(path); encoder.Save(file);
    }

    private static void PumpUntil(Func<bool> complete)
    {
        var frame = new DispatcherFrame(); var deadline = DateTime.UtcNow.AddSeconds(20);
        var timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(10) };
        timer.Tick += (_, _) => { if (complete() || DateTime.UtcNow >= deadline) frame.Continue = false; };
        timer.Start(); Dispatcher.PushFrame(frame); timer.Stop();
        if (!complete()) throw new TimeoutException("Performance fixture did not complete.");
    }
}
