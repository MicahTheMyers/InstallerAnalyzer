using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class Program
{
    private static int passed;
    private static void Check(bool condition, string name)
    {
        if (!condition) throw new Exception("FAIL " + name);
        Console.WriteLine("PASS " + name); passed++;
    }
    private static RegressionTestRecord Item(string hash, string result = "PASS", FailureCategory category = FailureCategory.None, string owner = "") =>
        new() { Installer = hash + ".exe", InstallerSha256 = hash, ProductName = "Product", Publisher = "Publisher",
            InstallerType = "Msi", Result = result, Failure = new() { Category = category, Owner = owner } };
    private static RegressionRun Run(params RegressionTestRecord[] items) =>
        new() { Version = "test", Mode = "SilentOnlyUnattended", Completed = DateTimeOffset.Now, Tests = items.ToList() };
    private static string Classification(RegressionTestRecord old, RegressionTestRecord current) =>
        RegressionHistoryService.Compare(Run(current), Run(old)).First().Classification;

    [STAThread]
    public static int Main(string[] args)
    {
        var root = Path.GetFullPath(args[0]);
        Directory.CreateDirectory(root);
        if(args.Length>=2 && args[1]=="--netfx3-stage") { NetFx3SandboxSource.Stage(root); return 0; }
        if(args.Length>=2 && args[1]=="--netfx3-lifecycle") return NetFx3LifecycleChecks.Run(root);
        if(args.Length>=2 && args[1]=="--startup-profile") return StartupPerformanceChecks.Run(root);
        if(args.Length>=2 && args[1]=="--startup-live") return SandboxStartupLiveChecks.Run(root);
        if(args.Length>=3 && args[1]=="--recording-startup-live") return SandboxStartupLiveChecks.RunRecordingLaunch(root,args[2]);
        if(args.Length>=3 && args[1]=="--live-full-runner") return LiveRunnerChecks.Run(root,args[2],silentOnly:false);
        if(args.Length>=3 && args[1]=="--condition-oracle") return ConditionOracleChecks.Run(root,args[2]);
        if (args.Length >= 2 && args[1] == "--signed-untrusted") return RealSignedUpdateChecks.RunUntrusted(root);
        if (args.Length >= 3 && args[1] == "--signed-handoff") return RealSignedUpdateChecks.Run(root, args[2]);
        if (args.Length >= 3 && args[1] is "--live-cancel-startup" or "--live-cancel-install") return LiveCancellationChecks.Run(root, args[2], args[1] == "--live-cancel-install");
        if (args.Length >= 3 && args[1] == "--campaign") return LiveCampaignChecks.Run(root, args[2]);
        if (args.Length >= 3 && args[1] == "--live") return LiveSandboxChecks.Run(root, args[2]);
        if (args.Length >= 3 && args[1] == "--live-prerequisites") return LiveSandboxChecks.Run(root, args[2],requirePropertySnapshot:true);
        if (args.Length >= 3 && args[1] == "--live-runner") return LiveRunnerChecks.Run(root, args[2]);
        try
        {
            Check(Classification(Item("A"), Item("A")) == "UNCHANGED PASS", "Pass remains pass");
            Check(Classification(Item("A", "FAIL"), Item("A")) == "IMPROVED", "Failed installer improves");
            Check(Classification(Item("A"), Item("A", "FAIL")) == "REGRESSION", "Passed installer regresses");
            Check(Classification(Item("A", "FAIL"), Item("A", "FAIL")) == "UNCHANGED FAIL", "Failure remains failure");
            var changed = RegressionHistoryService.Compare(Run(Item("B")), Run(Item("A")));
            Check(changed.Count == 2 && changed[0].Classification == "NEW" && changed[1].Classification == "REMOVED / NOT TESTED",
                "Changed bytes are new even with identical product metadata");
            var renamed = Item("A"); renamed.Installer = "renamed.exe";
            Check(Classification(Item("A"), renamed) == "UNCHANGED PASS", "Renamed identical bytes match");
            Check(Classification(Item("A"), Item("A", "FAIL", FailureCategory.SandboxStartupFailure, "Sandbox")) == "INFRASTRUCTURE",
                "Sandbox failure is not installer regression");
            Check(Classification(Item("A", "FAIL", FailureCategory.AnalyzerInfrastructureFailure, "Analyzer"), Item("A")) == "INFRASTRUCTURE",
                "Recovery from analyzer failure is not installer improvement");
            Check(Classification(Item("A"), Item("A", "STOPPED", FailureCategory.Cancelled, "User")) == "REMOVED / NOT TESTED",
                "Cancellation is not a regression");
            Check(Classification(Item("A"), Item("A", "NOT TESTED")) == "REMOVED / NOT TESTED", "Queued untested installer remains untested");
            Check(Classification(Item("A"), Item("A", "TIMEOUT", FailureCategory.Timeout, "Unknown")) == "INCONCLUSIVE",
                "Unknown timeout is inconclusive rather than an installer regression");
            Check(Classification(Item("A"), Item("A", "TIMEOUT", FailureCategory.Timeout, "Sandbox")) == "INFRASTRUCTURE",
                "Known heartbeat timeout remains visibly infrastructure");
            var mode = Run(Item("A")); mode.Mode = "FullAnalysis";
            Check(RegressionHistoryService.Compare(mode, Run(Item("A")))[0].Classification == "NOT COMPARABLE", "Different modes are not compared as regressions");
            var filename1 = new RegressionTestRecord { Installer = "setup.exe" };
            var filename2 = new RegressionTestRecord { Installer = "setup.exe" };
            Check(!RegressionHistoryService.SameInstaller(filename1, filename2), "Filename alone never matches");
            var legacy = Item(""); var legacy2 = Item("");
            Check(RegressionHistoryService.SameInstaller(legacy, legacy2), "Hashless legacy match requires stable product identity");
            legacy2.Publisher = "Different";
            Check(!RegressionHistoryService.SameInstaller(legacy, legacy2), "Different publisher rejects legacy match");
            Check(!RegressionHistoryService.SameInstaller(Item("A"), legacy), "Missing hash does not match known hash");
            var duplicate = Run(Item(""), Item(""));
            Check(RegressionHistoryService.Compare(Run(Item("")), duplicate)[0].Classification == "NEW", "Ambiguous legacy identities are not paired");

            var historyRoot = Path.Combine(root, "history");
            var history = new RegressionHistoryService(historyRoot);
            var baseline = Run(Item("A")); history.Save(baseline); history.SetBaseline(baseline);
            var second = Run(Item("A", "FAIL")); history.Save(second);
            var reloaded = new RegressionHistoryService(historyRoot);
            Check(reloaded.Load().Count == 2, "All runs survive service restart");
            Check(reloaded.BaselineId() == baseline.Id, "Baseline survives service restart");
            Check(RegressionHistoryService.Compare(reloaded.Load().Single(r => r.Id == second.Id), baseline)[0].Classification == "REGRESSION",
                "Persisted results compare correctly after restart");
            history.ClearBaseline();
            Check(history.BaselineId() is null && history.Load().Count == 2, "Clearing baseline preserves runs");
            baseline.Stopped = true;
            try { history.SetBaseline(baseline); Check(false, "Stopped baseline rejected"); }
            catch (InvalidOperationException) { Check(true, "Stopped baseline rejected"); }
            baseline.Stopped = false; baseline.Completed = null;
            try { history.SetBaseline(baseline); Check(false, "Incomplete baseline rejected"); }
            catch (InvalidOperationException) { Check(true, "Incomplete baseline rejected"); }
            File.WriteAllText(Path.Combine(historyRoot, Guid.NewGuid().ToString("N") + ".json"), "{bad json");
            Check(history.Load().Count == 2 && history.Warnings.Count == 1, "Corrupt run is reported without hiding valid runs");
            File.WriteAllText(Path.Combine(historyRoot, "baseline.json"), "{bad");
            Check(history.BaselineId() is null && history.Warnings.Count == 2, "Corrupt baseline is reported without crash");
            var invalid = Run(Item("A")); invalid.SchemaVersion = 99;
            try { history.Save(invalid); Check(false, "Unknown schema rejected"); }
            catch (InvalidDataException) { Check(true, "Unknown schema rejected"); }
            invalid = Run(Item("A")); invalid.Id = "../escape";
            try { history.Save(invalid); Check(false, "Unsafe identity rejected"); }
            catch (InvalidDataException) { Check(true, "Unsafe identity rejected"); }
            Check(!Directory.EnumerateFiles(historyRoot, "*.tmp").Any(), "Atomic writes leave no temporary files");

            var file = Path.Combine(root, "setup.exe"); File.WriteAllText(file, "original");
            var hash1 = RegressionHistoryService.HashFile(file);
            File.WriteAllText(file, "changed");
            Check(hash1 != RegressionHistoryService.HashFile(file), "Retest identity detects replaced bytes");

            Check(FailureClassificationService.Classify("FAIL", "failed", new() { SilentUninstallUiDetected = true }, "Sandbox lifecycle").Category ==
                FailureCategory.UninstallerUiDetected, "Uninstaller UI classified");
            Check(FailureClassificationService.Classify("FAIL", "failed", new() { SilentReinstallUiDetected = true }, "Sandbox lifecycle").Category ==
                FailureCategory.InstallerUiDetected, "Installer UI classified");
            Check(FailureClassificationService.Classify("FAIL", "PREREQUISITE REQUIRED: runtime", null, "Sandbox lifecycle").Category ==
                FailureCategory.PrerequisiteMissing, "Prerequisite classified");
            Check(FailureClassificationService.Classify("FAIL", "PREREQUISITE REQUIRED during uninstall", null, "Sandbox lifecycle").Category ==
                FailureCategory.PrerequisiteMissing, "Required word is not mistaken for UI evidence");
            Check(FailureClassificationService.Classify("FAIL", "incomplete", new() { RebootRequired = true }, "Sandbox lifecycle").Category ==
                FailureCategory.RebootRequired, "Reboot classified separately");
            Check(FailureClassificationService.Classify("TIMEOUT", "No Sandbox heartbeat activity.", null, "Sandbox lifecycle").Infrastructure,
                "Heartbeat timeout belongs to infrastructure");
            Check(FailureClassificationService.Classify("FAIL", "Input error", null, "Static analysis").Owner == "Analyzer",
                "Static preparation failure belongs to analyzer");
            Check(FailureClassificationService.Classify("STOPPED", "cancelled", null, "Sandbox startup").Category == FailureCategory.Cancelled,
                "Startup cancellation is not a Sandbox fault");
            var explanation = FailureClassificationService.Explain(new() { Installer = "Example.msi",
                Failure = FailureClassificationService.Classify("FAIL", "visible uninstaller UI", new() { SilentUninstallUiDetected = true }, "Uninstall"),
                Attempts = new() { new() { Name = "MSI", Command = "/qn", ExitCode = 1603, Outcome = "Rejected", UiDetected = true } } });
            Check(explanation.Contains("UninstallerUiDetected") && explanation.Contains("1603") && explanation.Contains("/qn") && explanation.Contains("Next investigation"),
                "Local explanation exposes classification, evidence and attempts");

            RoadmapChecks.Run(root, Check);
            SandboxStartupChecks.Run(root, Check);
            AppControlChecks.Run(root, Check);
            FullRoadmapChecks.Run(root, Check);
            UpdateSecurityChecks.Run(root, Check);
            PrerequisiteFileChecks.Run(root, Check);
            PayloadTraceChecks.Run(root, Check);
            BitsMappingChecks.Run(root, Check);
            BitsCompletionChecks.Run(root, Check);
            ResponseFileChecks.Run(root, Check);
            PeDependencyChecks.Run(root, Check);
            MsiConditionChecks.Run(root, Check);
            MsiPropertyChecks.Run(root, Check);
            typeof(MainWindow).GetProperty("TestModeDirectoryOverride", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, Path.Combine(root, "ui-test-mode"));
            typeof(MainWindow).GetProperty("SettingsPathOverride", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, Path.Combine(root, "ui-settings.json"));
            typeof(InstallerCatalogService).GetField("TestDatabasePath", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, Path.Combine(root, "ui-catalog.db"));
            var app = new Application();
            typeof(AnalysisHistoryService).GetField("TestFolder", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, Path.Combine(root, "analysis-history"));
            SynchronizationContext.SetSynchronizationContext(new System.Windows.Threading.DispatcherSynchronizationContext(app.Dispatcher));
            var window = new MainWindow();
            T Field<T>(string name) => (T)typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!.GetValue(window)!;
            void Invoke(string name, params object[] values) => typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, values);
            var testPage = Field<Grid>("TestModePage");
            var scroll = (ScrollViewer)testPage.Children[0];
            Check(((Grid)scroll.Content).RowDefinitions.Count == 5, "Comparison area has its own layout row");
            var combo = Field<ComboBox>("RegressionCurrentRunBox");
            var baselineBox = Field<ComboBox>("RegressionBaselineBox");
            baseline = Run(Item("A"));
            second = Run(Item("A", "FAIL", FailureCategory.UninstallerUiDetected, "Installer"));
            combo.ItemsSource = new[] { second }; combo.SelectedItem = second;
            baselineBox.ItemsSource = new[] { baseline }; baselineBox.SelectedItem = baseline;
            Invoke("UpdateRegressionComparison");
            var comparisons = Field<ListBox>("RegressionComparisonList");
            Check(comparisons.Items.Count == 1 && ((RegressionComparison)comparisons.Items[0]).Classification == "REGRESSION",
                "WPF comparison presents persisted model classifications");
            comparisons.SelectedIndex = 0;
            Check(Field<TextBox>("RegressionResultDetails").Text.Contains("BASELINE") &&
                  Field<TextBox>("RegressionResultDetails").Text.Contains("CURRENT"), "WPF selection presents both results");
            typeof(MainWindow).GetField("_catalogRecords", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(window,
                new List<CatalogRecord>
                {
                    new() { Product = "WinDirStat", Version = "2.5", Publisher = "Example Publisher", Family = "Msi", Validations = 2,
                        Sha256 = new string('A', 64), ProductFamily = "WinDirStat", Architecture = "x64", DeploymentSource = "WinDirStat-x64.msi",
                        DeploymentMechanism = "MSI", InstallArguments = "/qn /norestart", UninstallType = "MsiProductCode" },
                    new() { Product = "Imported Tool", Origin = "Imported candidate", Family = "Nsis", Publisher = "Other" }
                });
            Field<TextBox>("CatalogSearchBox").Text = "Example Publisher";
            Check(Field<ListBox>("CatalogList").Items.Count == 1, "Catalog search filters by publisher metadata");
            Field<ListBox>("CatalogList").SelectedIndex = 0;
            Check(Field<TextBox>("CatalogDetailsText").Text.Contains("Deployment source: WinDirStat-x64.msi") &&
                  Field<TextBox>("CatalogDetailsText").Text.Contains("Local validations: 2"), "Catalog selection explains source, strategy and proof counts");
            Invoke("ShowPage", Field<Grid>("CatalogPage"));
            Check(Field<Grid>("CatalogPage").Visibility == Visibility.Visible && Field<Grid>("TestModePage").Visibility == Visibility.Collapsed,
                "Catalog navigation switches pages without overlapping Test Mode");
            var content = (FrameworkElement)window.Content;
            content.Measure(new Size(1240, 900)); content.Arrange(new Rect(0, 0, 1240, 900)); content.UpdateLayout();
            var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap(1240, 900, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
            bitmap.Render(content);
            var png = new System.Windows.Media.Imaging.PngBitmapEncoder(); png.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
            using (var output = File.Create(Path.Combine(root, "catalog-layout.png"))) png.Save(output);
            RegressionInteractionChecks.Run(window, root, Check);
            ApplicationLogoChecks.Run(root, Check);
            NetFx3Checks.Run(root, Check);
            PerformanceChecks.Run(window, root, Check);
            ClaudeAssistantChecks.Run(window, root, Check);
            RoadmapUiChecks.Run(window, root, Check);
            WindowBoundsChecks.Run(window, root, Check);
            window.Close();
            Console.WriteLine($"RESULT: {passed} passed, 0 failed");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
