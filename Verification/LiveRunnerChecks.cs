using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using InstallerAnalyzer;
using InstallerAnalyzer.Services;

internal static class LiveRunnerChecks
{
    public static int Run(string root, string installer, bool silentOnly = true)
    {
        if (SandboxIssRecorder.IsEnvironmentRunning() != false) throw new InvalidOperationException("A confirmed empty Sandbox environment is required.");
        Directory.CreateDirectory(Path.Combine(root, "TestInstallers"));
        File.Copy(installer, Path.Combine(root, "TestInstallers", Path.GetFileName(installer)), false);
        var database = typeof(InstallerCatalogService).GetField("TestDatabasePath", BindingFlags.Static | BindingFlags.NonPublic)!;
        database.SetValue(null, Path.Combine(root, "runner-test-catalog.db"));
        typeof(MainWindow).GetProperty("TestModeDirectoryOverride", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, root);
        typeof(MainWindow).GetProperty("SettingsPathOverride", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, Path.Combine(root, "runner-settings.json"));
        var application = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        var window = new MainWindow();
        T Field<T>(string name) => (T)typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!.GetValue(window)!;
        object? Invoke(string name, params object[] args) => typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, args);
        int result = 1; var start = DateTimeOffset.UtcNow; string last = "";
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += (_, _) =>
        {
            if (File.Exists(Path.Combine(root, "stop-request.flag")) && Field<bool>("_testModeRunning"))
                Field<CancellationTokenSource>("_testModeCts")?.Cancel();
            var status = Field<TextBlock>("TestOverviewText").Text;
            if (status != last) { Console.WriteLine(status); last = status; }
            if (DateTimeOffset.UtcNow - start > TimeSpan.FromMinutes(15))
            {
                Field<CancellationTokenSource>("_testModeCts")?.Cancel();
                Console.Error.WriteLine("Runner verification timed out; cancellation requested.");
            }
            if (Field<bool>("_testModeRunning")) return;
            timer.Stop();
            try
            {
                var runs = new RegressionHistoryService(Path.Combine(root, "RunHistory")).Load();
                var run = runs.Single(); var test = run.Tests.Single();
                if (run.Stopped && File.Exists(Path.Combine(root, "stop-request.flag")))
                {
                    DiagnosticBundleService.Export(Path.Combine(root, "live-diagnostics.zip"), run.Tests);
                    Console.WriteLine("INCOMPLETE: inspection stopped the Full Analysis test; diagnostics retained, no lifecycle pass claimed.");
                    result = 2; return;
                }
                if (run.Completed is null || run.Stopped || !test.Passed) throw new Exception("Test Mode did not complete: " + test.Failure.TechnicalReason);
                if (!test.DetectionStrategies.Any(d => d.Validated) || test.Attempts.Count == 0 || test.Intelligence.Nodes.Count == 0)
                    throw new Exception("Saved run summary lacks detection, attempt or relationship evidence.");
                if (!File.Exists(Path.Combine(test.ArtifactFolder, "installer-intelligence.json"))) throw new Exception("Intelligence artifact missing from run output.");
                var summary = File.ReadAllText(Path.Combine(test.ArtifactFolder, "install-analysis.json"));
                if (!summary.Contains("UiDiagnostics")) throw new Exception("Raw engine diagnostics were lost.");
                var history = new RegressionHistoryService(Path.Combine(root, "RunHistory")); history.SetBaseline(run);
                if (new RegressionHistoryService(Path.Combine(root, "RunHistory")).BaselineId() != run.Id) throw new Exception("Live baseline did not survive reload.");
                DiagnosticBundleService.Export(Path.Combine(root, "live-diagnostics.zip"), run.Tests);
                Console.WriteLine("PASS actual Test Mode runner completed a fresh silent lifecycle");
                Console.WriteLine("PASS durable history retains detection, attempts and graph evidence");
                Console.WriteLine("PASS raw diagnostics survive enriched report writing");
                Console.WriteLine("PASS live baseline survives reload and diagnostics export succeeds");
                Console.WriteLine("RESULT: live Test Mode runner verification passed"); result = 0;
            }
            catch (Exception ex) { Console.Error.WriteLine(ex); }
            finally { window.Close(); application.Shutdown(result); }
        };
        application.Dispatcher.BeginInvoke(new Action(async () =>
        {
            await (Task<bool>)Invoke("RefreshTestQueue")!; Field<ComboBox>("TestTypeBox").SelectedIndex = silentOnly ? 1 : 0;
            Invoke("StartTests_Click", window, new RoutedEventArgs()); timer.Start();
        }));
        application.Run();
        return result;
    }
}
