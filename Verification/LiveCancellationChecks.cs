using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class LiveCancellationChecks
{
    public static int Run(string root, string installer, bool afterLaunch, bool recording = false)
    {
        if (SandboxIssRecorder.IsEnvironmentRunning() != false) throw new InvalidOperationException("Cancellation test requires empty Sandbox state.");
        var temp = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer"); Directory.CreateDirectory(temp);
        var previous = Directory.GetDirectories(temp).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Directory.CreateDirectory(Path.Combine(root, "TestInstallers"));
        foreach (var name in new[] { Path.GetFileName(installer), "Queued-" + Path.GetFileName(installer) })
            File.Copy(installer, Path.Combine(root, "TestInstallers", name));
        typeof(InstallerCatalogService).GetField("TestDatabasePath", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, Path.Combine(root, "cancel-catalog.db"));
        typeof(MainWindow).GetProperty("TestModeDirectoryOverride", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, root);
        typeof(MainWindow).GetProperty("SettingsPathOverride", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, Path.Combine(root, "settings.json"));
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown }; var window = new MainWindow();
        T Field<T>(string name) => (T)typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!.GetValue(window)!;
        object? Invoke(string name, params object[] args) => typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, args);
        var start = DateTime.UtcNow; var requested = false; var reached = false; var result = 1;
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        timer.Tick += (_, _) =>
        {
            if (!requested && Field<bool>("_testModeRunning"))
            {
                var session = Directory.GetDirectories(temp).Where(p => !previous.Contains(p)).OrderByDescending(Directory.GetCreationTimeUtc).FirstOrDefault();
                if (session is not null)
                {
                    if (afterLaunch || recording)
                    {
                        var checkpoint = Path.Combine(session, "Output", "install-analysis.checkpoint.json");
                        try
                        {
                            using var json = JsonDocument.Parse(AnalysisArtifactReader.ReadText(checkpoint));
                            reached = json.RootElement.TryGetProperty("WorkflowStage", out var stage) &&
                                (recording ? stage.GetString()=="Record InstallShield installation response file" && File.Exists(Path.Combine(root,"recording-window-observed.flag"))
                                           : (stage.GetString()?.Contains("Process.Start returned PID") ?? false));
                        }
                        catch (Exception ex) when (ex is IOException or JsonException) { }
                    }
                    else reached = SandboxIssRecorder.IsEnvironmentRunning() == true;
                }
                if (reached || DateTime.UtcNow - start > TimeSpan.FromMinutes(3))
                {
                    Console.WriteLine(reached ? "Reached cancellation phase: " + (recording ? "Full Analysis response recording, wizard observed" : afterLaunch ? "installer launched" : "Sandbox startup") : "Cancellation phase deadline reached");
                    Invoke("StopTests_Click", window, new RoutedEventArgs()); requested = true;
                }
            }
            if (Field<bool>("_testModeRunning")) return;
            timer.Stop();
            try
            {
                if (!requested || !reached) throw new Exception("Requested cancellation phase was not reached.");
                var history = new RegressionHistoryService(Path.Combine(root, "RunHistory")); var run = history.Load().Single();
                if (!run.Stopped || run.Completed is null || run.Tests.Any(t => t.Passed)) throw new Exception("Stopped queue was saved as complete/pass.");
                if (!run.Tests.Any(t => t.Result == "STOPPED" && t.Failure.Category == FailureCategory.Cancelled) || !run.Tests.Any(t => t.Result == "NOT TESTED"))
                    throw new Exception("Cancellation or unstarted queue items lost their typed state.");
                if (history.BaselineId() is not null || InstallerCatalogService.ReadCatalog().Count != 0) throw new Exception("Cancelled proof promoted catalog trust or a baseline.");
                if (!run.Tests.Where(t => t.Result == "STOPPED").All(t => File.Exists(Path.Combine(t.ArtifactFolder, "install-analysis.json")))) throw new Exception("Cancelled raw diagnostic artifact missing.");
                if (SandboxIssRecorder.IsEnvironmentRunning() != false) throw new Exception("Sandbox teardown not confirmed.");
                Console.WriteLine("PASS cancelled run persisted STOPPED/Cancelled, unstarted queue remained NOT TESTED, no catalog/baseline promotion, raw diagnostics retained, Sandbox empty");
                result = 0;
            }
            catch (Exception ex) { Console.Error.WriteLine(ex); }
            finally { window.Close(); app.Shutdown(result); }
        };
        app.Dispatcher.BeginInvoke(new Action(async () => { await (Task<bool>)Invoke("RefreshTestQueue")!; Field<ComboBox>("TestTypeBox").SelectedIndex = recording ? 0 : 1; Invoke("StartTests_Click", window, new RoutedEventArgs()); timer.Start(); }));
        app.Run(); return result;
    }
}
