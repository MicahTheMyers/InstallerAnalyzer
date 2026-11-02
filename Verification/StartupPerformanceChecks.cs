using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using InstallerAnalyzer;
using InstallerAnalyzer.Services;

internal static class StartupPerformanceChecks
{
    public static int Run(string root)
    {
        Directory.CreateDirectory(root);
        var clients = new[] { "WindowsSandboxClient", "WindowsSandbox", "WindowsSandboxRemoteSession" };
        if (SandboxIssRecorder.IsEnvironmentRunning() != false) throw new InvalidOperationException("Profiling requires confirmed empty Sandbox inventory; existing sessions are untouched.");
        foreach (var name in clients)
            foreach (var process in Process.GetProcessesByName(name))
                using (process) throw new InvalidOperationException("Profiling requires no existing Sandbox viewers; they were left untouched.");
        var clock = Stopwatch.StartNew();
        typeof(MainWindow).GetMethod("EnsurePreviousSandboxSessionClosed", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, null);
        var cleanupMs = clock.Elapsed.TotalMilliseconds;
        typeof(MainWindow).GetProperty("SettingsPathOverride", BindingFlags.NonPublic | BindingFlags.Static)!.SetValue(null, Path.Combine(root, "settings.json"));
        typeof(MainWindow).GetProperty("TestModeDirectoryOverride", BindingFlags.NonPublic | BindingFlags.Static)!.SetValue(null, Path.Combine(root, "TestMode"));
        File.WriteAllText(Path.Combine(root, "settings.json"), "{\"AutomaticallyCheckForUpdates\":false}");
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(app.Dispatcher));
        clock.Restart();
        var window = new MainWindow();
        var constructorMs = clock.Elapsed.TotalMilliseconds;
        double? renderedMs = null;
        var frame = new DispatcherFrame();
        window.ContentRendered += (_, _) => { renderedMs = clock.Elapsed.TotalMilliseconds; frame.Continue = false; };
        var timeout = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        timeout.Tick += (_, _) => frame.Continue = false;
        timeout.Start(); window.Show(); Dispatcher.PushFrame(frame); timeout.Stop();
        window.Close();
        var report = new { EmptySandboxCleanupMs = cleanupMs, MainWindowConstructorMs = constructorMs, MainWindowFirstRenderMs = renderedMs,
            Scope = "Local empty-session cleanup and managed WPF startup; excludes Windows guest boot, installer execution, cold single-file extraction and other-machine performance." };
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.Combine(root, "startup-performance.json"), json); Console.WriteLine(json);
        return renderedMs is null ? 1 : 0;
    }
}
