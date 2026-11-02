using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using InstallerAnalyzer.Services;

internal static class SandboxStartupLiveChecks
{
    public static int RunRecordingLaunch(string root, string installer)
    {
        if (Ids().Length != 0) throw new InvalidOperationException("An existing Sandbox was left untouched.");
        Directory.CreateDirectory(root);
        var hash = RegressionHistoryService.HashFile(installer);
        string? owned = null;
        SandboxIssSession? session = null;
        try
        {
            session = SandboxIssRecorder.Start(installer, InstallerAnalyzer.Models.InstallerKind.InstallShield, true, "", "", true);
            File.WriteAllText(Path.Combine(root, "session-path.txt"), session.SessionFolder);
            SandboxStartupMonitor.WaitAsync(session, CancellationToken.None, (_, _) =>
            {
                if (owned is not null) return;
                var ids = Ids();
                if (ids.Length > 1) throw new InvalidOperationException("Ambiguous Sandbox ownership; unrelated sessions preserved.");
                if (ids.Length == 1) { owned = ids[0]; File.WriteAllText(Path.Combine(root, "owned-sandbox-id.txt"), owned); }
            }).GetAwaiter().GetResult();
            File.WriteAllText(Path.Combine(root, "inspection-ready.json"), JsonSerializer.Serialize(new { ReadyAt = DateTimeOffset.UtcNow, SessionFolder = session.SessionFolder }));
            Console.WriteLine("Production recording analysis heartbeat received; viewer held for inspection until completion signal (five-minute safety limit).");
            var until = Stopwatch.StartNew();
            while (until.Elapsed < TimeSpan.FromMinutes(5) && !File.Exists(Path.Combine(root, "inspection-complete.flag"))) Thread.Sleep(1000);
            File.WriteAllText(Path.Combine(root, "recording-launch-result.json"), JsonSerializer.Serialize(new
            {
                ProductionBootstrapReady = true, InstallerSha256 = hash, SessionFolder = session.SessionFolder,
                LifecycleValidated = false, Scope = "Production recording launch and display inspection; no wizard interaction or completed recording claimed"
            }));
            Console.WriteLine("Recording launch inspection ended; no lifecycle pass claimed.");
            return 0;
        }
        finally
        {
            if (owned is not null && Ids().Contains(owned))
            {
                using var stop = Process.Start(new ProcessStartInfo(Wsb, "stop --id " + owned) { UseShellExecute = false, CreateNoWindow = true });
                stop?.WaitForExit(15000);
            }
            if (RegressionHistoryService.HashFile(installer) != hash) throw new IOException("Input installer changed.");
            Console.WriteLine("Input hash unchanged; remaining Sandbox environments: " + Ids().Length);
        }
    }
    private static readonly string Wsb = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "wsb.exe");
    private static string[] Ids()
    {
        using var process = Process.Start(new ProcessStartInfo(Wsb, "list --raw") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
        var read = process.StandardOutput.ReadToEndAsync();
        if (!process.WaitForExit(5000) || process.ExitCode != 0 || !read.Wait(1000)) throw new IOException("Cannot establish Sandbox inventory.");
        using var json = JsonDocument.Parse(read.Result);
        return json.RootElement.GetProperty("WindowsSandboxEnvironments").EnumerateArray().Select(e => e.GetProperty("Id").GetString()!).ToArray();
    }
    public static int Run(string root)
    {
        if (Ids().Length != 0) throw new InvalidOperationException("An existing Sandbox was left untouched.");
        var input = Path.Combine(root, "Input"); var output = Path.Combine(root, "Output");
        Directory.CreateDirectory(input); Directory.CreateDirectory(output);
        var script = (string)typeof(SandboxIssRecorder).GetField("GuestBootstrapScript", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!;
        File.WriteAllText(Path.Combine(input, "Start-Analysis.ps1"), script);
        File.WriteAllText(Path.Combine(input, "Record-Iss.ps1"), "Set-Content -LiteralPath 'C:\\InstallerOutput\\analysis-heartbeat.txt' -Value 'inert live bootstrap fixture ready'");
        var configuration = (string)typeof(SandboxIssRecorder).GetMethod("BuildWsb", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [input, output])!;
        var path = Path.Combine(root, "startup-fixture.wsb"); File.WriteAllText(path, configuration);
        var session = new SandboxIssSession { SessionFolder = root, OutputFolder = output, IssPath = Path.Combine(output, "setup.iss"), WsbPath = path };
        string? owned = null; var watch = Stopwatch.StartNew();
        try
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden });
            SandboxStartupMonitor.WaitAsync(session, CancellationToken.None, (_, _) =>
            {
                if (owned is not null) return;
                var ids = Ids();
                if (ids.Length > 1) throw new InvalidOperationException("Sandbox ownership became ambiguous; unrelated sessions will be preserved.");
                if (ids.Length == 1) { owned = ids[0]; File.WriteAllText(Path.Combine(root, "owned-sandbox-id.txt"), owned); }
            }).GetAwaiter().GetResult();
            if (!File.Exists(Path.Combine(output, "sandbox-guest-startup.json"))) throw new InvalidOperationException("Bootstrap marker missing.");
            File.WriteAllText(Path.Combine(root, "startup-live-result.json"), JsonSerializer.Serialize(new { Passed = true, ReadySeconds = watch.Elapsed.TotalSeconds, InstallerExecuted = false, Scope = "Actual Sandbox bootstrap and analysis heartbeat handoff only" }));
            Console.WriteLine($"PASS live Sandbox bootstrap and heartbeat in {watch.Elapsed.TotalSeconds:0.0}s; no installer executed.");
            return 0;
        }
        finally
        {
            if (owned is not null && Ids().Contains(owned))
            {
                using var stop = Process.Start(new ProcessStartInfo(Wsb, "stop --id " + owned) { UseShellExecute = false, CreateNoWindow = true });
                stop?.WaitForExit(15000);
            }
            Console.WriteLine("Remaining Sandbox environments: " + Ids().Length);
        }
    }
}
