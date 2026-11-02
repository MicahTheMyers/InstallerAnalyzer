using System.IO;
using System.Reflection;
using InstallerAnalyzer.Services;

internal static class SandboxStartupChecks
{
    public static void Run(string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "sandbox-startup"); Directory.CreateDirectory(folder);
        var session = new SandboxIssSession { SessionFolder = folder, OutputFolder = folder, IssPath = Path.Combine(folder, "setup.iss"), WsbPath = "fixture.wsb" };
        File.WriteAllText(Path.Combine(folder, "sandbox-host-startup.json"), "host diagnostic only");
        check(SandboxStartupMonitor.Read(session).State == SandboxStartupState.WaitingForGuest, "Host startup diagnostics cannot establish guest readiness");
        File.WriteAllText(Path.Combine(folder, "sandbox-guest-startup.json"), "{}");
        check(SandboxStartupMonitor.Read(session).State == SandboxStartupState.GuestStarted, "Guest bootstrap marker is distinct from analysis readiness");
        File.WriteAllText(session.HeartbeatPath, "");
        check(SandboxStartupMonitor.Read(session).State == SandboxStartupState.GuestStarted, "An empty heartbeat cannot establish analysis startup");
        File.WriteAllText(session.HeartbeatPath, "analysis-start");
        check(SandboxStartupMonitor.Read(session).State == SandboxStartupState.AnalysisStarted, "A nonempty analysis heartbeat establishes startup only");
        File.WriteAllText(Path.Combine(folder, "sandbox-guest-startup-error.txt"), new string('x', 5000));
        var failed = SandboxStartupMonitor.Read(session);
        check(failed.State == SandboxStartupState.GuestFailed && failed.Detail.Length == 4096, "Guest bootstrap errors are retained with bounded reads");
        var method = typeof(SandboxStartupMonitor).GetMethod("WaitCoreAsync", BindingFlags.NonPublic | BindingFlags.Static)!;
        void Wait(Func<SandboxStartupObservation> observe, Func<TimeSpan> elapsed, Func<CancellationToken, Task> pause,
            CancellationToken token = default, Action<TimeSpan, SandboxStartupState>? progress = null) =>
            ((Task)method.Invoke(null, [observe, elapsed, pause, SandboxStartupMonitor.StartupBudget, token, progress])!).GetAwaiter().GetResult();
        var seconds = 0; var sawOldDeadline = false;
        Wait(() => new(seconds >= 60 ? SandboxStartupState.AnalysisStarted : SandboxStartupState.GuestStarted),
            () => TimeSpan.FromSeconds(seconds), _ => { seconds++; return Task.CompletedTask; }, progress: (duration, _) => sawOldDeadline |= duration.TotalSeconds > 35);
        check(seconds == 60 && sawOldDeadline, "Slow startup after the former 35-second deadline remains alive until its real heartbeat");
        seconds = 0; var timedOut = false;
        try { Wait(() => new(SandboxStartupState.WaitingForGuest), () => TimeSpan.FromSeconds(seconds), _ => { seconds++; return Task.CompletedTask; }); }
        catch (TimeoutException ex) { timedOut = ex.Message.Contains("180 seconds") && ex.Message.Contains("mapped-output"); }
        check(timedOut && seconds == 180, "Absent guest startup times out with phase-specific diagnostics at the bounded three-minute budget");
        seconds = 180; timedOut = false;
        try { Wait(() => new(SandboxStartupState.GuestStarted), () => TimeSpan.FromSeconds(seconds), _ => Task.CompletedTask); }
        catch (TimeoutException ex) { timedOut = ex.Message.Contains("bootstrap started"); }
        check(timedOut, "A started guest without analysis heartbeat explains the distinct startup phase");
        var pauses = 0; var errorSurfaced = false;
        try { Wait(() => new(SandboxStartupState.GuestFailed, "inert parse failure"), () => TimeSpan.Zero, _ => { pauses++; return Task.CompletedTask; }); }
        catch (InvalidOperationException ex) { errorSurfaced = ex.Message.Contains("inert parse failure"); }
        check(errorSurfaced && pauses == 0, "Guest script failures surface immediately instead of becoming silent startup retries");
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); var observed = false;
        try { Wait(() => { observed = true; return new(SandboxStartupState.AnalysisStarted); }, () => TimeSpan.Zero, _ => Task.CompletedTask, cancelled.Token); }
        catch (OperationCanceledException) { }
        check(!observed, "Startup cancellation wins even if a heartbeat would otherwise be ready");
        seconds = 0;
        Wait(() => seconds == 0 ? throw new IOException("inert sharing race") : new(SandboxStartupState.AnalysisStarted),
            () => TimeSpan.FromSeconds(seconds), _ => { seconds++; return Task.CompletedTask; });
        check(seconds == 1, "A transient startup artifact sharing race can recover without restarting the guest");
        File.WriteAllText(Path.Combine(folder, "Start-Analysis.ps1"), (string)typeof(SandboxIssRecorder).GetField("GuestBootstrapScript", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!);
    }
}
