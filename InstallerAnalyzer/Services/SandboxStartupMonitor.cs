using System.Diagnostics;
using System.IO;

namespace InstallerAnalyzer.Services;

public enum SandboxStartupState { WaitingForGuest, GuestStarted, AnalysisStarted, GuestFailed }
public sealed record SandboxStartupObservation(SandboxStartupState State, string Detail = "");

public static class SandboxStartupMonitor
{
    public static readonly TimeSpan StartupBudget = TimeSpan.FromMinutes(3);
    public static SandboxStartupObservation Read(SandboxIssSession session)
    {
        var error = Path.Combine(session.OutputFolder, "sandbox-guest-startup-error.txt");
        if (File.Exists(error))
        {
            using var reader = new StreamReader(new FileStream(error, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));
            var buffer = new char[4096]; var length = reader.Read(buffer, 0, buffer.Length);
            return new(SandboxStartupState.GuestFailed, new string(buffer, 0, length));
        }
        // Host diagnostics and a visible viewer do not establish that analysis started.
        if (new FileInfo(session.HeartbeatPath) is { Exists: true, Length: > 0 })
            return new(SandboxStartupState.AnalysisStarted);
        return new(File.Exists(Path.Combine(session.OutputFolder, "sandbox-guest-startup.json"))
            ? SandboxStartupState.GuestStarted : SandboxStartupState.WaitingForGuest);
    }
    public static Task WaitAsync(SandboxIssSession session, CancellationToken token, Action<TimeSpan, SandboxStartupState>? progress = null)
    {
        var clock = Stopwatch.StartNew();
        return WaitCoreAsync(() => Read(session), () => clock.Elapsed, ct => Task.Delay(1000, ct), StartupBudget, token, progress);
    }
    private static async Task WaitCoreAsync(Func<SandboxStartupObservation> observe, Func<TimeSpan> elapsed,
        Func<CancellationToken, Task> pause, TimeSpan budget, CancellationToken token, Action<TimeSpan, SandboxStartupState>? progress)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            SandboxStartupObservation state;
            try { state = observe(); }
            catch (IOException) { state = new(SandboxStartupState.WaitingForGuest); }
            catch (UnauthorizedAccessException) { state = new(SandboxStartupState.WaitingForGuest); }
            if (state.State == SandboxStartupState.GuestFailed)
                throw new InvalidOperationException("Sandbox guest startup script failed: " + state.Detail);
            if (state.State == SandboxStartupState.AnalysisStarted) return;
            var duration = elapsed();
            progress?.Invoke(duration, state.State);
            if (duration >= budget)
                throw new TimeoutException($"Windows Sandbox did not write an analysis heartbeat within {budget.TotalSeconds:0} seconds. " +
                    (state.State == SandboxStartupState.GuestStarted ? "The guest bootstrap started, but the analysis script did not signal readiness." : "No guest bootstrap marker was received; inspect Sandbox logon and mapped-output access."));
            await pause(token);
        }
    }
}
