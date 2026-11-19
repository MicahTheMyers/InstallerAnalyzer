using System.Windows;
using InstallerAnalyzer.Services;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private void UpdateSandboxProgress()
    {
        if (_sandboxStarting)
        {
            SandboxTimerText.Text = "Starting Windows Sandbox…";
            SandboxTimerText.Visibility = Visibility.Visible;
            SandboxSessionTimeText.Visibility = Visibility.Collapsed;
            SandboxPrerequisiteText.Visibility = Visibility.Collapsed;
            return;
        }
        var active = _sandboxElapsed.IsRunning && _issSession is not null;
        SandboxTimerText.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        SandboxSessionTimeText.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        SandboxPrerequisiteText.Visibility = Visibility.Collapsed;
        if (!active) return;
        var session = _issSession!;
        var progress = SandboxProgress.Read(session);
        SandboxTimerText.Text = progress?.Describe(DateTimeOffset.UtcNow) ?? "Waiting for the Sandbox to report its current step…";
        if (progress?.ApplicationTimerPaused == true)
        {
            SandboxPrerequisiteText.Text = progress.PauseDescription;
            SandboxPrerequisiteText.Visibility = Visibility.Visible;
        }
        var remaining = session.OverallTimeout - (DateTime.Now - session.StartedAt);
        SandboxSessionTimeText.Text = "Session limit · " + SandboxProgress.Duration(remaining.TotalSeconds) + " remaining";
    }
}
