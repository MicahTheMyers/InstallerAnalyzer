using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Threading;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class InstallerUsabilityChecks
{
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "installer-preferences");
        Directory.CreateDirectory(folder);
        var store = new InstallerPreferenceStore(Path.Combine(folder, "settings.dat"));
        var hash = new string('A', 64);
        var key = InstallerPreferenceStore.Key(hash, @"Media\setup.exe");
        var preferences = new InstallerPreferences("Example", InstallerKind.InstallShield, "/s secret-example", "CUSTOM=1", true, true, DateTimeOffset.UtcNow);
        store.Save(key, preferences, hash, @"Media\setup.exe");
        check(new InstallerPreferenceStore(Path.Combine(folder, "settings.dat")).Find(key) == preferences,
            "Installer preferences survive a store restart");
        check(!File.ReadAllText(Path.Combine(folder, "settings.dat")).Contains("secret-example"),
            "Remembered installer arguments use Windows user protection on disk");
        check(store.Find(InstallerPreferenceStore.Key(new string('B', 64), @"Media\setup.exe")) is null &&
              store.Find(InstallerPreferenceStore.Key(hash, @"Other\setup.exe")) is null,
            "Changed source bytes and different ZIP entries have independent settings");
        check(store.FindArchiveEntry(hash, new[] { @"Other\setup.exe", @"Media\setup.exe" }) == @"Media\setup.exe" &&
              store.FindArchiveEntry(hash, new[] { @"Other\setup.exe" }) is null,
            "ZIP setup selection restores only when that entry still exists");
        store.Remove(key, hash);
        check(store.Find(key) is null && store.FindArchiveEntry(hash, new[] { @"Media\setup.exe" }) is null,
            "Reset removes the remembered installer and ZIP selection");
        File.WriteAllText(Path.Combine(folder, "settings.dat"), "corrupted settings");
        store.Save(key, preferences, null, null);
        check(store.Find(key) == preferences && Directory.GetFiles(folder, "settings.dat.unreadable-*").Length == 1,
            "Unreadable preferences are retained while new settings can be saved");

        T Field<T>(string name) => (T)window.FindName(name);
        object? Invoke(string name, params object?[] args) => typeof(MainWindow).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, args);
        void Analyze(string path, string? entry = null)
        {
            Invoke("Analyze", path, entry);
            var end = DateTime.UtcNow.AddSeconds(45);
            var busy = typeof(MainWindow).GetField("_analysisBusy", BindingFlags.NonPublic | BindingFlags.Instance)!;
            while ((bool)busy.GetValue(window)! && DateTime.UtcNow < end)
                window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            check(!(bool)busy.GetValue(window)!, "Installer analysis completes through the normal entry point");
        }
        var source = Path.Combine(folder, "source.exe");
        File.Copy(Environment.ProcessPath!, source, true);
        Analyze(source);
        Field<ComboBox>("KindBox").SelectedItem = InstallerKind.InstallShield;
        Field<ToggleButton>("IssCheck").IsChecked = true;
        Field<TextBox>("ArgumentsBox").Text = "/s /custom-preserved";
        Field<TextBox>("AdditionalArgumentsBox").Text = "EXAMPLE=remembered";
        Field<TextBox>("ProductBox").Text = "Remembered product";
        Invoke("SaveInstallerPreferences");
        var renamed = Path.Combine(folder, "renamed.exe");
        File.Copy(source, renamed, true);
        Analyze(renamed);
        check(Field<TextBox>("ArgumentsBox").Text == "/s /custom-preserved" &&
              Field<TextBox>("AdditionalArgumentsBox").Text == "EXAMPLE=remembered" &&
              Field<TextBox>("ProductBox").Text == "Remembered product" &&
              Field<ToggleButton>("IssCheck").IsChecked == true,
            "Reopening renamed identical bytes restores arguments, product and response-file settings");
        using (var append = File.Open(renamed, FileMode.Append)) append.WriteByte(0);
        Analyze(renamed);
        check(Field<TextBox>("AdditionalArgumentsBox").Text == "" && Field<TextBox>("ProductBox").Text != "Remembered product",
            "Replacing an installer at the same path starts with fresh settings");

        var zip = Path.Combine(folder, "media.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            archive.CreateEntryFromFile(source, @"Media/setup.exe");
            archive.CreateEntryFromFile(source, @"Media/other.exe");
        }
        Analyze(zip, @"Media\setup.exe");
        Field<TextBox>("AdditionalArgumentsBox").Text = "ZIP=remembered";
        Invoke("SaveInstallerPreferences");
        Analyze(zip);
        check(Field<TextBox>("AdditionalArgumentsBox").Text == "ZIP=remembered" &&
              Field<Button>("ChangeArchiveInstallerButton").Visibility == Visibility.Visible,
            "Reopening a ZIP restores its selected setup and keeps manual reselection available");
        check(typeof(MainWindow).GetField("_installAnalysis", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(window) is null,
            "Restoring preferences does not create lifecycle validation");

        var now = DateTimeOffset.UtcNow;
        var progress = new SandboxProgress
        {
            Phase = "Prerequisite setup", ApplicationTimerPaused = true, Prerequisite = "vc_redist.x64.exe",
            CapturedAt = now.AddSeconds(-4), RemainingSeconds = 90, PhaseElapsedSeconds = 12
        };
        check(progress.Describe(now).Contains("00:01:26 remaining") && progress.PauseDescription.Contains("vc_redist.x64.exe"),
            "Live progress advances the reported countdown and names the prerequisite pause");
        check(progress.Describe(now.AddSeconds(30)).Contains("fresh progress report"),
            "Stale guest progress is visibly identified instead of presenting a current countdown");
        var session = new SandboxIssSession { SessionFolder = folder, OutputFolder = folder, IssPath = "", WsbPath = "" };
        File.WriteAllText(Path.Combine(folder, "analysis-progress.json"), "{partial");
        check(SandboxProgress.Read(session) is null, "A partial progress file cannot interrupt analysis");
        File.WriteAllText(Path.Combine(folder, "analysis-progress.json"), JsonSerializer.Serialize(progress));
        check(SandboxProgress.Read(session)?.ApplicationTimerPaused == true, "Guest progress survives its JSON handoff");
        var sessionField = typeof(MainWindow).GetField("_issSession", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var elapsed = (System.Diagnostics.Stopwatch)typeof(MainWindow).GetField("_sandboxElapsed", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(window)!;
        var previousSession = sessionField.GetValue(window);
        try
        {
            sessionField.SetValue(window, session);
            elapsed.Restart();
            Invoke("UpdateSandboxProgress");
            check(Field<TextBlock>("SandboxTimerText").Text.Contains("Prerequisite setup") &&
                  Field<TextBlock>("SandboxPrerequisiteText").Visibility == Visibility.Visible &&
                  Field<TextBlock>("SandboxSessionTimeText").Text.Contains("remaining"),
                "Sandbox Control Center displays the step timer, prerequisite pause and session limit");
            elapsed.Stop();
            Invoke("UpdateSandboxProgress");
            check(Field<TextBlock>("SandboxTimerText").Visibility == Visibility.Collapsed &&
                  Field<TextBlock>("SandboxPrerequisiteText").Visibility == Visibility.Collapsed,
                "Finished runs stop displaying active countdowns and prerequisite pauses");
        }
        finally { elapsed.Reset(); sessionField.SetValue(window, previousSession); }
        var build = typeof(SandboxIssRecorder).GetMethod("BuildDiscoveryScript", BindingFlags.NonPublic | BindingFlags.Static)!;
        var guest = (string)build.Invoke(null, new object[] { "setup.exe", InstallerKind.InstallShield, "/s", "", false, false })!;
        File.WriteAllText(Path.Combine(root, "usability-guest.ps1"), guest);
        check(guest.Contains("function Write-TimerProgress") && guest.Contains("analysis-progress.json") &&
              guest.Contains("ApplicationTimerPaused=[bool]$clock.Waiting"),
            "The generated guest includes timer and prerequisite progress reporting");
    }
}
