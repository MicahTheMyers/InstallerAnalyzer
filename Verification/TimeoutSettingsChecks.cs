using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class TimeoutSettingsChecks
{
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        var previous = TimeoutSettings.Current;
        var configured = new TimeoutSettings { Enabled = true, Seconds = new() { ["Startup"] = 240, ["SilentInstall"] = 1800, ["Operation"] = int.MaxValue } };
        check(configured.GetSeconds("Operation") == 10800 && configured.GetSeconds("NetFxInstall") == 600,
            "Timeout settings bound invalid saved values and default missing values");
        var snapshot = configured.Snapshot();
        configured.Seconds["Startup"] = 300;
        check(snapshot.GetSeconds("Startup") == 240, "An active session's timeout snapshot survives later setting changes");
        configured.Enabled = false;
        check(configured.GetSeconds("Startup") == 180 && configured.Seconds["Startup"] == 300,
            "Disabling custom timeouts retains custom values while restoring default operation");
        T Field<T>(string name) => (T)window.FindName(name);
        void Load(TimeoutSettings settings) => typeof(MainWindow).GetMethod("LoadTimeoutSettings", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, new object[] { settings });
        try
        {
            Load(snapshot);
            var rows = Field<ItemsControl>("TimeoutRows");
            var row = rows.Items.Cast<TimeoutSettingRow>().Single(r => r.Definition.Key == "SilentInstall");
            row.Seconds = 1500;
            var path = MainWindow.SettingsPathOverride!;
            using (var saved = JsonDocument.Parse(File.ReadAllText(path)))
                check(saved.RootElement.GetProperty("Timeouts").GetProperty("Seconds").GetProperty("SilentInstall").GetInt32() == 1500,
                    "Moving a timeout slider persists its value through the normal Settings path");
            var restored = JsonDocument.Parse(File.ReadAllText(path));
            Load(restored.RootElement.GetProperty("Timeouts").Deserialize<TimeoutSettings>()!);
            check(TimeoutSettings.Current.GetSeconds("SilentInstall") == 1500, "Saved timeout settings restore their active values");
            Field<ToggleButton>("CustomTimeoutToggle").IsChecked = false;
            check(TimeoutSettings.Current.GetSeconds("SilentInstall") == 600, "Settings toggle immediately restores default timers for new operations");
            Field<ToggleButton>("CustomTimeoutToggle").IsChecked = true;
            check(TimeoutSettings.Current.GetSeconds("SilentInstall") == 1500, "Re-enabling custom timers restores the retained slider selection");
            var build = typeof(SandboxIssRecorder).GetMethod("BuildDiscoveryScript", BindingFlags.NonPublic | BindingFlags.Static)!;
            var guest = (string)build.Invoke(null, new object[] { "setup.exe", InstallerKind.InstallShield, "/s", "", false, false })!;
            File.WriteAllText(Path.Combine(root, "timeout-custom-guest.ps1"), guest);
            check(guest.Contains("\"SilentInstall\":1500") && guest.Contains("$IATimeouts.SilentInstall") &&
                  guest.Contains("$IATimeouts.Prerequisite") && guest.Contains("$IATimeouts.NetFxInstall"),
                "The generated guest receives custom timeout values used by installation and prerequisite operations");
            var autoUpdates = Field<ToggleButton>("AutoUpdateToggle").IsChecked;
            Field<ToggleButton>("AutoUpdateToggle").IsChecked = false;
            foreach (var theme in new[] { "DarkThemeRadio", "LightThemeRadio", "PurpleThemeRadio" })
            {
                Field<RadioButton>(theme).IsChecked = true;
                typeof(MainWindow).GetMethod("ShowPage", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, new object[] { Field<Grid>("SettingsPage") });
                Field<Expander>("TimeoutSettingsExpander").IsExpanded = true;
                var content = (FrameworkElement)window.Content;
                content.Measure(new Size(1240, 900)); content.Arrange(new Rect(0, 0, 1240, 900)); content.UpdateLayout();
                Field<Expander>("TimeoutSettingsExpander").BringIntoView();
                content.UpdateLayout();
                var container = (ContentPresenter)rows.ItemContainerGenerator.ContainerFromIndex(0);
                container.ApplyTemplate();
                var slider = FindSlider(container)!;
                slider.ApplyTemplate();
                var track = (Track)slider.Template.FindName("PART_Track", slider);
                check(track is not null && slider.IsEnabled && slider.ActualWidth > 300,
                    theme + " renders usable timeout slider controls");
                track!.DecreaseRepeatButton.ApplyTemplate();
                var fill = (Border)VisualTreeHelper.GetChild(track.DecreaseRepeatButton, 0);
                check(((SolidColorBrush)fill.Background).Color == ((SolidColorBrush)window.Resources["Accent"]).Color,
                    theme + " timeout slider fill follows the active theme accent");
            }
            Field<ToggleButton>("AutoUpdateToggle").IsChecked = autoUpdates;
            typeof(MainWindow).GetMethod("ResetTimeouts_Click", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, new object[] { window, new RoutedEventArgs() });
            check(TimeoutSettings.Current.GetSeconds("SilentInstall") == 600 && Field<ToggleButton>("CustomTimeoutToggle").IsChecked == true,
                "Reset restores timeout defaults while retaining the user's custom-mode choice");
        }
        finally { Load(previous); Field<RadioButton>("DarkThemeRadio").IsChecked = true; }
    }

    private static Slider? FindSlider(DependencyObject parent)
    {
        if (parent is Slider slider) return slider;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            if (FindSlider(VisualTreeHelper.GetChild(parent, i)) is { } found) return found;
        return null;
    }
}
