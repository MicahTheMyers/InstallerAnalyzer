using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using InstallerAnalyzer.Services;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private readonly ObservableCollection<TimeoutSettingRow> _timeoutRows = new();
    private bool _loadingTimeouts;
    private void LoadTimeoutSettings(TimeoutSettings? settings)
    {
        _loadingTimeouts = true;
        var configured = settings ?? new TimeoutSettings();
        CustomTimeoutToggle.IsChecked = configured.Enabled;
        foreach (var row in _timeoutRows) row.PropertyChanged -= TimeoutRow_Changed;
        _timeoutRows.Clear();
        // Show retained custom values even while the default timers are enabled.
        var custom = new TimeoutSettings { Enabled = true, Seconds = configured.Seconds };
        foreach (var definition in TimeoutSettings.Definitions)
        {
            var row = new TimeoutSettingRow(definition, custom.GetSeconds(definition.Key));
            row.PropertyChanged += TimeoutRow_Changed;
            _timeoutRows.Add(row);
        }
        TimeoutRows.ItemsSource = _timeoutRows;
        _loadingTimeouts = false;
        PublishTimeoutSettings();
    }

    private TimeoutSettings ReadTimeoutSettings() => new()
    {
        Enabled = CustomTimeoutToggle.IsChecked == true,
        Seconds = _timeoutRows.ToDictionary(row => row.Definition.Key, row => (int)row.Seconds)
    };

    private void PublishTimeoutSettings() => TimeoutSettings.Current = ReadTimeoutSettings();
    private void TimeoutRow_Changed(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(TimeoutSettingRow.Seconds)) SaveTimeoutSettings();
    }
    private void TimeoutToggle_Changed(object sender, RoutedEventArgs e) => SaveTimeoutSettings();
    private void SaveTimeoutSettings()
    {
        if (_loadingTimeouts || !_settingsLoaded) return;
        PublishTimeoutSettings();
        SaveAppSettings();
    }
    private void ResetTimeouts_Click(object sender, RoutedEventArgs e)
    {
        LoadTimeoutSettings(new TimeoutSettings { Enabled = CustomTimeoutToggle.IsChecked == true });
        SaveTimeoutSettings();
    }
}
