using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Threading;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private string? _installerPreferenceKey;
    private bool _applyingInstallerPreferences;
    private readonly DispatcherTimer _installerPreferenceTimer = new() { Interval = TimeSpan.FromMilliseconds(600) };
    private InstallerPreferenceStore InstallerPreferencesStore => new(Path.Combine(Path.GetDirectoryName(SettingsPath)!, "installer-preferences.dat"));

    private void InitializeInstallerPreferences()
    {
        _installerPreferenceTimer.Tick += (_, _) => SaveInstallerPreferences();
        foreach (var box in new[] { ProductBox, ArgumentsBox, AdditionalArgumentsBox })
            box.TextChanged += (_, _) => QueueInstallerPreferencesSave();
        KindBox.SelectionChanged += (_, _) => QueueInstallerPreferencesSave();
        foreach (var toggle in new ToggleButton[] { IssCheck, SandboxToggle })
        {
            toggle.Checked += (_, _) => QueueInstallerPreferencesSave();
            toggle.Unchecked += (_, _) => QueueInstallerPreferencesSave();
        }
        Closing += (_, _) => SaveInstallerPreferences();
    }

    private void QueueInstallerPreferencesSave()
    {
        if (_analysisBusy || _applyingInstallerPreferences || _installerPreferenceKey is null) return;
        _installerPreferenceTimer.Stop();
        _installerPreferenceTimer.Start();
    }

    private void SaveInstallerPreferences()
    {
        _installerPreferenceTimer.Stop();
        if (_analysisBusy || _applyingInstallerPreferences || _installerPreferenceKey is null || _result is null) return;
        try
        {
            InstallerPreferencesStore.Save(_installerPreferenceKey,
                new(ProductBox.Text, _result.Kind, ArgumentsBox.Text, AdditionalArgumentsBox.Text,
                    IssCheck.IsChecked == true, SandboxToggle.IsChecked == true, DateTimeOffset.UtcNow),
                _result.Archive?.Sha256, _result.Archive?.Entry);
            RememberedInstallerText.Text = "Installer settings saved on this computer.";
            ResetInstallerPreferencesButton.Visibility = Visibility.Visible;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or FormatException or System.Text.Json.JsonException)
        { RememberedInstallerText.Text = "Installer settings could not be saved. " + ex.Message; }
    }

    private void RestoreInstallerPreferences(AnalysisResult detected)
    {
        _installerPreferenceKey = InstallerPreferenceStore.Key(detected.Archive?.Sha256 ?? detected.Identity.Sha256, detected.Archive?.Entry);
        RememberedInstallerText.Text = "";
        ResetInstallerPreferencesButton.Visibility = Visibility.Collapsed;
        _applyingInstallerPreferences = true;
        try
        {
            var saved = InstallerPreferencesStore.Find(_installerPreferenceKey);
            if (saved is null || !Enum.IsDefined(saved.Kind)) return;
            KindBox.SelectedItem = saved.Kind;
            ProductBox.Text = saved.Product;
            IssCheck.IsChecked = saved.Kind == InstallerKind.InstallShield && saved.RequiresResponseFile;
            SandboxToggle.IsChecked = detected.Archive is not null || saved.UseSandbox;
            ArgumentsBox.Text = saved.Arguments;
            AdditionalArgumentsBox.Text = saved.AdditionalArguments;
            RememberedInstallerText.Text = "Restored your settings for this installer.";
            ResetInstallerPreferencesButton.Visibility = Visibility.Visible;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or FormatException or System.Text.Json.JsonException)
        { RememberedInstallerText.Text = "Saved installer settings could not be read. " + ex.Message; }
        finally { _applyingInstallerPreferences = false; }
    }

    private void ResetInstallerPreferences_Click(object sender, RoutedEventArgs e)
    {
        if (_result is null || _analysisBusy || _issTimer.IsEnabled || _testModeRunning || _sandboxStarting || _sandboxStopping) return;
        _installerPreferenceTimer.Stop();
        try
        {
            if (_installerPreferenceKey is not null) InstallerPreferencesStore.Remove(_installerPreferenceKey, _result.Archive?.Sha256);
            _installerPreferenceKey = null;
            Analyze(_result.Archive?.Path ?? _result.FilePath, _result.Archive?.Entry);
        }
        catch (Exception ex) { RememberedInstallerText.Text = "Could not reset saved installer settings. " + ex.Message; }
    }

    private async void ChangeArchiveInstaller_Click(object sender, RoutedEventArgs e)
    {
        if (_result?.Archive is not { } archive || _analysisBusy || _issTimer.IsEnabled || _testModeRunning || _sandboxStarting || _sandboxStopping) return;
        try
        {
            var entries = await Task.Run(() => InstallerArchive.ListInstallers(archive.Path));
            var selected = ChooseArchiveInstaller(entries);
            if (selected is not null) Analyze(archive.Path, selected);
        }
        catch (Exception ex) { RememberedInstallerText.Text = ex.Message; }
    }
}
