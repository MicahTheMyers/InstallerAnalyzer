using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;
using Microsoft.Win32;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private string? _sandboxScriptKey;
    private bool _loadingSandboxScript;
    private bool _checkingSandboxScript;
    private readonly DispatcherTimer _sandboxScriptSaveTimer = new() { Interval = TimeSpan.FromMilliseconds(700) };
    private SandboxScriptStore SandboxScripts => new(Path.Combine(Path.GetDirectoryName(SettingsPath)!, "SandboxScripts"));

    private void InitializeSandboxScriptEditor()
    {
        _sandboxScriptSaveTimer.Tick += (_, _) => SaveSandboxScriptDraft();
        Closing += (_, _) => SaveSandboxScriptDraft();
    }

    private void LoadSandboxScriptEditor(AnalysisResult result)
    {
        _sandboxScriptSaveTimer.Stop();
        _sandboxScriptKey = InstallerPreferenceStore.Key(result.Archive?.Sha256 ?? result.Identity.Sha256, result.Archive?.Entry);
        _loadingSandboxScript = true;
        try
        {
            var saved = SandboxScripts.Load(_sandboxScriptKey);
            SandboxScriptEditor.Text = saved?.Template ?? SandboxIssRecorder.GetEditableScriptTemplate();
            UseEditedSandboxScript.IsChecked = saved?.Enabled == true;
            SandboxScriptEditor.IsReadOnly = false;
            SandboxScriptToolbar.IsEnabled = true;
            SandboxScriptStatus.Text = saved is null ? "Generated script. Edits are saved for this installer." :
                $"Saved script restored from v{saved.ApplicationVersion}. " + (saved.Enabled ? "Edits will be used in Sandbox." : "Generated script mode is active.");
        }
        catch (Exception ex)
        {
            SandboxScriptEditor.Text = SandboxIssRecorder.GetEditableScriptTemplate();
            SandboxScriptEditor.IsReadOnly = false;
            SandboxScriptToolbar.IsEnabled = true;
            UseEditedSandboxScript.IsChecked = false;
            SandboxScriptStatus.Text = "Could not restore the saved script. " + ex.Message;
        }
        finally { _loadingSandboxScript = false; }
    }

    private void SandboxScriptEditor_Changed(object sender, TextChangedEventArgs e)
    {
        if (_loadingSandboxScript || _sandboxScriptKey is null) return;
        UseEditedSandboxScript.IsChecked = true;
        QueueSandboxScriptSave();
    }

    private void UseEditedSandboxScript_Changed(object sender, RoutedEventArgs e)
    {
        if (!_loadingSandboxScript && _sandboxScriptKey is not null) QueueSandboxScriptSave();
    }

    private void QueueSandboxScriptSave()
    {
        _sandboxScriptSaveTimer.Stop();
        _sandboxScriptSaveTimer.Start();
        SandboxScriptStatus.Text = "Saving script edits…";
    }

    private void SaveSandboxScriptDraft()
    {
        _sandboxScriptSaveTimer.Stop();
        if (_loadingSandboxScript || _sandboxScriptKey is null) return;
        try
        {
            // Incomplete drafts can be saved while typing. They are syntax checked before launch.
            if (SandboxScriptEditor.Text.Length > SandboxScriptStore.MaximumCharacters)
                throw new InvalidDataException("The Sandbox script exceeds 2 MiB of text.");
            var text = SandboxScriptEditor.Text;
            if (text == SandboxIssRecorder.GetEditableScriptTemplate() && UseEditedSandboxScript.IsChecked != true)
                SandboxScripts.Remove(_sandboxScriptKey);
            else SandboxScripts.Save(_sandboxScriptKey, new(text, UseEditedSandboxScript.IsChecked == true, UpdateService.CurrentDisplayVersion, DateTimeOffset.UtcNow));
            SandboxScriptStatus.Text = UseEditedSandboxScript.IsChecked == true
                ? "Edits saved locally. New Sandbox runs will use this script."
                : "Generated script mode. Your edits are retained.";
        }
        catch (Exception ex) { SandboxScriptStatus.Text = "Could not save the Sandbox script. " + ex.Message; }
    }

    private string? EffectiveSandboxScript() => UseEditedSandboxScript.IsChecked == true
        ? SandboxScriptEditor.Text : null;

    private string? SavedSandboxScriptFor(AnalysisResult result)
    {
        var key = InstallerPreferenceStore.Key(result.Archive?.Sha256 ?? result.Identity.Sha256, result.Archive?.Entry);
        if (key == _sandboxScriptKey) { SaveSandboxScriptDraft(); return EffectiveSandboxScript(); }
        var saved = SandboxScripts.Load(key);
        return saved?.Enabled == true ? saved.Template : null;
    }

    private async void CheckSandboxScript_Click(object sender, RoutedEventArgs e)
    {
        if (_checkingSandboxScript) return;
        _checkingSandboxScript = true;
        var text = SandboxScriptEditor.Text;
        try
        {
            SandboxScriptStatus.Text = "Checking PowerShell syntax…";
            var errors = await Task.Run(() => SandboxScriptValidator.Validate(text));
            if (text == SandboxScriptEditor.Text)
                SandboxScriptStatus.Text = errors.Length == 0 ? "PowerShell syntax is valid. Sandbox execution checks behavior." : string.Join("\n", errors);
        }
        catch (Exception ex) { SandboxScriptStatus.Text = "Syntax check failed. " + ex.Message; }
        finally { _checkingSandboxScript = false; }
    }

    private void RestoreSandboxScript_Click(object sender, RoutedEventArgs e)
    {
        if (_sandboxScriptKey is null) return;
        _loadingSandboxScript = true;
        try
        {
            SandboxScripts.Remove(_sandboxScriptKey);
            SandboxScriptEditor.Text = SandboxIssRecorder.GetEditableScriptTemplate();
            UseEditedSandboxScript.IsChecked = false;
            SandboxScriptStatus.Text = "Current generated script restored.";
        }
        catch (Exception ex) { SandboxScriptStatus.Text = "Could not restore the generated script. " + ex.Message; }
        finally { _loadingSandboxScript = false; _sandboxScriptSaveTimer.Stop(); }
    }

    private void ImportSandboxScript_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "PowerShell script (*.ps1)|*.ps1" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            if (new FileInfo(dialog.FileName).Length > 8 * 1024 * 1024) throw new InvalidDataException("The Sandbox script is too large.");
            var text = File.ReadAllText(dialog.FileName);
            SandboxScriptStore.CheckLength(text);
            SandboxScriptEditor.Text = text;
            SaveSandboxScriptDraft();
        }
        catch (Exception ex) { SandboxScriptStatus.Text = "Could not import the Sandbox script. " + ex.Message; }
    }

    private void SaveSandboxScriptFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "PowerShell script (*.ps1)|*.ps1", FileName = "Sandbox-analysis.ps1" };
        if (dialog.ShowDialog(this) != true) return;
        try { File.WriteAllText(dialog.FileName, SandboxScriptEditor.Text, new System.Text.UTF8Encoding(true)); }
        catch (Exception ex) { SandboxScriptStatus.Text = "Could not save the script file. " + ex.Message; }
    }
}
