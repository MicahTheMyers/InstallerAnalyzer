using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Threading;
using InstallerAnalyzer.Services;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private readonly AiChatService _aiChat = new();
    private readonly ObservableCollection<AiChatTurn> _aiMessages = new();
    private readonly ObservableCollection<AiDiagnosticTarget> _aiTargets = new();
    private readonly List<AiChatTurn> _aiHistory = new();
    private CancellationTokenSource? _aiRequest;
    private int _aiGeneration;
    private bool _aiExpanded, _aiRecentTargetsLoaded;
    private Rect _aiOriginalBounds;
    private string _aiOpenAiModel = "", _aiOllamaModel = "", _aiClaudeModel = "";
    private string _aiHatzModel = "auto";
    private int _aiModelProviderIndex;
    private bool _includeAiEditorScript = true;
    private string SelectedAiProvider => AiProviderBox.SelectedIndex switch { 1 => "Ollama", 2 => "Claude", 3 => "Hatz", _ => "OpenAI" };
    private string SelectedAiModel => AiProviderBox.SelectedIndex switch { 1 => _aiOllamaModel, 2 => _aiClaudeModel, 3 => _aiHatzModel, _ => _aiOpenAiModel };
    private void RememberAiModel(int index)
    {
        var model = AiModelBox.Text.Trim();
        if (index == 1) _aiOllamaModel = model;
        else if (index == 2) _aiClaudeModel = model;
        else if (index == 3) _aiHatzModel = model;
        else _aiOpenAiModel = model;
    }

    private sealed record AiDiagnosticTarget(string Key, string Label, string Folder)
    {
        public override string ToString() => Label;
    }

    private void InitializeAiAssist()
    {
        _aiModelProviderIndex = AiProviderBox.SelectedIndex;
        AiMessagesList.ItemsSource = _aiMessages;
        AiTestBox.ItemsSource = _aiTargets;
        SizeChanged += (_, _) => { if (_aiExpanded) LayoutAiPanel(); };
        Closing += (_, _) =>
        {
            if (!_settingsLoaded) return;
            RememberAiModel(AiProviderBox.SelectedIndex);
            SaveAppSettings();
        };
        Closed += (_, _) => CancelAiRequest();
        UpdateAiAssistVisibility();
    }

    private bool AiIsEnabled => EnableAiAssistToggle.IsChecked == true;

    private void AiAssistSetting_Changed(object sender, RoutedEventArgs e)
    {
        if (!_settingsLoaded) return;
        UpdateAiAssistVisibility(); SaveAppSettings();
    }

    private void UpdateAiAssistVisibility()
    {
        if (AiAssistSettings is null) return;
        AiAssistSettings.Visibility = Visibility.Visible;
        AiConnectionSettings.Visibility = AiIsEnabled ? Visibility.Visible : Visibility.Collapsed;
        if (!AiIsEnabled)
        {
            CancelAiRequest(); _aiHistory.Clear(); _aiMessages.Clear(); AiQuestionBox.Clear();
            AiChatStatus.Text = "AI Assist is off. No requests are sent.";
        }
        else if (_aiRequest is null)
        {
            AiChatStatus.Text = "Ready. Preview diagnostics, then ask a question.";
        }
        var visible = AiIsEnabled && (AnalyzePage.Visibility == Visibility.Visible || SandboxPage.Visibility == Visibility.Visible ||
            DeploymentPage.Visibility == Visibility.Visible || TestModePage.Visibility == Visibility.Visible || SettingsPage.Visibility == Visibility.Visible);
        AiAssistPanel.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        if (visible && !_aiExpanded)
        {
            _aiOriginalBounds = new Rect(Left, Top, Width, Height);
            _aiExpanded = true;
            var area = SystemParameters.WorkArea;
            if (WindowState == WindowState.Normal)
            {
                if (area.Width >= Width + 380) Width += 380;
                else Height = Math.Min(area.Height, Height + 280);
                Left = Math.Clamp(Left, area.Left, Math.Max(area.Left, area.Right - Width));
                Top = Math.Clamp(Top, area.Top, Math.Max(area.Top, area.Bottom - Height));
            }
            LoadRecentAiTargets(); LayoutAiPanel();
        }
        else if (!visible && _aiExpanded)
        {
            _aiExpanded = false;
            SetWorkspaceColumns(0);
            AiBottomRow.Height = new GridLength(0);
            if (WindowState == WindowState.Normal)
            {
                var area = SystemParameters.WorkArea;
                Width = Math.Min(area.Width, _aiOriginalBounds.Width); Height = Math.Min(area.Height, _aiOriginalBounds.Height);
                Left = Math.Clamp(_aiOriginalBounds.Left, area.Left, Math.Max(area.Left, area.Right - Width));
                Top = Math.Clamp(_aiOriginalBounds.Top, area.Top, Math.Max(area.Top, area.Bottom - Height));
            }
        }
        UpdateAiProviderControls();
    }

    private void LayoutAiPanel()
    {
        if (ActualWidth >= 1420)
        {
            AiPrivacyText.Visibility = Visibility.Visible;
            SetWorkspaceColumns(380);
            AiBottomRow.Height = new GridLength(0);
            Grid.SetRow(AiAssistPanel, 0);
        }
        else
        {
            AiPrivacyText.Visibility = Visibility.Collapsed;
            SetWorkspaceColumns(0);
            AiBottomRow.Height = new GridLength(Math.Clamp(ActualHeight * .42, 360, 400));
            Grid.SetRow(AiAssistPanel, 1);
        }
    }

    private void SetWorkspaceColumns(double aiSideWidth)
    {
        var aiOnLeft = aiSideWidth > 0 && NavigationSideBox.SelectedIndex == 1;
        var mainWidth = new GridLength(1, GridUnitType.Star);
        var aiWidth = new GridLength(aiSideWidth);
        WorkspaceLeftColumn.Width = aiOnLeft ? aiWidth : mainWidth;
        WorkspaceRightColumn.Width = aiOnLeft ? mainWidth : aiWidth;
        Grid.SetColumn(MainWorkspace, aiOnLeft ? 1 : 0);
        Grid.SetColumn(AiAssistPanel, aiSideWidth > 0 && !aiOnLeft ? 1 : 0);
    }

    private void AiProvider_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_settingsLoaded) return;
        // SelectionChanged also fires for child controls; only this ComboBox is a provider switch.
        if (!ReferenceEquals(e.Source, AiProviderBox)) return;
        RememberAiModel(_aiModelProviderIndex);
        _aiModelProviderIndex = AiProviderBox.SelectedIndex;
        AiModelBox.Text = SelectedAiModel;
        AiApiKeyBox.Clear(); AiKeyStatus.Text = "";
        ClearAiChat(); UpdateAiProviderControls(); SaveAppSettings();
    }
    private void UpdateAiProviderControls()
    {
        if (AiCloudSettings is null || AiLocalSettings is null) return;
        var local = AiProviderBox.SelectedIndex == 1;
        AiCloudSettings.Visibility = local ? Visibility.Collapsed : Visibility.Visible;
        AiLocalSettings.Visibility = local ? Visibility.Visible : Visibility.Collapsed;
        var providerName = SelectedAiProvider == "Hatz" ? "Hatz AI" : SelectedAiProvider;
        var usageText = SelectedAiProvider == "Hatz" ? "API usage follows your Hatz account's limits. " : "API usage is billed separately from chat subscriptions. ";
        AiApiKeyLabel.Text = providerName + " API key";
        AiModelBox.ToolTip = SelectedAiProvider == "Hatz" ? "Use auto or a model ID available to your Hatz account."
            : "Enter an API model ID, or the name of an already installed local model.";
        AiCloudPrivacyText.Text = providerName + " receives the redacted diagnostics, your question, recent chat turns, and any editor draft you choose to include. "
            + usageText + "Saved keys are protected for your Windows account. Review the diagnostic preview before sending; automatic redaction cannot identify every possible secret.";
        AiPrivacyText.Text = local ? "Local Ollama • Only sends when you ask. Preview the diagnostic snapshot first."
            : providerName + " • Sends a redacted diagnostic snapshot and recent chat when you ask. Preview it first.";
    }
    private void AiConfiguration_Changed(object sender, RoutedEventArgs e)
    {
        if (!_settingsLoaded) return;
        RememberAiModel(AiProviderBox.SelectedIndex);
        ClearAiChat(); SaveAppSettings();
    }
    private void AiSaveKey_Click(object sender, RoutedEventArgs e)
    {
        try { AiCredentialStore.Save(AiApiKeyBox.Password, SelectedAiProvider); AiApiKeyBox.Clear(); AiKeyStatus.Text = "API key saved for this Windows account. The environment variable takes precedence if set."; }
        catch { AiKeyStatus.Text = "The API key could not be saved. Check that LocalAppData is writable and Windows data protection is available."; }
    }
    private void AiRemoveKey_Click(object sender, RoutedEventArgs e)
    {
        CancelAiRequest();
        try { AiCredentialStore.Clear(SelectedAiProvider); AiApiKeyBox.Clear(); AiKeyStatus.Text = "Saved key removed. An environment key, if set, is still available until removed outside the app."; }
        catch { AiKeyStatus.Text = "The saved API key could not be removed."; }
    }

    private void RegisterAiDiagnosticTarget(string key, string label, string folder, bool select = false)
    {
        var previous = _aiTargets.FirstOrDefault(t => t.Key == key);
        var target = new AiDiagnosticTarget(key, label, folder);
        var selected = previous is not null && ReferenceEquals(previous, AiTestBox.SelectedItem);
        if (previous is not null) _aiTargets[_aiTargets.IndexOf(previous)] = target; else _aiTargets.Insert(0, target);
        if (select || selected || AiTestBox.SelectedItem is null) AiTestBox.SelectedItem = target;
        while (_aiTargets.Count > 40) _aiTargets.RemoveAt(_aiTargets.Count - 1);
    }
    private void LoadRecentAiTargets()
    {
        if (_aiRecentTargetsLoaded || !Directory.Exists(TestResultsFolder)) return;
        _aiRecentTargetsLoaded = true;
        try
        {
            foreach (var run in Directory.EnumerateDirectories(TestResultsFolder).OrderByDescending(Path.GetFileName).Take(4))
            {
                if ((File.GetAttributes(run) & FileAttributes.ReparsePoint) != 0) continue;
                foreach (var folder in Directory.EnumerateDirectories(run).Take(10))
                {
                    if ((File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0) continue;
                    if (!_aiTargets.Any(target => string.Equals(target.Folder, folder, StringComparison.OrdinalIgnoreCase)))
                        _aiTargets.Add(new(folder, Path.GetFileName(folder) + " • " + Path.GetFileName(run), folder));
                }
            }
            if (_aiTargets.Count > 0) AiTestBox.SelectedIndex = 0;
        }
        catch { AiChatStatus.Text = "Recent diagnostics could not be listed. New completed tests will appear here."; }
    }
    private void AiTest_Changed(object sender, SelectionChangedEventArgs e)
    {
        ClearAiChat();
        if (AiIncludeEditorCheck is not null)
        {
            var hasEditor = AiTestBox.SelectedItem is AiDiagnosticTarget target && IsCurrentAiInstaller(target);
            AiIncludeEditorCheck.IsEnabled = hasEditor;
            AiIncludeEditorCheck.IsChecked = hasEditor && _includeAiEditorScript;
        }
    }
    private void AiIncludeEditor_Click(object sender, RoutedEventArgs e) =>
        _includeAiEditorScript = AiIncludeEditorCheck.IsChecked == true;

    private void AiClear_Click(object sender, RoutedEventArgs e) => ClearAiChat();
    private void ClearAiChat()
    {
        CancelAiRequest(); _aiHistory.Clear(); _aiMessages.Clear();
        if (AiChatStatus is not null) AiChatStatus.Text = "Ask about the selected installer or run, or press Explain. Nothing is sent automatically.";
    }
    private void CancelAiRequest()
    {
        _aiGeneration++; _aiRequest?.Cancel(); _aiRequest = null;
        if (AiSendButton is not null) { AiSendButton.IsEnabled = true; AiExplainButton.IsEnabled = true; AiCancelButton.IsEnabled = false; }
    }
    private void AiCancel_Click(object sender, RoutedEventArgs e) { CancelAiRequest(); AiChatStatus.Text = "AI request cancelled. Installer runs continue independently."; }
    private bool IsCurrentAiInstaller(AiDiagnosticTarget target) => _sandboxScriptKey is not null &&
        (string.Equals(target.Key, _installerPath, StringComparison.OrdinalIgnoreCase) ||
         string.Equals(target.Folder, _issSession?.OutputFolder, StringComparison.OrdinalIgnoreCase));

    private string? GetAiEditorScript(AiDiagnosticTarget target) =>
        AiIncludeEditorCheck.IsChecked == true && IsCurrentAiInstaller(target) ? SandboxScriptEditor.Text : null;

    private string AiControlsContext(AiDiagnosticTarget target)
    {
        var currentInstaller = IsCurrentAiInstaller(target);
        var editorState = currentInstaller
            ? "Use edited script is " + (UseEditedSandboxScript.IsChecked == true ? "enabled" : "disabled") +
              "; draft " + (SandboxScriptEditor.Text == SandboxIssRecorder.GetEditableScriptTemplate() ? "matches the current generated template." : "contains edits.")
            : null;
        var controls = AiDiagnosticContext.DescribeControls(ReadTimeoutSettings(), editorState);
        if (!currentInstaller || _result is null) return controls;
        string Safe(string value, int maximum) => AiDiagnosticContext.Redact(value[..Math.Min(value.Length, maximum)]);
        var selection = System.Text.Json.JsonSerializer.Serialize(new
        {
            Installer = Path.GetFileName(_result.Archive?.Path ?? _result.FilePath),
            SelectedArchiveEntry = _result.Archive?.Entry,
            Kind = _result.Kind.ToString(), _result.Confidence, _result.Architecture,
            Product = Safe(ProductBox.Text, 200), _result.CompanyName, _result.FileVersion,
            BaseArguments = Safe(ArgumentsBox.Text, 400),
            AdditionalArguments = Safe(AdditionalArgumentsBox.Text, 400),
            UiStatus = Safe(StatusText.Text, 500)
        });
        return "\n[Current Analyze selection — current configuration, separate from recorded run evidence]\n" + selection + "\n" + controls;
    }
    private async void AiPreview_Click(object sender, RoutedEventArgs e)
    {
        if (!AiIsEnabled) return;
        if (AiTestBox.SelectedItem is not AiDiagnosticTarget target) { AiChatStatus.Text = "Select an installer or a recorded run first."; return; }
        var generation = _aiGeneration;
        string snapshot;
        var controls = AiControlsContext(target);
        var editorScript = GetAiEditorScript(target);
        try
        {
            snapshot = await Task.Run(() => AiDiagnosticContext.Build(target.Label, target.Folder, controls) +
                (editorScript is null ? "" : AiDiagnosticContext.DescribeEditorScript(editorScript)));
        }
        catch (InvalidOperationException ex) { if (generation == _aiGeneration) AiChatStatus.Text = ex.Message; return; }
        catch { if (generation == _aiGeneration) AiChatStatus.Text = "Diagnostic preview is unavailable. Select a current test result."; return; }
        if (!AiIsEnabled || generation != _aiGeneration) return;
        var preview = new TextBox { Text = snapshot, IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(16) };
        preview.Foreground = (System.Windows.Media.Brush)Resources["Text"]; preview.Background = (System.Windows.Media.Brush)Resources["InputBg"];
        var window = new Window { Owner = this, Title = "Diagnostic snapshot • Read-only preview", Width = Math.Min(780, SystemParameters.WorkArea.Width),
            Height = Math.Min(600, SystemParameters.WorkArea.Height), WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = preview };
        window.Background = (System.Windows.Media.Brush)Resources["Card"]; window.ShowDialog();
    }
    private async void AiExplain_Click(object sender, RoutedEventArgs e)
    {
        var deploymentTarget = DeploymentTargetBox.SelectedIndex == 1 ? "Datto RMM" : "ImmyBot";
        await SendAiQuestionAsync(
            "Give a short outcome for the selected installer or run. For a pass, list the checks that passed. " +
            "For a failure, give the reason and the best first fix. For an incomplete run, give the current stage and what needs validation. " +
            "If suggesting a deployment script, use the selected target, " + deploymentTarget + ".");
    }
    private async void AiSend_Click(object sender, RoutedEventArgs e) => await SendAiQuestionAsync(AiQuestionBox.Text);
    private async void AiQuestion_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Keyboard.Modifiers.HasFlag(ModifierKeys.Control)) { e.Handled = true; await SendAiQuestionAsync(AiQuestionBox.Text); }
    }
    private async Task SendAiQuestionAsync(string question)
    {
        if (!AiIsEnabled || _aiRequest is not null) return;
        if (AiTestBox.SelectedItem is not AiDiagnosticTarget target) { AiChatStatus.Text = "Select an installer or a recorded run first."; return; }
        if (string.IsNullOrWhiteSpace(question)) { AiChatStatus.Text = "Enter a question or press Explain."; return; }
        var options = new AiChatOptions(true, SelectedAiProvider, AiModelBox.Text.Trim(), AiLocalServerBox.Text.Trim());
        var editorScript = GetAiEditorScript(target);
        var request = new CancellationTokenSource(); _aiRequest = request;
        var generation = ++_aiGeneration;
        AiSendButton.IsEnabled = false; AiExplainButton.IsEnabled = false; AiCancelButton.IsEnabled = true;
        AiChatStatus.Text = "Reading diagnostic snapshot…";
        var redactedQuestion = AiDiagnosticContext.Redact(question);
        _aiMessages.Add(new("You", redactedQuestion)); AiQuestionBox.Clear();
        try
        {
            var controls = AiControlsContext(target);
            var snapshot = await Task.Run(() => AiDiagnosticContext.Build(target.Label, target.Folder, controls), request.Token);
            request.Token.ThrowIfCancellationRequested();
            var key = options.Provider == "Ollama" ? "" : AiCredentialStore.Load(options.Provider);
            AiChatStatus.Text = "Waiting for " + options.Provider + "…";
            var answer = await _aiChat.SendAsync(options, key, snapshot, _aiHistory.ToArray(), redactedQuestion, request.Token, editorScript);
            if (generation != _aiGeneration || !AiIsEnabled) return;
            _aiMessages.Add(new("AI Assist", answer));
            if (editorScript is null)
            {
                _aiHistory.Add(new("user", redactedQuestion));
                _aiHistory.Add(new("assistant", answer));
            }
            while (_aiHistory.Count > 8) _aiHistory.RemoveAt(0);
            while (_aiMessages.Count > 30) _aiMessages.RemoveAt(0);
            AiMessagesList.ScrollIntoView(_aiMessages.Last());
            AiChatStatus.Text = "Read-only answer. No changes were applied.";
        }
        catch (OperationCanceledException) { if (generation == _aiGeneration) AiChatStatus.Text = "AI request cancelled."; }
        catch (Exception ex)
        {
            if (generation == _aiGeneration && AiIsEnabled)
                AiChatStatus.Text = ex is InvalidOperationException ? ex.Message : "AI Assist could not complete this request. Check the connection settings or saved key.";
        }
        finally
        {
            if (ReferenceEquals(_aiRequest, request)) _aiRequest = null;
            request.Dispose();
            if (generation == _aiGeneration) { AiSendButton.IsEnabled = true; AiExplainButton.IsEnabled = true; AiCancelButton.IsEnabled = false; }
        }
    }
}
