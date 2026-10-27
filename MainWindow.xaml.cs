using System.IO;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Diagnostics;
using System.Threading;
using System.Windows.Threading;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;
using MessageBox = System.Windows.MessageBox;
using Clipboard = System.Windows.Clipboard;
using DataFormats = System.Windows.DataFormats;
using DragDropEffects = System.Windows.DragDropEffects;
using Color = System.Windows.Media.Color;
using FontFamily = System.Windows.Media.FontFamily;
using ColorConverter = System.Windows.Media.ColorConverter;

namespace InstallerAnalyzer;
public partial class MainWindow : Window
{
    private readonly InstallerDetector _detector = new();
    private AnalysisResult? _result;
    private string? _installerPath;
    private SandboxIssSession? _issSession;
    private readonly DispatcherTimer _issTimer = new() { Interval = TimeSpan.FromSeconds(2) };
    private bool _updatingSettingsToggle;
    private InstallAnalysis? _installAnalysis;
    private UninstallEntry? _selectedUninstallEntry;
    private ScriptView _scriptView = ScriptView.Install;
    private bool _analysisLoaded;
    private DateTime? _sandboxCheckpointFirstSeen;
    private DateTime? _sandboxLastActivityAt;
    private DateTime? _sandboxLastActivityFileWrite;
    private string? _liveWorkflowStage;
    private DateTime? _liveWorkflowStageUpdatedAt;
    private readonly List<string> _liveWorkflowStageHistory = new();
    private string? _lastSandboxStageSignature;
    private DateTime? _analysisResultFirstSeenAt;
    private bool _hostValidatedCheckpointPromoted;
    private static readonly TimeSpan SandboxOverallTimeout = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan SandboxInactivityTimeout = TimeSpan.FromMinutes(12);
    private readonly DispatcherTimer _sandboxWindowTimer = new() { Interval = TimeSpan.FromMilliseconds(600) };
    private IntPtr _sandboxWindow = IntPtr.Zero;
    private bool _integratedViewerActive;
    private bool _settingsLoaded;
    private string? _logoPath;
    private readonly UpdateService _updateService = new();
    private UpdateInfo? _availableUpdate;
    private string SettingsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer", "settings.json");

    public MainWindow()
    {
        InitializeComponent();
        KindBox.ItemsSource = Enum.GetValues<InstallerKind>();
        _issTimer.Tick += IssTimer_Tick;
        _sandboxWindowTimer.Tick += SandboxWindowTimer_Tick;
        LoadAppSettings();
        RefreshSandboxSettings();
        UpdateSandboxPage();
        RefreshHistory();
        Loaded += MainWindow_Loaded;
    }

    private void Select_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "Installers (*.exe;*.msi;*.msix;*.appx;*.msixbundle;*.appxbundle)|*.exe;*.msi;*.msix;*.appx;*.msixbundle;*.appxbundle|All files (*.*)|*.*" };
        if (d.ShowDialog() == true) Analyze(d.FileName);
    }
    private void Window_DragOver(object sender, System.Windows.DragEventArgs e) => e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
    private void Window_Drop(object sender, System.Windows.DragEventArgs e) { if (e.Data.GetData(DataFormats.FileDrop) is string[] f && f.Length > 0) Analyze(f[0]); }

    private void Analyze(string path)
    {
        try
        {
            _result = _detector.Analyze(path); _installerPath = path; _issSession = null; _installAnalysis = null; _selectedUninstallEntry = null; _analysisLoaded = false; _liveWorkflowStage = null; _liveWorkflowStageUpdatedAt = null; _liveWorkflowStageHistory.Clear(); _lastSandboxStageSignature = null; _analysisResultFirstSeenAt = null; _hostValidatedCheckpointPromoted = false; _scriptView = ScriptView.Install; OpenIssButton.IsEnabled = false;
            _logoPath = ApplicationLogoService.ExtractPng(path);
            FileText.Text = path; KindBox.SelectedItem = _result.Kind; ConfidenceText.Text = $"{_result.Confidence}%"; ConfidenceBar.Value = _result.Confidence;
            StatusText.Text = $"Analyzed {Path.GetFileName(path)}"; ArchText.Text = _result.Architecture;
            ProductBox.Text = string.IsNullOrWhiteSpace(_result.ProductName) ? Path.GetFileNameWithoutExtension(path) : _result.ProductName;
            CompanyText.Text = _result.CompanyName; VersionText.Text = _result.FileVersion; ArgumentsBox.Text = _result.SuggestedArguments; AdditionalArgumentsBox.Text = string.Empty;
            ConfigurePackageProfile();
            IssCheck.IsChecked = _result.NeedsIss; EvidenceList.ItemsSource = _result.Evidence; UpdateSandboxControls(); UpdateSandboxPage(); Generate(); UpdateImmyBotPage(); SaveHistorySnapshot();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Analysis failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void Generate_Click(object sender, RoutedEventArgs e) => Generate();
    private void Generate()
    {
        if (_result is null) return;
        _result.Kind = (InstallerKind)(KindBox.SelectedItem ?? InstallerKind.Unknown); _result.NeedsIss = IssCheck.IsChecked == true;
        var script = _scriptView switch
        {
            ScriptView.Detection => ImmyBotScriptGenerator.GenerateDetection(_selectedUninstallEntry, ProductBox.Text),
            ScriptView.Uninstall => ImmyBotScriptGenerator.GenerateUninstall(_selectedUninstallEntry, ProductBox.Text, _installAnalysis),
            ScriptView.Validation => ValidationReportGenerator.Generate(_installAnalysis, _selectedUninstallEntry, ProductBox.Text),
            _ => ImmyBotScriptGenerator.Generate(_result, EffectiveSilentArguments(), ProductBox.Text)
        };
        SetHighlightedScript(script);
        UpdateImmyBotPage();
    }

    private void InstallTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Install; Generate(); }
    private void DetectionTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Detection; Generate(); }
    private void UninstallTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Uninstall; Generate(); }
    private void ValidationTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Validation; Generate(); }
    private void Copy_Click(object sender, RoutedEventArgs e) { var text = GetScriptText(); if (!string.IsNullOrWhiteSpace(text)) Clipboard.SetText(text); }
    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var text = GetScriptText();
        if (string.IsNullOrWhiteSpace(text)) return;
        var isValidation = _scriptView == ScriptView.Validation;
        var d = new SaveFileDialog { Filter = isValidation ? "Text report (*.txt)|*.txt" : "PowerShell script (*.ps1)|*.ps1", FileName = isValidation ? "Validation.txt" : $"{_scriptView}.ps1" };
        if (d.ShowDialog() == true) File.WriteAllText(d.FileName, text);
    }

    private void UpdateSandboxControls()
    {
        var isInstallShield = _result?.Kind == InstallerKind.InstallShield || KindBox.SelectedItem is InstallerKind.InstallShield;
        RecordIssButton.IsEnabled = _installerPath is not null && isInstallShield;
        RecordIssButton.Visibility = isInstallShield ? Visibility.Visible : Visibility.Collapsed;
        IssCheck.Visibility = isInstallShield ? Visibility.Visible : Visibility.Collapsed;
        OpenIssButton.Visibility = isInstallShield ? Visibility.Visible : Visibility.Collapsed;
        if (!isInstallShield) OpenIssButton.IsEnabled = false;
        SidebarSandboxButton.IsEnabled = true;
        if (_result?.Kind == InstallerKind.Squirrel) IssStatusText.Text = "Squirrel.Windows detected: response file not required. Uses --silent and normally installs per-user under %LocalAppData%.";
        else if (_result?.Kind == InstallerKind.QSetup) IssStatusText.Text = "QSetup detected: response file not required. /Hide lifecycle behavior is Sandbox validated; package-specific arguments may also be required.";
        else if (!isInstallShield) IssStatusText.Text = "setup.iss recording is only enabled for InstallShield installers.";
        else if (SandboxToggle.IsChecked == true && !SandboxIssRecorder.IsSandboxAvailable()) IssStatusText.Text = "Sandbox mode is selected, but Windows Sandbox is not enabled. Open Settings to enable it in Windows Features.";
        else if (SandboxToggle.IsChecked == true) IssStatusText.Text = "Ready to record setup.iss safely in Windows Sandbox.";
        else IssStatusText.Text = "Local mode selected. Generating setup.iss will run the installer on this computer.";
    }

    private static void EnsurePreviousSandboxSessionClosed()
    {
        // Windows Sandbox can leave a client/session process behind after a forced or host-side close.
        // Starting another .wsb while that stale client is still connected can produce the
        // "too many sessions established" error. Only clean up Windows Sandbox client processes;
        // never touch Hyper-V services or unrelated virtualization processes.
        var processNames = new[] { "WindowsSandboxClient", "WindowsSandbox", "WindowsSandboxRemoteSession" };
        var found = false;
        foreach (var processName in processNames)
        {
            foreach (var process in Process.GetProcessesByName(processName))
            {
                try
                {
                    found = true;
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    process.WaitForExit(5000);
                }
                catch { }
                finally { process.Dispose(); }
            }
        }
        if (found) Thread.Sleep(2500);
    }

    private void SandboxToggle_Changed(object sender, RoutedEventArgs e) { if (IsLoaded) UpdateSandboxControls(); }

    private void RecordIss_Click(object sender, RoutedEventArgs e)
    {
        if (_installerPath is null) return;
        try
        {
            if (SandboxToggle.IsChecked == true)
            {
                _analysisLoaded = false;
                _sandboxCheckpointFirstSeen = null;
                _sandboxLastActivityAt = DateTime.Now;
                _sandboxLastActivityFileWrite = null;
                _installAnalysis = null;
                _selectedUninstallEntry = null;
                if (!SandboxIssRecorder.IsSandboxAvailable())
                {
                    var answer = MessageBox.Show("Windows Sandbox is not enabled. Open Windows Features now?", "Windows Sandbox", MessageBoxButton.YesNo, MessageBoxImage.Information);
                    if (answer == MessageBoxResult.Yes) OpenWindowsFeatures();
                    return;
                }
                EnsurePreviousSandboxSessionClosed();
                _issSession = SandboxIssRecorder.Start(_installerPath, _result?.Kind ?? InstallerKind.Unknown, _result?.NeedsIss == true,
                    ArgumentsBox.Text?.Trim() ?? string.Empty, AdditionalArgumentsBox.Text?.Trim() ?? string.Empty,
                    BlockBundledMcAfeeToggle.IsChecked == true);
                _sandboxWindow = IntPtr.Zero;
                _integratedViewerActive = false;
                _sandboxWindowTimer.Start();
                BringSandboxFrontButton.IsEnabled = true;
                StopSandboxButton.IsEnabled = true;
                StartSandboxButton.IsEnabled = false;
                SandboxOpenOutputButton.IsEnabled = true;
                ShowPage(SandboxPage);
                SandboxRunStatus.Text = "Starting Windows Sandbox…";
                SandboxRunDetails.Text = $"Analyzing {Path.GetFileName(_installerPath)} using the {_result?.Kind ?? InstallerKind.Unknown} strategy.";
                SandboxArtifactText.Text = $"Output: {_issSession.OutputFolder}";
                IssStatusText.Text = _result?.NeedsIss == true ? "Windows Sandbox started. Complete the interactive InstallShield recording workflow." : "Windows Sandbox started. Complete the installer normally; Installer Analyzer will capture the installed application and registry changes.";
                StatusText.Text = _result?.NeedsIss == true ? "Sandbox ISS recording in progress" : "Sandbox installation analysis in progress";
            }
            else
            {
                var answer = MessageBox.Show("Sandbox is OFF. The installer will run in record mode on this computer and may install or modify the application locally. Continue?", "Local ISS recording", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes) return;
                _issSession = SandboxIssRecorder.StartLocal(_installerPath);
                IssStatusText.Text = "Installer started locally in record mode. Complete it normally. Waiting for setup.iss…";
                StatusText.Text = "Local ISS recording in progress";
            }
            OpenIssButton.IsEnabled = _issSession.RequiresIss; _issTimer.Start();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "ISS recorder", MessageBoxButton.OK, MessageBoxImage.Error); UpdateSandboxControls(); }
    }

    private void IssTimer_Tick(object? sender, EventArgs e)
    {
        if (_issSession is null) return;

        // v0.11.41 host-side activity-aware hang protection. The generated analysis script
        // writes a lightweight heartbeat while discovery/install/process monitoring is active.
        // Twelve minutes with no heartbeat/checkpoint activity is considered stalled, while a
        // 30-minute absolute ceiling remains as the final emergency guardrail.
        if (!_analysisLoaded)
        {
            if (File.Exists(_issSession.CheckpointPath) && _sandboxCheckpointFirstSeen is null)
                _sandboxCheckpointFirstSeen = DateTime.Now;

            DateTime? newestWrite = null;
            foreach (var activityPath in new[] { _issSession.HeartbeatPath, _issSession.CheckpointPath })
            {
                try
                {
                    if (!File.Exists(activityPath)) continue;
                    var write = File.GetLastWriteTime(activityPath);
                    if (newestWrite is null || write > newestWrite.Value) newestWrite = write;
                }
                catch { }
            }
            if (newestWrite is DateTime writeAt && (_sandboxLastActivityFileWrite is null || writeAt > _sandboxLastActivityFileWrite.Value))
            {
                _sandboxLastActivityFileWrite = writeAt;
                _sandboxLastActivityAt = DateTime.Now;
            }

            // Live Current Stage: checkpoints are partial diagnostics, not completion.
            // Read only the stage fields so the dashboard can update every timer tick without
            // marking the analysis as loaded/completed.
            try
            {
                if (File.Exists(_issSession.CheckpointPath))
                {
                    var checkpointRoot = JsonNode.Parse(File.ReadAllText(_issSession.CheckpointPath))?.AsObject();
                    var stage = checkpointRoot?["WorkflowStage"]?.GetValue<string>();
                    var updatedText = checkpointRoot?["WorkflowStageUpdatedAt"]?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(stage))
                    {
                        _liveWorkflowStage = stage;
                        if (DateTime.TryParse(updatedText, out var stageAt)) _liveWorkflowStageUpdatedAt = stageAt;
                        _liveWorkflowStageHistory.Clear();
                        if (checkpointRoot?["WorkflowStageHistory"] is JsonArray history)
                        {
                            foreach (var item in history)
                            {
                                var historicalStage = item?["Stage"]?.GetValue<string>();
                                if (!string.IsNullOrWhiteSpace(historicalStage) &&
                                    (_liveWorkflowStageHistory.Count == 0 || _liveWorkflowStageHistory[^1] != historicalStage))
                                    _liveWorkflowStageHistory.Add(historicalStage);
                            }
                        }
                        // v0.11.41 host-side completion recovery. Keep the Sandbox payload identical
                        // to the launch-stable v0.11.38 script. If lifecycle validation has already
                        // proven reinstall + final uninstall + absence, promote that checkpoint on
                        // the host instead of waiting for optional Sandbox finalization that may hang.
                        var postUninstallDetected = checkpointRoot?["PostUninstallDetected"]?.GetValue<bool?>();
                        var reinstallValidated = checkpointRoot?["SilentReinstallValidated"]?.GetValue<bool?>() == true;
                        var finalUninstallExit = checkpointRoot?["SilentUninstallExitCode"]?.GetValue<int?>();
                        if (!_hostValidatedCheckpointPromoted && reinstallValidated && finalUninstallExit is 0 or 3010 &&
                            postUninstallDetected == false && stage.StartsWith("Final absence verification", StringComparison.OrdinalIgnoreCase))
                        {
                            checkpointRoot!["SilentUninstallValidated"] = true;
                            checkpointRoot["ValidationError"] = null;
                            checkpointRoot["WorkflowStage"] = "Deployment validation complete (host-confirmed)";
                            checkpointRoot["WorkflowStageUpdatedAt"] = DateTime.Now.ToString("o");
                            File.WriteAllText(_issSession.AnalysisPath, checkpointRoot.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                            _hostValidatedCheckpointPromoted = true;
                            _analysisResultFirstSeenAt = DateTime.Now;
                            _installAnalysis = JsonSerializer.Deserialize<InstallAnalysis>(checkpointRoot.ToJsonString(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            _selectedUninstallEntry = ChooseBestEntry(_installAnalysis?.NewUninstallEntries ?? new List<UninstallEntry>());
                            _analysisLoaded = true;
                            _liveWorkflowStage = "Deployment validation complete (host-confirmed)";
                            try { File.WriteAllText(_issSession.CompleteFlagPath, "host-confirmed " + DateTime.Now.ToString("o")); } catch { }
                        }
                        SandboxRunStatus.Text = "Analysis running";
                        SandboxRunDetails.Text = stage;
                        UpdateSandboxDashboard();
                    }
                }
            }
            catch { }

            var overallTimedOut = DateTime.Now - _issSession.StartedAt >= SandboxOverallTimeout;
            var inactivityTimedOut = _sandboxLastActivityAt is DateTime lastActivity &&
                                     DateTime.Now - lastActivity >= SandboxInactivityTimeout;
            if (overallTimedOut || inactivityTimedOut)
            {
                FinalizeTimedOutSandboxRun(overallTimedOut
                    ? "Sandbox analysis exceeded the 30-minute absolute safety limit."
                    : "Sandbox analysis produced no heartbeat or checkpoint activity for 12 minutes.");
                return;
            }
        }

        if (!_analysisLoaded && File.Exists(_issSession.AnalysisPath))
        {
            try
            {
                _installAnalysis = JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(_issSession.AnalysisPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                _selectedUninstallEntry = ChooseBestEntry(_installAnalysis?.NewUninstallEntries ?? new List<UninstallEntry>());
                _analysisLoaded = true;
                _analysisResultFirstSeenAt ??= DateTime.Now;
                UpdateSandboxDashboard();
                if (_selectedUninstallEntry is not null)
                {
                    StatusText.Text = $"Detected installed app: {_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}".Trim();
                    if (!string.IsNullOrWhiteSpace(_selectedUninstallEntry.DisplayName)) ProductBox.Text = _selectedUninstallEntry.DisplayName;
                    if (!string.IsNullOrWhiteSpace(_selectedUninstallEntry.DisplayVersion)) VersionText.Text = _selectedUninstallEntry.DisplayVersion;
                }
            }
            catch { }
        }
        var requiresIss = _issSession.RequiresIss;
        if (!_analysisLoaded)
        {
            if (requiresIss && File.Exists(_issSession.IssPath)) IssStatusText.Text = "setup.iss created. Waiting for Sandbox installation analysis…";
            StatusText.Text = "Waiting for installation analysis";
            return;
        }
        if (requiresIss && !File.Exists(_issSession.IssPath)) return;

        if (!_hostValidatedCheckpointPromoted && !File.Exists(_issSession.CompleteFlagPath))
        {
            SandboxRunStatus.Text = "Finalizing analysis";
            SandboxRunDetails.Text = _liveWorkflowStage ?? "Validated result captured; waiting for completion handoff.";
            UpdateSandboxDashboard();
            if (_analysisResultFirstSeenAt is not DateTime resultSeen || DateTime.Now - resultSeen < TimeSpan.FromMinutes(2))
                return;

            // The validated result is already safely on the host. Optional Sandbox cleanup must
            // never strand the UI indefinitely. After two minutes, accept the committed result
            // and close the Sandbox while preserving any bundled-software verification state.
            try { File.WriteAllText(_issSession.CompleteFlagPath, "host-finalization-fallback " + DateTime.Now.ToString("o")); } catch { }
            SandboxRunDetails.Text = "Validated analysis captured. Optional Sandbox finalization exceeded two minutes; host completed the handoff safely.";
        }

        _issTimer.Stop(); UpdateSandboxDashboard(); SandboxRunStatus.Text = "Analysis complete";
        SandboxRunDetails.Text = _selectedUninstallEntry is null ? "Sandbox completed. No primary application was identified." : $"Detected {_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}. Installation analysis captured.";
        StopSandboxButton.IsEnabled = false;
        StartSandboxButton.IsEnabled = _installerPath is not null;
        if (AutoCloseSandboxToggle.IsChecked == true)
        {
            SandboxWindowEmbedder.ForceCloseSandboxWindow(_sandboxWindow);
            _sandboxWindowTimer.Stop();
            BringSandboxFrontButton.IsEnabled = false;
            _sandboxWindow = IntPtr.Zero;
            SandboxRunDetails.Text += " Windows Sandbox closed automatically after output capture.";
        }
        if (requiresIss)
        {
            IssCheck.IsChecked = true; IssStatusText.Text = $"setup.iss created: {_issSession.IssPath}"; ArgumentsBox.Text = "/s /f1`\"$ResponseFile`\"";
            StatusText.Text = _selectedUninstallEntry is null ? "setup.iss recorded successfully" : "setup.iss + install analysis captured";
        }
        else
        {
            IssCheck.IsChecked = false; IssStatusText.Text = "Installation analysis captured. This installer strategy does not require setup.iss.";
            StatusText.Text = _selectedUninstallEntry is null ? "Installation analysis captured" : "Installed application identified";
        }
        _scriptView = ScriptView.Install; Generate();
        var details = _selectedUninstallEntry is null ? "No new uninstall registry entry was identified." : $"Detected: {_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}\n\nDetection, Uninstall, and Validation results are now available.";
        // Completion is reflected in the dashboard; avoid a routine informational modal.
        _ = details;
    }

    private void FinalizeTimedOutSandboxRun(string reason)
    {
        if (_issSession is null) return;
        try
        {
            var source = File.Exists(_issSession.CheckpointPath) ? _issSession.CheckpointPath : null;
            JsonObject root;
            if (source is not null)
                root = JsonNode.Parse(File.ReadAllText(source))?.AsObject() ?? new JsonObject();
            else
                root = new JsonObject
                {
                    ["Installer"] = _installerPath is null ? null : Path.GetFileName(_installerPath),
                    ["DiscoverySucceeded"] = false,
                    ["NewUninstallEntries"] = new JsonArray()
                };

            root["CapturedAt"] = DateTime.Now.ToString("o");
            root["ValidationError"] = reason;
            var lastStage = root["WorkflowStage"]?.GetValue<string>();
            root["TimedOutStage"] = !string.IsNullOrWhiteSpace(lastStage)
                ? lastStage
                : (_sandboxCheckpointFirstSeen is null ? "Initial analysis / discovery" : "Lifecycle validation");
            root["WorkflowStage"] = "Timed out by host safety watchdog";
            root["HostTimeout"] = true;
            File.WriteAllText(_issSession.AnalysisPath, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

            // v0.11.41: immediately hydrate the promoted checkpoint so timeout UI still shows
            // the discovered primary application, dependencies, commands, and partial confidence.
            _installAnalysis = JsonSerializer.Deserialize<InstallAnalysis>(root.ToJsonString(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            _selectedUninstallEntry = ChooseBestEntry(_installAnalysis?.NewUninstallEntries ?? new List<UninstallEntry>());
            _analysisLoaded = _installAnalysis is not null;
        }
        catch
        {
            // Even if diagnostic promotion fails, never leave an unattended Sandbox hung.
        }

        SandboxWindowEmbedder.ForceCloseSandboxWindow(_sandboxWindow);
        _sandboxWindowTimer.Stop();
        BringSandboxFrontButton.IsEnabled = false;
        StopSandboxButton.IsEnabled = false;
        StartSandboxButton.IsEnabled = _installerPath is not null;
        _sandboxWindow = IntPtr.Zero;
        SandboxRunStatus.Text = "Analysis timed out";
        SandboxRunDetails.Text = reason + " Partial diagnostics were preserved when available.";
        StatusText.Text = "Sandbox analysis timed out — diagnostics preserved";
        // Leave the normal timer running for one more tick so the promoted final JSON
        // is loaded through the exact same result path as a normal completed analysis.
    }

    private UninstallEntry? ChooseBestEntry(List<UninstallEntry> entries)
    {
        if (entries.Count == 0) return null;

        var expectedNames = new[]
        {
            ProductBox.Text,
            _result?.ProductName,
            _installerPath is null ? null : Path.GetFileNameWithoutExtension(_installerPath)
        }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => NormalizeName(x!)).Distinct().ToArray();

        return entries
            .Select(e => new { Entry = e, Score = ScoreEntry(e, expectedNames) })
            .OrderByDescending(x => x.Score)
            .ThenByDescending(x => !string.IsNullOrWhiteSpace(x.Entry.DisplayVersion))
            .Select(x => x.Entry)
            .FirstOrDefault();
    }

    private static int ScoreEntry(UninstallEntry e, string[] expectedNames)
    {
        var score = 0;
        var name = NormalizeName(e.DisplayName ?? string.Empty);

        foreach (var expected in expectedNames)
        {
            if (name == expected) score += 100;
            else if (name.Contains(expected) || expected.Contains(name)) score += 60;
        }

        if (!string.IsNullOrWhiteSpace(e.InstallLocation)) score += 15;
        if (!string.IsNullOrWhiteSpace(e.UninstallString)) score += 10;
        if (!string.IsNullOrWhiteSpace(e.DisplayVersion)) score += 5;

        // Prerequisite runtimes are commonly installed alongside the primary application.
        // Penalize them unless the installer itself appears to be that runtime.
        var dependencyLike = name.Contains("microsoftvisualc") || name.Contains("redistributable") || name.Contains("runtime");
        var expectedDependency = expectedNames.Any(x => x.Contains("visualc") || x.Contains("redistributable") || x.Contains("runtime"));
        if (dependencyLike && !expectedDependency) score -= 50;

        return score;
    }

    private static string NormalizeName(string value)
        => new(value.Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());

    private bool IsEnsoftQSetupProfile()
        => _result?.Kind == InstallerKind.QSetup &&
           ((_result.CompanyName?.Contains("Ensoft", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (_result.ProductName?.Contains("LPILE", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (_result.ProductName?.Contains("LPile", StringComparison.OrdinalIgnoreCase) ?? false));

    private void ConfigurePackageProfile()
    {
        if (EnsoftProfilePanel is null || EnsoftLicenseBox is null) return;
        var enabled = IsEnsoftQSetupProfile();
        EnsoftProfilePanel.Visibility = enabled ? Visibility.Visible : Visibility.Collapsed;
        if (!enabled) return;

        if (_result is not null && !_result.Evidence.Contains("Validated Ensoft QSetup deployment profile available: /silent /[EULA_accept]=Yes plus /[License]=... ."))
            _result.Evidence.Add("Validated Ensoft QSetup deployment profile available: /silent /[EULA_accept]=Yes plus /[License]=... .");

        // Cloud is the validated LPile profile. The user can switch to Single User or Network Client.
        EnsoftLicenseBox.SelectedIndex = 0;
        ApplyEnsoftLicenseProfile();
    }

    private void EnsoftLicenseBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || !IsEnsoftQSetupProfile()) return;
        ApplyEnsoftLicenseProfile();
        Generate();
    }

    private void ApplyEnsoftLicenseProfile()
    {
        if (!IsEnsoftQSetupProfile() || EnsoftLicenseBox is null) return;
        switch (EnsoftLicenseBox.SelectedIndex)
        {
            case 1:
                AdditionalArgumentsBox.Text = "/silent /[EULA_accept]=Yes /[License]=single";
                EnsoftProfileHint.Text = "Single-user license profile. Ensoft EULA acceptance syntax is included automatically.";
                break;
            case 2:
                AdditionalArgumentsBox.Text = "/silent /[EULA_accept]=Yes /[License]=client";
                EnsoftProfileHint.Text = "Network client selected. Add the environment-specific /[ServerIP]=... value to Additional package arguments if required by this package.";
                break;
            default:
                AdditionalArgumentsBox.Text = "/silent /[EULA_accept]=Yes /[License]=cloud";
                EnsoftProfileHint.Text = "Cloud Subscription profile. This exact LPile/QSetup syntax has passed silent reinstall and uninstall lifecycle validation.";
                break;
        }
    }

    private string EffectiveSilentArguments()
    {
        var baseArgs = ArgumentsBox.Text?.Trim() ?? string.Empty;
        var extraArgs = AdditionalArgumentsBox.Text?.Trim() ?? string.Empty;
        return string.Join(" ", new[] { baseArgs, extraArgs }.Where(x => !string.IsNullOrWhiteSpace(x)));
    }

    private void OpenIss_Click(object sender, RoutedEventArgs e) { if (_issSession is null) return; Directory.CreateDirectory(_issSession.OutputFolder); Process.Start(new ProcessStartInfo { FileName = _issSession.OutputFolder, UseShellExecute = true }); }

    private void KindBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_result is null || KindBox.SelectedItem is not InstallerKind k) return;
        _result.Kind = k; UpdateSandboxControls();
        ArgumentsBox.Text = k switch { InstallerKind.Msi => "/qn /norestart", InstallerKind.InnoSetup => "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", InstallerKind.Nsis => "/S", InstallerKind.WixBurn => "/quiet /norestart", InstallerKind.Squirrel => "--silent", InstallerKind.NvidiaSfx => "-s", InstallerKind.QSetup => "/Hide", InstallerKind.InstallShield when IssCheck.IsChecked == true => "/s /f1`\"$ResponseFile`\"", InstallerKind.InstallShield => "/s", _ => ArgumentsBox.Text };
        ConfigurePackageProfile();
    }
    private void IssCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_result is null) return; _result.NeedsIss = IssCheck.IsChecked == true;
        if (_result.Kind == InstallerKind.InstallShield) ArgumentsBox.Text = _result.NeedsIss ? "/s /f1`\"$ResponseFile`\"" : "/s";
    }

    private void AnalyzeNav_Click(object sender, RoutedEventArgs e) => ShowPage(AnalyzePage);
    private void SandboxNav_Click(object sender, RoutedEventArgs e) { UpdateSandboxPage(); ShowPage(SandboxPage); }
    private void ImmyBotNav_Click(object sender, RoutedEventArgs e) { UpdateImmyBotPage(); ShowPage(ImmyBotPage); }
    private void HistoryNav_Click(object sender, RoutedEventArgs e) { RefreshHistory(); ShowPage(HistoryPage); }
    private void SettingsNav_Click(object sender, RoutedEventArgs e) { RefreshSandboxSettings(); ShowPage(SettingsPage); }
    private void AboutNav_Click(object sender, RoutedEventArgs e) => ShowPage(AboutPage);
    private void ShowPage(UIElement page)
    {
        AnalyzePage.Visibility = Visibility.Collapsed; SandboxPage.Visibility = Visibility.Collapsed; ImmyBotPage.Visibility = Visibility.Collapsed; HistoryPage.Visibility = Visibility.Collapsed; SettingsPage.Visibility = Visibility.Collapsed; AboutPage.Visibility = Visibility.Collapsed;
        page.Visibility = Visibility.Visible;
        foreach (var b in new[] { AnalyzeNavButton, SidebarSandboxButton, ImmyBotNavButton, HistoryNavButton, SettingsNavButton, AboutNavButton }) b.Background = Brushes.Transparent;
        var active = ReferenceEquals(page, AnalyzePage) ? AnalyzeNavButton : ReferenceEquals(page, SandboxPage) ? SidebarSandboxButton : ReferenceEquals(page, ImmyBotPage) ? ImmyBotNavButton : ReferenceEquals(page, HistoryPage) ? HistoryNavButton : ReferenceEquals(page, SettingsPage) ? SettingsNavButton : AboutNavButton;
        active.Background = (Brush)Resources["AccentSoft"];
    }

    private bool UseIntegratedViewer => EmbeddedModeRadio.IsChecked == true;

    private void UpdateSandboxPage()
    {
        if (SandboxModeBadge is null) return;
        SandboxModeBadge.Text = UseIntegratedViewer ? "Integrated Viewer" : "Separate Window";
        StartSandboxButton.IsEnabled = _installerPath is not null && (_result is not null || KindBox.SelectedItem is InstallerKind);
        if (_issSession is null)
        {
            SandboxRunStatus.Text = SandboxIssRecorder.IsSandboxAvailable() ? "Ready" : "Windows Sandbox unavailable";
            SandboxRunDetails.Text = _installerPath is null ? "Select an installer on the Analyze page." : _result?.Kind == InstallerKind.Squirrel ? $"{Path.GetFileName(_installerPath)} is Squirrel.Windows. No .iss is required. Full Squirrel lifecycle validation is intentionally not enabled until its per-user uninstall path is validated." : _result?.Kind == InstallerKind.NvidiaSfx ? $"{Path.GetFileName(_installerPath)} is an NVIDIA 7-Zip SFX bootstrapper. No InstallShield .iss is expected; NVIDIA uses its own setup engine." : _result?.Kind == InstallerKind.QSetup ? $"{Path.GetFileName(_installerPath)} is QSetup. No .iss is required; /Hide is the validated base strategy. Review any package-specific arguments before starting analysis." : $"Ready to analyze {Path.GetFileName(_installerPath)}.";
        }
        SandboxPlaceholderText.Visibility = _integratedViewerActive ? Visibility.Collapsed : Visibility.Visible;
        SandboxPreviewImage.Visibility = _integratedViewerActive ? Visibility.Visible : Visibility.Collapsed;
        UpdateSandboxDashboard();
    }

    private void UpdateSandboxDashboard()
    {
        if (SandboxStageList is null) return;
        var stages = new List<string>();
        var stage = _liveWorkflowStage ?? string.Empty;
        var lowerStage = stage.ToLowerInvariant();
        var hasSession = _issSession is not null;
        var hasPrimary = _selectedUninstallEntry is not null || (_installAnalysis?.NewUninstallEntries?.Count ?? 0) > 0;
        var hasCandidates = (_installAnalysis?.SilentStrategyCandidates?.Count ?? 0) > 0 || lowerStage.Contains("candidate");
        var reinstallValidated = _installAnalysis?.SilentReinstallValidated == true;
        var finalUninstallSucceeded = _installAnalysis?.SilentUninstallExitCode is 0 or 3010;
        var finalAbsent = _installAnalysis?.PostUninstallDetected == false && finalUninstallSucceeded;
        var completed = _analysisLoaded && (_hostValidatedCheckpointPromoted || (_issSession is not null && File.Exists(_issSession.CompleteFlagPath)));

        int current = 0;
        if (hasSession) current = 1;
        if (lowerStage.Contains("discover") || lowerStage.Contains("initial install") || hasPrimary) current = 2;
        if (hasPrimary) current = 3;
        if (lowerStage.Contains("uninstall candidate") || lowerStage.Contains("silent uninstall") || hasCandidates) current = 4;
        if (lowerStage.Contains("initial silent uninstall") || lowerStage.Contains("initial absence") || hasCandidates) current = 5;
        if (hasCandidates || lowerStage.Contains("reinstall") || reinstallValidated) current = 6;
        if (reinstallValidated && (lowerStage.Contains("final") || finalUninstallSucceeded)) current = 7;
        if (finalUninstallSucceeded && (lowerStage.Contains("absence") || finalAbsent)) current = 8;
        if (finalAbsent || lowerStage.Contains("finaliz") || lowerStage.Contains("deployment validation complete")) current = 9;
        if (completed) current = 10;

        string Mark(int index, string label)
        {
            if (completed || index < current) return $"✓ {label}";
            if (index == current && hasSession) return $"◉ NOW: {label}";
            return $"○ {label}";
        }

        stages.Add(Mark(1, "Sandbox session"));
        stages.Add(Mark(2, "Initial installation / discovery"));
        stages.Add(Mark(3, "Identify primary application"));
        stages.Add(Mark(4, "Build silent uninstall strategy"));
        stages.Add(Mark(5, "Validate initial uninstall"));
        stages.Add(Mark(6, "Test silent reinstall candidates"));
        stages.Add(Mark(7, "Validate final uninstall"));
        stages.Add(Mark(8, "Verify final removal"));
        stages.Add(Mark(9, "Generate final analysis"));
        stages.Add(Mark(10, "Analysis complete"));

        if (hasSession && !string.IsNullOrWhiteSpace(stage) && !completed)
            stages.Add($"   ↳ {stage}");

        if (_installAnalysis?.SilentStrategyAttempts is { Count: > 0 } attempts)
        {
            for (var i = 0; i < attempts.Count; i++)
            {
                var attempt = attempts[i];
                var marker = string.Equals(attempt.Outcome, "Validated", StringComparison.OrdinalIgnoreCase) ? "✓" : "✗";
                stages.Add($"   {marker} Candidate {i + 1}/{attempts.Count}: {attempt.Name} — {attempt.Outcome}");
            }
        }
        var stageSignature = string.Join("\n", stages);
        if (!string.Equals(_lastSandboxStageSignature, stageSignature, StringComparison.Ordinal))
        {
            _lastSandboxStageSignature = stageSignature;
            SandboxStageList.ItemsSource = stages;
        }

        var files = new List<string>();
        if (_issSession is not null)
        {
            if (_issSession.RequiresIss)
            {
                foreach (var name in new[] { "setup.iss", "uninstall.iss", "install-analysis.json", "analysis-debug.jsonl" })
                {
                    var fp = Path.Combine(_issSession.OutputFolder, name);
                    files.Add((File.Exists(fp) ? "✓ " : "○ ") + name);
                }
            }
            else
            {
                files.Add("✓ Response files not required");
                var analysis = Path.Combine(_issSession.OutputFolder, "install-analysis.json");
                files.Add((File.Exists(analysis) ? "✓ " : "○ ") + "install-analysis.json");
                var debug = Path.Combine(_issSession.OutputFolder, "analysis-debug.jsonl");
                files.Add((File.Exists(debug) ? "✓ " : "○ ") + "analysis-debug.jsonl");
            }
        }
        SandboxFilesList.ItemsSource = files;

        if (_selectedUninstallEntry is null)
        {
            SandboxPrimaryText.Text = "No primary application identified yet.";
            SandboxDependencyList.ItemsSource = null;
        }
        else
        {
            SandboxPrimaryText.Text = $"{_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}  •  {_selectedUninstallEntry.Publisher}".Trim();
            SandboxDependencyList.ItemsSource = (_installAnalysis?.NewUninstallEntries ?? new List<UninstallEntry>())
                .Where(x => !ReferenceEquals(x, _selectedUninstallEntry))
                .Select(x => $"{x.DisplayName} {x.DisplayVersion}".Trim()).ToList();
        }

        var confidence = DeploymentConfidenceService.Calculate(_result, _installAnalysis, _selectedUninstallEntry);
        var ready = _installerPath is not null && confidence.Score == 100;
        DeploymentReadinessText.Text = confidence.Status;
        DeploymentConfidenceText.Text = $"Deployment Confidence: {confidence.Score}%";
        DeploymentConfidenceList.ItemsSource = confidence.Checks;
        DeploymentReadinessText.Foreground = BrushFrom(ready ? "#35D07F" : confidence.Score >= 75 ? "#E7B75D" : "#E58B8B");
        ExportImmyBotButton.IsEnabled = ready;
        if (ImmyExportButton is not null) ImmyExportButton.IsEnabled = ready;
        UpdateImmyBotPage();
        SaveHistorySnapshot();
    }

    private void ExportImmyBot_Click(object sender, RoutedEventArgs e)
    {
        if (_installerPath is null || _result is null || _selectedUninstallEntry is null || _installAnalysis is null) return;
        if (!_installAnalysis.SilentUninstallValidated)
        {
            MessageBox.Show("Complete Sandbox validation before exporting an ImmyBot package.", "ImmyBot export", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var suggested = NormalizeName(_selectedUninstallEntry.DisplayName ?? ProductBox.Text);
        if (string.IsNullOrWhiteSpace(suggested)) suggested = "ImmyBotPackage";
        var d = new SaveFileDialog { Filter = "ZIP package (*.zip)|*.zip", FileName = $"{suggested}-ImmyBot.zip" };
        if (d.ShowDialog() != true) return;
        try
        {
            ImmyBotPackageExporter.Export(d.FileName, _installerPath, _issSession?.OutputFolder, _logoPath);
            StatusText.Text = "ImmyBot package exported";
            MessageBox.Show($"ImmyBot package created successfully.\n\n{d.FileName}", "ImmyBot export", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "ImmyBot export failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void UpdateImmyBotPage()
    {
        if (ImmyInstallBox is null) return;
        if (_result is null)
        {
            SetHighlightedScript(ImmyInstallBox, "# Select an installer on the Analyze page.");
            SetHighlightedScript(ImmyDetectionBox, "# Sandbox analysis is required.");
            SetHighlightedScript(ImmyUninstallBox, "# Sandbox analysis is required.");
        }
        else
        {
            SetHighlightedScript(ImmyInstallBox, ImmyBotScriptGenerator.Generate(_result, EffectiveSilentArguments(), ProductBox.Text));
            SetHighlightedScript(ImmyDetectionBox, ImmyBotScriptGenerator.GenerateDetection(_selectedUninstallEntry, ProductBox.Text));
            SetHighlightedScript(ImmyUninstallBox, ImmyBotScriptGenerator.GenerateUninstall(_selectedUninstallEntry, ProductBox.Text, _installAnalysis));
        }
        LoadLogoPreview();
        var ready = _installerPath is not null && _selectedUninstallEntry is not null && _installAnalysis?.SilentUninstallValidated == true;
        ImmyExportButton.IsEnabled = ready;
        UpdateDeploymentIntelligence(ready);
    }

    private void UpdateDeploymentIntelligence(bool sandboxValidated)
    {
        if (DetectionIntelligenceText is null || ScriptInspectionText is null) return;
        var candidates = DeploymentIntelligenceService.RankDetection(_selectedUninstallEntry);
        DetectionIntelligenceText.Text = candidates.Count == 0
            ? "Complete Sandbox analysis to rank detection methods."
            : string.Join("\n", candidates.Take(4).Select((x, i) => $"{(i == 0 ? "★" : "•")} {x.Name} — {x.Score}/100\n   {x.Detail}"));
        if (_result is null) { ScriptInspectionText.Text = "Select an installer to inspect generated scripts."; return; }
        var install = ImmyBotScriptGenerator.Generate(_result, EffectiveSilentArguments(), ProductBox.Text);
        var detection = ImmyBotScriptGenerator.GenerateDetection(_selectedUninstallEntry, ProductBox.Text);
        var uninstall = ImmyBotScriptGenerator.GenerateUninstall(_selectedUninstallEntry, ProductBox.Text, _installAnalysis);
        var inspection = DeploymentIntelligenceService.Inspect(install, detection, uninstall, _result.NeedsIss, sandboxValidated);
        ScriptInspectionText.Text = $"{(inspection.Passed ? "✓" : "✕")} {inspection.Errors} errors  •  {inspection.Warnings} warnings\n" + string.Join("\n", inspection.Checks);
    }

    private void SaveHistorySnapshot()
    {
        if (_result is null || string.IsNullOrWhiteSpace(_installerPath)) return;
        var best = DeploymentIntelligenceService.RankDetection(_selectedUninstallEntry).FirstOrDefault();
        AnalysisHistoryService.Save(new AnalysisHistoryItem
        {
            AnalyzedAt = DateTime.Now, InstallerPath = _installerPath, ProductName = ProductBox.Text,
            Version = _selectedUninstallEntry?.DisplayVersion ?? _result.FileVersion, InstallerType = _result.Kind.ToString(),
            Confidence = _result.Confidence, SandboxValidated = _installAnalysis?.SilentUninstallValidated == true,
            DetectionMethod = best?.Name ?? "Pending Sandbox analysis"
        });
        RefreshHistory();
    }

    private void RefreshHistory()
    {
        if (HistoryList is null) return;
        var items = AnalysisHistoryService.Load(); HistoryList.ItemsSource = items;
        HistoryStatusText.Text = items.Count == 0 ? "No analysis history yet." : $"{items.Count} saved analysis record{(items.Count == 1 ? "" : "s")}.";
    }
    private void HistoryList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (HistoryList.SelectedItem is not AnalysisHistoryItem item) return;
        if (!File.Exists(item.InstallerPath)) { MessageBox.Show("The original installer is no longer available at the saved path.", "Analysis History", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        Analyze(item.InstallerPath); ShowPage(AnalyzePage);
    }
    private void ClearHistory_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Clear all saved analysis history?", "Analysis History", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        AnalysisHistoryService.Clear(); RefreshHistory();
    }

    private void LoadLogoPreview()
    {
        if (ImmyLogoImage is null) return;
        ImmyLogoImage.Source = null;
        var valid = !string.IsNullOrWhiteSpace(_logoPath) && File.Exists(_logoPath);
        ImmyLogoPlaceholder.Visibility = valid ? Visibility.Collapsed : Visibility.Visible;
        ImmyLogoStatus.Text = valid ? $"Logo ready: {Path.GetFileName(_logoPath)}" : "No application logo selected.";
        if (!valid) return;
        try
        {
            var image = new BitmapImage();
            image.BeginInit(); image.CacheOption = BitmapCacheOption.OnLoad; image.UriSource = new Uri(_logoPath!, UriKind.Absolute); image.EndInit(); image.Freeze();
            ImmyLogoImage.Source = image;
        }
        catch { ImmyLogoStatus.Text = "The selected logo could not be previewed."; }
    }

    private void ReplaceLogo_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "PNG images (*.png)|*.png" };
        if (d.ShowDialog() == true) { _logoPath = d.FileName; LoadLogoPreview(); }
    }
    private void ReextractLogo_Click(object sender, RoutedEventArgs e) { if (_installerPath is null) return; _logoPath = ApplicationLogoService.ExtractPng(_installerPath); LoadLogoPreview(); }
    private void RemoveLogo_Click(object sender, RoutedEventArgs e) { _logoPath = null; LoadLogoPreview(); }
    private void CopyImmyInstall_Click(object sender, RoutedEventArgs e) => CopyRichText(ImmyInstallBox);
    private void CopyImmyDetection_Click(object sender, RoutedEventArgs e) => CopyRichText(ImmyDetectionBox);
    private void CopyImmyUninstall_Click(object sender, RoutedEventArgs e) => CopyRichText(ImmyUninstallBox);
    private static void CopyRichText(RichTextBox box)
    {
        var text = new TextRange(box.Document.ContentStart, box.Document.ContentEnd).Text.TrimEnd('\r', '\n');
        if (!string.IsNullOrWhiteSpace(text)) Clipboard.SetText(text);
    }

    private void AppSetting_Changed(object sender, RoutedEventArgs e)
    {
        if (_settingsLoaded) SaveAppSettings();
    }

    private void SandboxDisplayMode_Changed(object sender, RoutedEventArgs e)
    {
        if (!_settingsLoaded) return;
        SaveAppSettings();
        _integratedViewerActive = false;
        SandboxPreviewImage.Source = null;
        UpdateSandboxPage();
        if (_issSession is not null) _sandboxWindowTimer.Start();
    }

    private void SandboxWindowTimer_Tick(object? sender, EventArgs e)
    {
        if (_issSession is null)
        {
            _sandboxWindowTimer.Stop();
            _integratedViewerActive = false;
            SandboxPreviewImage.Source = null;
            UpdateSandboxPage();
            return;
        }

        if (_sandboxWindow == IntPtr.Zero) _sandboxWindow = SandboxWindowEmbedder.FindSandboxWindow();
        if (_sandboxWindow == IntPtr.Zero) return;
        BringSandboxFrontButton.IsEnabled = true;

        if (!UseIntegratedViewer)
        {
            _integratedViewerActive = false;
            SandboxPreviewImage.Source = null;
            if (_analysisLoaded)
            {
                SandboxRunStatus.Text = "Analysis complete";
            }
            else if (string.IsNullOrWhiteSpace(_liveWorkflowStage))
            {
                SandboxRunStatus.Text = "Analysis running";
                SandboxRunDetails.Text = "Windows Sandbox is running in a separate window.";
            }
            UpdateSandboxPage();
            _sandboxWindowTimer.Stop();
            return;
        }

        var preview = SandboxWindowPreview.Capture(_sandboxWindow);
        if (preview is not null)
        {
            SandboxPreviewImage.Source = preview;
            _integratedViewerActive = true;
            // Viewer state is presentation-only. Do not overwrite the authoritative analysis status.
            SandboxPlaceholderText.Visibility = Visibility.Collapsed;
            SandboxPreviewImage.Visibility = Visibility.Visible;
        }
        else
        {
            _integratedViewerActive = false;
            SandboxPreviewImage.Visibility = Visibility.Collapsed;
            SandboxPlaceholderText.Visibility = Visibility.Visible;
            SandboxPlaceholderText.Text = "Waiting for a renderable Windows Sandbox frame…\n\nUse Bring to Front if Sandbox is minimized or still starting.";
        }
    }

    private void StopSandbox_Click(object sender, RoutedEventArgs e)
    {
        if (_issSession is null) return;
        try
        {
            if (!File.Exists(_issSession.AnalysisPath))
            {
                var diagnostic = new
                {
                    Installer = _installerPath is null ? null : Path.GetFileName(_installerPath),
                    InstallerExitCode = -3,
                    CapturedAt = DateTimeOffset.Now,
                    NewUninstallEntries = Array.Empty<object>(),
                    PrimaryKey = (string?)null,
                    UninstallValidationMethod = "Stopped by user",
                    UninstallRecordingAttempted = false,
                    UninstallResponseFileCreated = false,
                    RecordedUninstallExitCode = (int?)null,
                    BaseSilentArguments = ArgumentsBox.Text?.Trim() ?? string.Empty,
                    AdditionalPackageArguments = AdditionalArgumentsBox.Text?.Trim() ?? string.Empty,
                    CombinedSilentArguments = EffectiveSilentArguments(),
                    SilentInstallCommand = (string?)null,
                    SilentInstallStdOut = (string?)null,
                    SilentInstallStdErr = (string?)null,
                    SilentReinstallExitCode = (int?)null,
                    SilentReinstallValidated = false,
                    SilentUninstallExitCode = (int?)null,
                    PostUninstallDetected = (bool?)null,
                    SilentUninstallValidated = false,
                    DiscoverySucceeded = false,
                    DiscoveryMethod = (string?)null,
                    UninstallCandidate = (string?)null,
                    ValidationError = "Analysis stopped by user before Sandbox validation completed.",
                    BootstrapperProcesses = Array.Empty<string>(),
                    DiscoveredInstallerFiles = Array.Empty<string>()
                };
                File.WriteAllText(_issSession.AnalysisPath, JsonSerializer.Serialize(diagnostic, new JsonSerializerOptions { WriteIndented = true }));
            }
        }
        catch { }

        SandboxWindowEmbedder.ForceCloseSandboxWindow(_sandboxWindow);
        _sandboxWindowTimer.Stop();
        _issTimer.Stop();
        _sandboxWindow = IntPtr.Zero;
        BringSandboxFrontButton.IsEnabled = false;
        StopSandboxButton.IsEnabled = false;
        StartSandboxButton.IsEnabled = _installerPath is not null;
        SandboxRunStatus.Text = "Analysis stopped";
        SandboxRunDetails.Text = "Analysis stopped by user. Any diagnostic output captured before shutdown remains in the output folder.";
        StatusText.Text = "Sandbox analysis stopped by user";
        UpdateSandboxDashboard();
    }

    private void BringSandboxFront_Click(object sender, RoutedEventArgs e)
    {
        if (_sandboxWindow == IntPtr.Zero) _sandboxWindow = SandboxWindowEmbedder.FindSandboxWindow();
        SandboxWindowEmbedder.BringToFront(_sandboxWindow);
    }

    private sealed class AppSettings { public string SandboxDisplayMode { get; set; } = "Separate"; public bool AutoCloseSandbox { get; set; } = true; public bool AutomaticallyCheckForUpdates { get; set; } = true; public bool BlockBundledMcAfee { get; set; } = true; public string Theme { get; set; } = "Dark"; public string AccentColor { get; set; } = "Blue"; }
    private void LoadAppSettings()
    {
        try
        {
            var settings = File.Exists(SettingsPath) ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath)) : null;
            if (string.Equals(settings?.SandboxDisplayMode, "Integrated", StringComparison.OrdinalIgnoreCase) || string.Equals(settings?.SandboxDisplayMode, "Embedded", StringComparison.OrdinalIgnoreCase)) EmbeddedModeRadio.IsChecked = true;
            else SeparateModeRadio.IsChecked = true;
            AutoCloseSandboxToggle.IsChecked = settings?.AutoCloseSandbox ?? true;
            AutoUpdateToggle.IsChecked = settings?.AutomaticallyCheckForUpdates ?? true;
            BlockBundledMcAfeeToggle.IsChecked = settings?.BlockBundledMcAfee ?? true;
            if (string.Equals(settings?.Theme, "Light", StringComparison.OrdinalIgnoreCase)) LightThemeRadio.IsChecked = true; else if (string.Equals(settings?.Theme, "SuperDark", StringComparison.OrdinalIgnoreCase)) SuperDarkThemeRadio.IsChecked = true; else if (string.Equals(settings?.Theme, "Purple", StringComparison.OrdinalIgnoreCase)) PurpleThemeRadio.IsChecked = true; else if (string.Equals(settings?.Theme, "Hacker", StringComparison.OrdinalIgnoreCase)) HackerThemeRadio.IsChecked = true; else DarkThemeRadio.IsChecked = true;
            var accent = settings?.AccentColor ?? "Blue";
            PurpleAccentRadio.IsChecked = accent.Equals("Purple", StringComparison.OrdinalIgnoreCase);
            TealAccentRadio.IsChecked = accent.Equals("Teal", StringComparison.OrdinalIgnoreCase);
            OrangeAccentRadio.IsChecked = accent.Equals("Orange", StringComparison.OrdinalIgnoreCase);
            RedAccentRadio.IsChecked = accent.Equals("Red", StringComparison.OrdinalIgnoreCase);
            GreenAccentRadio.IsChecked = accent.Equals("Green", StringComparison.OrdinalIgnoreCase);
            PinkAccentRadio.IsChecked = accent.Equals("Pink", StringComparison.OrdinalIgnoreCase);
            GoldAccentRadio.IsChecked = accent.Equals("Gold", StringComparison.OrdinalIgnoreCase);
            BlueAccentRadio.IsChecked = !(PurpleAccentRadio.IsChecked == true || TealAccentRadio.IsChecked == true || OrangeAccentRadio.IsChecked == true || RedAccentRadio.IsChecked == true || GreenAccentRadio.IsChecked == true || PinkAccentRadio.IsChecked == true || GoldAccentRadio.IsChecked == true);
            ApplyAppearance();
        }
        catch { SeparateModeRadio.IsChecked = true; }
        _settingsLoaded = true;
    }
    private void SaveAppSettings()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(new AppSettings { SandboxDisplayMode = UseIntegratedViewer ? "Integrated" : "Separate", AutoCloseSandbox = AutoCloseSandboxToggle.IsChecked == true, AutomaticallyCheckForUpdates = AutoUpdateToggle.IsChecked == true, BlockBundledMcAfee = BlockBundledMcAfeeToggle.IsChecked == true, Theme = LightThemeRadio.IsChecked == true ? "Light" : SuperDarkThemeRadio.IsChecked == true ? "SuperDark" : PurpleThemeRadio.IsChecked == true ? "Purple" : HackerThemeRadio.IsChecked == true ? "Hacker" : "Dark", AccentColor = PurpleAccentRadio.IsChecked == true ? "Purple" : TealAccentRadio.IsChecked == true ? "Teal" : OrangeAccentRadio.IsChecked == true ? "Orange" : RedAccentRadio.IsChecked == true ? "Red" : GreenAccentRadio.IsChecked == true ? "Green" : PinkAccentRadio.IsChecked == true ? "Pink" : GoldAccentRadio.IsChecked == true ? "Gold" : "Blue" }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private void RefreshSandboxSettings()
    {
        var available = SandboxIssRecorder.IsSandboxAvailable();
        _updatingSettingsToggle = true; SettingsSandboxToggle.IsChecked = available; _updatingSettingsToggle = false;
        SettingsSandboxStatus.Text = available ? "Windows Sandbox is enabled and available." : "Windows Sandbox is not currently available.";
    }
    private void SettingsSandboxToggle_Click(object sender, RoutedEventArgs e)
    {
        if (_updatingSettingsToggle) return;
        OpenWindowsFeatures();
        RefreshSandboxSettings();
    }
    private void OpenWindowsFeatures_Click(object sender, RoutedEventArgs e) => OpenWindowsFeatures();
    private void OpenWindowsFeatures()
    {
        try { Process.Start(new ProcessStartInfo { FileName = "OptionalFeatures.exe", UseShellExecute = true }); StatusText.Text = "Opened Windows Features"; }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Windows Features", MessageBoxButton.OK, MessageBoxImage.Error); }
    }


    private void Appearance_Changed(object sender, RoutedEventArgs e)
    {
        if (!_settingsLoaded) return;
        ApplyAppearance();
        SaveAppSettings();
    }

    private void ApplyAppearance()
    {
        var light = LightThemeRadio.IsChecked == true;
        var superDarkTheme = SuperDarkThemeRadio.IsChecked == true;
        var purpleTheme = PurpleThemeRadio.IsChecked == true;
        var hackerTheme = HackerThemeRadio.IsChecked == true;

        if (hackerTheme)
        {
            // Classic hacker theme: near-black surfaces with phosphor-green text throughout.
            SetThemeBrush("Bg", "#020502");
            SetThemeBrush("Sidebar", "#030803");
            SetThemeBrush("Card", "#061006");
            SetThemeBrush("Border", "#145C22");
            SetThemeBrush("Text", "#39FF6A");
            SetThemeBrush("Muted", "#20C94C");
            SetThemeBrush("InputBg", "#010401");
            SetThemeBrush("InputBorder", "#168A32");
            SetThemeBrush("ButtonBg", "#071507");
            SetThemeBrush("ButtonHover", "#0C2A10");
            SetThemeBrush("CodeBg", "#000200");
            SetThemeBrush("ScrollTrackBg", "#020702");
            SetThemeBrush("ScrollThumb", "#158A32");
            SetThemeBrush("ScrollThumbHover", "#39FF6A");
        }
        else if (superDarkTheme)
        {
            // Super Dark theme: true black/charcoal surfaces while retaining the normal accent system.
            SetThemeBrush("Bg", "#000000");
            SetThemeBrush("Sidebar", "#050505");
            SetThemeBrush("Card", "#0A0A0A");
            SetThemeBrush("Border", "#242424");
            SetThemeBrush("Text", "#F5F5F5");
            SetThemeBrush("Muted", "#A3A3A3");
            SetThemeBrush("InputBg", "#050505");
            SetThemeBrush("InputBorder", "#303030");
            SetThemeBrush("ButtonBg", "#111111");
            SetThemeBrush("ButtonHover", "#1C1C1C");
            SetThemeBrush("CodeBg", "#000000");
            SetThemeBrush("ScrollTrackBg", "#050505");
            SetThemeBrush("ScrollThumb", "#525252");
            SetThemeBrush("ScrollThumbHover", "#737373");
        }
        else if (purpleTheme)
        {
            // Full purple theme: deep violet surfaces with brighter purple hierarchy.
            SetThemeBrush("Bg", "#120D1D");
            SetThemeBrush("Sidebar", "#1A1029");
            SetThemeBrush("Card", "#211532");
            SetThemeBrush("Border", "#493463");
            SetThemeBrush("Text", "#F8F4FF");
            SetThemeBrush("Muted", "#C3B4D8");
            SetThemeBrush("InputBg", "#180F27");
            SetThemeBrush("InputBorder", "#5A4077");
            SetThemeBrush("ButtonBg", "#2A1940");
            SetThemeBrush("ButtonHover", "#3A2257");
            SetThemeBrush("CodeBg", "#0F0918");
            SetThemeBrush("ScrollTrackBg", "#160D22");
            SetThemeBrush("ScrollThumb", "#76548F");
            SetThemeBrush("ScrollThumbHover", "#A276C2");
        }
        else
        {
            SetThemeBrush("Bg", light ? "#F3F6FA" : "#08111F");
            SetThemeBrush("Sidebar", light ? "#FFFFFF" : "#0B1626");
            SetThemeBrush("Card", light ? "#FFFFFF" : "#101C2B");
            SetThemeBrush("Border", light ? "#D5DDE8" : "#22354B");
            SetThemeBrush("Text", light ? "#172033" : "#F4F7FB");
            SetThemeBrush("Muted", light ? "#66758A" : "#A7B4C7");
            SetThemeBrush("InputBg", light ? "#F8FAFC" : "#0B1625");
            SetThemeBrush("InputBorder", light ? "#C8D2DF" : "#36506D");
            SetThemeBrush("ButtonBg", light ? "#EDF2F7" : "#14243A");
            SetThemeBrush("ButtonHover", light ? "#E1E8F0" : "#1A3150");
            SetThemeBrush("CodeBg", light ? "#F7F9FC" : "#07111D");
            SetThemeBrush("ScrollTrackBg", light ? "#E8EDF3" : "#09131F");
            SetThemeBrush("ScrollThumb", light ? "#9AA9BA" : "#657C94");
            SetThemeBrush("ScrollThumbHover", light ? "#73859A" : "#8EA3B8");
        }

        // Hacker mode intentionally overrides accent selection so the entire interface stays black + green.
        var accent = hackerTheme ? "#00FF41"
            : PurpleAccentRadio.IsChecked == true ? "#9B6DFF"
            : TealAccentRadio.IsChecked == true ? "#14B8A6"
            : OrangeAccentRadio.IsChecked == true ? "#F97316"
            : RedAccentRadio.IsChecked == true ? "#EF4444"
            : GreenAccentRadio.IsChecked == true ? "#22C55E"
            : PinkAccentRadio.IsChecked == true ? "#EC4899"
            : GoldAccentRadio.IsChecked == true ? "#EAB308"
            : "#3B82F6";
        var soft = hackerTheme ? "#0A3514"
            : PurpleAccentRadio.IsChecked == true ? (light ? "#EDE9FE" : purpleTheme ? "#44256A" : "#30245A")
            : TealAccentRadio.IsChecked == true ? (light ? "#CCFBF1" : purpleTheme ? "#173F3E" : "#123F3B")
            : OrangeAccentRadio.IsChecked == true ? (light ? "#FFEDD5" : purpleTheme ? "#4A281E" : "#512A16")
            : RedAccentRadio.IsChecked == true ? (light ? "#FEE2E2" : purpleTheme ? "#4B202F" : "#4A1D24")
            : GreenAccentRadio.IsChecked == true ? (light ? "#DCFCE7" : purpleTheme ? "#183F31" : "#123B28")
            : PinkAccentRadio.IsChecked == true ? (light ? "#FCE7F3" : purpleTheme ? "#4B2047" : "#4A1937")
            : GoldAccentRadio.IsChecked == true ? (light ? "#FEF9C3" : purpleTheme ? "#44351E" : "#44370F")
            : (light ? "#DBEAFE" : purpleTheme ? "#252D62" : "#123967");
        SetThemeBrush("Accent", accent); SetThemeBrush("AccentSoft", soft); SetThemeBrush("Link", accent);
        ShowPage(AnalyzePage.Visibility == Visibility.Visible ? AnalyzePage : SandboxPage.Visibility == Visibility.Visible ? SandboxPage : ImmyBotPage.Visibility == Visibility.Visible ? ImmyBotPage : HistoryPage.Visibility == Visibility.Visible ? HistoryPage : SettingsPage.Visibility == Visibility.Visible ? SettingsPage : AboutPage);
    }

    private void SetThemeBrush(string key, string hex) => Resources[key] = BrushFrom(hex);

    private void AutoUpdateToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_settingsLoaded) SaveAppSettings();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        if (AutoUpdateToggle.IsChecked == true) await CheckForUpdatesAsync(false);
    }

    private async void CheckForUpdates_Click(object sender, RoutedEventArgs e) => await CheckForUpdatesAsync(true);

    private async Task CheckForUpdatesAsync(bool interactive)
    {
        try
        {
            CheckUpdateButton.IsEnabled = false;
            UpdateStatusText.Text = "Checking GitHub Releases…";
            var latest = await _updateService.GetLatestAsync();
            _availableUpdate = latest is not null && UpdateService.IsNewer(latest) ? latest : null;
            InstallUpdateButton.IsEnabled = _availableUpdate?.InstallerAsset is not null;
            if (latest is null)
            {
                UpdateStatusText.Text = "No published releases exist yet. v0.9.2 can still be used as the first GitHub release.";
                ReleaseNotesText.Text = "";
            }
            else if (_availableUpdate is null)
            {
                UpdateStatusText.Text = $"You're up to date. Installed: {UpdateService.CurrentVersion.ToString(3)}  •  Latest: {latest.Version}";
                ReleaseNotesText.Text = latest.ReleaseNotes;
            }
            else
            {
                UpdateStatusText.Text = _availableUpdate.InstallerAsset is null
                    ? $"Version {_availableUpdate.Version} is available, but the release does not contain {UpdateService.InstallerAssetName}."
                    : $"Update available: {UpdateService.CurrentVersion.ToString(3)} → {_availableUpdate.Version}";
                ReleaseNotesText.Text = _availableUpdate.ReleaseNotes;
                if (interactive && _availableUpdate.InstallerAsset is not null)
                    MessageBox.Show($"Installer Analyzer {_availableUpdate.Version} is available.\n\nUse Download & Install Update to install it.", "Update available", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            UpdateStatusText.Text = "Unable to check for updates.";
            if (interactive) MessageBox.Show(ex.Message, "Update check failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally { CheckUpdateButton.IsEnabled = true; }
    }

    private async void InstallUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (_availableUpdate?.InstallerAsset is null) return;
        try
        {
            InstallUpdateButton.IsEnabled = false;
            UpdateStatusText.Text = $"Downloading Installer Analyzer {_availableUpdate.Version}…";
            var progress = new Progress<double>(p => UpdateStatusText.Text = $"Downloading Installer Analyzer {_availableUpdate.Version}… {p:0}%");
            var installer = await _updateService.DownloadInstallerAsync(_availableUpdate, progress);
            UpdateStatusText.Text = "Download verified. Starting installer…";
            UpdateService.LaunchInstaller(installer);
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            InstallUpdateButton.IsEnabled = true;
            UpdateStatusText.Text = "Update installation could not be started.";
            MessageBox.Show(ex.Message, "Update failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private string GetScriptText()
    {
        return new TextRange(ScriptBox.Document.ContentStart, ScriptBox.Document.ContentEnd).Text.TrimEnd('\r', '\n');
    }

    private void SetHighlightedScript(string script) => SetHighlightedScript(ScriptBox, script);

    private void SetHighlightedScript(RichTextBox target, string script)
    {
        var doc = new FlowDocument { PagePadding = new Thickness(0), Background = (Brush)Resources["CodeBg"], FontFamily = new FontFamily("Cascadia Mono, Consolas"), FontSize = 13 };
        var paragraph = new Paragraph { Margin = new Thickness(0), LineHeight = 19 };
        doc.Blocks.Add(paragraph);

        var tokenPattern = new Regex(@"(?<comment>#[^\r\n]*)|(?<string>""(?:`""|[^""])*"")|(?<variable>\$[A-Za-z_][A-Za-z0-9_:.]*)|(?<keyword>\b(?:if|else|elseif|switch|default|throw|foreach|for|while|return|param|function|try|catch|finally)\b)|(?<command>\b(?:Write-Host|Start-Process|Test-Path|Join-Path|Set-Location|Copy-Item|New-Item|Remove-Item)\b)|(?<number>\b\d+\b)", RegexOptions.IgnoreCase);
        int pos = 0;
        foreach (Match m in tokenPattern.Matches(script))
        {
            if (m.Index > pos) paragraph.Inlines.Add(new Run(script.Substring(pos, m.Index - pos)) { Foreground = (Brush)Resources["Text"] });
            string color = m.Groups["comment"].Success ? "#6A9955" :
                           m.Groups["string"].Success ? "#FF8C5A" :
                           m.Groups["variable"].Success ? "#4FC1FF" :
                           m.Groups["keyword"].Success ? "#D670D6" :
                           m.Groups["command"].Success ? "#FFD75F" : "#B5CEA8";
            paragraph.Inlines.Add(new Run(m.Value) { Foreground = BrushFrom(color), FontWeight = m.Groups["keyword"].Success ? FontWeights.SemiBold : FontWeights.Normal });
            pos = m.Index + m.Length;
        }
        if (pos < script.Length) paragraph.Inlines.Add(new Run(script.Substring(pos)) { Foreground = (Brush)Resources["Text"] });
        target.Document = doc;
    }

    private static SolidColorBrush BrushFrom(string hex) => new((Color)ColorConverter.ConvertFromString(hex));

    private enum ScriptView { Install, Detection, Uninstall, Validation }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) { if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized; else DragMove(); }
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
