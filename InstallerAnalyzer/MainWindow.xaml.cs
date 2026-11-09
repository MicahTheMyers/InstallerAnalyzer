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
using System.Runtime.InteropServices;
using System.Collections.ObjectModel;
using System.IO.Compression;
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
    private int _analysisRequestId;
    private bool _analysisBusy;
    private bool _testModeRunning;
    private bool _sandboxStarting, _sandboxStopping, _stopSandboxRequested;
    private bool _checkingSandboxLiveness;
    private DateTime _nextSandboxLivenessCheck;
    private string _customThemeColor = "#182438"; private string _customAccentColor = "#3B82F6";
    private AnalysisResult? _result;
    private string? _installerPath;
    private SandboxIssSession? _issSession;
    private readonly DispatcherTimer _issTimer = new() { Interval = TimeSpan.FromSeconds(2) };
    private bool _updatingSettingsToggle;
    private InstallAnalysis? _installAnalysis;
    private InstallAnalysis? _liveLifecycleProof;
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
    private static readonly TimeSpan SandboxInactivityTimeout = TimeSpan.FromMinutes(12);
    private readonly DispatcherTimer _sandboxWindowTimer = new() { Interval = TimeSpan.FromMilliseconds(600) };
    private readonly Stopwatch _sandboxElapsed = new();
    private readonly DispatcherTimer _sandboxElapsedTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private IntPtr _sandboxWindow = IntPtr.Zero;
    private bool _integratedViewerActive;
    private bool _settingsLoaded;
    private string? _logoPath;
    private readonly UpdateService _updateService = new();
    private UpdateInfo? _availableUpdate;
    private ObservableCollection<TestQueueItem> _testQueue = new();
    private CancellationTokenSource? _queueScanCts;
    private bool _refreshingTestQueue;
    private bool _windowClosed;
    private bool _dashboardImmyInitialized;
    private AnalysisResult? _dashboardImmyResult;
    private InstallAnalysis? _dashboardImmyProof;
    private UninstallEntry? _dashboardImmyEntry;
    private (string Path, long Length, long Modified, long Created)? _logoPreviewStamp;
    private readonly Dictionary<RichTextBox, (string Script, Color Text, Color Background, FlowDocument Document)> _highlightedScripts = new();
    private readonly ObservableCollection<string> _testResults = new();
    private CancellationTokenSource? _testModeCts;
    internal static string? TestModeDirectoryOverride { get; set; }
    private string TestModeRoot => TestModeDirectoryOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer", "TestMode");
    private string TestInstallerFolder => Path.Combine(TestModeRoot, "TestInstallers");
    private string TestResultsFolder => Path.Combine(TestModeRoot, "TestResults");
    internal static string? SettingsPathOverride { get; set; }
    private string SettingsPath => SettingsPathOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer", "settings.json");

    public MainWindow()
    {
        InitializeComponent();
        AboutVersionText.Text = "Version " + UpdateService.CurrentDisplayVersion;
        FooterVersionText.Text = "v" + UpdateService.CurrentDisplayVersion;
        InitializeWindowBounds();
        var workArea = SystemParameters.WorkArea;
        MinHeight = Math.Min(MinHeight, workArea.Height);
        MinWidth = Math.Min(MinWidth, workArea.Width);
        Height = Math.Min(Height, workArea.Height);
        Width = Math.Min(Width, workArea.Width);
        Left = workArea.Left + (workArea.Width - Width) / 2;
        Top = workArea.Top + (workArea.Height - Height) / 2;
        KindBox.ItemsSource = Enum.GetValues<InstallerKind>();
        _issTimer.Tick += IssTimer_Tick;
        _sandboxWindowTimer.Tick += SandboxWindowTimer_Tick;
        _sandboxElapsedTimer.Tick += (_, _) => UpdateSandboxElapsedTime();
        Closed += (_, _) => { _sandboxElapsedTimer.Stop(); _windowClosed = true; _queueScanCts?.Cancel(); };
        TestQueueList.ItemsSource = _testQueue;
        TestResultsList.ItemsSource = _testResults;
        LoadAppSettings();
        InitializeAiAssist();
        RefreshSandboxSettings();
        UpdateSandboxControls();
        UpdateSandboxPage();
        // These pages refresh on navigation; loading all saved runs before the first
        // frame makes startup depend on the size and speed of the history folder.
        ContentRendered += MainWindow_FirstRendered;
    }

    private void Select_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "Installers (*.exe;*.msi;*.msix;*.appx;*.msixbundle;*.appxbundle)|*.exe;*.msi;*.msix;*.appx;*.msixbundle;*.appxbundle|All files (*.*)|*.*" };
        if (d.ShowDialog() == true) Analyze(d.FileName);
    }
    private void Window_DragOver(object sender, System.Windows.DragEventArgs e) => e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
    private void Window_Drop(object sender, System.Windows.DragEventArgs e) { if (e.Data.GetData(DataFormats.FileDrop) is string[] f && f.Length > 0) Analyze(f[0]); }

    private async void Analyze(string path)
    {
        if (_issTimer.IsEnabled || _testModeRunning || _sandboxStarting || _sandboxStopping) { StatusText.Text = "Stop the current analysis before selecting another installer."; return; }
        var requestId = ++_analysisRequestId;
        _analysisBusy = true;
        try
        {
            StatusText.Text = $"Analyzing {Path.GetFileName(path)}…";
            var detected = await Task.Run(() => InstallerCatalogService.AnalyzeWithCatalog(path, _detector));
            var logo = await Task.Run(() => ApplicationLogoService.ExtractPng(path));
            if (requestId != _analysisRequestId) return;
            _sandboxElapsed.Reset(); _sandboxElapsedTimer.Stop(); UpdateSandboxElapsedTime();
            _result = detected; _installerPath = path; _issSession = null; _installAnalysis = null; _liveLifecycleProof = null; _selectedUninstallEntry = null; _analysisLoaded = false; _liveWorkflowStage = null; _liveWorkflowStageUpdatedAt = null; _liveWorkflowStageHistory.Clear(); _lastSandboxStageSignature = null; _analysisResultFirstSeenAt = null; _hostValidatedCheckpointPromoted = false; _scriptView = ScriptView.Install; OpenIssButton.IsEnabled = false;
            _logoPath = logo;
            FileText.Text = path; KindBox.SelectedItem = _result.Kind; ConfidenceText.Text = $"{_result.Confidence}%"; ConfidenceBar.Value = _result.Confidence;
            StatusText.Text = $"Analyzed {Path.GetFileName(path)}"; ArchText.Text = _result.Architecture;
            ProductBox.Text = string.IsNullOrWhiteSpace(_result.ProductName) ? Path.GetFileNameWithoutExtension(path) : _result.ProductName;
            CompanyText.Text = _result.CompanyName; VersionText.Text = _result.FileVersion; ArgumentsBox.Text = _result.SuggestedArguments; AdditionalArgumentsBox.Text = string.Empty;
            ConfigurePackageProfile();
            IssCheck.IsChecked = _result.NeedsIss; EvidenceList.ItemsSource = _result.Evidence; UpdateSandboxControls(); UpdateSandboxPage(); Generate(); UpdateImmyBotPage(); SaveHistorySnapshot();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Analysis failed", MessageBoxButton.OK, MessageBoxImage.Error); }
        finally { if (requestId == _analysisRequestId) _analysisBusy = false; }
    }

    private void Generate_Click(object sender, RoutedEventArgs e) => Generate();
    private void Generate()
    {
        if (_result is null) return;
        _result.Kind = (InstallerKind)(KindBox.SelectedItem ?? InstallerKind.Unknown); _result.NeedsIss = IssCheck.IsChecked == true;
        var script = _scriptView switch
        {
            ScriptView.Detection => ValidatedDetectionScriptService.Generate(_installAnalysis) ?? ImmyBotScriptGenerator.GenerateDetection(_selectedUninstallEntry, ProductBox.Text),
            ScriptView.Uninstall => ImmyBotScriptGenerator.GenerateUninstall(_selectedUninstallEntry, ProductBox.Text, _installAnalysis),
            ScriptView.Intelligence => IntelligenceReportService.Generate(_result, _installAnalysis),
            ScriptView.Validation => ValidationReportGenerator.Generate(_installAnalysis, _selectedUninstallEntry, ProductBox.Text),
            _ when VirtualBoxReducedProfile.IsProfile(_installAnalysis) => "# VirtualBox requires its MSI cabinet and Visual C++ attachments. Deployment export for this profile needs separate validation.",
            _ => _installAnalysis?.ComponentDeployment is not null ? "# Select Deployment > Datto RMM to generate the complete component recipe and prerequisite attachments." : ImmyBotScriptGenerator.Generate(_result, EffectiveSilentArguments(), ProductBox.Text, _installAnalysis)
        };
        SetHighlightedScript(script);
        UpdateImmyBotPage();
    }

    private void InstallTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Install; Generate(); }
    private void DetectionTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Detection; Generate(); }
    private void UninstallTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Uninstall; Generate(); }
    private void IntelligenceTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Intelligence; Generate(); }
    private void ValidationTab_Click(object sender, RoutedEventArgs e) { _scriptView = ScriptView.Validation; Generate(); }
    private void Copy_Click(object sender, RoutedEventArgs e) { var text = GetScriptText(); if (!string.IsNullOrWhiteSpace(text)) Clipboard.SetText(text); }
    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var text = GetScriptText();
        if (string.IsNullOrWhiteSpace(text)) return;
        var isValidation = _scriptView is ScriptView.Validation or ScriptView.Intelligence;
        var d = new SaveFileDialog { Filter = isValidation ? "Text report (*.txt)|*.txt" : "PowerShell script (*.ps1)|*.ps1", FileName = isValidation ? "Validation.txt" : $"{_scriptView}.ps1" };
        if (d.ShowDialog() == true) File.WriteAllText(d.FileName, text);
    }

    private void UpdateSandboxControls()
    {
        var isInstallShield = _result?.Kind == InstallerKind.InstallShield || KindBox.SelectedItem is InstallerKind.InstallShield;
        RecordIssButton.IsEnabled = _installerPath is not null && isInstallShield;
        RecordIssButton.Visibility = Visibility.Visible;
        IssCheck.Visibility = isInstallShield ? Visibility.Visible : Visibility.Collapsed;
        OpenIssButton.Visibility = Visibility.Visible;
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
        // A confirmed empty environment with no client needs no teardown grace period.
        // Unknown/unsupported CLI results and existing viewers retain the bounded cleanup.
        if (SandboxIssRecorder.IsEnvironmentRunning() == false)
        {
            var hasClient = false;
            foreach (var name in new[] { "WindowsSandboxClient", "WindowsSandbox", "WindowsSandboxRemoteSession" })
                foreach (var client in Process.GetProcessesByName(name))
                    using (client) hasClient = true;
            if (!hasClient) return;
        }
        // v0.12.7: Windows 11 24H2+ exposes the supported Windows Sandbox CLI. Closing only
        // the client window/process can leave the Sandbox environment itself alive, so the next
        // .wsb launch is rejected because Windows permits only one Sandbox at a time. Stop every
        // Sandbox ID reported by `wsb list --raw`, then retain the v0.11.45 process cleanup as a
        // fallback for inbox/older Sandbox builds where the CLI is unavailable.
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wsb.exe", Arguments = "list --raw", UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
            };
            using var list = Process.Start(psi);
            if (list is not null)
            {
                var text = list.StandardOutput.ReadToEnd();
                list.WaitForExit(5000);
                foreach (System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(text, @"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"))
                {
                    try
                    {
                        using var stop = Process.Start(new ProcessStartInfo
                        {
                            FileName = "wsb.exe", Arguments = $"stop --id {match.Value}",
                            UseShellExecute = false, CreateNoWindow = true
                        });
                        stop?.WaitForExit(15000);
                    }
                    catch { }
                }
            }
        }
        catch { }

        var processNames = new[] { "WindowsSandboxClient", "WindowsSandbox", "WindowsSandboxRemoteSession" };
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(45);
        var quietPasses = 0;
        while (DateTime.UtcNow < deadline && quietPasses < 4)
        {
            var foundThisPass = false;
            foreach (var processName in processNames)
            {
                foreach (var process in Process.GetProcessesByName(processName))
                {
                    try
                    {
                        foundThisPass = true;
                        if (!process.HasExited) process.Kill(entireProcessTree: true);
                        process.WaitForExit(5000);
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
            }

            // The CLI is authoritative when present: do not declare the handoff clean while it
            // still reports a Sandbox environment, even if the visible client process is gone.
            var cliReportsSandbox = false;
            try
            {
                var checkInfo = new ProcessStartInfo
                {
                    FileName = "wsb.exe", Arguments = "list --raw", UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
                };
                using var check = Process.Start(checkInfo);
                if (check is not null)
                {
                    var output = check.StandardOutput.ReadToEnd();
                    check.WaitForExit(4000);
                    cliReportsSandbox = System.Text.RegularExpressions.Regex.IsMatch(output, @"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}");
                }
            }
            catch { }

            if (foundThisPass || cliReportsSandbox) quietPasses = 0; else quietPasses++;
            Thread.Sleep(1500);
        }
        Thread.Sleep(3000);
    }

    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    private const int SwMinimize = 6;
    private static void MinimizeSandboxClientWindows()
    {
        foreach (var name in new[] { "WindowsSandboxClient", "WindowsSandbox", "WindowsSandboxRemoteSession" })
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                try { process.Refresh(); if (process.MainWindowHandle != IntPtr.Zero) ShowWindow(process.MainWindowHandle, SwMinimize); }
                catch { } finally { process.Dispose(); }
            }
        }
    }

    private async Task<SandboxIssSession> StartFreshTestSandboxAsync(string installerPath, AnalysisResult staticResult, CancellationToken token, bool silentOnly)
    {
        Exception? lastError = null;
        SandboxIssSession? lastSession = null;
        var attempts = new List<object>();
        try
        {
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            token.ThrowIfCancellationRequested();
            await Task.Run(EnsurePreviousSandboxSessionClosed);
            if (attempt > 1) await Task.Delay(TimeSpan.FromSeconds(5), token);
            SandboxIssSession? session = null;
            var started = DateTimeOffset.UtcNow;
            try
            {
                session = SandboxIssRecorder.Start(installerPath, staticResult.Kind, staticResult.NeedsIss,
                    staticResult.SuggestedArguments ?? string.Empty, string.Empty, BlockBundledMcAfeeToggle.IsChecked == true, silentOnly, PrepareNetFx3Check.IsChecked == true, _activeRegressionRun?.SandboxInstallerCompatibility ?? SandboxCompatibilityCheck.IsChecked == true);
                lastSession = session;
                await SandboxStartupMonitor.WaitAsync(session, token, (elapsed, state) =>
                {
                    var phase = state == SandboxStartupState.GuestStarted ? "Guest started; waiting for the analysis heartbeat" : "Waiting for guest logon and the startup script";
                    TestOverviewText.Text = $"Starting Sandbox for {Path.GetFileName(installerPath)} • attempt {attempt}/2\n{phase} • {elapsed.TotalSeconds:0}/180 seconds";
                });
                attempts.Add(new { Attempt = attempt, Started = started, Finished = DateTimeOffset.UtcNow, Outcome = "Analysis heartbeat received", OutputFolder = session.OutputFolder });
                AnalysisArtifactWriter.Write(Path.Combine(session.OutputFolder, "sandbox-host-startup.json"), JsonSerializer.Serialize(attempts, new JsonSerializerOptions { WriteIndented = true }));
                if (silentOnly)
                {
                    for (var i = 0; i < 4; i++) { MinimizeSandboxClientWindows(); await Task.Delay(300, token); }
                }
                return session;
            }
            catch (OperationCanceledException ex) { if (session is not null) ex.Data["InstallerAnalyzer.Session"] = session; throw; }
            catch (Exception ex)
            {
                lastError = ex;
                attempts.Add(new { Attempt = attempt, Started = started, Finished = DateTimeOffset.UtcNow, Outcome = "Startup failed", Error = ex.Message, OutputFolder = session?.OutputFolder });
                if (session is not null)
                {
                    AnalysisArtifactWriter.Write(Path.Combine(session.OutputFolder, "sandbox-host-startup.json"), JsonSerializer.Serialize(attempts, new JsonSerializerOptions { WriteIndented = true }));
                    // A guest that reached its bootstrap needs diagnosis, not repeated forced restarts.
                    try { if (SandboxStartupMonitor.Read(session).State != SandboxStartupState.WaitingForGuest) break; }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
        throw new InvalidOperationException("Windows Sandbox startup failed: " + lastError?.Message, lastError);
        }
        catch (Exception ex)
        {
            if (lastSession is not null) ex.Data["InstallerAnalyzer.Session"] = lastSession;
            throw;
        }
    }

    private void SandboxToggle_Changed(object sender, RoutedEventArgs e) { if (IsLoaded) UpdateSandboxControls(); }

    private async void RecordIss_Click(object sender, RoutedEventArgs e)
    {
        if (_analysisBusy || _testModeRunning || _sandboxStarting || _sandboxStopping || _issTimer.IsEnabled) { StatusText.Text = "Wait for the current analysis to finish."; return; }
        if (_installerPath is null) return;
        try
        {
            if (SandboxToggle.IsChecked == true)
            {
                _analysisResultFirstSeenAt = null;
                _hostValidatedCheckpointPromoted = false;
                _liveWorkflowStage = null; _liveWorkflowStageUpdatedAt = null;
                _liveWorkflowStageHistory.Clear(); _lastSandboxStageSignature = null;
                _analysisLoaded = false;
                _sandboxCheckpointFirstSeen = null;
                _sandboxLastActivityAt = DateTime.Now;
                _sandboxLastActivityFileWrite = null;
                _installAnalysis = null; _liveLifecycleProof = null;
                _selectedUninstallEntry = null;
                if (!SandboxIssRecorder.IsSandboxAvailable())
                {
                    var answer = MessageBox.Show("Windows Sandbox is not enabled. Open Windows Features now?", "Windows Sandbox", MessageBoxButton.YesNo, MessageBoxImage.Information);
                    if (answer == MessageBoxResult.Yes) OpenWindowsFeatures();
                    return;
                }
                _sandboxStarting = true; _stopSandboxRequested = false;
                _sandboxElapsed.Restart(); _sandboxElapsedTimer.Start(); UpdateSandboxElapsedTime();
                StartSandboxButton.IsEnabled = false; RecordIssButton.IsEnabled = false;
                StopSandboxButton.IsEnabled = true; ShowPage(SandboxPage);
                SandboxRunStatus.Text = "Starting Windows Sandbox…";
                var path = _installerPath; var kind = _result?.Kind ?? InstallerKind.Unknown;
                var needsIss = _result?.NeedsIss == true;
                var arguments = ArgumentsBox.Text?.Trim() ?? string.Empty;
                var additional = AdditionalArgumentsBox.Text?.Trim() ?? string.Empty;
                var blockBundled = BlockBundledMcAfeeToggle.IsChecked == true;
                var prepareNetFx3 = PrepareNetFx3Check.IsChecked == true;
                var installerCompatibility = SandboxCompatibilityCheck.IsChecked == true;
                await Task.Run(EnsurePreviousSandboxSessionClosed);
                if (_stopSandboxRequested) { SandboxRunStatus.Text = "Analysis stopped"; StatusText.Text = "Sandbox startup stopped by user"; return; }
                _issSession = await Task.Run(() => SandboxIssRecorder.Start(path, kind, needsIss, arguments, additional, blockBundled, prepareNetFx3: prepareNetFx3, installerCompatibility: installerCompatibility));
                _sandboxStarting = false;
                if (_stopSandboxRequested) { await StopSandboxSessionAsync(); return; }
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
        finally
        {
            _sandboxStarting = false;
            if (!_issTimer.IsEnabled && !_sandboxStopping)
            {
                StopSandboxElapsedTime();
                StartSandboxButton.IsEnabled = _installerPath is not null;
                StopSandboxButton.IsEnabled = false;
                UpdateSandboxControls();
            }
        }
    }

    private async void IssTimer_Tick(object? sender, EventArgs e)
    {
        if (_issSession is not null && !_analysisLoaded && !_checkingSandboxLiveness &&
            DateTime.Now >= _nextSandboxLivenessCheck && File.Exists(_issSession.HeartbeatPath) &&
            DateTime.Now - File.GetLastWriteTime(_issSession.HeartbeatPath) > TimeSpan.FromSeconds(20))
        {
            var observed = _issSession;
            _checkingSandboxLiveness = true; _nextSandboxLivenessCheck = DateTime.Now.AddSeconds(15);
            bool? alive;
            try { alive = await Task.Run(SandboxIssRecorder.IsEnvironmentRunning); }
            finally { _checkingSandboxLiveness = false; }
            if (!ReferenceEquals(observed, _issSession) || !_issTimer.IsEnabled) return;
            if (alive == false && !File.Exists(observed.AnalysisPath))
            {
                FinalizeTimedOutSandboxRun("Windows Sandbox environment ended unexpectedly before lifecycle completion.", false);
                return;
            }
        }
        if (_issSession is null) return;

        // v0.11.41 host-side activity-aware hang protection. The generated analysis script
        // writes a lightweight heartbeat while discovery/install/process monitoring is active.
        // Twelve minutes with no heartbeat/checkpoint activity is considered stalled, while a
        // The session-wide ceiling remains as the final emergency guardrail.
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
                    var checkpointRoot = JsonNode.Parse(AnalysisArtifactReader.ReadText(_issSession.CheckpointPath))?.AsObject();
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
                        var checkpointProof = checkpointRoot is null ? null : JsonSerializer.Deserialize<InstallAnalysis>(checkpointRoot.ToJsonString(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        _liveLifecycleProof = checkpointProof;
                        if (!_hostValidatedCheckpointPromoted && LifecycleValidationService.CanPromoteCheckpoint(checkpointProof))
                        {
                            checkpointRoot!["SilentUninstallValidated"] = true;
                            // Preserve errors; eligibility already required none.
                            checkpointRoot["WorkflowStage"] = "Deployment validation complete (host-confirmed)";
                            checkpointRoot["WorkflowStageUpdatedAt"] = DateTime.Now.ToString("o");
                            AnalysisArtifactWriter.Write(_issSession.AnalysisPath, checkpointRoot.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                            _hostValidatedCheckpointPromoted = true;
                            _analysisResultFirstSeenAt = DateTime.Now;
                            _installAnalysis = JsonSerializer.Deserialize<InstallAnalysis>(checkpointRoot.ToJsonString(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            IntelligenceReportService.Enrich(_installAnalysis, _result, _issSession.OutputFolder);
                if (_installAnalysis is not null) IntelligenceReportService.WriteArtifacts(_installAnalysis, _result, _issSession.OutputFolder);
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

            var overallTimedOut = DateTime.Now - _issSession.StartedAt >= _issSession.OverallTimeout;
            var inactivityTimedOut = _sandboxLastActivityAt is DateTime lastActivity &&
                                     DateTime.Now - lastActivity >= SandboxInactivityTimeout;
            if (overallTimedOut || inactivityTimedOut)
            {
                FinalizeTimedOutSandboxRun(overallTimedOut
                    ? $"Sandbox analysis exceeded the {_issSession.OverallTimeout.TotalMinutes:0}-minute absolute safety limit."
                    : "Sandbox analysis produced no heartbeat or checkpoint activity for 12 minutes.");
                return;
            }
        }

        if (!_analysisLoaded && File.Exists(_issSession.AnalysisPath))
        {
            try
            {
                _installAnalysis = JsonSerializer.Deserialize<InstallAnalysis>(AnalysisArtifactReader.ReadText(_issSession.AnalysisPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                IntelligenceReportService.Enrich(_installAnalysis, _result, _issSession.OutputFolder);
                if (_installAnalysis is not null) IntelligenceReportService.WriteArtifacts(_installAnalysis, _result, _issSession.OutputFolder);
                _selectedUninstallEntry = ChooseBestEntry(_installAnalysis?.NewUninstallEntries ?? new List<UninstallEntry>());
                ApplyValidatedInstallArguments();
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

        ApplyValidatedInstallArguments();
        _issTimer.Stop(); StopSandboxElapsedTime(); UpdateSandboxDashboard(); SandboxRunStatus.Text = CompletedSandboxStatus;
        SandboxRunDetails.Text = !string.IsNullOrWhiteSpace(_installAnalysis?.ValidationError) ? "Validation failed: " + _installAnalysis.ValidationError : _selectedUninstallEntry is null ? "Sandbox completed. No primary application was identified." : $"Detected {_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}. Installation analysis captured.";
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
        if (!string.IsNullOrWhiteSpace(_installAnalysis?.ValidationError)) StatusText.Text = "Analysis failed — diagnostics captured";
        _scriptView = ScriptView.Install; Generate();
        SaveHistorySnapshot();
        var details = _selectedUninstallEntry is null ? "No new uninstall registry entry was identified." : $"Detected: {_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}\n\nDetection, Uninstall, and Validation results are now available.";
        // Completion is reflected in the dashboard; avoid a routine informational modal.
        _ = details;
    }

    private void FinalizeTimedOutSandboxRun(string reason, bool timedOut = true)
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
            root["WorkflowStage"] = timedOut ? "Timed out by host safety watchdog" : "Sandbox environment ended unexpectedly";
            root["HostTimeout"] = timedOut;
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
        _issTimer.Stop();
        StopSandboxElapsedTime();
        UpdateSandboxDashboard();
        SandboxRunStatus.Text = timedOut ? "Analysis timed out" : "Sandbox ended unexpectedly";
        SandboxRunDetails.Text = reason + " Partial diagnostics were preserved when available.";
        StatusText.Text = timedOut ? "Sandbox analysis timed out — diagnostics preserved" : "Sandbox ended unexpectedly — diagnostics preserved";
        Generate();
        SaveHistorySnapshot();
    }

    private string CompletedSandboxStatus => !string.IsNullOrWhiteSpace(_installAnalysis?.ValidationError) ? "Analysis failed" : _installAnalysis is not null && LifecycleValidationService.IsComplete(_installAnalysis) ? "Analysis complete — validated" : "Analysis finished — validation incomplete";

    private UninstallEntry? ChooseBestEntry(List<UninstallEntry> entries)
    {
        if (_installAnalysis?.ExpectedPrimaryProduct == AdobeReaderInstaller.DesktopProduct)
            entries = entries.Where(AdobeReaderInstaller.IsDesktopEntry).ToList();
        else if (!string.IsNullOrWhiteSpace(_installAnalysis?.ExpectedPrimaryProduct))
        {
            var pattern = @"(?:^|[^a-z0-9])" + System.Text.RegularExpressions.Regex.Escape(_installAnalysis.ExpectedPrimaryProduct.Trim()) + @"(?:$|[^a-z0-9])";
            entries = entries.Where(e => System.Text.RegularExpressions.Regex.IsMatch(e.DisplayName ?? "", pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase) && (e.Publisher ?? "").StartsWith("Bentley Systems", StringComparison.OrdinalIgnoreCase)).ToList();
        }
        if (entries.Count == 0) return null;
        if (_installAnalysis?.PrimaryKey is { Length: > 0 } primaryKey && entries.FirstOrDefault(e => e.Key == primaryKey) is { } exact) return exact;

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

    private void ApplyValidatedInstallArguments()
    {
        if (_selectedUninstallEntry is not null && _installAnalysis is not null && LifecycleValidationService.UninstallPassed(_installAnalysis) &&
            !_installAnalysis.SilentUninstallUiDetected && _installAnalysis.PostUninstallDetected == false &&
            !string.IsNullOrWhiteSpace(_installAnalysis.UninstallCandidate))
            _selectedUninstallEntry.QuietUninstallString = _installAnalysis.UninstallCandidate;
        if (_result is null || !LifecycleValidationService.InstallPassed(_installAnalysis) || _installAnalysis is null ||
            _installAnalysis.SilentReinstallUiDetected || _installAnalysis.SilentReinstallExitCode is not (0 or 3010)) return;
        var candidate = _installAnalysis.SilentStrategyCandidates.FirstOrDefault(c => c.Name == _installAnalysis.SelectedSilentStrategy);
        var source = candidate?.File ?? _installAnalysis.DeploymentSource;
        if (source is null || !(source.Equals(Path.Combine("C:\\InstallerInput", _result.FileName), StringComparison.OrdinalIgnoreCase) ||
                               source.Equals(_result.FilePath, StringComparison.OrdinalIgnoreCase))) return;
        var arguments = candidate?.Arguments ?? _installAnalysis.CombinedSilentArguments;
        if (string.IsNullOrWhiteSpace(arguments)) return;
        ArgumentsBox.Text = arguments;
        AdditionalArgumentsBox.Text = "";
        _result.SuggestedArguments = arguments;
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
    private void DeploymentNav_Click(object sender, RoutedEventArgs e) => ShowPage(DeploymentPage);
    private void HistoryNav_Click(object sender, RoutedEventArgs e) { RefreshHistory(); ShowPage(HistoryPage); }
    private async void TestModeNav_Click(object sender, RoutedEventArgs e) { ShowPage(TestModePage); await RefreshTestQueue(); RefreshRunHistory(); }
    private void SettingsNav_Click(object sender, RoutedEventArgs e) { RefreshSandboxSettings(); ShowPage(SettingsPage); }
    private void AboutNav_Click(object sender, RoutedEventArgs e) => ShowPage(AboutPage);
    private void ShowPage(UIElement page)
    {
        if (ReferenceEquals(page, DeploymentPage)) page = DeploymentTargetBox.SelectedIndex == 1 ? DattoPage : ImmyBotPage;
        bool deployment = ReferenceEquals(page, ImmyBotPage) || ReferenceEquals(page, DattoPage);
        DeploymentPage.Visibility = deployment ? Visibility.Visible : Visibility.Collapsed;
        if (deployment) DeploymentTargetBox.SelectedIndex = ReferenceEquals(page, DattoPage) ? 1 : 0;
        DattoPage.Visibility = Visibility.Collapsed;
        CatalogPage.Visibility = Visibility.Collapsed; AnalyzePage.Visibility = Visibility.Collapsed; SandboxPage.Visibility = Visibility.Collapsed; ImmyBotPage.Visibility = Visibility.Collapsed; HistoryPage.Visibility = Visibility.Collapsed; TestModePage.Visibility = Visibility.Collapsed; SettingsPage.Visibility = Visibility.Collapsed; AboutPage.Visibility = Visibility.Collapsed;
        page.Visibility = Visibility.Visible;
        foreach (var b in new[] { CatalogNavButton, AnalyzeNavButton, SidebarSandboxButton, DeploymentNavButton, HistoryNavButton, TestModeNavButton, SettingsNavButton, AboutNavButton }) b.Background = Brushes.Transparent;
        var active = ReferenceEquals(page, CatalogPage) ? CatalogNavButton : ReferenceEquals(page, AnalyzePage) ? AnalyzeNavButton : ReferenceEquals(page, SandboxPage) ? SidebarSandboxButton : ReferenceEquals(page, ImmyBotPage) ? DeploymentNavButton : ReferenceEquals(page, HistoryPage) ? HistoryNavButton : ReferenceEquals(page, TestModePage) ? TestModeNavButton : ReferenceEquals(page, SettingsPage) ? SettingsNavButton : AboutNavButton;
        if (ReferenceEquals(page, DattoPage)) active=DeploymentNavButton;
        active.Background = (Brush)Resources["AccentSoft"];
        if (deployment) { if (ReferenceEquals(page, DattoPage)) UpdateDattoPage(); else UpdateImmyBotPage(); }
        UpdateAiAssistVisibility();
    }

    private bool UseIntegratedViewer => EmbeddedModeRadio.IsChecked == true;

    private void UpdateSandboxPage()
    {
        if (SandboxModeBadge is null) return;
        SandboxModeBadge.Text = UseIntegratedViewer ? "Integrated Viewer" : "Separate Window";
        SandboxPreviewPanel.Visibility = UseIntegratedViewer ? Visibility.Visible : Visibility.Collapsed;
        SandboxPreviewColumn.Width = UseIntegratedViewer ? new GridLength(1.35, GridUnitType.Star) : new GridLength(0);
        SandboxPreviewGapColumn.Width = new GridLength(UseIntegratedViewer ? 12 : 0);
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
        var hasPrimary = _selectedUninstallEntry is not null || !string.IsNullOrWhiteSpace(_liveLifecycleProof?.PrimaryKey) || (_installAnalysis?.NewUninstallEntries?.Count ?? 0) > 0;
        var hasCandidates = ((_analysisLoaded ? _installAnalysis : _liveLifecycleProof)?.CleanBaselineVerified == true && ((_analysisLoaded ? _installAnalysis : _liveLifecycleProof)?.SilentStrategyCandidates?.Count ?? 0) > 0) || lowerStage.Contains("candidate state");
        var liveProof = _analysisLoaded ? _installAnalysis : _liveLifecycleProof;
        var reinstallValidated = LifecycleValidationService.InstallPassed(liveProof);
        var finalUninstallSucceeded = liveProof?.SilentUninstallExitCode is 0 or 3010 && liveProof.SilentUninstallUiDetected == false;
        var finalAbsent = LifecycleValidationService.UninstallPassed(liveProof);
        var runFinished = _analysisLoaded && (_hostValidatedCheckpointPromoted || (_issSession is not null && File.Exists(_issSession.CompleteFlagPath)));
        var completed = runFinished && LifecycleValidationService.IsComplete(liveProof);

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
            var proved = index switch
            {
                1 => hasSession,
                2 => liveProof?.InitialInstallValidated == true || liveProof?.DiscoverySucceeded == true,
                3 => !string.IsNullOrWhiteSpace(liveProof?.PrimaryKey),
                4 => !string.IsNullOrWhiteSpace(liveProof?.UninstallCandidate) || liveProof?.InitialUninstallExitCode is not null,
                5 => liveProof?.CleanBaselineVerified == true && liveProof.InitialUninstallValidated || completed,
                6 => reinstallValidated,
                7 => reinstallValidated && finalUninstallSucceeded,
                8 => finalAbsent,
                9 => runFinished,
                10 => completed,
                _ => false
            };
            if (proved) return $"✓ {label}";
            if (runFinished) return $"○ {label} — not validated";
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
        var ready = _installAnalysis?.ComponentDeployment is null && !VirtualBoxReducedProfile.IsProfile(_installAnalysis) && _installerPath is not null && confidence.Score == 100;
        DeploymentReadinessText.Text = confidence.Status;
        DeploymentConfidenceText.Text = $"Deployment Confidence: {confidence.Score}%";
        DeploymentConfidenceList.ItemsSource = confidence.Checks;
        DeploymentReadinessText.Foreground = BrushFrom(ready ? "#35D07F" : confidence.Score >= 75 ? "#E7B75D" : "#E58B8B");
        ExportImmyBotButton.IsEnabled = ready;
        if (ImmyExportButton is not null) ImmyExportButton.IsEnabled = ready;
        if (!_dashboardImmyInitialized || !ReferenceEquals(_dashboardImmyResult, _result) ||
            !ReferenceEquals(_dashboardImmyProof, _installAnalysis) || !ReferenceEquals(_dashboardImmyEntry, _selectedUninstallEntry))
        {
            _dashboardImmyInitialized = true; _dashboardImmyResult = _result;
            _dashboardImmyProof = _installAnalysis; _dashboardImmyEntry = _selectedUninstallEntry;
            UpdateImmyBotPage();
        }
    }

    private void ExportImmyBot_Click(object sender, RoutedEventArgs e)
    {
        if (_installAnalysis?.ComponentDeployment is not null) { StatusText.Text = "Select Datto RMM to export this component recipe."; return; }
        if (VirtualBoxReducedProfile.IsProfile(_installAnalysis)) { StatusText.Text = "VirtualBox attachment export needs separate validation."; return; }
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
            ImmyBotPackageExporter.Export(d.FileName, _installerPath, _issSession?.OutputFolder, _logoPath, _installAnalysis.MsixDependencies);
            StatusText.Text = "ImmyBot package exported";
            MessageBox.Show($"ImmyBot package created successfully.\n\n{d.FileName}", "ImmyBot export", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "ImmyBot export failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void UpdateImmyBotPage()
    {
        if (DattoPage?.Visibility == Visibility.Visible) UpdateDattoPage();
        if (ImmyInstallBox is null) return;
        var install = VirtualBoxReducedProfile.IsProfile(_installAnalysis)
            ? "# VirtualBox requires its MSI cabinet and Visual C++ attachments. Deployment export for this profile needs separate validation."
            : _installAnalysis?.ComponentDeployment is not null ? "# This component recipe requires its prerequisite attachments. Select Datto RMM to export the complete kit." : _result is null ? "# Select an installer on the Analyze page." : ImmyBotScriptGenerator.Generate(_result, EffectiveSilentArguments(), ProductBox.Text, _installAnalysis);
        var detection = _result is null ? "# Sandbox analysis is required." : ImmyBotScriptGenerator.GenerateDetection(_selectedUninstallEntry, ProductBox.Text);
        var uninstall = _result is null ? "# Sandbox analysis is required." : ImmyBotScriptGenerator.GenerateUninstall(_selectedUninstallEntry, ProductBox.Text, _installAnalysis);
        SetHighlightedScript(ImmyInstallBox, install);
        SetHighlightedScript(ImmyDetectionBox, detection);
        SetHighlightedScript(ImmyUninstallBox, uninstall);
        LoadLogoPreview();
        var ready = _installAnalysis?.ComponentDeployment is null && !VirtualBoxReducedProfile.IsProfile(_installAnalysis) && _installerPath is not null && _selectedUninstallEntry is not null && LifecycleValidationService.IsComplete(_installAnalysis);
        ImmyExportButton.IsEnabled = ready;
        UpdateDeploymentIntelligence(ready, install, detection, uninstall);
    }

    private void UpdateDeploymentIntelligence(bool sandboxValidated, string install, string detection, string uninstall)
    {
        if (DetectionIntelligenceText is null || ScriptInspectionText is null) return;
        var candidates = DeploymentIntelligenceService.RankDetection(_selectedUninstallEntry);
        DetectionIntelligenceText.Text = candidates.Count == 0
            ? "Complete Sandbox analysis to rank detection methods."
            : string.Join("\n", candidates.Take(4).Select((x, i) => $"{(i == 0 ? "★" : "•")} {x.Name} — {x.Score}/100\n   {x.Detail}"));
        if (_result is null) { ScriptInspectionText.Text = "Select an installer to inspect generated scripts."; return; }
        var inspection = DeploymentIntelligenceService.Inspect(install, detection, uninstall, _result.NeedsIss, sandboxValidated);
        ScriptInspectionText.Text = $"{(inspection.Passed ? "✓" : "✕")} {inspection.Errors} errors  •  {inspection.Warnings} warnings\n" + string.Join("\n", inspection.Checks);
    }

    private void SaveHistorySnapshot()
    {
        if (_result is null || string.IsNullOrWhiteSpace(_installerPath)) return;
        try { if (InstallerCatalogService.Remember(_result, _installAnalysis, responseFolder: _issSession?.OutputFolder) && CatalogPage.Visibility == Visibility.Visible) _ = RefreshCatalogAsync(); } catch (Exception ex) { StatusText.Text = "Catalog save failed: " + ex.Message; }
        var best = DeploymentIntelligenceService.RankDetection(_selectedUninstallEntry).FirstOrDefault();
        AnalysisHistoryService.Save(new AnalysisHistoryItem
        {
            AnalyzedAt = DateTime.Now, InstallerPath = _installerPath, ProductName = ProductBox.Text,
            Version = _selectedUninstallEntry?.DisplayVersion ?? _result.FileVersion, InstallerType = _result.Kind.ToString(),
            Confidence = _result.Confidence, SandboxValidated = LifecycleValidationService.IsComplete(_installAnalysis),
            DetectionMethod = best?.Name ?? "Pending Sandbox analysis"
        });
        if (HistoryPage.Visibility == Visibility.Visible) RefreshHistory();
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
        (string Path, long Length, long Modified, long Created)? stamp = null;
        try
        {
            var file = string.IsNullOrWhiteSpace(_logoPath) ? null : new FileInfo(_logoPath);
            if (file?.Exists == true) stamp = (file.FullName, file.Length, file.LastWriteTimeUtc.Ticks, file.CreationTimeUtc.Ticks);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        if (stamp is not null && _logoPreviewStamp == stamp && ImmyLogoImage.Source is not null) return;
        _logoPreviewStamp = null;
        ImmyLogoImage.Source = null;
        var valid = stamp is not null;
        ImmyLogoPlaceholder.Visibility = valid ? Visibility.Collapsed : Visibility.Visible;
        ImmyLogoStatus.Text = valid ? $"Logo ready: {Path.GetFileName(_logoPath)}" : "No application logo selected.";
        if (!valid) return;
        try
        {
            var image = new BitmapImage();
            using var input = File.OpenRead(_logoPath!);
            image.BeginInit(); image.CacheOption = BitmapCacheOption.OnLoad; image.StreamSource = input; image.EndInit(); image.Freeze();
            ImmyLogoImage.Source = image;
            _logoPreviewStamp = stamp;
            ImmyLogoStatus.Text = $"Logo ready: {Path.GetFileName(_logoPath)} • {image.PixelWidth} × {image.PixelHeight} px" +
                (Math.Min(image.PixelWidth, image.PixelHeight) < 128 ? " — small source; Replace Image can provide a sharper logo." : "");
        }
        catch { ImmyLogoStatus.Text = "The selected logo could not be previewed."; }
    }

    private void ReplaceLogo_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "PNG images (*.png)|*.png" };
        if (d.ShowDialog() == true) { _logoPath = d.FileName; _logoPreviewStamp = null; LoadLogoPreview(); }
    }
    private void ReextractLogo_Click(object sender, RoutedEventArgs e) { if (_installerPath is null) return; _logoPath = ApplicationLogoService.ExtractPng(_installerPath); _logoPreviewStamp = null; LoadLogoPreview(); }
    private void RemoveLogo_Click(object sender, RoutedEventArgs e) { _logoPath = null; LoadLogoPreview(); }
    private void CopyImmyInstall_Click(object sender, RoutedEventArgs e) => CopyRichText(ImmyInstallBox);
    private void CopyImmyDetection_Click(object sender, RoutedEventArgs e) => CopyRichText(ImmyDetectionBox);
    private void CopyImmyUninstall_Click(object sender, RoutedEventArgs e) => CopyRichText(ImmyUninstallBox);
    private static void CopyRichText(RichTextBox box)
    {
        var text = new TextRange(box.Document.ContentStart, box.Document.ContentEnd).Text.TrimEnd('\r', '\n');
        if (!string.IsNullOrWhiteSpace(text)) Clipboard.SetText(text);
    }

    private void SandboxInnerScroll_PreviewMouseWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        if (SandboxDetailsScroll is null) return;
        SandboxDetailsScroll.ScrollToVerticalOffset(SandboxDetailsScroll.VerticalOffset - e.Delta);
        e.Handled = true;
    }
    private void PageScroll_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (sender is not ScrollViewer outer) return;
        var node = e.OriginalSource as DependencyObject;
        while (node is not null && !ReferenceEquals(node, outer))
        {
            if (node is ScrollViewer inner &&
                ((e.Delta > 0 && inner.VerticalOffset > 0) ||
                 (e.Delta < 0 && inner.VerticalOffset < inner.ScrollableHeight))) return;
            node = node is System.Windows.Media.Visual || node is System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(node) : LogicalTreeHelper.GetParent(node);
        }
        outer.ScrollToVerticalOffset(outer.VerticalOffset - e.Delta);
        e.Handled = true;
    }

    private sealed class TestQueueItem : System.ComponentModel.INotifyPropertyChanged
    {
        public string Path { get; init; } = "";
        public string FileName => System.IO.Path.GetFileName(Path);
        private bool _selected = true;
        private string _status = "WAITING";
        public bool Selected { get => _selected; set { _selected = value; PropertyChanged?.Invoke(this, new(nameof(Selected))); } }
        public string Status { get => _status; set { _status = value; PropertyChanged?.Invoke(this, new(nameof(Status))); } }
        public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    }

    private void InitializeTestModeFolders()
    {
        Directory.CreateDirectory(TestInstallerFolder);
        Directory.CreateDirectory(TestResultsFolder);
        if (TestFolderText is not null) TestFolderText.Text = TestInstallerFolder;
    }
    private async void TestModeSetting_Changed(object sender, RoutedEventArgs e)
    {
        if (!_settingsLoaded) return;
        TestModeNavButton.Visibility = EnableTestModeToggle.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        if (EnableTestModeToggle.IsChecked == true) { await RefreshTestQueue(); }
        else if (TestModePage.Visibility == Visibility.Visible) ShowPage(SettingsPage);
        UpdateAiAssistVisibility();
        SaveAppSettings();
    }
    private void OpenTestFolder_Click(object sender, RoutedEventArgs e) { InitializeTestModeFolders(); Process.Start(new ProcessStartInfo { FileName = TestInstallerFolder, UseShellExecute = true }); }
    private void OpenTestOutputFolder_Click(object sender, RoutedEventArgs e) { InitializeTestModeFolders(); Process.Start(new ProcessStartInfo { FileName = TestResultsFolder, UseShellExecute = true }); }
    private async void RefreshTestQueue_Click(object sender, RoutedEventArgs e) => await RefreshTestQueue();
    private async Task<bool> RefreshTestQueue()
    {
        if (_testModeRunning || _windowClosed) return false;
        _queueScanCts?.Cancel();
        using var scan = new CancellationTokenSource();
        _queueScanCts = scan; _refreshingTestQueue = true;
        StartTestsButton.IsEnabled = false;
        TestQueueSummaryText.Text = "Refreshing installer queue…";
        var folder = TestInstallerFolder; var resultsFolder = TestResultsFolder;
        try
        {
            var files = await Task.Run(() =>
            {
                scan.Token.ThrowIfCancellationRequested();
                Directory.CreateDirectory(folder); Directory.CreateDirectory(resultsFolder);
                return InstallerQueueScanner.Scan(folder, scan.Token);
            }, scan.Token);
            if (scan.IsCancellationRequested || !ReferenceEquals(_queueScanCts, scan) || _testModeRunning || _windowClosed || folder != TestInstallerFolder) return false;
            var existing = _testQueue.ToDictionary(x => x.Path, StringComparer.OrdinalIgnoreCase);
            var items = files.Select(file => existing.TryGetValue(file, out var old) ? old : new TestQueueItem { Path = file }).ToArray();
            foreach (var old in _testQueue) old.PropertyChanged -= TestQueueItem_Changed;
            foreach (var item in items) item.PropertyChanged += TestQueueItem_Changed;
            _testQueue = new ObservableCollection<TestQueueItem>(items);
            TestQueueList.ItemsSource = _testQueue;
            TestQueueSummaryText.Text = _testQueue.Count == 0 ? "No installers found. Drop installers into the TestInstallers folder, then click Refresh." : $"{_testQueue.Count} installer(s) found • {_testQueue.Count(x => x.Selected)} selected";
            TestFolderText.Text = folder;
            return true;
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex)
        {
            if (ReferenceEquals(_queueScanCts, scan) && !_windowClosed) TestQueueSummaryText.Text = "Queue refresh failed: " + ex.Message;
            return false;
        }
        finally
        {
            if (ReferenceEquals(_queueScanCts, scan))
            {
                _queueScanCts = null; _refreshingTestQueue = false;
                if (!_windowClosed) StartTestsButton.IsEnabled = !_testModeRunning;
            }
        }
    }
    private void TestQueueItem_Changed(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(TestQueueItem.Selected)) RefreshTestQueueSummary();
    }
    private void SelectAllTests_Click(object sender, RoutedEventArgs e) { foreach (var x in _testQueue) x.Selected = true; RefreshTestQueueSummary(); }
    private void ClearAllTests_Click(object sender, RoutedEventArgs e) { foreach (var x in _testQueue) x.Selected = false; RefreshTestQueueSummary(); }
    private void RefreshTestQueueSummary() => TestQueueSummaryText.Text = $"{_testQueue.Count} installer(s) found • {_testQueue.Count(x => x.Selected)} selected";
    private async void StartTests_Click(object sender, RoutedEventArgs e)
    {
        if (_analysisBusy || _testModeRunning || _refreshingTestQueue || _issTimer.IsEnabled || _sandboxStarting || _sandboxStopping) { TestOverviewText.Text = "Finish the queue refresh or current analysis first."; return; }
        var selected = _testQueue.Where(x => x.Selected).ToList();
        var silentOnly = TestTypeBox.SelectedIndex == 1;
        if (selected.Count == 0) { TestOverviewText.Text = "Select at least one installer to begin."; return; }
        if (!SandboxIssRecorder.IsSandboxAvailable()) { TestOverviewText.Text = "Windows Sandbox is required for lifecycle regression tests."; return; }

        _testModeRunning = true;
        try
        {
        _testModeCts = new CancellationTokenSource();
        foreach (var pending in selected) pending.Status = "WAITING";
        StartTestsButton.IsEnabled = false; StopTestsButton.IsEnabled = true; ExportTestResultsButton.IsEnabled = false;
        _testResults.Clear(); TestModeStatusBadge.Text = "RUNNING";
        var startedAt = DateTime.Now;
        // Preserve each run's evidence. History and baselines are saved separately.
        Directory.CreateDirectory(TestResultsFolder);
        _activeRegressionRun = new RegressionRun
        {
            Version = typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "development",
            Mode = silentOnly ? "SilentOnlyUnattended" : "FullAnalysis",
            SandboxInstallerCompatibility = SandboxCompatibilityCheck.IsChecked == true,
            Started = startedAt,
            Tests = selected.Select(item => new RegressionTestRecord { Installer = item.FileName, InstallerPath = item.Path }).ToList()
        };
        var runFolder = Path.Combine(TestResultsFolder, startedAt.ToString("yyyy-MM-dd_HHmmss") + "_" + _activeRegressionRun.Id);
        _activeRegressionRun.ArtifactFolder = runFolder;
        // Record identities for the entire queue so stopped/untested rows still match baselines.
        var identitySnapshot = _activeRegressionRun.Tests;
        await Task.Run(() =>
        {
            foreach (var queued in identitySnapshot)
            {
                try { queued.InstallerSha256 = RegressionHistoryService.HashFile(queued.InstallerPath); }
                catch (Exception ex) { queued.Failure.TechnicalReason = "Input hash unavailable: " + ex.Message; }
            }
        });
        SaveRunProgress();
        Directory.CreateDirectory(runFolder);
        var rows = new List<object>();
        int passed = 0, failed = 0, timedOut = 0;

        await RegressionQueueExecutor.ExecuteAsync(selected, async (item, queueToken) =>
        {
            if (_testModeCts.IsCancellationRequested) { item.Status = "STOPPED"; return; }
            item.Status = "RUNNING";
            TestOverviewText.Text = $"{(silentOnly ? "Silent-only" : "Full lifecycle")} regression: {item.FileName}\nStarting a fresh Windows Sandbox…";
            var testStarted = DateTime.Now;
            AnalysisResult? staticResult = null;
            SandboxIssSession? session = null;
            InstallAnalysis? lifecycle = null;
            string outcome = "FAIL";
            string failure = "";
            string catalogWarning = "";
            string hostStage = "Static analysis";
            var historyItem = _activeRegressionRun.Tests.First(t => t.InstallerPath == item.Path);
            try
            {
                historyItem.InstallerSha256 = await Task.Run(() => RegressionHistoryService.HashFile(item.Path));
                SaveRunProgress();
                staticResult = await Task.Run(() => InstallerCatalogService.AnalyzeWithCatalog(item.Path, _detector));
                TestOverviewText.Text = $"Lifecycle regression: {item.FileName}\nPreparing a clean Windows Sandbox session…";
                hostStage = "Sandbox startup";
                session = await StartFreshTestSandboxAsync(item.Path, staticResult, _testModeCts.Token, silentOnly);
                hostStage = "Sandbox lifecycle";
                RegisterAiDiagnosticTarget(item.Path, item.FileName + " • current run", session.OutputFolder);

                var deadline = DateTime.Now + session.OverallTimeout;
                DateTime lastActivity = DateTime.Now;
                DateTime? lastWrite = null;
                var nextLivenessCheck = DateTime.MinValue;
                while (!_testModeCts.IsCancellationRequested && DateTime.Now < deadline)
                {
                    await Task.Delay(2000, _testModeCts.Token);
                    DateTime? newest = null;
                    foreach (var path in new[] { session.HeartbeatPath, session.CheckpointPath, session.AnalysisPath, session.CompleteFlagPath })
                    {
                        try { if (File.Exists(path)) { var w = File.GetLastWriteTime(path); if (newest is null || w > newest) newest = w; } } catch { }
                    }
                    if (newest is DateTime nw && (lastWrite is null || nw > lastWrite)) { lastWrite = nw; lastActivity = DateTime.Now; }
                    if (DateTime.Now >= nextLivenessCheck && DateTime.Now - lastActivity > TimeSpan.FromSeconds(20))
                    {
                        nextLivenessCheck = DateTime.Now.AddSeconds(15);
                        var alive = await Task.Run(SandboxIssRecorder.IsEnvironmentRunning);
                        _testModeCts.Token.ThrowIfCancellationRequested();
                        if (alive == false && !File.Exists(session.AnalysisPath)) throw new InvalidOperationException("Windows Sandbox environment ended unexpectedly before lifecycle completion.");
                    }

                    string stage = "Waiting for Sandbox analysis";
                    try
                    {
                        var source = File.Exists(session.CheckpointPath) ? session.CheckpointPath : File.Exists(session.AnalysisPath) ? session.AnalysisPath : null;
                        if (source is not null)
                        {
                            var node = JsonNode.Parse(File.ReadAllText(source))?.AsObject();
                            stage = node?["WorkflowStage"]?.GetValue<string>() ?? stage;
                            var checkpointProof = node is null ? null : JsonSerializer.Deserialize<InstallAnalysis>(node.ToJsonString(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            if (LifecycleValidationService.CanPromoteCheckpoint(checkpointProof) && !File.Exists(session.AnalysisPath))
                            {
                                node!["SilentUninstallValidated"] = true;
                                // Never erase an error to manufacture a PASS.
                                node["WorkflowStage"] = "Deployment validation complete (test-mode host-confirmed)";
                                AnalysisArtifactWriter.Write(session.AnalysisPath, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                                AnalysisArtifactWriter.Write(session.CompleteFlagPath, "host-confirmed strict lifecycle proof");
                            }
                        }
                    }
                    catch { }
                    TestOverviewText.Text = $"Lifecycle regression: {item.FileName}\n{stage}";

                    if (File.Exists(session.AnalysisPath) && (File.Exists(session.CompleteFlagPath) || DateTime.Now - lastActivity > TimeSpan.FromMinutes(2))) break;
                    if (DateTime.Now - lastActivity >= SandboxInactivityTimeout) { failure = "No Sandbox heartbeat/checkpoint activity for 12 minutes."; break; }
                }

                if (_testModeCts.IsCancellationRequested) throw new OperationCanceledException();
                if (!File.Exists(session.AnalysisPath))
                {
                    outcome = DateTime.Now >= deadline ? "TIMEOUT" : "FAIL";
                    failure = string.IsNullOrWhiteSpace(failure) ? "Sandbox lifecycle did not produce a final analysis result." : failure;
                }
                else
                {
                    lifecycle = JsonSerializer.Deserialize<InstallAnalysis>(AnalysisArtifactReader.ReadText(session.AnalysisPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    IntelligenceReportService.Enrich(lifecycle, staticResult, session.OutputFolder);
                    var lifecyclePass = LifecycleValidationService.IsComplete(lifecycle);
                    outcome = lifecyclePass ? "PASS" : "FAIL";
                    if (lifecyclePass && staticResult is not null) { try { if (InstallerCatalogService.Remember(staticResult, lifecycle, _nextRunSource, session.OutputFolder) && CatalogPage.Visibility == Visibility.Visible) _ = RefreshCatalogAsync(); } catch (Exception ex) { catalogWarning = "Catalog save failed: " + ex.Message; } }
                    failure = lifecyclePass ? "" : lifecycle?.ValidationError ?? "Lifecycle validation did not satisfy install + uninstall + final absence requirements.";
                }
            }
            catch (OperationCanceledException ex) { session ??= ex.Data["InstallerAnalyzer.Session"] as SandboxIssSession; outcome = "STOPPED"; failure = "Regression run stopped by user."; }
            catch (Exception ex) { session ??= ex.Data["InstallerAnalyzer.Session"] as SandboxIssSession; outcome = "FAIL"; failure = ex.Message; }
            finally
            {
                await Task.Run(EnsurePreviousSandboxSessionClosed);
                await Task.Delay(4000);
            }

            var appFolder = Path.Combine(runFolder, (_activeRegressionRun.Tests.IndexOf(historyItem) + 1).ToString("D3") + "_" + SanitizeFolderName(item.FileName));
            Directory.CreateDirectory(appFolder);
            if (session is not null) CopyRegressionArtifacts(session.OutputFolder, appFolder);
            if (outcome != "PASS") SaveIncompleteTestAnalysis(appFolder, item.FileName, outcome, failure);
            RegisterAiDiagnosticTarget(item.Path, item.FileName + " • " + outcome, appFolder);
            var elapsed = DateTime.Now - testStarted;
            if (lifecycle is null && session is not null)
            {
                try
                {
                    var partialPath = File.Exists(session.AnalysisPath) ? session.AnalysisPath : session.CheckpointPath;
                    if (File.Exists(partialPath))
                        lifecycle = JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(partialPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
                catch { /* Incomplete/malformed checkpoints remain failures with host evidence. */ }
            }
            var product = lifecycle?.NewUninstallEntries.FirstOrDefault(e => e.Key == lifecycle.PrimaryKey)
                ?? lifecycle?.NewUninstallEntries.FirstOrDefault();
            historyItem.ProductName = product?.DisplayName ?? staticResult?.ProductName ?? "";
            historyItem.Publisher = product?.Publisher ?? staticResult?.CompanyName ?? "";
            historyItem.InstallerType = staticResult?.Kind.ToString() ?? "Unknown";
            historyItem.Result = outcome;
            historyItem.Install = LifecycleValidationService.InstallPassed(lifecycle) ? "PASS" : "FAIL";
            historyItem.Uninstall = LifecycleValidationService.UninstallPassed(lifecycle) ? "PASS" : "FAIL";
            historyItem.Removal = lifecycle?.PostUninstallDetected == false ? "PASS" : "FAIL";
            historyItem.ArtifactFolder = appFolder;
            historyItem.DurationSeconds = Math.Round(elapsed.TotalSeconds, 1);
            historyItem.RebootRequired = lifecycle?.RebootRequired == true;
            historyItem.Failure = FailureClassificationService.Classify(outcome, failure, lifecycle, hostStage);
            IntelligenceReportService.Enrich(lifecycle, staticResult, appFolder);
            if (lifecycle is not null)
            {
                IntelligenceReportService.WriteArtifacts(lifecycle, staticResult, appFolder);
                historyItem.Intelligence = lifecycle.Intelligence; historyItem.DetectionStrategies = lifecycle.DetectionStrategies;
            }
            if (outcome is "FAIL" or "TIMEOUT")
                try { InstallerCatalogService.RecordFailure(historyItem.InstallerSha256); } catch (Exception ex) { catalogWarning = "Catalog failure history unavailable: " + ex.Message; }
            historyItem.Attempts = lifecycle?.SilentStrategyAttempts ?? new();
            SaveRunProgress();
            var resultRecord = new
            {
                Installer = item.FileName, Result = outcome, InstallerType = staticResult?.Kind.ToString() ?? "Unknown",
                Confidence = staticResult?.Confidence ?? 0, Architecture = staticResult?.Architecture,
                ProductName = historyItem.ProductName,
                Install = LifecycleValidationService.InstallPassed(lifecycle) ? "PASS" : "FAIL",
                Uninstall = LifecycleValidationService.UninstallPassed(lifecycle) ? "PASS" : "FAIL",
                Removal = lifecycle?.PostUninstallDetected == false ? "PASS" : "FAIL",
                DurationSeconds = Math.Round(elapsed.TotalSeconds, 1), Failure = failure,
                WorkflowStage = lifecycle?.WorkflowStage, ValidationError = lifecycle?.ValidationError,
                CatalogWarning = catalogWarning, InstallerSha256 = historyItem.InstallerSha256,
                Publisher = historyItem.Publisher, FailureDetail = historyItem.Failure
            };
            File.WriteAllText(Path.Combine(appFolder, "regression-result.json"), JsonSerializer.Serialize(resultRecord, new JsonSerializerOptions { WriteIndented = true }));
            rows.Add(resultRecord);
            item.Status = outcome == "FAIL" && failure.StartsWith("PACKAGE CONFIGURATION REQUIRED", StringComparison.OrdinalIgnoreCase) ? "NEEDS CONFIG" : outcome == "FAIL" && failure.StartsWith("INSTALL FAILED", StringComparison.OrdinalIgnoreCase) ? "INSTALL FAIL" : outcome == "FAIL" && failure.StartsWith("PREREQUISITE REQUIRED", StringComparison.OrdinalIgnoreCase) ? "PREREQ" : outcome == "FAIL" && failure.StartsWith("Windows Sandbox environment", StringComparison.OrdinalIgnoreCase) ? "SANDBOX FAIL" : outcome == "FAIL" && failure.StartsWith("NO SILENT STRATEGY", StringComparison.OrdinalIgnoreCase) ? "NO SILENT" : outcome == "FAIL" && failure.StartsWith("REBOOT REQUIRED", StringComparison.OrdinalIgnoreCase) ? "REBOOT" : outcome == "FAIL" && failure.StartsWith("INTERACTION OR PREREQUISITE REQUIRED", StringComparison.OrdinalIgnoreCase) ? "NEEDS INPUT" : outcome;
            if (outcome == "PASS") passed++; else if (outcome == "TIMEOUT") { failed++; timedOut++; } else if (outcome == "FAIL") failed++;
            _testResults.Add($"{outcome} ({historyItem.Failure.Category})   {item.FileName}   {staticResult?.Kind ?? InstallerKind.Unknown}   Install:{resultRecord.Install} Uninstall:{resultRecord.Uninstall} Removal:{resultRecord.Removal}   {elapsed:mm\\:ss}");
            if (outcome == "STOPPED") return;
        }, _testModeCts.Token);

        var stopped = _testModeCts.IsCancellationRequested;
        if (stopped) foreach (var pending in selected.Where(x => x.Status == "WAITING")) pending.Status = "STOPPED";
        _activeRegressionRun.Stopped = stopped;
        _activeRegressionRun.Completed = DateTimeOffset.Now;
        SaveRunProgress();
        RefreshRunHistory(_activeRegressionRun.Id);
        var summary = new { RunId = _activeRegressionRun.Id, SchemaVersion = 1, Version = _activeRegressionRun.Version, Mode = silentOnly ? "SilentOnlyUnattended" : "FullAnalysis", Started = startedAt, Completed = DateTime.Now, Passed = passed, Failed = failed, TimedOut = timedOut, Stopped = stopped, Tests = rows };
        File.WriteAllText(Path.Combine(runFolder, "Summary.json"), JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }));
        WriteRegressionCsv(Path.Combine(runFolder, "Summary.csv"), rows);
        TestModeStatusBadge.Text = stopped ? "STOPPED" : failed == 0 ? "PASS" : "REVIEW";
        TestOverviewText.Text = stopped ? $"Regression run stopped. {passed} passed, {failed} failed." : $"{(silentOnly ? "Silent-only unattended" : "Full-analysis")} regression complete: {passed} passed, {failed} failed{(timedOut > 0 ? $" ({timedOut} timed out)" : "")}. Each installer ran in its own Sandbox session.";
        StartTestsButton.IsEnabled = true; StopTestsButton.IsEnabled = false; ExportTestResultsButton.IsEnabled = true; ExportTestResultsButton.Tag = runFolder;
        }
        catch (Exception ex) { TestModeStatusBadge.Text = "FAIL"; TestOverviewText.Text = "Test run could not finish: " + ex.Message; }
        finally
        {
            _testModeRunning = false;
            _testModeCts?.Dispose(); _testModeCts = null;
            _activeRegressionRun = null; _nextRunSource = "Test Mode";
            StartTestsButton.IsEnabled = true; StopTestsButton.IsEnabled = false;
            RefreshRunHistory();
        }
    }

    private static void SaveIncompleteTestAnalysis(string folder, string installer, string outcome, string failure)
    {
        var analysis = Path.Combine(folder, "install-analysis.json");
        if (File.Exists(analysis)) return;
        JsonObject result;
        try { result = JsonNode.Parse(AnalysisArtifactReader.ReadText(Path.Combine(folder, "install-analysis.checkpoint.json")))?.AsObject() ?? new(); }
        catch { result = new(); }
        result["Installer"] = installer;
        result["InstallerExitCode"] ??= -1;
        result["CapturedAt"] ??= DateTime.Now.ToString("O");
        result["HostTermination"] = outcome;
        result["ValidationError"] = string.IsNullOrWhiteSpace(failure) ? "Session ended without a final analysis result." : failure;
        File.WriteAllText(analysis, result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    private static void CopyRegressionArtifacts(string sourceFolder, string destinationFolder)
    {
        if (!Directory.Exists(sourceFolder)) return;
        foreach (var file in Directory.EnumerateFiles(sourceFolder, "*", SearchOption.AllDirectories))
        {
            try
            {
                var relative = Path.GetRelativePath(sourceFolder, file);
                var target = Path.Combine(destinationFolder, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(file, target, true);
            }
            catch { }
        }
    }

    private static void WriteRegressionCsv(string path, List<object> rows)
    {
        var sb = new System.Text.StringBuilder("Application,Result,Installer Type,Install,Uninstall,Removal,Time Seconds\r\n");
        foreach (var row in rows)
        {
            var json = JsonSerializer.SerializeToNode(row)?.AsObject();
            string C(string key) => "\"" + (json?[key]?.ToString() ?? "").Replace("\"", "\"\"") + "\"";
            sb.AppendLine(string.Join(",", C("Installer"), C("Result"), C("InstallerType"), C("Install"), C("Uninstall"), C("Removal"), C("DurationSeconds")));
        }
        File.WriteAllText(path, sb.ToString());
    }
    private void StopTests_Click(object sender, RoutedEventArgs e) { _testModeCts?.Cancel(); StopTestsButton.IsEnabled = false; TestModeStatusBadge.Text = "STOPPING"; }
    private void ExportTestResults_Click(object sender, RoutedEventArgs e)
    {
        if (ExportTestResultsButton.Tag is not string folder || !Directory.Exists(folder)) return;
        var zip = folder.TrimEnd(Path.DirectorySeparatorChar) + ".zip";
        if (File.Exists(zip)) File.Delete(zip);
        ZipFile.CreateFromDirectory(folder, zip, CompressionLevel.Optimal, false);
        Process.Start(new ProcessStartInfo { FileName = System.IO.Path.GetDirectoryName(zip)!, UseShellExecute = true });
    }
    private static string SanitizeFolderName(string value) => string.Concat(value.Select(c => System.IO.Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));

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
                SandboxRunStatus.Text = CompletedSandboxStatus;
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

    private async void StopSandbox_Click(object sender, RoutedEventArgs e)
    {
        _stopSandboxRequested = true;
        StopSandboxButton.IsEnabled = false;
        SandboxRunStatus.Text = "Stopping analysis…";
        if (_sandboxStarting) return;
        await StopSandboxSessionAsync();
    }

    private void UpdateSandboxElapsedTime()
    {
        var elapsed = _sandboxElapsed.Elapsed;
        SandboxElapsedText.Text = $"Elapsed: {(long)elapsed.TotalHours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00}";
    }

    private void StopSandboxElapsedTime()
    {
        _sandboxElapsed.Stop(); _sandboxElapsedTimer.Stop(); UpdateSandboxElapsedTime();
    }

    private async Task StopSandboxSessionAsync()
    {
        if (_sandboxStopping || _issSession is null) return;
        _sandboxStopping = true;
        _issTimer.Stop(); _sandboxWindowTimer.Stop();
        StopSandboxButton.IsEnabled = false; StartSandboxButton.IsEnabled = false;
        var session = _issSession;
        var hwnd = _sandboxWindow;
        try
        {
            await Task.Run(() => SandboxWindowEmbedder.ForceCloseSandboxWindow(hwnd));
            if (!File.Exists(session.AnalysisPath))
                SaveIncompleteTestAnalysis(session.OutputFolder, _installerPath is null ? "Unknown" : Path.GetFileName(_installerPath),
                    "STOPPED", "Analysis stopped by user before Sandbox validation completed.");
            try
            {
                _installAnalysis = JsonSerializer.Deserialize<InstallAnalysis>(AnalysisArtifactReader.ReadText(session.AnalysisPath),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                _selectedUninstallEntry = ChooseBestEntry(_installAnalysis?.NewUninstallEntries ?? new());
                _analysisLoaded = _installAnalysis is not null;
            }
            catch { }
            UpdateSandboxDashboard(); Generate();
            SandboxRunStatus.Text = "Analysis stopped";
            SandboxRunDetails.Text = "Analysis stopped by user. Partial diagnostics remain in the output folder.";
            StatusText.Text = "Sandbox analysis stopped by user";
            SaveHistorySnapshot();
        }
        finally
        {
            _sandboxStopping = false; _sandboxWindow = IntPtr.Zero;
            StopSandboxElapsedTime();
            BringSandboxFrontButton.IsEnabled = false;
            StartSandboxButton.IsEnabled = _installerPath is not null;
            UpdateSandboxControls();
        }
    }
    private void BringSandboxFront_Click(object sender, RoutedEventArgs e)
    {
        if (_sandboxWindow == IntPtr.Zero) _sandboxWindow = SandboxWindowEmbedder.FindSandboxWindow();
        SandboxWindowEmbedder.BringToFront(_sandboxWindow);
    }

    private sealed class AppSettings { public bool SandboxInstallerCompatibility { get; set; } = false; public bool PrepareNetFx3 { get; set; } = false; public bool EnableAiAssist { get; set; } = false; public string AiProvider { get; set; } = "OpenAI"; public string AiOpenAiModel { get; set; } = ""; public string AiOllamaModel { get; set; } = ""; public string AiClaudeModel { get; set; } = ""; public string AiLocalServer { get; set; } = "http://127.0.0.1:11434"; public string SandboxDisplayMode { get; set; } = "Separate"; public bool AutoCloseSandbox { get; set; } = true; public bool AutomaticallyCheckForUpdates { get; set; } = true; public bool BlockBundledMcAfee { get; set; } = true; public bool EnableTestMode { get; set; } = false; public string CustomThemeColor { get; set; } = "#182438"; public string CustomAccentColor { get; set; } = "#3B82F6"; public string Theme { get; set; } = "Dark"; public string AccentColor { get; set; } = "Blue"; }
    private void LoadAppSettings()
    {
        try
        {
            var settings = File.Exists(SettingsPath) ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath)) : null;
            if (string.Equals(settings?.SandboxDisplayMode, "Integrated", StringComparison.OrdinalIgnoreCase) || string.Equals(settings?.SandboxDisplayMode, "Embedded", StringComparison.OrdinalIgnoreCase)) EmbeddedModeRadio.IsChecked = true;
            else SeparateModeRadio.IsChecked = true;
            AutoCloseSandboxToggle.IsChecked = settings?.AutoCloseSandbox ?? true;
            PrepareNetFx3Check.IsChecked = settings?.PrepareNetFx3 ?? false;
            SandboxCompatibilityCheck.IsChecked = settings?.SandboxInstallerCompatibility ?? false;
            AutoUpdateToggle.IsChecked = settings?.AutomaticallyCheckForUpdates ?? true;
            BlockBundledMcAfeeToggle.IsChecked = settings?.BlockBundledMcAfee ?? true;
            EnableTestModeToggle.IsChecked = settings?.EnableTestMode ?? false;
            TestModeNavButton.Visibility = EnableTestModeToggle.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            EnableAiAssistToggle.IsChecked = settings?.EnableAiAssist == true && EnableTestModeToggle.IsChecked == true;
            _aiOpenAiModel = settings?.AiOpenAiModel ?? ""; _aiOllamaModel = settings?.AiOllamaModel ?? ""; _aiClaudeModel = settings?.AiClaudeModel ?? "";
            AiProviderBox.SelectedIndex = settings?.AiProvider == "Ollama" ? 1 : settings?.AiProvider == "Claude" ? 2 : 0;
            AiModelBox.Text = SelectedAiModel;
            AiLocalServerBox.Text = settings?.AiLocalServer ?? "http://127.0.0.1:11434";
            AiKeyStatus.Text = "Enter a key to save it, or use INSTALLERANALYZER_OPENAI_API_KEY. Existing protected keys are used automatically.";
            if (TestFolderText is not null) TestFolderText.Text = TestInstallerFolder;
            if (string.Equals(settings?.Theme, "Light", StringComparison.OrdinalIgnoreCase)) LightThemeRadio.IsChecked = true; else if (string.Equals(settings?.Theme, "SuperDark", StringComparison.OrdinalIgnoreCase)) SuperDarkThemeRadio.IsChecked = true; else if (string.Equals(settings?.Theme, "Purple", StringComparison.OrdinalIgnoreCase)) PurpleThemeRadio.IsChecked = true; else if (string.Equals(settings?.Theme, "Hacker", StringComparison.OrdinalIgnoreCase)) HackerThemeRadio.IsChecked = true; else DarkThemeRadio.IsChecked = true;
            _customThemeColor = ValidColor(settings?.CustomThemeColor, "#182438"); _customAccentColor = ValidColor(settings?.CustomAccentColor, "#3B82F6");
            CustomThemeRadio.IsChecked = settings?.Theme == "Custom"; CustomAccentRadio.IsChecked = settings?.AccentColor == "Custom";
            var accent = settings?.AccentColor ?? "Blue";
            PurpleAccentRadio.IsChecked = accent.Equals("Purple", StringComparison.OrdinalIgnoreCase);
            TealAccentRadio.IsChecked = accent.Equals("Teal", StringComparison.OrdinalIgnoreCase);
            OrangeAccentRadio.IsChecked = accent.Equals("Orange", StringComparison.OrdinalIgnoreCase);
            RedAccentRadio.IsChecked = accent.Equals("Red", StringComparison.OrdinalIgnoreCase);
            GreenAccentRadio.IsChecked = accent.Equals("Green", StringComparison.OrdinalIgnoreCase);
            PinkAccentRadio.IsChecked = accent.Equals("Pink", StringComparison.OrdinalIgnoreCase);
            GoldAccentRadio.IsChecked = accent.Equals("Gold", StringComparison.OrdinalIgnoreCase);
            BlueAccentRadio.IsChecked = !(CustomAccentRadio.IsChecked == true || PurpleAccentRadio.IsChecked == true || TealAccentRadio.IsChecked == true || OrangeAccentRadio.IsChecked == true || RedAccentRadio.IsChecked == true || GreenAccentRadio.IsChecked == true || PinkAccentRadio.IsChecked == true || GoldAccentRadio.IsChecked == true);
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
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(new AppSettings { SandboxInstallerCompatibility = SandboxCompatibilityCheck.IsChecked == true, PrepareNetFx3 = PrepareNetFx3Check.IsChecked == true, SandboxDisplayMode = UseIntegratedViewer ? "Integrated" : "Separate", AutoCloseSandbox = AutoCloseSandboxToggle.IsChecked == true, AutomaticallyCheckForUpdates = AutoUpdateToggle.IsChecked == true, BlockBundledMcAfee = BlockBundledMcAfeeToggle.IsChecked == true, EnableTestMode = EnableTestModeToggle.IsChecked == true, EnableAiAssist = AiIsEnabled, AiProvider = SelectedAiProvider, AiOpenAiModel = _aiOpenAiModel, AiOllamaModel = _aiOllamaModel, AiClaudeModel = _aiClaudeModel, AiLocalServer = AiLocalServerBox.Text.Trim(), CustomThemeColor = _customThemeColor, CustomAccentColor = _customAccentColor, Theme = CustomThemeRadio.IsChecked == true ? "Custom" : LightThemeRadio.IsChecked == true ? "Light" : SuperDarkThemeRadio.IsChecked == true ? "SuperDark" : PurpleThemeRadio.IsChecked == true ? "Purple" : HackerThemeRadio.IsChecked == true ? "Hacker" : "Dark", AccentColor = CustomAccentRadio.IsChecked == true ? "Custom" : PurpleAccentRadio.IsChecked == true ? "Purple" : TealAccentRadio.IsChecked == true ? "Teal" : OrangeAccentRadio.IsChecked == true ? "Orange" : RedAccentRadio.IsChecked == true ? "Red" : GreenAccentRadio.IsChecked == true ? "Green" : PinkAccentRadio.IsChecked == true ? "Pink" : GoldAccentRadio.IsChecked == true ? "Gold" : "Blue" }, new JsonSerializerOptions { WriteIndented = true }));
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

        if (CustomThemeRadio.IsChecked == true)
        {
            var c = (Color)ColorConverter.ConvertFromString(_customThemeColor);
            var bright = 0.2126*c.R + 0.7152*c.G + 0.0722*c.B > 145;
            string Mix(double factor) => $"#{(byte)(c.R*factor):X2}{(byte)(c.G*factor):X2}{(byte)(c.B*factor):X2}";
            foreach (var key in new[] { "Bg","Sidebar","Card","InputBg","ButtonBg","CodeBg","ScrollTrackBg" }) SetThemeBrush(key, key == "Bg" ? _customThemeColor : Mix(0.88));
            foreach (var key in new[] { "Border","InputBorder","ButtonHover","ScrollThumb","ScrollThumbHover" }) SetThemeBrush(key, bright ? "#66758A" : "#8094AC");
            SetThemeBrush("Text", bright ? "#101820" : "#FFFFFF"); SetThemeBrush("Muted", bright ? "#253548" : "#CFDAE8");
        }
        SetThemeBrush("StopBg", hackerTheme ? "#071507" : "#B91C1C");
        SetThemeBrush("StopHover", hackerTheme ? "#0C2A10" : "#DC2626");
        SetThemeBrush("StopText", hackerTheme ? "#39FF6A" : "#FFFFFF");
        // Hacker mode intentionally overrides accent selection so the entire interface stays black + green.
        var accent = hackerTheme ? "#00FF41"
            : CustomAccentRadio.IsChecked == true ? _customAccentColor : PurpleAccentRadio.IsChecked == true ? "#9B6DFF"
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
        var accentRgb = (Color)ColorConverter.ConvertFromString(accent);
        SetThemeBrush("PrimaryText", 0.2126*accentRgb.R + 0.7152*accentRgb.G + 0.0722*accentRgb.B > 145 ? "#08111F" : "#FFFFFF");
        if (!hackerTheme && CustomAccentRadio.IsChecked == true)
        {
            var bg = ((SolidColorBrush)Resources["Bg"]).Color;
            soft = Color.FromRgb((byte)(bg.R*0.8+accentRgb.R*0.2),(byte)(bg.G*0.8+accentRgb.G*0.2),(byte)(bg.B*0.8+accentRgb.B*0.2)).ToString();
        }
        SetThemeBrush("Accent", accent); SetThemeBrush("AccentSoft", soft); SetThemeBrush("Link", accent);
        ShowPage(CatalogPage.Visibility == Visibility.Visible ? CatalogPage : AnalyzePage.Visibility == Visibility.Visible ? AnalyzePage : SandboxPage.Visibility == Visibility.Visible ? SandboxPage : DattoPage.Visibility == Visibility.Visible ? DattoPage : ImmyBotPage.Visibility == Visibility.Visible ? ImmyBotPage : HistoryPage.Visibility == Visibility.Visible ? HistoryPage : TestModePage.Visibility == Visibility.Visible ? TestModePage : SettingsPage.Visibility == Visibility.Visible ? SettingsPage : AboutPage);
    }

    private static string ValidColor(string? value, string fallback) => value is not null && Regex.IsMatch(value, "^#[0-9A-Fa-f]{6}$") ? value : fallback;
    private void ViewCatalog_Click(object sender, RoutedEventArgs e) => CatalogNav_Click(sender, e);
    private void CustomTheme_Click(object sender, RoutedEventArgs e)
    {
        var picker = new ColorPickerWindow(this, _customThemeColor);
        if (picker.ShowDialog() != true) return;
        _customThemeColor = picker.SelectedColor; CustomThemeRadio.IsChecked = true; ApplyAppearance(); SaveAppSettings();
    }
    private void CustomAccent_Click(object sender, RoutedEventArgs e)
    {
        var picker = new ColorPickerWindow(this, _customAccentColor);
        if (picker.ShowDialog() != true) return;
        _customAccentColor = picker.SelectedColor; CustomAccentRadio.IsChecked = true; ApplyAppearance(); SaveAppSettings();
    }
    private void SetThemeBrush(string key, string hex) => Resources[key] = BrushFrom(hex);

    private void AutoUpdateToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_settingsLoaded) SaveAppSettings();
    }

    private async void MainWindow_FirstRendered(object? sender, EventArgs e)
    {
        ContentRendered -= MainWindow_FirstRendered;
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
            using var installer = await _updateService.DownloadInstallerAsync(_availableUpdate, progress);
            UpdateStatusText.Text = "Checksum and publisher verified. Starting installer…";
            await _updateService.LaunchInstallerAsync(installer);
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            InstallUpdateButton.IsEnabled = true;
            UpdateStatusText.Text = "Update not installed: " + ex.Message;
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
        var textColor = ((SolidColorBrush)Resources["Text"]).Color;
        var backgroundColor = ((SolidColorBrush)Resources["CodeBg"]).Color;
        if (_highlightedScripts.TryGetValue(target, out var cached) && cached.Script == script &&
            cached.Text == textColor && cached.Background == backgroundColor && ReferenceEquals(cached.Document, target.Document)) return;
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
        _highlightedScripts[target] = (script, textColor, backgroundColor, doc);
    }

    private static SolidColorBrush BrushFrom(string hex) => new((Color)ColorConverter.ConvertFromString(hex));

    private enum ScriptView { Install, Detection, Uninstall, Validation, Intelligence }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) { if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized; else DragMove(); }
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
