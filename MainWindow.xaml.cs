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
using System.Diagnostics;
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
        Loaded += MainWindow_Loaded;
    }

    private void Select_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "Installers (*.exe;*.msi)|*.exe;*.msi|All files (*.*)|*.*" };
        if (d.ShowDialog() == true) Analyze(d.FileName);
    }
    private void Window_DragOver(object sender, System.Windows.DragEventArgs e) => e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
    private void Window_Drop(object sender, System.Windows.DragEventArgs e) { if (e.Data.GetData(DataFormats.FileDrop) is string[] f && f.Length > 0) Analyze(f[0]); }

    private void Analyze(string path)
    {
        try
        {
            _result = _detector.Analyze(path); _installerPath = path; _issSession = null; _installAnalysis = null; _selectedUninstallEntry = null; _analysisLoaded = false; _scriptView = ScriptView.Install; OpenIssButton.IsEnabled = false;
            _logoPath = ApplicationLogoService.ExtractPng(path);
            FileText.Text = path; KindBox.SelectedItem = _result.Kind; ConfidenceText.Text = $"{_result.Confidence}%"; ConfidenceBar.Value = _result.Confidence;
            StatusText.Text = $"Analyzed {Path.GetFileName(path)}"; ArchText.Text = _result.Architecture;
            ProductBox.Text = string.IsNullOrWhiteSpace(_result.ProductName) ? Path.GetFileNameWithoutExtension(path) : _result.ProductName;
            CompanyText.Text = _result.CompanyName; VersionText.Text = _result.FileVersion; ArgumentsBox.Text = _result.SuggestedArguments;
            IssCheck.IsChecked = _result.NeedsIss; EvidenceList.ItemsSource = _result.Evidence; UpdateSandboxControls(); UpdateSandboxPage(); Generate(); UpdateImmyBotPage();
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
            _ => ImmyBotScriptGenerator.Generate(_result, ArgumentsBox.Text, ProductBox.Text)
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
        SidebarSandboxButton.IsEnabled = true;
        if (!isInstallShield) IssStatusText.Text = "setup.iss recording is only enabled for InstallShield installers.";
        else if (SandboxToggle.IsChecked == true && !SandboxIssRecorder.IsSandboxAvailable()) IssStatusText.Text = "Sandbox mode is selected, but Windows Sandbox is not enabled. Open Settings to enable it in Windows Features.";
        else if (SandboxToggle.IsChecked == true) IssStatusText.Text = "Ready to record setup.iss safely in Windows Sandbox.";
        else IssStatusText.Text = "Local mode selected. Generating setup.iss will run the installer on this computer.";
    }

    private void SandboxToggle_Changed(object sender, RoutedEventArgs e) { if (IsLoaded) UpdateSandboxControls(); }

    private void RecordIss_Click(object sender, RoutedEventArgs e)
    {
        if (_installerPath is null) return;
        try
        {
            if (SandboxToggle.IsChecked == true)
            {
                if (!SandboxIssRecorder.IsSandboxAvailable())
                {
                    var answer = MessageBox.Show("Windows Sandbox is not enabled. Open Windows Features now?", "Windows Sandbox", MessageBoxButton.YesNo, MessageBoxImage.Information);
                    if (answer == MessageBoxResult.Yes) OpenWindowsFeatures();
                    return;
                }
                _issSession = SandboxIssRecorder.Start(_installerPath);
                _sandboxWindow = IntPtr.Zero;
                _integratedViewerActive = false;
                _sandboxWindowTimer.Start();
                BringSandboxFrontButton.IsEnabled = true;
                SandboxOpenOutputButton.IsEnabled = true;
                ShowPage(SandboxPage);
                SandboxRunStatus.Text = "Starting Windows Sandbox…";
                SandboxRunDetails.Text = $"Analyzing {Path.GetFileName(_installerPath)}. v0.9.1 will guide validation and prepare the deployment for ImmyBot export.";
                SandboxArtifactText.Text = $"Output: {_issSession.OutputFolder}";
                IssStatusText.Text = "Windows Sandbox started. Follow the v0.9.1 prompts for install and uninstall validation.";
                StatusText.Text = "Sandbox ISS recording in progress";
            }
            else
            {
                var answer = MessageBox.Show("Sandbox is OFF. The installer will run in record mode on this computer and may install or modify the application locally. Continue?", "Local ISS recording", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes) return;
                _issSession = SandboxIssRecorder.StartLocal(_installerPath);
                IssStatusText.Text = "Installer started locally in record mode. Complete it normally. Waiting for setup.iss…";
                StatusText.Text = "Local ISS recording in progress";
            }
            OpenIssButton.IsEnabled = true; _issTimer.Start();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "ISS recorder", MessageBoxButton.OK, MessageBoxImage.Error); UpdateSandboxControls(); }
    }

    private void IssTimer_Tick(object? sender, EventArgs e)
    {
        if (_issSession is null) return;
        if (!_analysisLoaded && File.Exists(_issSession.AnalysisPath))
        {
            try
            {
                _installAnalysis = JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(_issSession.AnalysisPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                _selectedUninstallEntry = ChooseBestEntry(_installAnalysis?.NewUninstallEntries ?? new List<UninstallEntry>());
                _analysisLoaded = true;
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
        if (!File.Exists(_issSession.IssPath)) return;

        // Sandbox writes setup.iss and install-analysis.json separately. On fast installs the ISS
        // can appear first, so keep polling until the analysis file has also been consumed.
        var sandboxSession = !string.IsNullOrWhiteSpace(_issSession.WsbPath);
        if (sandboxSession && !_analysisLoaded)
        {
            IssStatusText.Text = "setup.iss created. Waiting for Sandbox installation analysis…";
            StatusText.Text = "Waiting for installation analysis";
            return;
        }

        _issTimer.Stop(); UpdateSandboxDashboard(); SandboxRunStatus.Text = "Analysis complete"; SandboxRunDetails.Text = _selectedUninstallEntry is null ? "Sandbox completed. No primary application was identified." : $"Detected {_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}. Generated setup.iss and installation analysis."; IssCheck.IsChecked = true; IssStatusText.Text = $"setup.iss created: {_issSession.IssPath}"; StatusText.Text = _selectedUninstallEntry is null ? "setup.iss recorded successfully" : "setup.iss + install analysis captured";
        ArgumentsBox.Text = "/s /f1`\"$ResponseFile`\""; _scriptView = ScriptView.Install; Generate();
        var details = _selectedUninstallEntry is null ? "No new uninstall registry entry was identified." : $"Detected: {_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}\n\nDetection, Uninstall, and Validation results are now available.";
        MessageBox.Show("Sandbox analysis completed.\n\n" + details, "Installation analysis complete", MessageBoxButton.OK, MessageBoxImage.Information);
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

    private void OpenIss_Click(object sender, RoutedEventArgs e) { if (_issSession is null) return; Directory.CreateDirectory(_issSession.OutputFolder); Process.Start(new ProcessStartInfo { FileName = _issSession.OutputFolder, UseShellExecute = true }); }

    private void KindBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_result is null || KindBox.SelectedItem is not InstallerKind k) return;
        _result.Kind = k; UpdateSandboxControls();
        ArgumentsBox.Text = k switch { InstallerKind.Msi => "/qn /norestart", InstallerKind.InnoSetup => "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", InstallerKind.Nsis => "/S", InstallerKind.WixBurn => "/quiet /norestart", InstallerKind.InstallShield when IssCheck.IsChecked == true => "/s /f1`\"$ResponseFile`\"", InstallerKind.InstallShield => "/s", _ => ArgumentsBox.Text };
    }
    private void IssCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_result is null) return; _result.NeedsIss = IssCheck.IsChecked == true;
        if (_result.Kind == InstallerKind.InstallShield) ArgumentsBox.Text = _result.NeedsIss ? "/s /f1`\"$ResponseFile`\"" : "/s";
    }

    private void AnalyzeNav_Click(object sender, RoutedEventArgs e) => ShowPage(AnalyzePage);
    private void SandboxNav_Click(object sender, RoutedEventArgs e) { UpdateSandboxPage(); ShowPage(SandboxPage); }
    private void ImmyBotNav_Click(object sender, RoutedEventArgs e) { UpdateImmyBotPage(); ShowPage(ImmyBotPage); }
    private void SettingsNav_Click(object sender, RoutedEventArgs e) { RefreshSandboxSettings(); ShowPage(SettingsPage); }
    private void AboutNav_Click(object sender, RoutedEventArgs e) => ShowPage(AboutPage);
    private void ShowPage(UIElement page)
    {
        AnalyzePage.Visibility = Visibility.Collapsed; SandboxPage.Visibility = Visibility.Collapsed; ImmyBotPage.Visibility = Visibility.Collapsed; SettingsPage.Visibility = Visibility.Collapsed; AboutPage.Visibility = Visibility.Collapsed;
        page.Visibility = Visibility.Visible;
        foreach (var b in new[] { AnalyzeNavButton, SidebarSandboxButton, ImmyBotNavButton, SettingsNavButton, AboutNavButton }) b.Background = Brushes.Transparent;
        var active = ReferenceEquals(page, AnalyzePage) ? AnalyzeNavButton : ReferenceEquals(page, SandboxPage) ? SidebarSandboxButton : ReferenceEquals(page, ImmyBotPage) ? ImmyBotNavButton : ReferenceEquals(page, SettingsPage) ? SettingsNavButton : AboutNavButton;
        active.Background = (Brush)Resources["AccentSoft"];
    }

    private bool UseIntegratedViewer => EmbeddedModeRadio.IsChecked == true;

    private void UpdateSandboxPage()
    {
        if (SandboxModeBadge is null) return;
        SandboxModeBadge.Text = UseIntegratedViewer ? "Integrated Viewer" : "Separate Window";
        StartSandboxButton.IsEnabled = _installerPath is not null && (_result?.Kind == InstallerKind.InstallShield || KindBox.SelectedItem is InstallerKind.InstallShield);
        if (_issSession is null)
        {
            SandboxRunStatus.Text = SandboxIssRecorder.IsSandboxAvailable() ? "Ready" : "Windows Sandbox unavailable";
            SandboxRunDetails.Text = _installerPath is null ? "Select an InstallShield installer on the Analyze page, then start Sandbox analysis here." : $"Ready to analyze {Path.GetFileName(_installerPath)}.";
        }
        SandboxPlaceholderText.Visibility = _integratedViewerActive ? Visibility.Collapsed : Visibility.Visible;
        SandboxPreviewImage.Visibility = _integratedViewerActive ? Visibility.Visible : Visibility.Collapsed;
        UpdateSandboxDashboard();
    }

    private void UpdateSandboxDashboard()
    {
        if (SandboxStageList is null) return;
        var stages = new List<string>();
        if (_issSession is null)
        {
            stages.Add("○ Waiting for Sandbox session");
        }
        else
        {
            stages.Add("✓ Sandbox session started");
            stages.Add(File.Exists(_issSession.IssPath) ? "✓ setup.iss captured" : "◉ Installing / recording setup.iss");
            stages.Add(_analysisLoaded ? "✓ Installation analysis captured" : "○ Waiting for registry analysis");
            if (_installAnalysis is not null)
            {
                stages.Add(_selectedUninstallEntry is not null ? $"✓ Primary app: {_selectedUninstallEntry.DisplayName} {_selectedUninstallEntry.DisplayVersion}".Trim() : "! Primary application not identified");
                stages.Add(_installAnalysis.UninstallResponseFileCreated ? "✓ uninstall.iss captured" : "○ Waiting for uninstall recording");
                stages.Add(_installAnalysis.SilentReinstallExitCode == 0 ? "✓ Silent reinstall validated" : "○ Silent reinstall pending");
                stages.Add(_installAnalysis.SilentUninstallValidated ? "✓ Silent uninstall validated" : "○ Silent uninstall validation pending");
                stages.Add(_installAnalysis.PostUninstallDetected == false ? "✓ Post-uninstall detection passed" : "○ Removal verification pending");
            }
        }
        SandboxStageList.ItemsSource = stages;

        var files = new List<string>();
        if (_issSession is not null)
        {
            foreach (var name in new[] { "setup.iss", "uninstall.iss", "install-analysis.json" })
            {
                var fp = Path.Combine(_issSession.OutputFolder, name);
                files.Add((File.Exists(fp) ? "✓ " : "○ ") + name);
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

        var ready = _installerPath is not null && _result is not null && _selectedUninstallEntry is not null && _installAnalysis?.SilentUninstallValidated == true;
        DeploymentReadinessText.Text = ready ? "READY FOR IMMYBOT" : "Sandbox validation required";
        DeploymentReadinessText.Foreground = BrushFrom(ready ? "#35D07F" : "#E7B75D");
        ExportImmyBotButton.IsEnabled = ready;
        if (ImmyExportButton is not null) ImmyExportButton.IsEnabled = ready;
        UpdateImmyBotPage();
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
            SetHighlightedScript(ImmyInstallBox, ImmyBotScriptGenerator.Generate(_result, ArgumentsBox.Text, ProductBox.Text));
            SetHighlightedScript(ImmyDetectionBox, ImmyBotScriptGenerator.GenerateDetection(_selectedUninstallEntry, ProductBox.Text));
            SetHighlightedScript(ImmyUninstallBox, ImmyBotScriptGenerator.GenerateUninstall(_selectedUninstallEntry, ProductBox.Text, _installAnalysis));
        }
        LoadLogoPreview();
        var ready = _installerPath is not null && _selectedUninstallEntry is not null && _installAnalysis?.SilentUninstallValidated == true;
        ImmyExportButton.IsEnabled = ready;
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
            SandboxRunStatus.Text = "Windows Sandbox running";
            SandboxRunDetails.Text = "Sandbox is running in a separate window. Complete the installer normally.";
            UpdateSandboxPage();
            _sandboxWindowTimer.Stop();
            return;
        }

        var preview = SandboxWindowPreview.Capture(_sandboxWindow);
        if (preview is not null)
        {
            SandboxPreviewImage.Source = preview;
            _integratedViewerActive = true;
            SandboxRunStatus.Text = "Integrated Sandbox viewer active";
            SandboxRunDetails.Text = "Showing a live preview of Windows Sandbox. Click Bring to Front when direct mouse or keyboard interaction is needed.";
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

    private void BringSandboxFront_Click(object sender, RoutedEventArgs e)
    {
        if (_sandboxWindow == IntPtr.Zero) _sandboxWindow = SandboxWindowEmbedder.FindSandboxWindow();
        SandboxWindowEmbedder.BringToFront(_sandboxWindow);
    }

    private sealed class AppSettings { public string SandboxDisplayMode { get; set; } = "Separate"; public bool AutomaticallyCheckForUpdates { get; set; } = true; public string Theme { get; set; } = "Dark"; public string AccentColor { get; set; } = "Blue"; }
    private void LoadAppSettings()
    {
        try
        {
            var settings = File.Exists(SettingsPath) ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath)) : null;
            if (string.Equals(settings?.SandboxDisplayMode, "Integrated", StringComparison.OrdinalIgnoreCase) || string.Equals(settings?.SandboxDisplayMode, "Embedded", StringComparison.OrdinalIgnoreCase)) EmbeddedModeRadio.IsChecked = true;
            else SeparateModeRadio.IsChecked = true;
            AutoUpdateToggle.IsChecked = settings?.AutomaticallyCheckForUpdates ?? true;
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
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(new AppSettings { SandboxDisplayMode = UseIntegratedViewer ? "Integrated" : "Separate", AutomaticallyCheckForUpdates = AutoUpdateToggle.IsChecked == true, Theme = LightThemeRadio.IsChecked == true ? "Light" : SuperDarkThemeRadio.IsChecked == true ? "SuperDark" : PurpleThemeRadio.IsChecked == true ? "Purple" : HackerThemeRadio.IsChecked == true ? "Hacker" : "Dark", AccentColor = PurpleAccentRadio.IsChecked == true ? "Purple" : TealAccentRadio.IsChecked == true ? "Teal" : OrangeAccentRadio.IsChecked == true ? "Orange" : RedAccentRadio.IsChecked == true ? "Red" : GreenAccentRadio.IsChecked == true ? "Green" : PinkAccentRadio.IsChecked == true ? "Pink" : GoldAccentRadio.IsChecked == true ? "Gold" : "Blue" }, new JsonSerializerOptions { WriteIndented = true }));
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
        ShowPage(AnalyzePage.Visibility == Visibility.Visible ? AnalyzePage : SandboxPage.Visibility == Visibility.Visible ? SandboxPage : ImmyBotPage.Visibility == Visibility.Visible ? ImmyBotPage : SettingsPage.Visibility == Visibility.Visible ? SettingsPage : AboutPage);
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
