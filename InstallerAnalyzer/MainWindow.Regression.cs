using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private RegressionHistoryService RunHistory => new(Path.Combine(TestModeRoot, "RunHistory"));
    private RegressionRun? _activeRegressionRun;
    private List<RegressionRun> _savedRegressionRuns = new();
    private List<RegressionComparison> _comparisons = new();
    private bool _refreshingRunHistory;
    private string? _explicitBaselineId;
    private string _nextRunSource = "Test Mode";
    private bool _legacyHistoryImported;
    private string _legacyHistoryStatus = "";
    private bool _preparingRetest;

    private RegressionRun? DisplayedRun => RegressionCurrentRunBox.SelectedItem as RegressionRun;

    private void RefreshRunHistory(string? preferRunId = null)
    {
        if (RegressionCurrentRunBox is null) return;
        var history = RunHistory;
        if (!_legacyHistoryImported)
        {
            _legacyHistoryImported = true;
            Dispatcher.BeginInvoke(new Action(async () => await ImportLegacyHistoryAsync()));
        }
        var selectedId = preferRunId ?? DisplayedRun?.Id;
        _savedRegressionRuns = history.Load();
        var baselineId = _explicitBaselineId ?? history.BaselineId();
        _refreshingRunHistory = true;
        try
        {
            RegressionCurrentRunBox.ItemsSource = _savedRegressionRuns;
            RegressionCurrentRunBox.SelectedItem = _savedRegressionRuns.FirstOrDefault(r => r.Id == selectedId) ?? _savedRegressionRuns.FirstOrDefault();
            RegressionBaselineBox.ItemsSource = _savedRegressionRuns.Where(r => r.Completed is not null && !r.Stopped).ToList();
            RegressionBaselineBox.SelectedItem = _savedRegressionRuns.FirstOrDefault(r => r.Id == baselineId) ??
                _savedRegressionRuns.FirstOrDefault(r => r.Id != DisplayedRun?.Id && r.Completed is not null && !r.Stopped);
            RegressionHistoryStatus.Text = history.Warnings.Count == 0 ?
                "Run summaries and the saved baseline survive restart. Installer hashes identify comparisons." :
                "Some history could not be loaded: " + string.Join("; ", history.Warnings);
            if (baselineId is not null && !_savedRegressionRuns.Any(r => r.Id == baselineId))
                RegressionHistoryStatus.Text += " The saved baseline is missing; choose a replacement.";
            RegressionHistoryStatus.Text += _legacyHistoryStatus;
        }
        finally { _refreshingRunHistory = false; }
        UpdateRegressionComparison();
    }

    private async Task ImportLegacyHistoryAsync()
    {
        try
        {
            var history = RunHistory; var path = TestResultsFolder;
            var migration = await Task.Run(() => history.ImportLegacyRuns(path));
            _legacyHistoryStatus = migration.Imported > 0 ? $" Imported {migration.Imported} historical run summaries; the saved baseline was not changed." : "";
            if (migration.Warnings.Count > 0) _legacyHistoryStatus += " Historical import warnings: " + string.Join("; ", migration.Warnings.Take(3));
        }
        catch (Exception ex) { _legacyHistoryStatus = " Historical import unavailable: " + ex.Message; }
        if (!Dispatcher.HasShutdownStarted) RefreshRunHistory();
    }

    private void RegressionRun_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshingRunHistory) return;
        if (ReferenceEquals(sender, RegressionBaselineBox))
            _explicitBaselineId = (RegressionBaselineBox.SelectedItem as RegressionRun)?.Id;
        UpdateRegressionComparison();
    }

    private void UpdateRegressionComparison()
    {
        var current = DisplayedRun;
        var baseline = RegressionBaselineBox.SelectedItem as RegressionRun;
        if (current is null)
        {
            _comparisons = new();
            RegressionComparisonList.ItemsSource = null;
            RegressionComparisonSummary.Text = "No saved runs yet.";
            return;
        }
        _comparisons = baseline is null || baseline.Id == current.Id
            ? current.Tests.Select(t => new RegressionComparison { Classification = "CURRENT", Current = t }).ToList()
            : RegressionHistoryService.Compare(current, baseline);
        RegressionComparisonList.ItemsSource = _comparisons;
        RegressionComparisonSummary.Text = baseline?.Id == current.Id ? "Select a different baseline to compare." :
            baseline is null ? "No baseline selected. Showing saved results." :
            string.Join(" • ", _comparisons.GroupBy(c => c.Classification).Select(g => $"{g.Count()} {g.Key}"));
        RegressionResultDetails.Text = "Select a result to inspect previous and current evidence.";
    }

    private void RegressionResult_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (RegressionComparisonList.SelectedItem is not RegressionComparison row) return;
        RegressionResultDetails.Text = "CURRENT\n" + FailureClassificationService.Explain(row.Current) +
            "\n\nBASELINE\n" + FailureClassificationService.Explain(row.Previous);
    }

    private void SetRegressionBaseline_Click(object sender, RoutedEventArgs e)
    {
        if (_testModeRunning || DisplayedRun is not { } run) return;
        try
        {
            RunHistory.SetBaseline(run);
            _explicitBaselineId = run.Id;
            RefreshRunHistory(run.Id);
            RegressionHistoryStatus.Text = "Saved baseline: " + run.Display;
        }
        catch (Exception ex) { RegressionHistoryStatus.Text = ex.Message; }
    }

    private void ClearRegressionBaseline_Click(object sender, RoutedEventArgs e)
    {
        if (_testModeRunning) return;
        try
        {
            RunHistory.ClearBaseline();
            _explicitBaselineId = null;
            _refreshingRunHistory = true;
            RegressionBaselineBox.SelectedItem = null;
            _refreshingRunHistory = false;
            UpdateRegressionComparison();
            RegressionHistoryStatus.Text = "Saved baseline cleared. Historical results were preserved.";
        }
        catch (Exception ex) { _refreshingRunHistory = false; RegressionHistoryStatus.Text = ex.Message; }
    }

    private async void Retest_Click(object sender, RoutedEventArgs e)
    {
        if (_preparingRetest || _testModeRunning || _analysisBusy || _issTimer.IsEnabled || _sandboxStarting || _sandboxStopping) return;
        if (sender is not Button button) return;
        var action = button.Tag?.ToString();
        if (action == "Selected") { _nextRunSource = "Retest"; StartTests_Click(sender, e); return; }
        var run = DisplayedRun;
        if (run is null) { RegressionHistoryStatus.Text = "Choose a saved run first."; return; }
        var targets = action == "Regressions"
            ? _comparisons.Where(c => c.Classification == "REGRESSION" && c.Current is not null).Select(c => c.Current!).ToList()
            : run.Tests.Where(t => action switch
            {
                "Failed" => t.Result is "FAIL" or "TIMEOUT",
                "Infrastructure" => t.Failure.Infrastructure,
                "Unknown" => t.InstallerType == "Unknown" || t.Failure.Category == FailureCategory.NoSilentStrategy,
                _ => false
            }).ToList();
        try
        {
            _preparingRetest = true;
            if (!await RefreshTestQueue()) return;
            // Recalculate current file hashes: a replaced file is a new installer, not a retest.
            var queueSnapshot = _testQueue.ToList();
            var matches = await Task.Run(() => queueSnapshot.Where(q =>
            {
                var identity = new RegressionTestRecord { InstallerSha256 = RegressionHistoryService.HashFile(q.Path) };
                return targets.Any(t => RegressionHistoryService.SameInstaller(identity, t));
            }).Select(q => q.Path).ToHashSet(StringComparer.OrdinalIgnoreCase));
            if (_testModeRunning || _analysisBusy || _issTimer.IsEnabled || _sandboxStarting || _sandboxStopping || DisplayedRun?.Id != run.Id)
            {
                RegressionHistoryStatus.Text = "Retest preparation cancelled because the selected run or application activity changed.";
                return;
            }
            if (matches.Count == 0)
            {
                RegressionHistoryStatus.Text = "No matching installer bytes are available in TestInstallers for this retest.";
                return;
            }
            foreach (var item in _testQueue) item.Selected = matches.Contains(item.Path);
            TestTypeBox.SelectedIndex = run.Mode == "SilentOnlyUnattended" ? 1 : 0;
            _nextRunSource = "Retest";
            StartTests_Click(sender, e);
        }
        catch (Exception ex) { RegressionHistoryStatus.Text = "Could not prepare retest: " + ex.Message; }
        finally { _preparingRetest = false; }
    }

    private void SaveRunProgress()
    {
        if (_activeRegressionRun is not null) RunHistory.Save(_activeRegressionRun);
    }

    private async void ExportDiagnostics_Click(object sender, RoutedEventArgs e)
    {
        if (_testModeRunning || sender is not Button button || DisplayedRun is not { } run) return;
        var mode = button.Tag?.ToString();
        var selected = mode == "Selected"
            ? new[] { (RegressionComparisonList.SelectedItem as RegressionComparison)?.Current ?? (RegressionComparisonList.SelectedItem as RegressionComparison)?.Previous }.OfType<RegressionTestRecord>().ToArray()
            : run.Tests.Where(t => mode != "Failed" || t.Result is "FAIL" or "TIMEOUT").ToArray();
        if (selected.Length == 0) { RegressionHistoryStatus.Text = "Select a result or a run with matching tests first."; return; }
        var dialog = new Microsoft.Win32.SaveFileDialog { Filter = "Diagnostic ZIP (*.zip)|*.zip", FileName = "InstallerAnalyzer-diagnostics.zip" };
        if (dialog.ShowDialog(this) != true) return;
        var includeScreenshots = IncludeDiagnosticScreenshots.IsChecked == true;
        try
        {
            var exported = await Task.Run(() => DiagnosticBundleService.Export(dialog.FileName, selected, includeScreenshots));
            RegressionHistoryStatus.Text = $"Diagnostic bundle saved: {exported.Included} files; {exported.Omitted} unavailable or over size limits. Installer binaries were excluded.";
        }
        catch (Exception ex) { RegressionHistoryStatus.Text = "Export failed: " + ex.Message; }
    }
}
