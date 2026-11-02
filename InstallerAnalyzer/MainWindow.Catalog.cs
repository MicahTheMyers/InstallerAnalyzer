using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;
using Microsoft.Win32;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private List<CatalogRecord> _catalogRecords = new();
    private async void CatalogNav_Click(object sender, RoutedEventArgs e)
    {
        ShowPage(CatalogPage);
        await RefreshCatalogAsync();
    }
    private async Task RefreshCatalogAsync()
    {
        try
        {
            _catalogRecords = await Task.Run(() => InstallerCatalogService.ReadCatalog());
            FilterCatalog();
            CatalogStatusText.Text = $"{_catalogRecords.Count} entries. Imported candidates require their own complete Sandbox validation.";
        }
        catch (Exception ex) { CatalogStatusText.Text = "Catalog unavailable: " + ex.Message; }
    }
    private void CatalogSearch_Changed(object sender, TextChangedEventArgs e) { if (CatalogList is not null) FilterCatalog(); }
    private void FilterCatalog()
    {
        var text = CatalogSearchBox.Text.Trim();
        CatalogList.ItemsSource = _catalogRecords.Where(r => text.Length == 0 ||
            $"{r.Product} {r.Version} {r.Publisher} {r.Family} {r.Sha256} {r.Origin}".Contains(text, StringComparison.OrdinalIgnoreCase)).ToList();
    }
    private void CatalogSelection_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (CatalogList.SelectedItem is not CatalogRecord row) { CatalogDetailsText.Text = "Select an entry to inspect its strategy and validation history."; return; }
        var sb = new StringBuilder($"{row.Product} {row.Version}\n{row.Publisher}\n\n");
        sb.AppendLine($"Origin: {row.Origin}\nArchitecture: {row.Architecture}\nInstaller technology: {row.Family}\nSHA-256: {row.Sha256}");
        sb.AppendLine($"Signature: {row.SigningIdentity.SignatureStatus}\nSigner: {row.SigningIdentity.SignerSubject}\nCertificate: {row.SigningIdentity.SignerThumbprint}");
        if (row.Family == "Msi") sb.AppendLine($"MSI ProductCode: {row.SigningIdentity.Msi.ProductCode}\nUpgradeCode: {row.SigningIdentity.Msi.UpgradeCode}");
        sb.AppendLine($"\nDeployment source: {row.DeploymentSource}\nDeployment mechanism: {row.DeploymentMechanism}\nApplication identity: {row.ApplicationIdentity}");
        sb.AppendLine($"\nInstall arguments: {row.InstallArguments}\nDetection: {row.Detection?.Type ?? "No independently validated strategy recorded"}");
        if (row.Detection is { } detection) sb.AppendLine($"{detection.Identity}\nBefore / installed / removed: {detection.BeforeInstall} / {detection.AfterInstall} / {detection.AfterUninstall}");
        sb.AppendLine($"Uninstall: {row.UninstallType} • {row.UninstallIdentity}\n\nFirst validated: {row.FirstValidatedUtc}\nLast validated: {row.LastValidatedUtc}\nLocal validations: {row.Validations}\nRecorded failed retests: {row.Failures}\n\nValidation history:");
        sb.AppendLine($"Reboot required: {row.RebootRequired}; Post-reboot validation: {row.PostRebootValidated}\n");
        foreach (var entry in row.History.OrderByDescending(h => h.TimestampUtc))
            sb.AppendLine($"{entry.TimestampUtc} • v{entry.AnalyzerVersion} • {entry.Source}\n{entry.StrategyType} {entry.InstallArguments}\nInstall {entry.InstallPassed}, Detection {entry.DetectionPassed}, Uninstall {entry.UninstallPassed}, Removal {entry.RemovalPassed}\nElapsed {entry.DurationSeconds?.ToString("F1") ?? "unknown"} seconds; confidence {entry.Confidence}%\n");
        if (row.History.Count == 0) sb.AppendLine("No detailed history was retained by the version that created this entry.");
        CatalogDetailsText.Text = sb.ToString();
    }
    private async void CatalogRefresh_Click(object sender, RoutedEventArgs e) => await RefreshCatalogAsync();
    private async void CatalogRemove_Click(object sender, RoutedEventArgs e)
    {
        if (_testModeRunning || CatalogList.SelectedItem is not CatalogRecord row) return;
        if (MessageBox.Show(this, $"Remove {row.Product} and its catalog validation history? This does not uninstall the application or delete its installer.", "Remove catalog entry", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        try { await Task.Run(() => InstallerCatalogService.RemoveEntry(row.Sha256)); await RefreshCatalogAsync(); }
        catch (Exception ex) { CatalogStatusText.Text = ex.Message; }
    }
    private async void CatalogTransfer_Click(object sender, RoutedEventArgs e)
    {
        if (_testModeRunning || sender is not Button button) return;
        var action = button.Tag?.ToString();
        bool save = action is "Export" or "Backup";
        var filter = action is "Backup" or "Restore" ? "SQLite backup (*.db)|*.db" : "Catalog JSON (*.json)|*.json";
        string path;
        if (save)
        {
            var dialog = new SaveFileDialog { Filter = filter, FileName = action == "Backup" ? "InstallerCatalog-backup.db" : "InstallerCatalog.json" };
            if (dialog.ShowDialog(this) != true) return;
            path = dialog.FileName;
        }
        else
        {
            var dialog = new OpenFileDialog { Filter = filter };
            if (dialog.ShowDialog(this) != true) return;
            path = dialog.FileName;
        }
        try
        {
            var message = await Task.Run(() =>
            {
                if (action == "Export") { InstallerCatalogService.ExportCatalog(path); return "Catalog exported."; }
                if (action == "Backup") { InstallerCatalogService.BackupCatalog(path); return "Consistent catalog backup saved."; }
                var result = action == "Restore" ? InstallerCatalogService.RestoreCatalog(path) : InstallerCatalogService.ImportCatalog(path);
                return $"{result.Imported} candidates imported; {result.Preserved} existing entries preserved. Fresh Sandbox validation is required.";
            });
            await RefreshCatalogAsync(); CatalogStatusText.Text = message;
        }
        catch (Exception ex) { CatalogStatusText.Text = "Catalog operation failed: " + ex.Message; }
    }
    private async void CatalogRetest_Click(object sender, RoutedEventArgs e)
    {
        if (_testModeRunning || _analysisBusy || _issTimer.IsEnabled || _sandboxStarting || _sandboxStopping || CatalogList.SelectedItem is not CatalogRecord row) return;
        var path = row.LocalInstallerPath;
        try
        {
            if (!File.Exists(path) || !row.Sha256.Equals(await Task.Run(() => RegressionHistoryService.HashFile(path)), StringComparison.OrdinalIgnoreCase))
            {
                var dialog = new OpenFileDialog { Title = "Select the installer with this catalog SHA-256", Filter = "Installer|*.exe;*.msi;*.msix;*.appx;*.msixbundle;*.appxbundle" };
                if (dialog.ShowDialog(this) != true) return;
                path = dialog.FileName;
                if (!row.Sha256.Equals(await Task.Run(() => RegressionHistoryService.HashFile(path)), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("The selected installer has different bytes. Analyze it as a new version instead.");
            }
            if (_testModeRunning || _analysisBusy || _issTimer.IsEnabled || _sandboxStarting || _sandboxStopping) return;
            InitializeTestModeFolders();
            var target = Path.Combine(TestInstallerFolder, "CatalogRetests", row.Sha256, Path.GetFileName(path));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            if (!File.Exists(target)) await Task.Run(() => File.Copy(path, target, false));
            if (!row.Sha256.Equals(await Task.Run(() => RegressionHistoryService.HashFile(target)), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The queued file differs from the catalog identity.");
            if (_testModeRunning || _analysisBusy || _issTimer.IsEnabled || _sandboxStarting || _sandboxStopping) return;
            EnableTestModeToggle.IsChecked = true;
            if (!await RefreshTestQueue()) return;
            foreach (var item in _testQueue) item.Selected = item.Path.Equals(target, StringComparison.OrdinalIgnoreCase);
            TestTypeBox.SelectedIndex = 1; _nextRunSource = "Retest"; ShowPage(TestModePage); StartTests_Click(sender, e);
        }
        catch (Exception ex) { CatalogStatusText.Text = "Retest could not start: " + ex.Message; }
    }
}
