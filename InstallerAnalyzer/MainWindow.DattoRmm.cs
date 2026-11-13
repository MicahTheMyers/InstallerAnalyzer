using System.IO;
using System.Windows;
using System.Windows.Controls;
using InstallerAnalyzer.Services;
using Microsoft.Win32;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private DattoRmmScripts? _dattoScripts;
    private bool _dattoExportBusy;

    private void DeploymentTarget_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (DeploymentPage?.Visibility == Visibility.Visible && ImmyBotPage is not null && DattoPage is not null)
            ShowPage(DeploymentTargetBox.SelectedIndex == 1 ? DattoPage : ImmyBotPage);
    }
    private void DattoScriptKind_Changed(object sender, SelectionChangedEventArgs e) => UpdateDattoPage();

    private void UpdateDattoPage()
    {
        if (DattoScriptBox is null) return;
        _dattoScripts = null;
        var reason = DattoRmmDeploymentService.BlockReason(_result, _selectedUninstallEntry, _installAnalysis, _issSession?.OutputFolder);
        if (reason is null)
        {
            try { _dattoScripts=DattoRmmDeploymentService.Generate(_result!, _selectedUninstallEntry!, _installAnalysis!, _issSession?.OutputFolder); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException) { reason=ex.Message; }
        }
        DattoStatusText.Text = reason ?? (DattoRmmDeploymentService.RequiresPreinstalledNetFx3(_installAnalysis)
            ? "Ready to export. The Install job requires .NET Framework 3.5 on each target device."
            : "Sandbox-validated package ready to export. Datto RMM tenant execution has not been verified.");
        DattoExportButton.IsEnabled = _dattoScripts is not null && !_dattoExportBusy;
        DattoCopyButton.IsEnabled = _dattoScripts is not null;
        var script = _dattoScripts is null ? "# " + reason : DattoScriptKindBox.SelectedIndex switch
        {
            1 => _dattoScripts.Component,
            2 => _dattoScripts.Install,
            3 => _dattoScripts.Detection,
            4 => _dattoScripts.Uninstall,
            5 => DattoRmmDeploymentService.Instructions,
            _ => _dattoScripts.Launcher
        };
        SetHighlightedScript(DattoScriptBox, script);
    }

    private void CopyDattoScript_Click(object sender, RoutedEventArgs e) => CopyRichText(DattoScriptBox);

    private async void ExportDatto_Click(object sender, RoutedEventArgs e)
    {
        if (_dattoExportBusy || _result is null || _selectedUninstallEntry is null || _installAnalysis is null) return;
        var source=_result; var entry=_selectedUninstallEntry; var proof=_installAnalysis; var responses=_issSession?.OutputFolder;
        var reason=DattoRmmDeploymentService.BlockReason(source,entry,proof,responses);
        if (reason is not null) { DattoStatusText.Text=reason; return; }
        var name=NormalizeName(entry.DisplayName ?? ProductBox.Text); if(string.IsNullOrWhiteSpace(name))name="Application";
        var dialog=new SaveFileDialog { Filter="Component creation kit (*.zip)|*.zip",FileName=name+"-DattoRMM.zip" };
        if(dialog.ShowDialog()!=true)return;
        _dattoExportBusy=true; DattoExportButton.IsEnabled=false;
        try
        {
            await Task.Run(()=>DattoRmmDeploymentService.Export(dialog.FileName,source,entry,proof,responses));
            StatusText.Text="Datto RMM component creation kit exported";
            MessageBox.Show("Kit created. Extract the ZIP and follow README.md to create a Datto RMM component. Test it on a disposable Datto-managed device before production use.\n\n"+dialog.FileName,"Datto RMM export",MessageBoxButton.OK,MessageBoxImage.Information);
        }
        catch(Exception ex) { MessageBox.Show(ex.Message,"Datto RMM export failed",MessageBoxButton.OK,MessageBoxImage.Error); }
        finally { _dattoExportBusy=false; UpdateDattoPage(); }
    }
}
