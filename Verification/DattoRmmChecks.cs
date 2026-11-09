using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class DattoRmmChecks
{
    public static void Run(MainWindow window, string root, Action<bool,string> check)
    {
        var folder=Path.Combine(root,"datto");Directory.CreateDirectory(folder);
        var path=Path.Combine(folder,"source [test] O'Brien.exe");File.WriteAllText(path,"inert source; never execute");
        var source=new AnalysisResult{FilePath=path,Kind=InstallerKind.Nsis};
        var entry=new UninstallEntry{Key=@"HKLM:\SOFTWARE\Fixture",DisplayName="Product '$(untrusted)'",UninstallString="\"C:\\Program Files\\Fixture\\uninstall.exe\""};
        var proof=new InstallAnalysis{ValidationSchemaVersion=3,EvidenceCollectionComplete=true,InitialInstallValidated=true,InitialUninstallValidated=true,InitialUninstallExitCode=0,CleanBaselineVerified=true,SilentReinstallValidated=true,SilentReinstallExitCode=0,SilentUninstallValidated=true,SilentUninstallExitCode=0,PostUninstallDetected=false,DiscoverySucceeded=true,PrimaryKey=entry.Key,CapturedAt=DateTimeOffset.UtcNow.ToString("o"),InstallerSha256=RegressionHistoryService.HashFile(path),CombinedSilentArguments="/S /tag=__DETECT__ /data='$(data)'",UninstallCandidate=entry.UninstallString+" /S",NewUninstallEntries=new(){entry},DetectionStrategies=new(){new(){Type="UninstallRegistryKey",RegistryPath=@"HKLM:\SOFTWARE\Fixture",BeforeInstall=false,AfterInstall=true,AfterUninstall=false,Rank=90}}};
        check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is null,"Datto accepts complete machine-wide lifecycle and measured detection");
        check(DattoRmmDeploymentService.BlockReason(source,entry,null,null) is not null,"Datto refuses unvalidated exports");
        source.IsPerUser=true;check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto refuses user-profile deployment under LocalSystem");source.IsPerUser=false;
        source.Kind=InstallerKind.Msix;check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto does not silently convert MSIX into a machine-wide install");source.Kind=InstallerKind.Nsis;
        var other=new UninstallEntry{Key=@"HKLM:\SOFTWARE\Other"};check(DattoRmmDeploymentService.BlockReason(source,other,proof,null) is not null,"Datto rejects a secondary product with another identity");
        var rule=proof.DetectionStrategies[0];rule.RegistryPath=@"HKCU:\SOFTWARE\Fixture";check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto rejects measured current-user detection");rule.RegistryPath=@"HKLM:\SOFTWARE\Fixture";
        var args=proof.CombinedSilentArguments;proof.CombinedSilentArguments="/S PASSWORD=private";check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto blocks recognized credential arguments instead of embedding them");proof.CombinedSilentArguments=args;
        proof.NetFx3Provisioning.Evidence="Requires .NET Framework 3.5";check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto does not assume Sandbox-provisioned prerequisites exist on managed devices");proof.NetFx3Provisioning.Evidence="";
        proof.CombinedSilentArguments="/qn TRANSFORMS=custom.mst";check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto does not omit required MSI transforms from a single-file package");proof.CombinedSilentArguments=args;
        proof.DeploymentSource=@"C:\Extracted\different.msi";check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto rejects an extracted payload instead of exporting the wrong source");proof.DeploymentSource=null;
        proof.SelectedSilentStrategy="Recorded InstallShield response file";check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto refuses response-mode changes after a recorded validation");proof.SelectedSilentStrategy=null;
        var scripts=DattoRmmDeploymentService.Generate(source,entry,proof,null);
        check(scripts.Component.Contains("/tag=__DETECT__") && !scripts.Component.Contains(entry.DisplayName),"Datto preserves literal template-token arguments and keeps display names out of executable source");
        File.WriteAllText(Path.Combine(folder,"DattoComponent.ps1"),scripts.Component);
        File.WriteAllText(Path.Combine(folder,"Component.cmd"),scripts.Launcher);
        var zip=Path.Combine(folder,"kit.zip");DattoRmmDeploymentService.Export(zip,source,entry,proof,null);
        using(var archive=ZipFile.OpenRead(zip))
        {
            check(archive.Entries.Select(e=>e.FullName).Order().SequenceEqual(new[]{"Component.cmd","DattoComponent.ps1","README.md","component-settings.json","installer.exe"}.Order()),"Datto kit contains only its launcher, payload, guidance, settings and original installer");
            using var metadata=new StreamReader(archive.GetEntry("component-settings.json")!.Open());using var json=JsonDocument.Parse(metadata.ReadToEnd());
            check(!json.RootElement.GetProperty("DattoTenantValidated").GetBoolean() && json.RootElement.GetProperty("InputVariable").GetProperty("Default").GetString()=="Detect","Datto metadata defaults to detection and keeps tenant validation false");
        }
        File.WriteAllText(path,"changed source");var before=File.ReadAllBytes(zip);bool rejected=false;
        try{DattoRmmDeploymentService.Export(zip,source,entry,proof,null);}catch(InvalidDataException){rejected=true;}
        check(rejected && before.SequenceEqual(File.ReadAllBytes(zip)),"Datto refuses changed source bytes without replacing an existing kit");
        File.WriteAllText(path,"inert source; never execute");
        source.NeedsIss=true;check(DattoRmmDeploymentService.BlockReason(source,entry,proof,folder) is not null,"Datto requires a genuine recorded response before packaging");
        File.WriteAllText(Path.Combine(folder,"setup.iss"),"[InstallShield Silent]\r\nFile=Response File\r\nCount=1\r\n");
        check(DattoRmmDeploymentService.BlockReason(source,entry,proof,folder) is null,"Datto accepts bounded recorded response files");source.NeedsIss=false;
        // An MSI fixture preserves native property strings as data rather than PowerShell expressions.
        var msi=Path.Combine(folder,"inert.msi");File.WriteAllText(msi,"inert MSI; never execute");source.FilePath=msi;source.Kind=InstallerKind.Msi;proof.InstallerSha256=RegressionHistoryService.HashFile(msi);
        source.Kind=InstallerKind.Nsis;check(DattoRmmDeploymentService.BlockReason(source,entry,proof,null) is not null,"Datto refuses exporting an MSI through an executable strategy");source.Kind=InstallerKind.Msi;
        proof.CombinedSilentArguments="/qn PROPERTY=\"$(data)\" OBRIEN='value'";
        File.WriteAllText(Path.Combine(folder,"MsiComponent.ps1"),DattoRmmDeploymentService.Generate(source,entry,proof,null).Component);
        DattoRmmDeploymentService.Export(Path.Combine(folder,"msi-kit.zip"),source,entry,proof,null);

        var msiEntry = new UninstallEntry { WindowsInstaller = 1, ProductCode = "{11111111-1111-1111-1111-111111111111}" };
        var msiRemoval = new InstallAnalysis
        {
            SilentUninstallValidated = true,
            UninstallCandidate = $"msiexec.exe /x {msiEntry.ProductCode} /qn /norestart USED_DATA_ALREADY_REMOVED=1"
        };
        check(ImmyBotScriptGenerator.GenerateUninstall(msiEntry, "Fixture", msiRemoval).Contains("USED_DATA_ALREADY_REMOVED=1"),
            "ImmyBot preserves the validated MSI removal property");
        msiRemoval.SilentUninstallValidated = false;
        check(!ImmyBotScriptGenerator.GenerateUninstall(msiEntry, "Fixture", msiRemoval).Contains("USED_DATA_ALREADY_REMOVED=1"),
            "ImmyBot does not reuse an unvalidated MSI removal property");

        T Field<T>(string name)=>(T)typeof(MainWindow).GetField(name,BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public)!.GetValue(window)!;
        object? Invoke(string name,params object[] values)=>typeof(MainWindow).GetMethod(name,BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(window,values);
        var resultField=typeof(MainWindow).GetField("_result",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var proofField=typeof(MainWindow).GetField("_installAnalysis",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var entryField=typeof(MainWindow).GetField("_selectedUninstallEntry",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var previous=new[]{resultField.GetValue(window),proofField.GetValue(window),entryField.GetValue(window)};
        try
        {
            resultField.SetValue(window,source);proofField.SetValue(window,proof);entryField.SetValue(window,entry);
            Invoke("DeploymentNav_Click",window,new RoutedEventArgs());
            check(Field<ComboBox>("DeploymentTargetBox").SelectedIndex==0 && Field<Grid>("ImmyBotPage").Visibility==Visibility.Visible,"Deployment defaults to ImmyBot");
            Field<ComboBox>("DeploymentTargetBox").SelectedIndex=1;
            check(Field<Grid>("DattoPage").Visibility==Visibility.Visible && Field<Grid>("ImmyBotPage").Visibility==Visibility.Collapsed && Field<Button>("DattoExportButton").IsEnabled,"Deployment target switches to gated Datto export without overlapping ImmyBot");
            Field<ComboBox>("DattoScriptKindBox").SelectedIndex=1;
            check(new System.Windows.Documents.TextRange(Field<RichTextBox>("DattoScriptBox").Document.ContentStart,Field<RichTextBox>("DattoScriptBox").Document.ContentEnd).Text.Contains("IA_ACTION"),"Datto preview selector shows the generated payload");
            var content=(FrameworkElement)window.Content;content.Measure(new Size(1240,900));content.Arrange(new Rect(0,0,1240,900));content.UpdateLayout();
            var bitmap=new System.Windows.Media.Imaging.RenderTargetBitmap(1240,900,96,96,System.Windows.Media.PixelFormats.Pbgra32);bitmap.Render(content);
            var png=new System.Windows.Media.Imaging.PngBitmapEncoder();png.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));using(var output=File.Create(Path.Combine(folder,"Datto-Ready.png")))png.Save(output);
            Field<ComboBox>("DeploymentTargetBox").SelectedIndex=0;
            check(Field<Grid>("ImmyBotPage").Visibility==Visibility.Visible && Field<Grid>("DattoPage").Visibility==Visibility.Collapsed,"Deployment target switches back to ImmyBot");
            Field<ComboBox>("DeploymentTargetBox").SelectedIndex=1;
            source.IsPerUser=true;Invoke("UpdateDattoPage");check(!Field<Button>("DattoExportButton").IsEnabled,"Datto UI disables export for unsupported execution context");source.IsPerUser=false;
        }
        finally{resultField.SetValue(window,previous[0]);proofField.SetValue(window,previous[1]);entryField.SetValue(window,previous[2]);Invoke("ShowPage",Field<Grid>("AnalyzePage"));}
    }
}
