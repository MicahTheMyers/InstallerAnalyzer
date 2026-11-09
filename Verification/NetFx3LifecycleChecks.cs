using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class NetFx3LifecycleChecks
{
    public static int Run(string root, bool installerCompatibility = false)
    {
        string Wsb = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Microsoft","WindowsApps","wsb.exe");
        string[] Ids()
        {
            using var process=Process.Start(new ProcessStartInfo(Wsb,"list --raw"){UseShellExecute=false,RedirectStandardOutput=true,CreateNoWindow=true})!;
            var output=process.StandardOutput.ReadToEnd();process.WaitForExit();if(process.ExitCode!=0)throw new IOException("Sandbox inventory failed");
            using var json=JsonDocument.Parse(output);return json.RootElement.GetProperty("WindowsSandboxEnvironments").EnumerateArray().Select(e=>e.GetProperty("Id").GetString()!).ToArray();
        }
        if(Ids().Length!=0)throw new InvalidOperationException("Existing Sandbox left untouched");
        var fixture=Path.Combine(root,"NetFx3-Lifecycle-Fixture.msi"); CreateMsi(fixture);
        var before=RegressionHistoryService.HashFile(fixture);string? owned=null;
        try
        {
            var session=SandboxIssRecorder.Start(fixture,InstallerKind.Msi,false,"/qn /norestart","",true,true,installerCompatibility: installerCompatibility);
            File.WriteAllText(Path.Combine(root,"session-path.txt"),session.SessionFolder);
            var deadline=DateTime.UtcNow.AddMinutes(20);
            while(DateTime.UtcNow<deadline)
            {
                if(owned is null){var ids=Ids();if(ids.Length>1)throw new InvalidOperationException("Ambiguous Sandbox ownership");if(ids.Length==1)owned=ids[0];}
                if(File.Exists(session.CompleteFlagPath))break;
                Thread.Sleep(1000);
            }
            if(!File.Exists(session.AnalysisPath))throw new InvalidOperationException("No final lifecycle result");
            File.Copy(session.AnalysisPath,Path.Combine(root,"install-analysis.json"));
            var proof=JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(session.AnalysisPath),new JsonSerializerOptions{PropertyNameCaseInsensitive=true})!;
            var pass=proof.NetFx3Provisioning.RuntimeVerified && proof.InitialInstallValidated && proof.InitialUninstallValidated && proof.CleanBaselineVerified && proof.SilentReinstallValidated && proof.SilentUninstallValidated && proof.PostUninstallDetected==false && (!installerCompatibility || proof.SandboxCompatibility is { Requested: true, Prepared: true, AfterState: 0, RefreshExitCode: 0 });
            File.WriteAllText(Path.Combine(root,"acceptance.json"),JsonSerializer.Serialize(new{Passed=pass,proof.NetFx3Provisioning,proof.InitialInstallValidated,proof.InitialUninstallValidated,proof.CleanBaselineVerified,proof.SilentReinstallValidated,proof.SilentUninstallValidated,proof.PostUninstallDetected,proof.ValidationError,SourceHashUnchanged=before==RegressionHistoryService.HashFile(fixture)}));
            Console.WriteLine(pass?"PASS production Sandbox NetFx3 provisioning and real MSI install/remove/reinstall/remove fixture":"FAIL lifecycle: "+proof.ValidationError);
            return pass?0:1;
        }
        finally
        {
            if(owned is not null && Ids().Contains(owned)){using var stop=Process.Start(new ProcessStartInfo(Wsb,"stop --id "+owned){UseShellExecute=false,CreateNoWindow=true});stop?.WaitForExit(15000);}
            Console.WriteLine("Remaining Sandbox environments: "+Ids().Length);
        }
    }

    private static void CreateMsi(string path)
    {
        object? engine=null,db=null,summary=null;
        try
        {
            engine=Activator.CreateInstance(Type.GetTypeFromProgID("WindowsInstaller.Installer")!);db=((dynamic)engine!).OpenDatabase(path,3);
            void Sql(string sql){object? view=null;try{view=((dynamic)db).OpenView(sql);((dynamic)view).Execute();}finally{if(view is not null)Marshal.FinalReleaseComObject(view);}}
            foreach(var sql in new[]{
                "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) PRIMARY KEY `Property`)",
                "CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` LONG NOT NULL, `DiskPrompt` CHAR(64), `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`)",
                "CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` LONG NOT NULL PRIMARY KEY `File`)",
                "CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL PRIMARY KEY `Directory`)",
                "CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64), `Description` CHAR(255), `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`)",
                "CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)",
                "CREATE TABLE `FeatureComponents` (`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`)",
                "CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL, `Name` CHAR(255), `Value` CHAR(0), `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)",
                "CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)",
                "CREATE TABLE `LaunchCondition` (`Condition` CHAR(255) NOT NULL, `Description` CHAR(255) NOT NULL PRIMARY KEY `Condition`)",
                "CREATE TABLE `AppSearch` (`Property` CHAR(72) NOT NULL, `Signature_` CHAR(72) NOT NULL PRIMARY KEY `Property`, `Signature_`)",
                "CREATE TABLE `Signature` (`Signature` CHAR(72) NOT NULL, `FileName` CHAR(255), `MinVersion` CHAR(20), `MaxVersion` CHAR(20), `MinSize` LONG, `MaxSize` LONG, `MinDate` LONG, `MaxDate` LONG, `Languages` CHAR(255) PRIMARY KEY `Signature`)",
                "CREATE TABLE `RegLocator` (`Signature_` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL, `Name` CHAR(255), `Type` SHORT PRIMARY KEY `Signature_`)",
                "INSERT INTO `Directory` (`Directory`,`DefaultDir`) VALUES ('TARGETDIR','SourceDir')",
                "INSERT INTO `Feature` (`Feature`,`Title`,`Display`,`Level`,`Directory_`,`Attributes`) VALUES ('Main','Inert fixture',1,1,'TARGETDIR',0)",
                "INSERT INTO `FeatureComponents` (`Feature_`,`Component_`) VALUES ('Main','MarkerComponent')",
                "INSERT INTO `Registry` (`Registry`,`Root`,`Key`,`Name`,`Value`,`Component_`) VALUES ('Marker',2,'Software\\InstallerAnalyzer\\NetFx3LifecycleFixture','Installed','1','MarkerComponent')",
                "INSERT INTO `LaunchCondition` (`Condition`,`Description`) VALUES ('Installed OR NETFRAMEWORK35','This application requires .NET Framework 3.5')",
                "INSERT INTO `AppSearch` (`Property`,`Signature_`) VALUES ('NETFRAMEWORK35','NetFx35')",
                "INSERT INTO `RegLocator` (`Signature_`,`Root`,`Key`,`Name`,`Type`) VALUES ('NetFx35',2,'SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5','Install',18)"
            })Sql(sql);
            var product="{"+Guid.NewGuid().ToString().ToUpperInvariant()+"}";
            foreach(var property in new Dictionary<string,string>{{"ProductName","Installer Analyzer NetFx3 Lifecycle Fixture"},{"ProductVersion","1.0.0"},{"Manufacturer","Installer Analyzer verification"},{"ProductLanguage","1033"},{"ProductCode",product},{"UpgradeCode","{"+Guid.NewGuid()+"}"},{"ALLUSERS","1"},{"INSTALLLEVEL","1"}})
                Sql($"INSERT INTO `Property` (`Property`,`Value`) VALUES ('{property.Key}','{property.Value}')");
            Sql("INSERT INTO `Component` (`Component`,`ComponentId`,`Directory_`,`Attributes`,`KeyPath`) VALUES ('MarkerComponent','{"+Guid.NewGuid()+"}','TARGETDIR',260,'Marker')");
            foreach(var action in new Dictionary<string,int>{{"AppSearch",50},{"LaunchConditions",100},{"CostInitialize",800},{"FileCost",900},{"CostFinalize",1000},{"InstallValidate",1400},{"InstallInitialize",1500},{"ProcessComponents",1600},{"UnpublishFeatures",1800},{"RemoveRegistryValues",2600},{"WriteRegistryValues",5000},{"RegisterUser",6000},{"RegisterProduct",6100},{"PublishFeatures",6300},{"PublishProduct",6400},{"InstallFinalize",6600}})
                Sql($"INSERT INTO `InstallExecuteSequence` (`Action`,`Sequence`) VALUES ('{action.Key}',{action.Value})");
            ((dynamic)db).Commit();summary=((dynamic)db).SummaryInformation(6);
            ((dynamic)summary).Property[7]="x64;1033";((dynamic)summary).Property[9]="{"+Guid.NewGuid()+"}";((dynamic)summary).Property[14]=500;((dynamic)summary).Property[15]=2;((dynamic)summary).Persist();((dynamic)db).Commit();
        }
        finally{if(summary is not null)Marshal.FinalReleaseComObject(summary);if(db is not null)Marshal.FinalReleaseComObject(db);if(engine is not null)Marshal.FinalReleaseComObject(engine);}
    }
}
