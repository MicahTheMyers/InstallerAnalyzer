using System.IO;
using System.IO.Compression;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class MsiPropertyChecks
{
    public static void Run(string root,Action<bool,string> check)
    {
        const string code="{DA52A36C-7890-478B-AB4A-B6C28549D747}";
        var metadata=new MsiMetadata {ProductCode=code,HiddenProperties=["PRIVATE_FLAG"],LaunchConditions=[
            new(){Condition="VersionNT >= 600 AND RUNTIME_RELEASE >= 10",Description="OS and declared runtime"},
            new(){Condition="NOT Installed"},new(){Condition="PRIVATE_FLAG"},new(){Condition="API_TOKEN"},new(){Condition="NOT EMPTY"}]};
        string Dump(string content,string product=code,bool finish=true) => "Property(S): ProductCode = "+product+"\r\n"+content+(finish?"MSI (s) (01:02) [10:00:00:000]: MainEngineThread is returning 0\r\n":"");
        const string values="Property(S): VersionNT = 603\r\nProperty(S): RUNTIME_RELEASE = 14\r\nProperty(S): PRIVATE_FLAG = private-value-never-export\r\nProperty(S): API_TOKEN = token-never-export\r\nProperty(S): EMPTY = \r\n";
        var snapshot=MsiLogPropertyService.Parse(Dump(values),metadata).Single();
        check(snapshot.Conditions[0].Result==true,"Terminal MSI property observations resolve known numeric prerequisite expressions");
        check(snapshot.Conditions[1].Result is null,"Missing Installed in a terminal dump is unknown rather than inherited from the earlier product baseline");
        check(snapshot.Conditions[2].Result is null && snapshot.Conditions[3].Result is null,"Hidden and sensitive-name properties remain unbound even when a log exposes values");
        check(snapshot.Conditions[4].Result==true,"An explicitly empty terminal property remains distinct from an unreported property");
        check(snapshot.Conditions.All(c=>c.Scope.Contains("not launch-time")),"Terminal property condition results retain their phase boundary");
        var json=JsonSerializer.Serialize(snapshot);
        check(!json.Contains("private-value-never-export") && !json.Contains("token-never-export") && !json.Contains(" = 603"),"Normalized MSI property evidence retains no raw property values");
        check(MsiLogPropertyService.Parse(Dump(values,product:"{11111111-1111-1111-1111-111111111111}"),metadata).Single().Properties.Count==0,"A different product cannot contribute MSI property bindings");
        check(MsiLogPropertyService.Parse(Dump(values,finish:false),metadata).Single().Properties.Count==0,"A truncated terminal property block contributes no bindings");
        check(MsiLogPropertyService.Parse(Dump(values+"unrecognized continuation\r\n"),metadata).Single().Properties.Count==0,"Multiline/unsupported log continuation invalidates the property block");
        check(MsiLogPropertyService.Parse(Dump(values+"Property(S): ProductCode = "+code+"\r\n"),metadata).Single().Properties.Count==0,"Duplicated package identity invalidates property attribution");
        check(MsiLogPropertyService.Parse(Dump(values+"Property(S): RUNTIME_RELEASE = 99\r\n"),metadata).Single().Conditions[0].Result is null,"Duplicate property records are ambiguous rather than last-value-wins");
        check(MsiLogPropertyService.Parse(Dump(values+"Property(S): MsiHiddenProperties = RUNTIME_RELEASE\r\n"),metadata).Single().Conditions[0].Result is null,"Runtime hidden-property declarations suppress bindings");
        check(MsiLogPropertyService.Parse(Dump(values+"Property(S): MsiHiddenProperties = *****\r\n"),metadata).Single().Properties.All(p=>p.IsSet is null),"Masked hidden-property lists cause all values to remain withheld");
        metadata.HiddenPropertiesTruncated=true;
        check(MsiLogPropertyService.Parse(Dump(values),metadata).Single().Properties.All(p=>p.IsSet is null),"Truncated metadata hidden-property lists cannot expose later hidden values");metadata.HiddenPropertiesTruncated=false;
        check(MsiLogPropertyService.Parse(Dump(values.Replace("RUNTIME_RELEASE = 14","RUNTIME_RELEASE = *****")),metadata).Single().Conditions[0].Result is null,"Masked values never become condition operands");
        check(MsiLogPropertyService.Parse(Dump(values.Replace("RUNTIME_RELEASE = 14","RUNTIME_RELEASE = "+new string('1',4097))),metadata).Single().Conditions[0].Result is null,"Oversized property values remain unknown");
        check(MsiLogPropertyService.Parse("Property(C): ProductCode = "+code+"\nProperty(C): VersionNT = 603\n",metadata).Single().Properties.Count==0,"Client-side properties are not merged into a server snapshot");
        check(MsiLogPropertyService.Parse(new string('x',4*1024*1024+1),metadata).Single().Properties.Count==0,"Property log input has a bounded read budget");
        var folder=Path.Combine(root,"msi-property-artifacts");Directory.CreateDirectory(folder);File.WriteAllText(Path.Combine(folder,"msi-install.log"),Dump(values));
        var installer=new AnalysisResult();installer.Identity.Msi=metadata;
        var proof=new InstallAnalysis {MsiProductStateBefore=-1,PrerequisiteServices=[new(){Name="FixtureSvc",Property="RUNTIME_RELEASE",Present=false,State="Not found",Evidence="SCM read-only observation"}]};
        IntelligenceReportService.Enrich(proof,installer,folder);IntelligenceReportService.WriteArtifacts(proof,installer,folder);
        check(proof.MsiConditions[1].Result==true && proof.MsiPropertySnapshots.Single().Conditions[1].Result is null,"Initial product-state and terminal log evaluations remain separate through report enrichment");
        check(proof.Intelligence.Prerequisites.Any(p=>p.Status=="Service not found; requirement unestablished") && !proof.PrerequisiteServices[0].RequirementEstablished,"Service absence alone does not establish a missing requirement");
        check(!File.ReadAllText(Path.Combine(folder,"msi-property-observations.json")).Contains("private-value-never-export") && IntelligenceReportService.Generate(installer,proof).Contains("Condition in terminal log context"),"Property evidence artifacts and readable reports carry scoped results without raw values");
        var zip=Path.Combine(root,"msi-property-diagnostics.zip");DiagnosticBundleService.Export(zip,[new(){Installer="Fixture.msi",ArtifactFolder=folder}]);
        using var archive=ZipFile.OpenRead(zip);
        check(archive.Entries.Any(e=>e.FullName.EndsWith("msi-property-observations.json")) && archive.Entries.Any(e=>e.FullName.EndsWith("prerequisite-services.json")),"Diagnostic exports include property and service evidence");
        check(MsiLogPropertyService.Read(Path.Combine(folder,"not-present.log"),metadata).Single().Properties.Count==0,"Unavailable property logs cannot create observations");
    }
}
