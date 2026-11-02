using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class NetFx3Checks
{
    public static void Run(string root, Action<bool,string> check)
    {
        check(NetFx3RequirementService.IsExplicitRequirement("This app requires Microsoft .NET Framework 3.5."), "NetFx3 explicit requirement recognized");
        foreach (var text in new[] { "Missing DLL 0xc0000135", ".NET Framework 4.8 is required", ".NET Framework 3.5 is optional", ".NET Framework 3.5 is not required" })
            check(!NetFx3RequirementService.IsExplicitRequirement(text), "NetFx3 does not infer requirement from: " + text);
        var metadata = new MsiMetadata { LaunchConditions = new() { new() { Description = "This app requires .NET Framework 3.5", Condition = "NETFRAMEWORK35" } } };
        check(NetFx3RequirementService.Detect("not-a-file", metadata).StartsWith("MSI LaunchCondition:"), "NetFx3 declared MSI preflight evidence is retained");
        var managed = Path.Combine(root,"clr2-fixture.exe");
        var tables = new MetadataBuilder();
        tables.AddModule(0, tables.GetOrAddString("Fixture"), tables.GetOrAddGuid(Guid.NewGuid()), default, default);
        var image = new ManagedPEBuilder(new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(tables,"v2.0.50727"),new BlobBuilder());
        var bytes = new BlobBuilder(); image.Serialize(bytes); File.WriteAllBytes(managed,bytes.ToArray());
        check(NetFx3RequirementService.Detect(managed,new()).Contains("CLR v2.0"), "Managed CLR2 metadata establishes NetFx3 preflight requirement without executing installer");
        File.WriteAllText(managed+".config","<configuration><startup><supportedRuntime version=\"v4.0\"/></startup></configuration>");
        check(NetFx3RequirementService.Detect(managed,new()) == "", "CLR4 runtime configuration prevents unnecessary CLR2 provisioning");
        var proof = new InstallAnalysis { NetFx3Provisioning = new() { RequiresFullWindowsVM = true, Detail = "A full Windows VM is required" }, SilentReinstallUiDetected = true };
        var failure = FailureClassificationService.Classify("FAIL", "Installer UI", proof, "Sandbox lifecycle");
        check(failure.Category == FailureCategory.PrerequisiteMissing && failure.Owner == "Environment" && failure.Explanation.Contains("full Windows VM"), "NetFx3 environment failure takes precedence over prerequisite UI");
        var blocked = new InstallAnalysis { NetFx3Provisioning = new() { Blocked=true, Detail="Microsoft feature source unavailable", ExitCode=12006 } };
        var blockedFailure=FailureClassificationService.Classify("FAIL","source failed",blocked,"Sandbox lifecycle");
        check(blockedFailure.Category==FailureCategory.PrerequisiteMissing && blockedFailure.Owner=="Environment" && blockedFailure.ExitCode==12006 && !blockedFailure.NextInvestigation.Contains("full Windows VM"), "Recoverable Sandbox provisioning failure does not require a second VM backend");
        proof.NetFx3Provisioning.RestartNeeded = true;
        check(FailureClassificationService.Classify("FAIL", "Missing runtime", proof, "Sandbox lifecycle").Category == FailureCategory.RebootRequired, "NetFx3 restart-needed is not installation success");
        check(FailureClassificationService.Classify("PASS", "passed", proof, "Sandbox lifecycle").Category == FailureCategory.None, "Final lifecycle pass still takes precedence over earlier prerequisite evidence");
        var resolved = new InstallAnalysis { NetFx3Provisioning = new() { Status = "Provisioned", Provisioned = true, RuntimeVerified = true },
            UiTextEvidence = new() { new() { Labels = new() { "Error: .NET Framework 3.5 is required and missing" } } } };
        IntelligenceReportService.Enrich(resolved,null,null);
        check(!resolved.Intelligence.Prerequisites.Any(p => p.Capability == "NetFx3" && p.Status == "Required / missing evidence"), "Verified provisioning resolves earlier missing-runtime UI evidence");
        var script = (string)typeof(SandboxIssRecorder).GetField("NetFx3ProvisioningScript", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!;
        File.WriteAllText(Path.Combine(root,"netfx3-helper.ps1"), script);
        check(script.Contains("/NoRestart") && script.Contains("'netfx3-install.txt' 600") && script.Contains("$script:NetFx3Attempted"), "NetFx3 servicing has bounded execution and no automatic reboot");
        var windows = Path.Combine(root,"fake-windows"); var winsxs = Path.Combine(windows,"WinSxS");
        var component = "x86_microsoft-windows-wpfcorecomp.resources_31bf3856ad364e35_10.0.26100.1_en-us_52e904ed407f5d73";
        Directory.CreateDirectory(Path.Combine(winsxs,component)); Directory.CreateDirectory(Path.Combine(winsxs,"Manifests"));
        File.WriteAllText(Path.Combine(winsxs,component,"fixture.mui"),"inert component data");
        File.WriteAllText(Path.Combine(winsxs,"Manifests",component+".manifest"),"inert metadata");
        Directory.CreateDirectory(Path.Combine(winsxs,"unrelated-private-data"));
        File.WriteAllText(Path.Combine(winsxs,"unrelated-private-data","secret.txt"),"must not stage");
        var field = typeof(NetFx3SandboxSource).GetField("TestWindowsFolder",BindingFlags.NonPublic|BindingFlags.Static)!;
        var previous = field.GetValue(null); var staged = Path.Combine(root,"netfx3-source-fixture");
        try { field.SetValue(null,windows); NetFx3SandboxSource.Stage(staged); }
        finally { field.SetValue(null,previous); }
        check(File.Exists(Path.Combine(staged,"NetFx3RepairSource",component,"fixture.mui")) && !Directory.Exists(Path.Combine(staged,"NetFx3RepairSource","unrelated-private-data")), "Sandbox source staging copies only matching Windows .NET components");
        using var source = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(staged,"NetFx3RepairSource","source-manifest.json")));
        check(source.RootElement.GetProperty("Entries").GetArrayLength()==1 && source.RootElement.GetProperty("Entries")[0].GetProperty("Files")[0].GetProperty("Sha256").GetString()!.Length==64, "Sandbox staged components have bounded manifest and file hashes");
    }
}
