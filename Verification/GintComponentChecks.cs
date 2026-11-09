using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;
using InstallerAnalyzer;
using System.Windows.Controls;

internal static class GintComponentChecks
{
    public static int PrepareDatto(string root, string installer, string evidence)
    {
        DattoRmmLiveChecks.Prepare(root, installer, evidence);
        var input = Path.Combine(root, "Input");
        var helpers = string.Join("\n", new[] { "NetFx3ProvisioningScript", "GintPrerequisiteScript", "SandboxCompatibilityScript" }.Select(name => (string)typeof(SandboxIssRecorder).GetField(name, BindingFlags.Static | BindingFlags.NonPublic)!.GetRawConstantValue()!));
        File.WriteAllText(Path.Combine(input, "helper.ps1"), helpers);
        NetFx3SandboxSource.Stage(input);
        Console.WriteLine("Prepared exported gINT Datto kit and separate disposable-guest Windows feature setup.");
        return 0;
    }
    public static int Live(string root, string installer)
    {
        var wsb = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "wsb.exe");
        string[] Ids()
        {
            using var process = Process.Start(new ProcessStartInfo(wsb, "list --raw") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
            var output = process.StandardOutput.ReadToEnd(); process.WaitForExit(); if (process.ExitCode != 0) throw new IOException("Sandbox inventory failed.");
            using var json = JsonDocument.Parse(output); return json.RootElement.GetProperty("WindowsSandboxEnvironments").EnumerateArray().Select(e => e.GetProperty("Id").GetString()!).ToArray();
        }
        if (Ids().Length != 0) throw new InvalidOperationException("Existing Sandbox left untouched.");
        string? owned = null;
        try
        {
            var detected = new InstallerDetector().Analyze(installer);
            var session = SandboxIssRecorder.Start(installer, detected.Kind, false, "/qn /norestart", "", true, true, true, true);
            File.WriteAllText(Path.Combine(root, "session-path.txt"), session.SessionFolder);
            var end = DateTime.UtcNow.AddMinutes(35); string? stage = null;
            while (DateTime.UtcNow < end)
            {
                if (owned is null) { var ids = Ids(); if (ids.Length > 1) throw new IOException("Ambiguous Sandbox ownership."); if (ids.Length == 1) owned = ids[0]; }
                if (File.Exists(session.CheckpointPath)) try { using var json = JsonDocument.Parse(File.ReadAllText(session.CheckpointPath)); var current = json.RootElement.GetProperty("WorkflowStage").GetString(); if (stage != current) { stage = current; Console.WriteLine(stage); } } catch { }
                if (File.Exists(session.CompleteFlagPath)) break;
                Thread.Sleep(1000);
            }
            var proof = JsonSerializer.Deserialize<InstallAnalysis>(File.ReadAllText(session.AnalysisPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            File.Copy(session.AnalysisPath, Path.Combine(root, "install-analysis.json"));
            if (!LifecycleValidationService.IsComplete(proof) || !GintDeploymentPlanService.IsCanonical(proof.ComponentDeployment)) throw new IOException("Component lifecycle failed: " + proof.ValidationError);
            var entry = proof.NewUninstallEntries.Single(e => e.Key == proof.PrimaryKey);
            DattoRmmDeploymentService.Export(Path.Combine(root, "gINT-DattoRMM.zip"), detected, entry, proof, session.OutputFolder);
            File.WriteAllText(Path.Combine(root, "acceptance.json"), JsonSerializer.Serialize(new { Passed = true, proof.ComponentDeployment, proof.SandboxCompatibility, proof.RebootRequired, DattoTenantValidated = false }));
            Console.WriteLine("PASS production gINT component lifecycle and Datto kit export"); return 0;
        }
        finally
        {
            if (owned is not null && Ids().Contains(owned)) { using var stop = Process.Start(new ProcessStartInfo(wsb, "stop --id " + owned) { UseShellExecute = false, CreateNoWindow = true }); stop?.WaitForExit(15000); }
        }
    }

    public static void Run(MainWindow window, string root, Action<bool,string> check)
    {
        var plan = GintDeploymentPlanService.Canonical();
        check(GintDeploymentPlanService.IsCanonical(plan), "gINT component recipe matches its tested source and all attachments");
        plan.Files["gINT.msi"] = new string('0',64);
        check(!GintDeploymentPlanService.IsCanonical(plan), "Changed component attachment evidence is rejected");
        plan = GintDeploymentPlanService.Canonical(); plan.Files["../extra.exe"] = new string('0',64);
        check(!GintDeploymentPlanService.IsCanonical(plan), "Unexpected and traversal attachment names are rejected");
        var path = Path.Combine(root, "inert-gint.exe"); File.WriteAllText(path, "Never execute; export binding refusal fixture");
        var source = new AnalysisResult { FilePath = path, Kind = InstallerKind.Bootstrapper };
        var key = @"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + GintDeploymentPlanService.ProductCode;
        var entry = new UninstallEntry { Key = key, DisplayName = "gINT CONNECT Edition 10.02.00.04", ProductCode = GintDeploymentPlanService.ProductCode };
        var proof = new InstallAnalysis { ComponentDeployment = GintDeploymentPlanService.Canonical(), ValidationSchemaVersion = 3, EvidenceCollectionComplete = true, InitialInstallValidated = true, InitialUninstallValidated = true, InitialUninstallExitCode = 0, CleanBaselineVerified = true, SilentReinstallValidated = true, SilentReinstallExitCode = 0, SilentUninstallValidated = true, SilentUninstallExitCode = 0, PostUninstallDetected = false, DiscoverySucceeded = true, PrimaryKey = key, CapturedAt = DateTimeOffset.UtcNow.ToString("o"), InstallerSha256 = GintDeploymentPlanService.SourceHash, CombinedSilentArguments = "/qn /norestart", DeploymentSource = "gINT.msi", UninstallCandidate = "msiexec.exe /x " + GintDeploymentPlanService.ProductCode + " /qn /norestart", NewUninstallEntries = new() { entry }, DetectionStrategies = new() { new() { Type = "UninstallRegistryKey", RegistryPath = key, BeforeInstall = false, AfterInstall = true, AfterUninstall = false, Rank = 90 } } };
        proof.NetFx3Provisioning.Evidence = "gINT requires .NET 3.5";
        check(DattoRmmDeploymentService.BlockReason(source, entry, proof, null) is null, "Validated gINT plan covers extracted payload and target prerequisite planning");
        var scripts = DattoRmmDeploymentService.Generate(source, entry, proof, null);
        check(scripts.Install.Contains("/FeatureName:NetFx3") && scripts.Install.Contains("Invoke-IAGintPrerequisites"), "gINT export includes feature preparation and ordered prerequisite installation");
        check(!scripts.Component.Contains("VerifiedAndReputablePolicyState") && !scripts.Component.Contains("CiTool.exe"), "Datto recipe never changes target execution security policies");
        var existing = Path.Combine(root, "existing-gint-kit.zip"); File.WriteAllText(existing, "preserve this existing export");
        bool refused = false;
        try { DattoRmmDeploymentService.Export(existing, source, entry, proof, null); } catch (InvalidDataException) { refused = true; }
        check(refused && File.ReadAllText(existing) == "preserve this existing export", "Source bytes inconsistent with recipe proof cannot replace an existing component kit");
        proof.ValidationSchemaVersion = 1;
        check(DattoRmmDeploymentService.BlockReason(source, entry, proof, null) is not null, "Legacy proof cannot be promoted into component-recipe acceptance");
        proof.ValidationSchemaVersion = 3;
        var fields = new[] { "_result", "_installAnalysis", "_selectedUninstallEntry" }.Select(n => typeof(MainWindow).GetField(n, BindingFlags.NonPublic | BindingFlags.Instance)!).ToArray();
        var previous = fields.Select(f => f.GetValue(window)).ToArray();
        var target = (ComboBox)window.FindName("DeploymentTargetBox"); int previousTarget = target.SelectedIndex;
        try
        {
            fields[0].SetValue(window, source); fields[1].SetValue(window, proof); fields[2].SetValue(window, entry);
            typeof(MainWindow).GetMethod("ShowPage", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, new[] { window.FindName("DattoPage") });
            ((ComboBox)window.FindName("DattoScriptKindBox")).SelectedIndex = 1;
            var box = (RichTextBox)window.FindName("DattoScriptBox");
            check(((Button)window.FindName("DattoExportButton")).IsEnabled && new System.Windows.Documents.TextRange(box.Document.ContentStart, box.Document.ContentEnd).Text.Contains("Invoke-IAGintPrerequisites"), "Deployment UI enables complete gINT recipe export and previews the prerequisite script");
        }
        finally
        {
            for (int i = 0; i < fields.Length; i++) fields[i].SetValue(window, previous[i]);
            target.SelectedIndex = previousTarget;
            typeof(MainWindow).GetMethod("ShowPage", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, new[] { window.FindName("AnalyzePage") });
        }
        proof.ComponentDeployment = null;
        check(DattoRmmDeploymentService.BlockReason(source, entry, proof, null) is not null, "Generic extracted payload and feature requirements remain gated without a validated recipe");
        File.WriteAllText(Path.Combine(root, "gint-datto-component.ps1"), scripts.Component);
    }
}
