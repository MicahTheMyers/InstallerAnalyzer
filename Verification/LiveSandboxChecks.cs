using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class LiveSandboxChecks
{
    private static readonly string Wsb = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "wsb.exe");
    private static string Command(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo { FileName = Wsb, Arguments = arguments, UseShellExecute = false,
            CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true })!;
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15000)) { try { process.Kill(true); } catch { } throw new TimeoutException("Sandbox CLI command timed out."); }
        if (process.ExitCode != 0) throw new InvalidOperationException(error.GetAwaiter().GetResult());
        return output.GetAwaiter().GetResult();
    }
    private static string[] EnvironmentIds()
    {
        using var json = JsonDocument.Parse(Command("list --raw"));
        var environments = json.RootElement.GetProperty("WindowsSandboxEnvironments");
        return System.Text.RegularExpressions.Regex.Matches(environments.GetRawText(), @"[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}")
            .Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
    public static int Run(string root, string installerPath, TimeSpan? budget = null, bool requirePropertySnapshot = false, string? archiveEntry = null)
    {
        Directory.CreateDirectory(root);
        var before = EnvironmentIds();
        if (before.Length > 0) throw new InvalidOperationException("An existing Sandbox is running. It has not been stopped; live verification requires a fresh isolated session.");
        var database = typeof(InstallerCatalogService).GetField("TestDatabasePath", BindingFlags.NonPublic | BindingFlags.Static)!;
        var previousDb = database.GetValue(null);
        database.SetValue(null, Path.Combine(root, "live-fixture-catalog.db"));
        SandboxIssSession? session = null;
        try
        {
            InstallerArchive? archive = null;
            if (archiveEntry is not null)
                archive = InstallerArchive.Inspect(installerPath, archiveEntry, Path.Combine(root, "Inspection"), out installerPath);
            var installer = new InstallerDetector().Analyze(installerPath);
            installer.Archive = archive;
            Console.WriteLine("Installer: " + Path.GetFileName(installerPath) + "; hash " + installer.Identity.Sha256);
            session = SandboxIssRecorder.Start(installerPath, installer.Kind, false, installer.SuggestedArguments, "", true, true, archive: archive);
            Console.WriteLine("Fresh Sandbox launched; session " + session.SessionFolder);
            var start = DateTime.UtcNow; string previousStage = "";
            while (DateTime.UtcNow - start < (budget ?? TimeSpan.FromMinutes(14)))
            {
                Thread.Sleep(2000);
                var source = File.Exists(session.CheckpointPath) ? session.CheckpointPath : session.AnalysisPath;
                if (File.Exists(source))
                    try
                    {
                        using var json = JsonDocument.Parse(AnalysisArtifactReader.ReadText(source));
                        if (json.RootElement.TryGetProperty("WorkflowStage", out var stage) && stage.GetString() is { } current && current != previousStage)
                        { Console.WriteLine(current); previousStage = current; }
                    }
                    catch (Exception ex) when (ex is JsonException or IOException) { /* Checkpoint replacement is transient; retain the previous stage and retry. */ }
                if (File.Exists(session.CompleteFlagPath) && File.Exists(session.AnalysisPath)) break;
                if (DateTime.UtcNow - start > TimeSpan.FromMinutes(2) && !File.Exists(session.HeartbeatPath))
                    throw new TimeoutException("Sandbox did not produce a startup heartbeat within two minutes.");
            }
            foreach (var file in Directory.EnumerateFiles(session.OutputFolder))
                try { File.Copy(file, Path.Combine(root, Path.GetFileName(file)), true); }
                catch (IOException) when (!Path.GetFileName(file).Equals("install-analysis.json", StringComparison.OrdinalIgnoreCase)) { /* Optional live logs can still be in use. */ }
            if (!File.Exists(session.AnalysisPath)) throw new TimeoutException("No final analysis was returned.");
            var proof = JsonSerializer.Deserialize<InstallAnalysis>(AnalysisArtifactReader.ReadText(session.AnalysisPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            IntelligenceReportService.Enrich(proof, installer, root);
            IntelligenceReportService.WriteArtifacts(proof, installer, root);
            File.WriteAllText(Path.Combine(root, "enriched-analysis.json"), JsonSerializer.Serialize(proof, new JsonSerializerOptions { WriteIndented = true }));
            if (!LifecycleValidationService.IsComplete(proof)) throw new Exception("Lifecycle failed: " + proof.ValidationError);
            Console.WriteLine("PASS fresh install, initial removal, clean reinstall, final uninstall and final absence");
            if (requirePropertySnapshot)
            {
                if (!proof.MsiPropertySnapshots.Any(s=>s.Properties.Any(p=>p.Property=="VersionNT" && p.IsSet==true)))
                    throw new Exception("No attributed terminal MSI VersionNT observation was captured.");
                using var raw = JsonDocument.Parse(AnalysisArtifactReader.ReadText(session.AnalysisPath));
                if (!raw.RootElement.TryGetProperty("PrerequisiteServices",out _)) throw new Exception("Guest service collector output missing.");
                if (!File.Exists(Path.Combine(root,"msi-property-observations.json")) || !File.Exists(Path.Combine(root,"prerequisite-services.json")))
                    throw new Exception("New prerequisite artifacts missing.");
                Console.WriteLine("PASS actual MSI terminal property attribution, guest service collector wiring and normalized artifacts");
            }
            if (!proof.DetectionStrategies.Any(d => d.Validated)) throw new Exception("No independently validated detection strategy was captured.");
            Console.WriteLine("PASS independently validated detection: " + string.Join(", ", proof.DetectionStrategies.Where(d => d.Validated).Select(d => d.Type)));
            if (proof.ProcessTree.Count == 0) throw new Exception("No installer process evidence was collected.");
            Console.WriteLine("PASS installer-scoped process observations: " + proof.ProcessTree.Count);
            if (!proof.SilentStrategyAttempts.Any(a => a.StartedAt is not null && a.CompletedAt is not null)) throw new Exception("Attempt timestamps are missing.");
            Console.WriteLine("PASS timestamped strategy attempts");
            if (archive is not null)
            {
                if (!archive.SupportsDeployment(proof)) throw new Exception("The lifecycle did not bind the validated ZIP to its selected installer.");
                var entry = proof.NewUninstallEntries.Single(e => e.Key == proof.PrimaryKey);
                ImmyBotPackageExporter.Export(Path.Combine(root, "ImmyBot.zip"), installerPath, null, null, archive: archive, proof: proof);
                DattoRmmDeploymentService.Export(Path.Combine(root, "DattoRMM.zip"), installer, entry, proof, null);
                File.WriteAllText(Path.Combine(root, "ImmyBot-install.ps1"), ImmyBotScriptGenerator.Generate(installer, installer.SuggestedArguments, "ZIP fixture", proof));
                Console.WriteLine("PASS ImmyBot and Datto RMM exports retain the ZIP validated in Sandbox");
                return 0;
            }
            if (!InstallerCatalogService.Remember(installer, proof, "Live verification")) throw new Exception("Fresh lifecycle did not enter the isolated test catalog.");
            var record = InstallerCatalogService.ReadCatalog().Single();
            if (record.Detection?.Validated != true || record.History.Count != 1) throw new Exception("Catalog did not retain fresh detection evidence and history.");
            Console.WriteLine("PASS isolated catalog retained validated detection and per-proof history");
            Console.WriteLine("RESULT: live Sandbox verification passed");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            File.WriteAllText(Path.Combine(root, "verification-error.json"), JsonSerializer.Serialize(new { Type = ex.GetType().Name, ex.Message, SourceSession = session?.SessionFolder }));
            if (session is not null)
                foreach (var file in Directory.EnumerateFiles(session.OutputFolder))
                    try { File.Copy(file, Path.Combine(root, Path.GetFileName(file)), true); } catch { }
            return 1;
        }
        finally
        {
            database.SetValue(null, previousDb);
            foreach (var id in EnvironmentIds().Except(before, StringComparer.OrdinalIgnoreCase))
                try { Console.WriteLine(Command("stop --id " + id)); } catch (Exception ex) { Console.WriteLine("Sandbox cleanup warning: " + ex.Message); }
        }
    }
}

