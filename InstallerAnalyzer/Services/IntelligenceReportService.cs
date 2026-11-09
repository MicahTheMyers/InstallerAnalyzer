using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class IntelligenceReportService
{
    private static readonly (string Name, string Pattern, string? Capability)[] Runtimes =
    [
        (".NET Framework 3.5", @"(?i)NetFx3|NETFRAMEWORK35|\.NET Framework\s*3\.5", "NetFx3"),
        (".NET Framework 4.x", @"(?i)\.NET Framework\s*4(?:\.\d+)*", null),
        (".NET Desktop Runtime", @"(?i)\.NET (?:Windows )?Desktop Runtime|Microsoft\.WindowsDesktop\.App", null),
        ("Visual C++ Redistributable", @"(?i)Visual C\+\+|vc_redist|vcruntime\d+|msvcp\d+", null),
        ("WebView2 Runtime", @"(?i)WebView2(?: Runtime)?", null),
        ("Java Runtime", @"(?i)Java (?:Runtime|Development)|\bJRE\b|\bJDK\b", null),
        ("DirectX components", @"(?i)DirectX|d3dx9_\d+", null)
    ];

    public static void Enrich(InstallAnalysis? proof, AnalysisResult? installer, string? folder)
    {
        if (proof is null) return;
        var report = new InstallerIntelligence();
        if (proof.NetFx3Provisioning.Status != "Not required")
            report.Prerequisites.Add(new() { Name = ".NET Framework 3.5", Capability = "NetFx3", Status = proof.NetFx3Provisioning.Status,
                Provisioned = proof.NetFx3Provisioning.Provisioned, Source = "Guest command-line prerequisite step",
                Evidence = AiDiagnosticContext.Redact(proof.NetFx3Provisioning.Evidence + " — " + proof.NetFx3Provisioning.Detail) });
        report.InstalledProducts = BundledProductClassificationService.Classify(installer, proof);
        if (installer is not null && folder is not null)
        {
            var propertyLog = Path.Combine(folder,"msi-install.log");
            if (File.Exists(propertyLog)) proof.MsiPropertySnapshots = MsiLogPropertyService.Read(propertyLog,installer.Identity.Msi);
        }
        var conditionInputs = new Dictionary<string, string?>(StringComparer.Ordinal);
        if (proof.MsiProductStateBefore is -1 or 5) conditionInputs["Installed"] = proof.MsiProductStateBefore == 5 ? "1" : null;
        proof.MsiConditions = installer?.Identity.Msi.LaunchConditions.Select(c =>
        {
            var observation = MsiConditionEvaluator.Evaluate(c.Condition, conditionInputs);
            observation.Description = c.Description; return observation;
        }).ToList() ?? new();
        if (installer is not null)
            foreach (var condition in installer.Identity.Msi.LaunchConditions)
            {
                var runtime = Runtimes.FirstOrDefault(r => Regex.IsMatch(condition.Condition + " " + condition.Description, r.Pattern));
                report.Prerequisites.Add(new() { Name = string.IsNullOrWhiteSpace(runtime.Name) ? "Declared MSI condition" : runtime.Name,
                    Capability = runtime.Capability, Status = "Declared; not evaluated", Source = "MSI LaunchCondition table",
                    Evidence = AiDiagnosticContext.Redact(condition.Condition + " — " + condition.Description) });
            }
        foreach (var service in proof.PrerequisiteServices)
            report.Prerequisites.Add(new() { Name = "Declared service probe: " + service.Name,
                Status = service.Present == true ? "Service observed: " + service.State : service.Present == false ? "Service not found; requirement unestablished" : "Service observation unavailable",
                Source = "Sandbox local service query; MSI property " + service.Property,
                Evidence = AiDiagnosticContext.Redact(service.Evidence) });
        foreach (var probe in proof.PrerequisiteProbes)
        {
            var runtime = Runtimes.FirstOrDefault(r => Regex.IsMatch(probe.Property + " " + probe.ConditionDescription + " " + probe.Target, r.Pattern));
            report.Prerequisites.Add(new() { Name = string.IsNullOrWhiteSpace(runtime.Name) ? "MSI prerequisite probe: " + probe.Property : runtime.Name + " (MSI probe)",
                Capability = runtime.Capability,
                Status = probe.ValuePresent == true ? "Registry value present; condition not evaluated" : probe.ValuePresent == false ? "Registry value absent; condition not evaluated" : "Observation unavailable",
                Source = "Sandbox " + probe.RegistryView + " probe", Evidence = AiDiagnosticContext.Redact(probe.Target + " — " + probe.ConditionDescription + " — " + probe.Evidence) });
        }
        foreach (var probe in proof.PrerequisiteFiles)
            report.Prerequisites.Add(new() {
                Name = "MSI file criteria: " + probe.Property,
                Status = probe.Present == false ? "Path absent; condition not evaluated" : probe.Present == true
                    ? probe.SignatureMatched == true ? "Path present; file criteria match; condition not evaluated"
                    : probe.SignatureMatched == false ? "Path present; file criteria mismatch; condition not evaluated"
                    : "Path present; file criteria not evaluated" : "Observation unavailable",
                Source = "Sandbox " + probe.Phase + " " + probe.Kind + " probe",
                Evidence = AiDiagnosticContext.Redact(probe.Target + " — " + probe.ConditionDescription + " — " + probe.Evidence +
                    " — Version: " + probe.Version + "; size: " + probe.SizeBytes?.ToString()) });
        foreach (var dll in proof.DllFiles)
            report.Prerequisites.Add(new() { Name = dll.Module + " (" + dll.Kind + " import)",
                Status = dll.Present == true ? "File observed; loader resolution not established" : dll.Present == false ? "File not observed in this location; loader resolution unknown" : "Observation unavailable / loader contract",
                Source = "Sandbox before install: " + dll.Location + " / " + dll.Architecture,
                Evidence = AiDiagnosticContext.Redact(dll.Path + " — " + dll.Version + " — " + dll.Evidence) });
        var sources = new List<(string Source, string Text)> { ("Validation", proof.ValidationError ?? "") };
        sources.AddRange(proof.SilentStrategyAttempts.Select(a => ("Strategy attempt", (a.Outcome ?? "") + " " + string.Join(" ", a.VisibleWindows))));
        sources.Add(("Installer windows", string.Join("\n", proof.SilentReinstallVisibleWindows)));
        sources.Add(("Uninstaller windows", string.Join("\n", proof.SilentUninstallVisibleWindows)));
        sources.AddRange(proof.ProcessTree.Select(p => ("Installer child process", p.Name + " " + p.CommandLine)));
        sources.AddRange(proof.UiTextEvidence.Select(w => ("Installer-owned static UI labels", string.Join("\n", w.Labels))));
        if (folder is not null)
            foreach (var name in new[] { "msi-install.log", "msi-uninstall-initial.log", "msi-uninstall-final.log" })
                try
                {
                    var file = new FileInfo(Path.Combine(folder, name));
                    if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    // Limit input; do not block finalization on unbounded MSI logs.
                    using var input = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var reader = new StreamReader(input, Encoding.UTF8, true);
                    if (input.Length <= 256 * 1024) sources.Add((name, reader.ReadToEnd()));
                    else
                    {
                        var bom = new byte[2]; input.ReadExactly(bom); var unicode = bom[0] == 255 && bom[1] == 254;
                        input.Position = Math.Max(0, input.Length - 64 * 1024); if (unicode && input.Position % 2 != 0) input.Position++;
                        using var tail = new StreamReader(input, unicode ? Encoding.Unicode : Encoding.UTF8, false, 1024, true);
                        sources.Add((name, tail.ReadToEnd()));
                    }
                }
                catch { report.Limitations.Add(name + " unavailable; prerequisite evidence may be incomplete."); }
        foreach (var source in sources)
            foreach (var line in source.Text.Split('\n').Where(l => l.Length <= 4000))
                foreach (var runtime in Runtimes)
                    if (Regex.IsMatch(line, runtime.Pattern) && !report.Prerequisites.Any(p => p.Name == runtime.Name && p.Source == source.Source))
                    {
                        var negated = Regex.IsMatch(line, @"(?i)not (?:required|needed|missing)|does not require|no prerequisite|no missing");
                        var requirement = !negated && Regex.IsMatch(line, @"(?i)requires?|prerequisite");
                        var missing = !negated && (Regex.IsMatch(line, @"(?i)not (?:installed|found|available)|missing|must (?:first )?install|cannot (?:find|load)") ||
                            requirement && (source.Source == "Validation" || Regex.IsMatch(line, @"(?i)\berror\b|\bfailed\b|\bblocked\b")));
                        report.Prerequisites.Add(new() { Name = runtime.Name, Capability = runtime.Capability,
                            Status = runtime.Capability == "NetFx3" && proof.NetFx3Provisioning.RuntimeVerified ? "Earlier requirement; runtime now verified" : missing ? "Required / missing evidence" : requirement ? "Requirement indicated; absence not established" : "Observed; requirement not established",
                            Source = source.Source, Evidence = AiDiagnosticContext.Redact(line.Trim()[..Math.Min(line.Trim().Length, 600)]) });
                    }
        if (proof.InstallerExitCode == -1073741515 || proof.SilentStrategyAttempts.Any(a => a.ExitCode == -1073741515))
            report.Prerequisites.Add(new() { Name = "Unidentified DLL dependency", Status = "Missing", Source = "Process exit",
                Evidence = "0xC0000135. The missing DLL/runtime has not been identified; this does not specifically prove Visual C++ is missing." });

        report.Nodes.Add(new() { Id = "source", Role = "Deployment Source", Label = installer?.FileName ?? proof.Installer ?? "Original installer", Evidence = "User-selected source remains the deployment source." });
        report.Nodes.Add(new() { Id = "mechanism", Role = "Deployment Mechanism", Label = proof.DeploymentMechanism ?? "Undetermined", Evidence = proof.DiscoveryMethod ?? "No validated mechanism" });
        report.Edges.Add(new() { From = "source", To = "mechanism", Relationship = "Analysis discovered" });
        foreach (var process in proof.ProcessTree)
        {
            var id = ProcessNodeId(process);
            report.Nodes.Add(new() { Id = id, Role = "Bootstrapper", Label = process.Name, Evidence = "Observed in installer process tree; executable role may need review." });
            var parent = proof.ProcessTree.Where(p => p.ProcessId == process.ParentProcessId && string.CompareOrdinal(p.CreatedAt, process.CreatedAt) <= 0).OrderByDescending(p => p.CreatedAt).FirstOrDefault();
            if (parent is not null)
                report.Edges.Add(new() { From = ProcessNodeId(parent), To = id, Relationship = "Parent process at observation" });
            else report.Edges.Add(new() { From = "source", To = id, Relationship = "Tracked installer process" });
        }
        foreach (var path in proof.DiscoveredInstallerFiles.Concat(proof.PayloadTrace.Files.Select(f => f.Path)).Concat(proof.PayloadTrace.BitsDownloads.Select(d=>d.Path)).Distinct(StringComparer.OrdinalIgnoreCase).Take(120))
        {
            var file = Path.GetFileName(path); var extension = Path.GetExtension(path).ToLowerInvariant();
            var role = Regex.IsMatch(file, @"(?i)vc_redist|dotnet|webview2|directx|jre-?") ? "Prerequisite candidate" :
                Regex.IsMatch(file, @"(?i)^unins|uninstall") ? "Uninstaller" :
                Regex.IsMatch(file, @"(?i)update") ? "Updater" : extension is ".iss" or ".rsp" or ".response" ? "Response file candidate" :
                extension is ".config" or ".ini" ? "Configuration file candidate" :
                extension is ".msi" or ".msix" or ".appx" or ".msixbundle" or ".appxbundle" or ".msp" ? "Deployment payload candidate" :
                extension is ".cab" or ".zip" or ".7z" ? "Archive candidate" : "Unknown";
            var process = proof.ProcessTree.FirstOrDefault(p => ExecutesPayload(p, path));
            var downloadReference = proof.ProcessTree.FirstOrDefault(p => ReferencesDownloadOutput(p, path));
            var writes = proof.PayloadTrace.Files.Where(f => f.Operation == "Write completed" && f.Bytes > 0 &&
                string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase) && proof.ProcessTree.Any(p => p.ProcessId == f.ProcessId && SameBirth(p.CreatedAt, f.ProcessCreatedAt))).ToList();
            var networkWriters = writes.Where(f => proof.NetworkActivity.Any(n => n.ProcessId == f.ProcessId && SameBirth(n.ProcessCreatedAt, f.ProcessCreatedAt)))
                .Select(f => f.ProcessId).Distinct().ToList();
            var downloads = proof.PayloadTrace.BitsDownloads.Where(d=>string.Equals(d.Path,path,StringComparison.OrdinalIgnoreCase) &&
                proof.ProcessTree.Any(p=>p.ProcessId==d.ProcessId && SameBirth(p.CreatedAt,d.ProcessCreatedAt))).ToList();
            report.Payloads.Add(new() { Path = path, Type = extension.TrimStart('.'), Role = role, ProcessId = process?.ProcessId,
                Writes = writes, Downloads = downloads, NetworkActiveWriterProcessIds = networkWriters,
                Executed = process is null ? null : true,
                Evidence = (process is null ? "Observed during Sandbox analysis; execution not established." :
                    string.Equals(process.Path, path, StringComparison.OrdinalIgnoreCase) ? "Executable path matched an observed installer-tree process." : "MSI path matched the installation arguments of an observed system msiexec process.") +
                    (writes.Count > 0 ? " Completed writes attributed to " + writes.Count + " observed process lifetime(s)." : " Writing process unknown.") +
                    (networkWriters.Count > 0 ? " A writer also had an established TCP connection; file download is not established by that connection." : "") +
                    (downloads.Count > 0 ? " BITS download completion reported; requested origin and later file snapshot are separate observations." : ""),
                DownloadReferenceProcessId = downloadReference?.ProcessId,
                DownloadEvidence = downloadReference is null ? null : "Installer-process command text referenced this path as a download output. Command execution and download success are not independently established." });
            var id = "payload:" + report.Payloads.Count;
            report.Nodes.Add(new() { Id = id, Role = role == "Uninstaller" ? role : "Observed Payload", Label = file, Evidence = report.Payloads[^1].Evidence });
            report.Edges.Add(new() { From = process is null ? "source" : ProcessNodeId(process), To = id, Relationship = process is null ? "Observed during analysis" : "Executed payload" });
            foreach (var write in writes)
            {
                var writer = proof.ProcessTree.First(p => p.ProcessId == write.ProcessId && SameBirth(p.CreatedAt, write.ProcessCreatedAt));
                report.Edges.Add(new() { From = ProcessNodeId(writer), To = id, Relationship = "Completed file write (kernel trace)" });
            }
            foreach (var download in downloads)
            {
                var client = proof.ProcessTree.First(p=>p.ProcessId==download.ProcessId && SameBirth(p.CreatedAt,download.ProcessCreatedAt));
                report.Edges.Add(new() {From=ProcessNodeId(client),To=id,Relationship="BITS download completion reported"});
            }
        }
        foreach (var entry in proof.NewUninstallEntries)
        {
            var primary = !string.IsNullOrWhiteSpace(proof.PrimaryKey) && entry.Key == proof.PrimaryKey;
            var name = entry.DisplayName ?? "Unknown installed product";
            var assessment = report.InstalledProducts.FirstOrDefault(p => p.Identity == (entry.Key ?? "") && p.Name == name);
            var role = primary ? "Installed Application" : assessment?.DisplayRole ?? "Unknown secondary product";
            var id = "application:" + report.Nodes.Count;
            report.Nodes.Add(new() { Id = id, Role = role, Label = name, Evidence = "New installed identity in Sandbox. Secondary-product purpose is not automatically trusted." });
            report.Edges.Add(new() { From = "mechanism", To = id, Relationship = primary ? "Installs" : "Observed secondary installation" });
            if (primary && !string.IsNullOrWhiteSpace(proof.UninstallCandidate))
            {
                report.Nodes.Add(new() { Id = "uninstaller", Role = "Uninstaller", Label = proof.UninstallValidationMethod ?? "Discovered uninstall", Evidence = proof.SilentUninstallValidated ? "Silent removal validated" : "Candidate not fully validated" });
                report.Edges.Add(new() { From = id, To = "uninstaller", Relationship = "Removed by" });
            }
        }
        foreach (var component in proof.Components)
        {
            // A machine-wide delta alone does not establish that a service belongs to this product.
            if (component.Kind == "Service" && proof.DetectionStrategies.Any(d => d.Type == "ServiceAndExecutable" && d.Identity == component.Name) &&
                !proof.DetectionStrategies.Any(d => d.Type == "WindowsService" && d.Identity == component.Name))
                proof.DetectionStrategies.Add(new() { Type = "WindowsService", Identity = component.Name, Rank = 65,
                    BeforeInstall = component.BeforeInstall, AfterInstall = component.AfterInstall, AfterUninstall = component.AfterUninstall });
            var id = "component:" + report.Nodes.Count;
            report.Nodes.Add(new() { Id = id, Role = component.Kind, Label = component.Name, Evidence = $"Before / installed / removed presence: {component.BeforeInstall} / {component.AfterInstall} / {component.AfterUninstall}" });
            report.Edges.Add(new() { From = "mechanism", To = id, Relationship = "Appeared during installation; causality not independently proved" });
        }
        report.Limitations.Add("Payload timestamps and network connections do not prove which process downloaded a file or whether Internet access is required.");
        if (proof.PayloadScanIncomplete) report.Limitations.Add("Payload discovery reached a time, item, depth, link or access boundary. An unobserved payload is not evidence that none was created.");
        report.Limitations.Add("File trace: " + proof.PayloadTrace.Status + ". " + proof.PayloadTrace.Limitation);
        report.Limitations.Add("BITS job observations: " + proof.PayloadTrace.BitsObservationStatus + " Completion records and later file fingerprints do not establish redirected origins or network-to-file content integrity.");
        report.Limitations.Add("No prerequisites are automatically provisioned. No post-reboot or full driver validation is claimed.");
        proof.Intelligence = report;
    }

    private static bool ExecutesPayload(ProcessEvidence process, string path)
    {
        if (string.Equals(process.Path, path, StringComparison.OrdinalIgnoreCase)) return true;
        if (!Path.GetExtension(path).Equals(".msi", StringComparison.OrdinalIgnoreCase) ||
            !Regex.IsMatch(process.Path ?? "", @"(?i)^[A-Z]:\\Windows\\(?:System32|SysWOW64)\\msiexec\.exe$")) return false;
        var match = Regex.Match(process.CommandLine ?? "", "(?i)(?:^|\\s)/(?:i|package)\\s+(?:\"(?<path>[^\"]+)\"|(?<path>[^\\s\"]+))");
        return match.Success && string.Equals(match.Groups["path"].Value, path, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ReferencesDownloadOutput(ProcessEvidence process, string path)
    {
        string pattern;
        if (process.Name.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) || process.Name.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (!Regex.IsMatch(process.CommandLine ?? "", @"(?i)\bInvoke-(?:WebRequest|RestMethod)\b")) return false;
            pattern = "(?i)(?:^|\\s)-OutFile\\s+(?:\"(?<path>[^\"]+)\"|'(?<path>[^']+)'|(?<path>[^\\s;'\"]+))";
        }
        else if (process.Name.Equals("curl.exe", StringComparison.OrdinalIgnoreCase))
            pattern = "(?:^|\\s)(?:-o|--output)\\s+(?:\"(?<path>[^\"]+)\"|'(?<path>[^']+)'|(?<path>[^\\s;'\"]+))";
        else return false;
        var match = Regex.Match(process.CommandLine ?? "", pattern);
        return match.Success && string.Equals(match.Groups["path"].Value, path, StringComparison.OrdinalIgnoreCase);
    }

    private static string ProcessNodeId(ProcessEvidence process) => "process:" + process.ProcessId + ":" + process.CreatedAt;
    private static bool SameBirth(string? first, string? second) => DateTimeOffset.TryParse(first, out var a) && DateTimeOffset.TryParse(second, out var b) && Math.Abs((a - b).Ticks) <= TimeSpan.TicksPerMillisecond;

    public static void WriteArtifacts(InstallAnalysis proof, AnalysisResult? installer, string folder)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        void Save(string name, object value) => AnalysisArtifactWriter.Write(Path.Combine(folder, name), JsonSerializer.Serialize(value, options));
        Save("prerequisite-results.json", proof.Intelligence.Prerequisites);
        Save("netfx3-provisioning.json", proof.NetFx3Provisioning);
        Save("sandbox-compatibility.json", proof.SandboxCompatibility);
        if (proof.ComponentDeployment is not null) Save("component-deployment.json", proof.ComponentDeployment);
        Save("prerequisite-probes.json", proof.PrerequisiteProbes);
        Save("prerequisite-files.json", proof.PrerequisiteFiles);
        Save("dll-file-observations.json", proof.DllFiles);
        Save("msi-condition-observations.json", proof.MsiConditions);
        Save("msi-property-observations.json", proof.MsiPropertySnapshots);
        Save("prerequisite-services.json", proof.PrerequisiteServices);
        Save("runtime-environment.json", proof.RuntimeEnvironment);
        Save("installer-ui-text.json", proof.UiTextEvidence);
        Save("bundled-products.json", proof.Intelligence.InstalledProducts);
        Save("relationship-graph.json", new { proof.Intelligence.Nodes, proof.Intelligence.Edges });
        Save("strategy-attempts.json", proof.SilentStrategyAttempts);
        Save("detection-strategies.json", proof.DetectionStrategies);
        Save("component-evidence.json", proof.Components);
        Save("network-evidence.json", proof.NetworkActivity);
        Save("payload-file-activity.json", proof.PayloadTrace);
        Save("bits-file-mappings.json", proof.PayloadTrace.BitsMappings);
        Save("bits-download-evidence.json", proof.PayloadTrace.BitsDownloads);
        var outcome = LifecycleValidationService.IsComplete(proof) ? "PASS" : proof.HostTermination == "STOPPED" ? "STOPPED" : "FAIL";
        Save("analysis-summary.json", new RegressionTestRecord
        {
            Installer = installer?.FileName ?? proof.Installer ?? "Unknown", InstallerSha256 = proof.InstallerSha256 ?? installer?.Identity.Sha256 ?? "",
            ProductName = installer?.ProductName ?? "", Publisher = installer?.CompanyName ?? "", InstallerType = installer?.Kind.ToString() ?? "Unknown",
            Result = outcome, Install = LifecycleValidationService.InstallPassed(proof) ? "PASS" : "FAIL",
            Uninstall = LifecycleValidationService.UninstallPassed(proof) ? "PASS" : "FAIL", Removal = proof.PostUninstallDetected == false ? "PASS" : "FAIL",
            RebootRequired = proof.RebootRequired, Intelligence = proof.Intelligence, DetectionStrategies = proof.DetectionStrategies,
            Attempts = proof.SilentStrategyAttempts, Failure = FailureClassificationService.Classify(outcome, proof.ValidationError ?? "Incomplete lifecycle evidence.", proof, "Sandbox lifecycle")
        });
        AnalysisArtifactWriter.Write(Path.Combine(folder, "installer-intelligence.json"), JsonSerializer.Serialize(proof.Intelligence, new JsonSerializerOptions { WriteIndented = true }));
        AnalysisArtifactWriter.Write(Path.Combine(folder, "installer-intelligence.txt"), Generate(installer, proof));
        // Preserve raw diagnostic fields that the typed model does not know about.
        var analysisPath = Path.Combine(folder, "install-analysis.json");
        if (File.Exists(analysisPath))
            try
            {
                if (JsonNode.Parse(AnalysisArtifactReader.ReadText(analysisPath)) is JsonObject raw)
                {
                    raw["Intelligence"] = JsonSerializer.SerializeToNode(proof.Intelligence);
                    raw["DetectionStrategies"] = JsonSerializer.SerializeToNode(proof.DetectionStrategies);
                    AnalysisArtifactWriter.Write(analysisPath, raw.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                }
            }
            catch (JsonException) { /* Preserve the original malformed artifact for investigation. */ }
    }

    public static string Generate(AnalysisResult? installer, InstallAnalysis? proof)
    {
        var sb = new StringBuilder("INSTALLER INTELLIGENCE\n=====================\n");
        if (installer?.Identity.Pe.Imports.Count > 0)
        {
            sb.AppendLine("PE import declarations (not a loader diagnosis): " + installer.Identity.Pe.Architecture + " / " + installer.Identity.Pe.Status);
            foreach (var import in installer.Identity.Pe.Imports) sb.AppendLine(import.Kind + ": " + import.Module + (import.ApiSetContract ? " (API-set contract)" : ""));
            foreach (var limitation in installer.Identity.Pe.Limitations) sb.AppendLine(limitation);
        }
        if (installer is not null)
        {
            sb.AppendLine($"Product: {installer.ProductName}\nPublisher metadata: {installer.CompanyName}\nArchitecture: {installer.Architecture}\nSignature: {installer.Identity.SignatureStatus}\nSigner: {installer.Identity.SignerSubject}\nSHA-256: {installer.Identity.Sha256}\nTechnology evidence: {installer.Kind} ({installer.Confidence}%)\nCatalog: {installer.CatalogMatch}");
            foreach (var item in installer.Evidence) sb.AppendLine("• " + item);
            if (installer.Kind == InstallerKind.Msi)
            {
                sb.AppendLine($"MSI ProductCode: {installer.Identity.Msi.ProductCode}\nUpgradeCode: {installer.Identity.Msi.UpgradeCode}");
                foreach (var condition in installer.Identity.Msi.LaunchConditions) sb.AppendLine("Declared launch condition (not evaluated): " + condition.Condition + " — " + condition.Description);
                sb.AppendLine($"Declared MSI registry searches: {installer.Identity.Msi.RegistryProbes.Count}");
            }
        }
        if (proof is null) { sb.AppendLine("\nSandbox analysis has not been performed."); return sb.ToString(); }
        sb.AppendLine($"\nDISCOVERED DEPLOYMENT\nSource: {installer?.FileName ?? proof.Installer}\nMechanism: {proof.DeploymentMechanism ?? "Unknown"}\nApplication identity: {proof.PrimaryKey ?? "Unknown"}\nInstall: {LifecycleValidationService.InstallPassed(proof)}\nUninstall: {LifecycleValidationService.UninstallPassed(proof)}\nRemoval absent: {proof.PostUninstallDetected == false}\nReboot required: {proof.RebootRequired}\nPost-reboot validation: Not performed");
        sb.AppendLine("\nDETECTION STRATEGIES (presence before / installed / removed)");
        foreach (var detection in proof.DetectionStrategies.OrderByDescending(d => d.Rank))
            sb.AppendLine($"{detection.Type}: {detection.Identity} • {detection.BeforeInstall?.ToString() ?? "unknown"} / {detection.AfterInstall?.ToString() ?? "unknown"} / {detection.AfterUninstall?.ToString() ?? "unknown"} • {(detection.Validated ? "Validated" : "Not independently validated")}");
        sb.AppendLine("\nPREREQUISITES");
        foreach (var condition in proof.MsiConditions)
            sb.AppendLine("MSI condition in initial observed context: " + AiDiagnosticContext.Redact(condition.Condition) + " => " +
                (condition.Result?.ToString() ?? "Unknown") + "; unresolved: " + string.Join(", ", condition.UnresolvedSymbols) + "\n" + condition.Scope + ". " + condition.Explanation);
        foreach (var prerequisite in proof.Intelligence.Prerequisites) sb.AppendLine($"{prerequisite.Name}: {prerequisite.Status}\n{prerequisite.Source}: {prerequisite.Evidence}");
        foreach (var snapshot in proof.MsiPropertySnapshots)
        {
            sb.AppendLine("MSI property evidence: " + snapshot.Status + "\n" + snapshot.Source + ": " + snapshot.Scope);
            foreach (var property in snapshot.Properties) sb.AppendLine(property.Property + ": " + (property.IsSet is null ? "Unknown" : property.IsSet == true ? "Set" : "Explicitly empty") + ". " + property.Evidence);
            foreach (var condition in snapshot.Conditions) sb.AppendLine("Condition in terminal log context: " + AiDiagnosticContext.Redact(condition.Condition) + " => " + (condition.Result?.ToString() ?? "Unknown") + "; unresolved: " + string.Join(", ", condition.UnresolvedSymbols) + "\n" + condition.Explanation);
        }
        if (proof.Intelligence.Prerequisites.Count == 0) sb.AppendLine("No prerequisite established by available evidence.");
        sb.AppendLine("\nRUNTIME ENVIRONMENT (availability does not establish an installer requirement)");
        if (proof.ComponentDeployment is not null)
            sb.AppendLine($"Component deployment recipe: {proof.ComponentDeployment.Recipe}; {proof.ComponentDeployment.Files.Count} required payload files.");
        if (proof.SandboxCompatibility.Requested)
            sb.AppendLine($"Sandbox installer compatibility: {proof.SandboxCompatibility.Status}\n{proof.SandboxCompatibility.Detail}");
        foreach (var observation in proof.RuntimeEnvironment)
            sb.AppendLine($"{observation.Phase}: {observation.Name} • {observation.State} • {observation.Version} • {observation.Architecture}\n{observation.Source}");
        sb.AppendLine("\nSTRATEGY ATTEMPTS");
        foreach (var attempt in proof.SilentStrategyAttempts)
            sb.AppendLine($"{attempt.Name} • {attempt.Source}\n{attempt.StartedAt ?? "unknown"} → {attempt.CompletedAt ?? "unknown"}\n{attempt.Command}\n{attempt.Outcome} • exit {attempt.ExitCode} • UI {attempt.UiDetected} • detected {attempt.ApplicationDetected}\n");
        sb.AppendLine("\nPAYLOADS AND RELATIONSHIPS");
        foreach (var assessment in proof.Intelligence.InstalledProducts)
            sb.AppendLine($"{assessment.Name}: {assessment.DisplayRole}\nEvidence: {assessment.EvidenceStrength}\n{string.Join("\n", assessment.Reasons)}");
        foreach (var payload in proof.Intelligence.Payloads)
        {
            sb.AppendLine($"{payload.Role}: {payload.Path}\n{payload.Evidence}" +
                (payload.DownloadReferenceProcessId is null ? "" : $"\nDownload reference process: {payload.DownloadReferenceProcessId}\n{payload.DownloadEvidence}"));
            foreach (var write in payload.Writes) sb.AppendLine($"Writer: {write.Process} ({write.ProcessId}), born {write.ProcessCreatedAt}; {write.ObservedAt}; first completed write {write.Bytes} bytes. {write.Evidence}");
        }
        foreach (var mapping in proof.PayloadTrace.BitsMappings)
            sb.AppendLine($"BITS requested source mapping: {mapping.RequestedOrigin} → {mapping.Path}\nClient: {mapping.Process} ({mapping.ProcessId}), born {mapping.ProcessCreatedAt}; job {mapping.JobId}; {mapping.ObservedAt}\n{mapping.CompletionStatus ?? "Completion not established"}\n{mapping.Evidence}");
        foreach (var download in proof.PayloadTrace.BitsDownloads)
            sb.AppendLine($"BITS download completion reported: {download.RequestedOrigin} → {download.Path}\nClient: {download.Process} ({download.ProcessId}), born {download.ProcessCreatedAt}; job {download.JobId}\nTransferred observed {download.TransferredObservedAt}; completion reported {download.CompletionObservedAt}; bytes {download.BytesReported}\nLocal snapshot: {download.FileSnapshotStatus}; {download.FileObservedAt}; SHA-256 {download.Sha256 ?? "unavailable"}\n{download.Evidence}");
        foreach (var component in proof.Components) sb.AppendLine($"{component.Kind}: {component.Name} • {component.Path}\nPresence {component.BeforeInstall} / {component.AfterInstall} / {component.AfterUninstall}");
        sb.AppendLine($"\nInstaller-tree network observations: {proof.NetworkActivity.Count}");
        foreach (var network in proof.NetworkActivity) sb.AppendLine($"{network.Process} (PID {network.ProcessId}): {network.Evidence}");
        foreach (var limitation in proof.Intelligence.Limitations) sb.AppendLine("Limit: " + limitation);
        return sb.ToString();
    }
}
