using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class SandboxTroubleshootingChecks
{
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "sandbox-troubleshooting");
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "analysis-debug.jsonl"), "Failure: password=secret-example");
        File.WriteAllText(Path.Combine(folder, "netfx3-install.txt"), "Feature source unavailable");
        File.WriteAllText(Path.Combine(folder, "bootstrapper-process-exits.json"), "{}");
        File.WriteAllText(Path.Combine(folder, "installer.exe"), "binary fixture");
        File.WriteAllText(Path.Combine(folder, "settings.json"), "private fixture");
        var flags = BindingFlags.NonPublic | BindingFlags.Instance;
        var sessionField = typeof(MainWindow).GetField("_issSession", flags)!;
        var proofField = typeof(MainWindow).GetField("_installAnalysis", flags)!;
        var previousSession = sessionField.GetValue(window);
        var previousProof = proofField.GetValue(window);
        var status = (TextBlock)window.FindName("SandboxRunStatus");
        var details = (TextBlock)window.FindName("SandboxRunDetails");
        var previousStatus = status.Text;
        var previousDetails = details.Text;
        try
        {
            sessionField.SetValue(window, new SandboxIssSession { SessionFolder = folder, OutputFolder = folder, IssPath = "", WsbPath = "" });
            proofField.SetValue(window, new InstallAnalysis { ValidationError = "Installer failed with exit 1603", WorkflowStage = "Initial installation" });
            status.Text = "Analysis failed";
            details.Text = "Installer failed with exit 1603";
            typeof(MainWindow).GetMethod("UpdateSandboxDashboard", flags)!.Invoke(window, null);
            var button = (Button)window.FindName("SandboxExportDiagnosticsButton");
            var open = (Button)window.FindName("SandboxOpenOutputButton");
            check(ReferenceEquals(button.Parent, open.Parent) && ((Panel)button.Parent).Children.IndexOf(button) == ((Panel)open.Parent).Children.IndexOf(open) + 1 &&
                  button.IsEnabled, "Troubleshooting export is enabled beside Open Output Folder for the current session");
            var record = (RegressionTestRecord)typeof(MainWindow).GetMethod("CreateSandboxDiagnosticRecord", flags)!.Invoke(window, null)!;
            var context = (string)typeof(MainWindow).GetMethod("CreateSandboxDiagnosticContext", flags)!.Invoke(window, null)!;
            var destination = Path.Combine(folder, "diagnostics.zip");
            var result = DiagnosticBundleService.Export(destination, new[] { record }, contextJson: context);
            using (var zip = ZipFile.OpenRead(destination))
            {
                string Read(ZipArchiveEntry entry) { using var reader = new StreamReader(entry.Open()); return reader.ReadToEnd(); }
                var summary = Read(zip.GetEntry("001/result-summary.txt")!);
                using var settings = JsonDocument.Parse(Read(zip.GetEntry("troubleshooting-context.json")!));
                check(summary.Contains("1603") && settings.RootElement.GetProperty("Settings").TryGetProperty("RunTimeouts", out _),
                    "Troubleshooting ZIP includes the current failure message and run settings");
                check(zip.Entries.Any(e => e.Name.EndsWith("netfx3-install.txt")) &&
                      zip.Entries.Any(e => e.Name.EndsWith("bootstrapper-process-exits.json")) &&
                      result.Included >= 4, "Troubleshooting ZIP includes prerequisite and bootstrapper diagnostics");
                check(zip.Entries.All(e => !e.Name.EndsWith("installer.exe") && !e.Name.EndsWith("settings.json")) &&
                      zip.Entries.Where(e => e.Name.EndsWith(".jsonl")).All(e => !Read(e).Contains("secret-example")),
                    "Troubleshooting export redacts logged credentials and excludes binaries and raw settings");
            }
            var existing = File.ReadAllBytes(destination);
            var failed = false;
            try { DiagnosticBundleService.Export(destination, new[] { record }, contextJson: "{invalid"); }
            catch (JsonException) { failed = true; }
            check(failed && File.ReadAllBytes(destination).SequenceEqual(existing) && Directory.GetFiles(folder, "*.tmp").Length == 0,
                "Failed troubleshooting export preserves the previous ZIP and removes its temporary file");
            sessionField.SetValue(window, null);
            typeof(MainWindow).GetMethod("UpdateSandboxDashboard", flags)!.Invoke(window, null);
            window.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.DataBind);
            check(!button.IsEnabled, "Troubleshooting export disables when there is no current Sandbox session");
        }
        finally
        {
            sessionField.SetValue(window, previousSession);
            proofField.SetValue(window, previousProof);
            status.Text = previousStatus;
            details.Text = previousDetails;
        }
    }
}
