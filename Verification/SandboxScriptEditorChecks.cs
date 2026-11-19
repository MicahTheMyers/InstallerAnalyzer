using System.IO;
using System.Reflection;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class SandboxScriptEditorChecks
{
    public static int Live(string root)
    {
        var wsb = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "wsb.exe");
        string[] Ids()
        {
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(wsb, "list --raw")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
            var output = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(5000) || process.ExitCode != 0) throw new IOException("Sandbox inventory is unavailable.");
            using var json = System.Text.Json.JsonDocument.Parse(output.GetAwaiter().GetResult());
            return json.RootElement.GetProperty("WindowsSandboxEnvironments").EnumerateArray().Select(item => item.GetProperty("Id").GetString()!).ToArray();
        }
        if (Ids().Length != 0) throw new InvalidOperationException("An existing Sandbox is running. This smoke check needs a fresh guest.");
        string? owned = null;
        try
        {
            var template = """
$ErrorActionPreference='Stop'
Set-Content -LiteralPath 'C:\InstallerOutput\analysis-heartbeat.txt' -Value 'editor-live-check' -Encoding UTF8
[ordered]@{CustomScriptExecuted=$true;InstallerStarted=$false;Version='__ANALYZER_VERSION__'} | ConvertTo-Json | Set-Content -LiteralPath 'C:\InstallerOutput\editor-live-check.json' -Encoding UTF8
Set-Content -LiteralPath 'C:\InstallerOutput\analysis-complete.flag' -Value 'editor-live-check'
""";
            var store = new SandboxScriptStore(Path.Combine(root, "saved-script"));
            store.Save("live-check", new(template, true, UpdateService.CurrentDisplayVersion, DateTimeOffset.UtcNow));
            var restored = store.Load("live-check")!;
            var session = SandboxIssRecorder.Start(Environment.ProcessPath!, InstallerKind.Unknown, false, "", "", false, scriptTemplate: restored.Template);
            File.WriteAllText(Path.Combine(root, "session-folder.txt"), session.SessionFolder);
            var ownershipDeadline = DateTime.UtcNow.AddSeconds(30);
            while (owned is null && DateTime.UtcNow < ownershipDeadline)
            {
                var ids = Ids();
                if (ids.Length > 1) throw new IOException("Cannot identify the disposable guest.");
                owned = ids.SingleOrDefault();
                if (owned is null) Thread.Sleep(1000);
            }
            if (owned is null) throw new IOException("The disposable Sandbox did not appear.");
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            SandboxStartupMonitor.WaitAsync(session, cancellation.Token).GetAwaiter().GetResult();
            var marker = Path.Combine(session.OutputFolder, "editor-live-check.json");
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (!File.Exists(marker) && DateTime.UtcNow < deadline) Thread.Sleep(500);
            if (!File.Exists(marker)) throw new IOException("The edited script did not write its marker.");
            var savedScript = Path.Combine(session.SessionFolder, "Input", "Record-Iss.ps1");
            if (!session.UsesCustomScript || session.ScriptSha256 != RegressionHistoryService.HashFile(savedScript))
                throw new IOException("The launched script provenance does not match.");
            File.Copy(marker, Path.Combine(root, "editor-live-check.json"), true);
            Console.WriteLine("PASS saved editor script executed inside a fresh Sandbox; runtime version substituted; no installer was started.");
            return 0;
        }
        finally
        {
            if (owned is not null && Ids().Contains(owned))
            {
                using var stop = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(wsb, "stop --id " + owned)
                    { UseShellExecute = false, CreateNoWindow = true });
                stop?.WaitForExit(15000);
            }
        }
    }

    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        var template = SandboxIssRecorder.GetEditableScriptTemplate();
        check(template.Contains("function Write-TimerProgress") && template.Contains("__INSTALLER__") &&
              !template.Contains("__ROADMAP_HELPERS__") && window.FindName("ScriptBox") is null,
            "Analyze replaces the generated ImmyBot section with the full editable Sandbox template");
        check(SandboxScriptValidator.Validate(template).Length == 0, "The complete editor template parses in Windows PowerShell 5.1");
        var marker = Path.Combine(root, "syntax-check-must-not-execute.txt");
        check(SandboxScriptValidator.Validate("Set-Content -LiteralPath '" + marker.Replace("'", "''") + "' -Value 'must not execute'").Length == 0 &&
              !File.Exists(marker), "Syntax checking never executes the script on the host");
        check(SandboxScriptValidator.Validate("if ($true) {").Any(error => error.Contains("Line ")),
            "Invalid editor scripts report a line and column before Sandbox launch");

        var build = typeof(SandboxIssRecorder).GetMethod("BuildDiscoveryScriptWithTimeouts", BindingFlags.NonPublic | BindingFlags.Static)!;
        string Render(string? custom) => (string)build.Invoke(null, new object?[]
        {
            "renamed.exe", InstallerKind.Nsis, "/S", "EXAMPLE=1", false, false, new MsiMetadata(),
            false, "", "", false, null, null, new TimeoutSettings(), custom, false
        })!;
        var generated = Render(null);
        var edited = Render(template);
        var withoutHeader = edited[(edited.IndexOf('\n', edited.IndexOf('\n') + 1) + 1)..];
        check(withoutHeader == generated, "An unchanged editor template produces the same runtime engine as normal generation");
        var changed = Render(template + "\n# persistent-editor-check");
        check(changed.EndsWith("# persistent-editor-check") && changed.Contains(@"C:\InstallerInput\renamed.exe") &&
              changed.Contains("$BaseSilentArguments = '/S'") && !changed.Contains("'__MSI_METADATA__'"),
            "Edited scripts receive current source paths, arguments and MSI metadata at launch");
        File.WriteAllText(Path.Combine(root, "editor-rendered.ps1"), changed);
        check(SandboxScriptValidator.Validate(changed).Length == 0, "A rendered edited script passes the guest PowerShell syntax check");

        var folder = Path.Combine(root, "script-store");
        var store = new SandboxScriptStore(folder);
        var key = InstallerPreferenceStore.Key(new string('C', 64), null);
        var saved = new SavedSandboxScript(template + "\n# password=private-script-fixture", true, UpdateService.CurrentDisplayVersion, DateTimeOffset.UtcNow);
        store.Save(key, saved);
        check(new SandboxScriptStore(folder).Load(key) == saved &&
              !File.ReadAllText(Directory.GetFiles(folder).Single()).Contains("private-script-fixture"),
            "Edited scripts survive restart in Windows-protected storage");
        store.Save(key, saved with { Enabled = false });
        check(store.Load(key) is { Enabled: false } retained && retained.Template == saved.Template,
            "Disabling an edited script retains its saved text");
        store.Save(key, saved with { Template = "" });
        check(store.Load(key)?.Template == "", "An empty draft can be retained while launch validation rejects it");
        var emptyRejected = false;
        try { SandboxScriptValidator.Validate(""); } catch (InvalidDataException) { emptyRejected = true; }
        check(emptyRejected, "An empty script cannot launch Sandbox analysis");
        check(store.Load(InstallerPreferenceStore.Key(new string('D', 64), null)) is null,
            "Custom scripts do not silently transfer to different installer bytes");

        T Field<T>(string name) => (T)window.FindName(name);
        object? Invoke(string name, params object?[] args) => typeof(MainWindow).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, args);
        var result = new AnalysisResult { Identity = new() { Sha256 = new string('E', 64) }, Kind = InstallerKind.Nsis };
        Invoke("LoadSandboxScriptEditor", result);
        var editor = Field<TextBox>("SandboxScriptEditor");
        editor.Text += "\n# saved-from-editor";
        Invoke("SaveSandboxScriptDraft");
        check(Field<ToggleButton>("UseEditedSandboxScript").IsChecked == true,
            "Typing in the Analyze editor enables its script for new Sandbox runs");
        Invoke("LoadSandboxScriptEditor", result);
        check(editor.Text.EndsWith("# saved-from-editor") && Field<ToggleButton>("UseEditedSandboxScript").IsChecked == true,
            "The Analyze editor restores saved text and mode when reopening an installer");
        Field<TextBox>("ArgumentsBox").Text = "/S /changed";
        Invoke("Generate");
        check(editor.Text.EndsWith("# saved-from-editor"),
            "Changing deployment arguments and refreshing scripts preserves the editor draft");
        check((string?)Invoke("SavedSandboxScriptFor", result) == editor.Text,
            "Test-mode selection resolves the same saved script used by Analyze");
        Field<ToggleButton>("UseEditedSandboxScript").IsChecked = false;
        Invoke("SaveSandboxScriptDraft");
        check(Invoke("EffectiveSandboxScript") is null && editor.Text.EndsWith("# saved-from-editor"),
            "Generated mode uses the normal engine while retaining the user's draft");
        Invoke("RestoreSandboxScript_Click", window, new System.Windows.RoutedEventArgs());
        check(editor.Text == template && Field<ToggleButton>("UseEditedSandboxScript").IsChecked == false,
            "Restore generated replaces the draft with the current application template");
    }
}
