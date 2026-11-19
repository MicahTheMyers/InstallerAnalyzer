using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class NormalRunAiChecks
{
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        T Field<T>(string name) => (T)window.FindName(name);
        var flags = BindingFlags.Instance | BindingFlags.NonPublic;
        object? Invoke(string name, params object?[] args) => typeof(MainWindow).GetMethod(name, flags)!.Invoke(window, args);
        var ai = Field<ToggleButton>("EnableAiAssistToggle");
        var test = Field<ToggleButton>("EnableTestModeToggle");
        var previousAi = ai.IsChecked;
        var previousTest = test.IsChecked;
        var resultField = typeof(MainWindow).GetField("_result", flags)!;
        var pathField = typeof(MainWindow).GetField("_installerPath", flags)!;
        var previousResult = resultField.GetValue(window);
        var previousPath = pathField.GetValue(window);
        var arguments = Field<TextBox>("ArgumentsBox");
        var previousArguments = arguments.Text;
        var editorPreference = typeof(MainWindow).GetField("_includeAiEditorScript", flags)!;
        var previousEditorPreference = editorPreference.GetValue(window);
        try
        {
            test.IsChecked = false;
            ai.IsChecked = true;
            Invoke("ShowPage", Field<Grid>("AnalyzePage"));
            check((bool)typeof(MainWindow).GetProperty("AiIsEnabled", flags)!.GetValue(window)! &&
                  Field<StackPanel>("AiAssistSettings").Visibility == Visibility.Visible &&
                  Field<Border>("AiAssistPanel").Visibility == Visibility.Visible,
                "Normal Analyze exposes AI Assist with Test Mode disabled");
            Invoke("ShowPage", Field<Grid>("SandboxPage"));
            check(Field<Border>("AiAssistPanel").Visibility == Visibility.Visible,
                "Normal Sandbox runs keep the read-only chat visible");
            Invoke("ShowPage", Field<Grid>("DeploymentPage"));
            check(Field<Border>("AiAssistPanel").Visibility == Visibility.Visible,
                "Deployment pages can use the selected installer's AI context");
            test.IsChecked = true;
            test.IsChecked = false;
            check(ai.IsChecked == true, "Turning off Test Mode preserves the independent AI Assist preference");
            Invoke("SaveAppSettings");
            Invoke("LoadAppSettings");
            check(ai.IsChecked == true && test.IsChecked == false,
                "AI Assist remains enabled after settings reload without enabling Test Mode");

            var source = new AnalysisResult
            {
                FilePath = "normal-ai-fixture.exe", ProductName = "Normal AI fixture", Kind = InstallerKind.Nsis,
                Identity = new() { Sha256 = new string('F', 64) }, Confidence = 95
            };
            resultField.SetValue(window, source);
            pathField.SetValue(window, source.FilePath);
            Invoke("LoadSandboxScriptEditor", source);
            arguments.Text = "/S password=normal-ai-secret";
            Invoke("RegisterAiDiagnosticTarget", source.FilePath, "Normal fixture • Analyze", "", true);
            var selected = Field<ComboBox>("AiTestBox").SelectedItem!;
            var include = Field<CheckBox>("AiIncludeEditorCheck");
            check(include.IsEnabled && include.IsChecked == true &&
                  (string?)Invoke("GetAiEditorScript", selected) == Field<TextBox>("SandboxScriptEditor").Text,
                "Editor sharing defaults on for the current installer and reads the entire draft");
            include.IsChecked = false;
            Invoke("AiIncludeEditor_Click", include, new RoutedEventArgs());
            check(Invoke("GetAiEditorScript", selected) is null,
                "Unchecking editor sharing omits the draft");
            Invoke("RegisterAiDiagnosticTarget", "other-ai-fixture.exe", "Other fixture", "", true);
            var otherTarget = Field<ComboBox>("AiTestBox").SelectedItem!;
            check(!include.IsEnabled && include.IsChecked == false && Invoke("GetAiEditorScript", otherTarget) is null,
                "Selecting a different installer resets editor sharing and prevents attaching the wrong draft");
            var controls = (string)Invoke("AiControlsContext", selected)!;
            var preview = AiDiagnosticContext.Build("Normal fixture • Analyze", "", controls);
            check(preview.Contains("Current Analyze selection") && preview.Contains("Nsis") &&
                  preview.Contains("current installer configuration") && !preview.Contains("normal-ai-secret"),
                "Pre-run AI has redacted installer metadata and settings without requiring test output");
            var folder = Path.Combine(root, "normal-ai-output");
            Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(folder, "install-analysis.checkpoint.json"),
                """{"WorkflowStage":"Initial installation","ValidationError":"Normal run failure 1603"}""");
            Invoke("RegisterAiDiagnosticTarget", source.FilePath, "Normal fixture • Sandbox run", folder, true);
            selected = Field<ComboBox>("AiTestBox").SelectedItem!;
            check(include.IsEnabled && include.IsChecked == false, "Editor sharing honors opt-out after a target change");
            var selectedFolder = (string)selected.GetType().GetProperty("Folder")!.GetValue(selected)!;
            var liveSnapshot = AiDiagnosticContext.Build("Normal fixture • Sandbox run", selectedFolder, (string)Invoke("AiControlsContext", selected)!);
            check(selectedFolder == folder && liveSnapshot.Contains("Normal run failure 1603"),
                "Starting a normal run switches AI to that run's live diagnostics");
            ai.IsChecked = false;
            check(Field<Border>("AiAssistPanel").Visibility == Visibility.Collapsed,
                "AI Assist remains an independent opt-in for normal runs");
            var links = new AiMessageText
            {
                Message = new("AI Assist", "See [vendor guide](https://example.com/guide(v1)) or (https://example.org/download). " +
                    "[local](file:///C:/Windows) [unsafe](javascript:alert(1)) https://user@example.org/ [other](mailto:help@example.org)")
            };
            var destinations = links.Inlines.OfType<Hyperlink>().Select(link => link.NavigateUri.AbsoluteUri).ToArray();
            check(destinations.SequenceEqual(new[] { "https://example.com/guide(v1)", "https://example.org/download" }) &&
                  links.Inlines.OfType<Hyperlink>().First().Inlines.OfType<Run>().Single().Text == "vendor guide",
                "AI replies link Markdown labels and plain web URLs without linking unsafe schemes or credential URLs");
            links.Message = new("You", "https://example.org/download");
            check(!links.Inlines.OfType<Hyperlink>().Any(), "User text remains plain when an AI message control is reused");
        }
        finally
        {
            ai.IsChecked = previousAi;
            test.IsChecked = previousTest;
            editorPreference.SetValue(window, previousEditorPreference);
            resultField.SetValue(window, previousResult);
            pathField.SetValue(window, previousPath);
            arguments.Text = previousArguments;
            if (previousResult is AnalysisResult source) Invoke("LoadSandboxScriptEditor", source);
        }
    }
}
