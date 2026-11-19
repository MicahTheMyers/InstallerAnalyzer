using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using InstallerAnalyzer.Services;

internal static class AiSettingsContextChecks
{
    private sealed class Handler(Action<HttpRequestMessage, string> inspect) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            inspect(request, await request.Content!.ReadAsStringAsync(cancellationToken));
            var body = request.RequestUri!.Host switch
            {
                "api.anthropic.com" => """{"content":[{"type":"text","text":"Read-only recommendation."}]}""",
                "api.openai.com" => """{"output":[{"type":"message","content":[{"type":"output_text","text":"Read-only recommendation."}]}]}""",
                "ai.hatz.ai" => """{"choices":[{"message":{"role":"assistant","content":"Read-only recommendation."}}]}""",
                _ => """{"message":{"content":"Read-only recommendation."}}"""
            };
            return new(HttpStatusCode.OK) { Content = new StringContent(body) };
        }
    }

    public static void Run(string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "ai-settings-context");
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "timeout-settings.json"), """{"Startup":180,"Operation":3000}""");
        File.WriteAllText(Path.Combine(folder, "sandbox-script.json"),
            """{"ApplicationVersion":"0.14.13","CustomScript":true,"ScriptSha256":"ABC","UnapprovedExtraField":"private-marker"}""");
        File.WriteAllText(Path.Combine(folder, "analysis-progress.json"),
            """{"Phase":"Prerequisite setup","ApplicationTimerPaused":true,"Prerequisite":"vc_redist.x64.exe","RemainingSeconds":45}""");
        File.WriteAllText(Path.Combine(folder, "install-analysis.json"), """{"ValidationError":"Installer timed out","WorkflowStage":"Initial installation"}""");
        File.WriteAllText(Path.Combine(folder, "Record-Iss.ps1"), "# private-script-body-must-not-be-sent");
        var controls = AiDiagnosticContext.DescribeControls(new TimeoutSettings { Enabled = true, Seconds = new() { ["Startup"] = 600 } },
            "Use edited script is enabled; draft contains edits.");
        var snapshot = AiDiagnosticContext.Build("Example installer", folder, controls);
        check(snapshot.Contains("Sandbox startup: 600 seconds") && snapshot.Contains("allowed 30–900 seconds") &&
              snapshot.Contains("[Selected run: timeout-settings.json]") && snapshot.Contains("Startup: 180"),
            "AI context separates current timeout sliders and ranges from the selected run's recorded values");
        check(snapshot.Contains("ApplicationTimerPaused: true") && snapshot.Contains("CustomScript: true") &&
              snapshot.Contains("Use edited script is enabled"),
            "AI context includes prerequisite pauses, run script provenance and relevant editor mode");
        check(!snapshot.Contains("private-marker") && !snapshot.Contains("private-script-body-must-not-be-sent") && snapshot.Length <= 22000,
            "AI context keeps its size bound and excludes unapproved fields and the editor's full script");
        var missing = AiDiagnosticContext.Build("user@example.com", null, controls + "\npassword=fixture-secret");
        check(!missing.Contains("user@example.com") && !missing.Contains("fixture-secret"),
            "AI settings remain redacted even when no run diagnostics are available");
        var failurePath = Path.Combine(folder, "install-analysis.json");
        const string bluebeamFailure = """
            {"Installer":"BbRevu21.11.0.exe","WorkflowStage":"Analysis complete","LifecycleValidated":false,
            "InstallerExitCode":-2147219701,"ValidationError":"InstallShield recording returned exit code -2147219701.",
            "NetFx3Provisioning":{"RuntimeVerified":true}}
            """;
        File.WriteAllText(failurePath, bluebeamFailure);
        var bluebeam = AiDiagnosticContext.Build("Bluebeam Revu", folder, controls);
        check(bluebeam.Contains("0x8004070B") && bluebeam.Contains("invalid setup command line") &&
              bluebeam.Contains("runtime was verified") && bluebeam.Contains("Bluebeam Revu x64 21.msi") &&
              bluebeam.Contains("support.bluebeam.com/revu/installation/deployment-guide-21.html"),
            "AI snapshot decodes the Bluebeam recording failure and prioritizes the vendor MSI");
        File.WriteAllText(failurePath, bluebeamFailure.Replace("BbRevu21.11.0.exe", "OtherSetup.exe"));
        var otherSetup = AiDiagnosticContext.Build("Other installer", folder);
        check(otherSetup.Contains("invalid setup command line") && !otherSetup.Contains("Bluebeam"),
            "InstallShield exit-code guidance applies across vendors while Bluebeam advice stays product-specific");
        File.WriteAllText(failurePath, bluebeamFailure.Replace("\"LifecycleValidated\":false", "\"LifecycleValidated\":true"));
        check(!AiDiagnosticContext.Build("Bluebeam Revu", folder).Contains("invalid setup command line"),
            "A successful lifecycle does not inherit a failure diagnosis");
        File.WriteAllText(failurePath, """
            {"LifecycleValidated":true,"InitialInstallValidated":true,"DiscoverySucceeded":true,
            "SilentReinstallValidated":true,"SilentUninstallValidated":true,"PostUninstallDetected":false}
            """);
        var passed = AiDiagnosticContext.Build("Validated installer", folder);
        check(passed.Contains("Recorded outcome: Sandbox lifecycle passed.") &&
              passed.Contains("- Installed application identified") && passed.Contains("- Silent reinstall") &&
              passed.Contains("- Silent uninstall") && passed.Contains("- Application absent after uninstall"),
            "AI snapshot summarizes the recorded pass and verified install, detection and removal checks");
        File.WriteAllText(failurePath, """
            {"LifecycleValidated":false,"InitialInstallValidated":true,"SilentUninstallValidated":false,
            "PostUninstallDetected":null,"InstallerExitCode":0,"WorkflowStage":"Validate final uninstall"}
            """);
        var incomplete = AiDiagnosticContext.Build("Incomplete installer", folder);
        check(incomplete.Contains("- Initial installation") && !incomplete.Contains("- Silent uninstall") &&
              !incomplete.Contains("- Application absent after uninstall") && !incomplete.Contains("lifecycle passed"),
            "AI snapshot does not count an entered stage, untested cleanup, or a zero exit code as a pass");
        using var handler = new Handler((request, body) =>
        {
            using var json = JsonDocument.Parse(body);
            check(body.Contains("Sandbox startup") && body.Contains("timeout-settings.json") &&
                  body.Contains("cannot apply") && body.Contains("exact setting labels"),
                "AI provider requests include settings context and read-only recommendation guidance");
            check(body.Contains("0x8004070B") && body.Contains("Bluebeam Revu x64 21.msi") &&
                  body.Contains("Lead with the strongest recorded evidence") &&
                  body.Contains("give the failing stage and the short reason") &&
                  body.Contains("When evidence supports a script fix") && body.Contains("logs show a real timeout"),
                "AI provider requests include the recorded failure and official deployment guidance");
            if (request.RequestUri?.Host == "ai.hatz.ai")
            {
                var payload = json.RootElement;
                check(request.RequestUri.AbsoluteUri == "https://ai.hatz.ai/v1/chat/completions" &&
                      request.Headers.GetValues("X-API-Key").Single() == "fixture-key" && !body.Contains("fixture-key"),
                    "Hatz uses its fixed HTTPS endpoint and sends the key only in the authentication header");
                check(payload.GetProperty("model").GetString() == "auto" &&
                      payload.GetProperty("messages")[0].GetProperty("role").GetString() == "system" &&
                      payload.GetProperty("tools_to_use").GetArrayLength() == 0 &&
                      !payload.GetProperty("auto_tool_selection").GetBoolean() && !payload.GetProperty("stream").GetBoolean() &&
                      !body.Contains("fixture-secret"),
                    "Hatz sends redacted text with tool selection disabled");
            }
        });
        using var client = new HttpClient(handler);
        var service = (AiChatService)Activator.CreateInstance(typeof(AiChatService), BindingFlags.NonPublic | BindingFlags.Instance,
            null, new object[] { client }, null)!;
        foreach (var provider in new[] { "OpenAI", "Claude", "Ollama", "Hatz" })
        {
            var response = service.SendAsync(new(true, provider, provider == "Hatz" ? "auto" : "fixture-model", "http://127.0.0.1:11434"),
                "fixture-key", bluebeam + "\nX-API-Key: fixture-secret", Array.Empty<AiChatTurn>(), "Which timeout should I change?", CancellationToken.None).GetAwaiter().GetResult();
            check(response == "Read-only recommendation.", provider + " accepts the updated settings snapshot");
        }

        var draft = "# editor-start\n" + new string('x', 30000) +
            "\n$Password = 'draft-only-secret'\n# fixture-key\n# editor-end";
        bool expectDraft = false;
        using var draftHandler = new Handler((request, body) =>
        {
            check(body.Contains("editor-start") == expectDraft && body.Contains("editor-end") == expectDraft &&
                  !body.Contains("draft-only-secret") && !body.Contains("fixture-key"),
                "Only explicit script requests include the entire redacted editor draft beyond the diagnostics cap");
            if (expectDraft && request.RequestUri!.IsLoopback)
            {
                using var requestJson = JsonDocument.Parse(body);
                check(!requestJson.RootElement.GetProperty("truncate").GetBoolean() &&
                      !requestJson.RootElement.GetProperty("shift").GetBoolean(),
                    "Ollama editor requests ask the server to preserve the full input");
            }
        });
        using var draftClient = new HttpClient(draftHandler);
        var draftService = (AiChatService)Activator.CreateInstance(typeof(AiChatService), BindingFlags.NonPublic | BindingFlags.Instance,
            null, new object[] { draftClient }, null)!;
        foreach (var provider in new[] { "Hatz", "Claude", "OpenAI", "Ollama" })
        {
            var options = new AiChatOptions(true, provider, "fixture-model", "http://127.0.0.1:11434");
            expectDraft = true;
            // Ollama has no stored key, so omit the deliberately embedded cloud credential.
            draftService.SendAsync(options, "fixture-key", bluebeam, [], "Review the script", CancellationToken.None,
                provider == "Ollama" ? draft.Replace("fixture-key", "") : draft).GetAwaiter().GetResult();
            expectDraft = false;
            draftService.SendAsync(options, "fixture-key", bluebeam, [], "Explain the result", CancellationToken.None).GetAwaiter().GetResult();
        }
    }
}
