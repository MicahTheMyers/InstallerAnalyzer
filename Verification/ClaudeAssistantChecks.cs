using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows.Controls;
using InstallerAnalyzer;
using InstallerAnalyzer.Services;

internal static class ClaudeAssistantChecks
{
    private sealed class Handler : HttpMessageHandler
    {
        public int Sends;
        public Func<HttpRequestMessage, Task<HttpResponseMessage>> Reply = _ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) { Sends++; return Reply(request); }
    }
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        using var handler = new Handler(); using var client = new HttpClient(handler);
        var service = (AiChatService)Activator.CreateInstance(typeof(AiChatService), BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { client }, null)!;
        var options = new AiChatOptions(true, true, "Claude", "claude-fixture-model", "http://127.0.0.1:11434");
        HttpResponseMessage Response(string json, HttpStatusCode code = HttpStatusCode.OK) => new(code) { Content = new StringContent(json) };
        Task<string> Send(AiChatOptions? config = null, string key = "fixture-key", CancellationToken token = default) => service.SendAsync(config ?? options, key,
            "Evidence password=fixture-secret", new[] { new AiChatTurn("system", "discard me"), new AiChatTurn("assistant", "Previous answer") }, "Explain this test", token);
        void Refused(Func<Task<string>> action, string fragment, string name)
        {
            try { action().GetAwaiter().GetResult(); check(false, name); }
            catch (InvalidOperationException ex) { check(ex.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase), name); }
        }
        handler.Reply = async request =>
        {
            var body = await request.Content!.ReadAsStringAsync().ConfigureAwait(false);
            using var json = JsonDocument.Parse(body); var value = json.RootElement;
            check(request.Method == HttpMethod.Post && request.RequestUri!.AbsoluteUri == "https://api.anthropic.com/v1/messages", "Claude uses fixed HTTPS Messages endpoint");
            check(request.Headers.GetValues("x-api-key").Single() == "fixture-key" && request.Headers.GetValues("anthropic-version").Single() == "2026-10-21" && request.Headers.Authorization is null && !body.Contains("fixture-key"), "Claude authentication stays in provider-specific headers");
            check(value.GetProperty("system").GetString()!.Contains("read-only") && value.GetProperty("tools").GetArrayLength() == 0 && value.GetProperty("max_tokens").GetInt32() == 1500, "Claude has read-only system instructions and no tools");
            check(!body.Contains("fixture-secret") && !body.Contains("discard me") && value.GetProperty("messages").GetArrayLength() == 3 && value.GetProperty("model").GetString() == "claude-fixture-model", "Claude redacts diagnostic secrets and filters history roles");
            return Response("{\"content\":[{\"type\":\"text\",\"text\":\"Observed evidence.\"},{\"type\":\"text\",\"text\":\"Check logs.\"}],\"stop_reason\":\"end_turn\"}");
        };
        check(Send().GetAwaiter().GetResult() == "Observed evidence.\nCheck logs.".Replace("\n", Environment.NewLine), "Claude aggregates text blocks");
        var count = handler.Sends;
        Refused(() => Send(options with { TestModeEnabled = false }), "Test Mode", "Claude requires Test Mode");
        Refused(() => Send(options with { Enabled = false }), "AI Assist", "Claude requires AI Assist enabled");
        Refused(() => Send(key: ""), "ANTHROPIC", "Claude missing key gives provider-specific setup advice");
        using (var cts = new CancellationTokenSource()) { cts.Cancel(); try { Send(token: cts.Token).GetAwaiter().GetResult(); check(false, "Claude pre-cancellation"); } catch (OperationCanceledException) { check(true, "Claude pre-cancellation"); } }
        check(handler.Sends == count, "Disabled, unconfigured and cancelled Claude requests send nothing");
        foreach (var data in new[] { "{\"content\":[{\"type\":\"tool_use\",\"name\":\"execute\"}]}", "{\"content\":[{\"type\":\"text\",\"text\":\"pending\"}],\"stop_reason\":\"tool_use\"}" })
        { handler.Reply = _ => Task.FromResult(Response(data)); Refused(() => Send(), "text replies only", "Claude refuses tool/action responses"); }
        handler.Reply = _ => Task.FromResult(Response(new string('x', 131073)));
        Refused(() => Send(), "text-size limit", "Claude response byte limit enforced");
        foreach (var (code, message) in new[] { (HttpStatusCode.Unauthorized, "rejected access"), (HttpStatusCode.TooManyRequests, "quota") })
        { handler.Reply = _ => Task.FromResult(Response("private provider error must not leak", code)); Refused(() => Send(), message, "Claude HTTP errors are safely explained: " + code); }
        handler.Reply = _ => Task.FromResult(Response("{\"content\":[{\"type\":\"text\",\"text\":\"password=fixture-output-secret\"}]}"));
        check(!Send().GetAwaiter().GetResult().Contains("fixture-output-secret"), "Claude answer secrets are redacted");
        handler.Reply = request => Task.FromResult(Response(request.RequestUri!.Host == "api.openai.com" ? "{\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"OpenAI OK\"}]}]}" : "{\"message\":{\"content\":\"Local OK\"}}"));
        check(Send(options with { Provider = "OpenAI" }).GetAwaiter().GetResult() == "OpenAI OK" && Send(options with { Provider = "Ollama", Model = "local-fixture" }, "").GetAwaiter().GetResult() == "Local OK", "OpenAI and local Ollama responses remain supported");

        var testFolder = typeof(AiCredentialStore).GetField("TestFolder", BindingFlags.NonPublic | BindingFlags.Static)!;
        var oldFolder = testFolder.GetValue(null); var folder = Path.Combine(root, "ai-credentials"); testFolder.SetValue(null, folder);
        try
        {
            AiCredentialStore.Save("fixture-openai", "OpenAI"); AiCredentialStore.Save("fixture-claude", "Claude");
            string Decrypt(string name) => Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(Path.Combine(folder, name)), null, DataProtectionScope.CurrentUser));
            check(Decrypt("ai-openai-key.dpapi") == "fixture-openai" && Decrypt("ai-anthropic-key.dpapi") == "fixture-claude", "Provider keys use separate Windows-protected files");
            AiCredentialStore.Clear("Claude"); check(File.Exists(Path.Combine(folder, "ai-openai-key.dpapi")) && !File.Exists(Path.Combine(folder, "ai-anthropic-key.dpapi")), "Removing Claude key preserves OpenAI key");
        }
        finally { testFolder.SetValue(null, oldFolder); }

        var flags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
        T Get<T>(string name) => (T)typeof(MainWindow).GetField(name, flags)!.GetValue(window)!;
        var provider = Get<ComboBox>("AiProviderBox"); var model = Get<TextBox>("AiModelBox");
        var oldIndex = provider.SelectedIndex; var oldText = model.Text;
        var fields = new[] { "_aiOpenAiModel", "_aiOllamaModel", "_aiClaudeModel" }.ToDictionary(n => n, n => typeof(MainWindow).GetField(n, flags)!.GetValue(window));
        try
        {
            provider.SelectedIndex = 0; model.Text = "openai-ui-fixture"; provider.SelectedIndex = 2;
            model.Text = "claude-ui-fixture"; Get<PasswordBox>("AiApiKeyBox").Password = "unsaved-fixture-key";
            provider.SelectedIndex = 1; model.Text = "local-ui-fixture"; provider.SelectedIndex = 2;
            check(model.Text == "claude-ui-fixture" && Get<PasswordBox>("AiApiKeyBox").Password == "", "Provider switching retains Claude model and clears unsaved key");
            check(Get<TextBlock>("AiApiKeyLabel").Text == "Claude API key" && Get<TextBlock>("AiCloudPrivacyText").Text.Contains("Claude receives"), "Claude settings show correct key label and privacy disclosure");
            typeof(MainWindow).GetMethod("AiConfiguration_Changed", flags)!.Invoke(window, new object[] { model, new System.Windows.RoutedEventArgs() });
            var settingsPath = (string)typeof(MainWindow).GetProperty("SettingsPath", flags)!.GetValue(window)!;
            using (var settings = JsonDocument.Parse(File.ReadAllText(settingsPath)))
                check(settings.RootElement.GetProperty("AiProvider").GetString() == "Claude" && settings.RootElement.GetProperty("AiClaudeModel").GetString() == "claude-ui-fixture" && !File.ReadAllText(settingsPath).Contains("unsaved-fixture-key"), "Claude provider and model persist without saving key into settings JSON");
            provider.SelectedIndex = 0; check(model.Text == "openai-ui-fixture", "Switching back restores OpenAI model");
        }
        finally
        {
            provider.SelectedIndex = oldIndex;
            foreach (var item in fields) typeof(MainWindow).GetField(item.Key, flags)!.SetValue(window, item.Value);
            model.Text = oldText;
            typeof(MainWindow).GetMethod("SaveAppSettings", flags)!.Invoke(window, null);
        }
    }
}
