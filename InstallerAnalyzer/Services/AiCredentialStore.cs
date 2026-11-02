using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace InstallerAnalyzer.Services;

public static class AiCredentialStore
{
    internal static string? TestFolder;
    private static string KeyPath(string provider) => Path.Combine(TestFolder ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer"), provider switch
        { "OpenAI" => "ai-openai-key.dpapi", "Claude" => "ai-anthropic-key.dpapi", _ => throw new InvalidOperationException("This provider does not use a saved cloud API key.") });
    public static string Load(string provider = "OpenAI")
    {
        var path = KeyPath(provider);
        var environment = Environment.GetEnvironmentVariable(provider == "Claude" ? "INSTALLERANALYZER_ANTHROPIC_API_KEY" : "INSTALLERANALYZER_OPENAI_API_KEY");
        if (!string.IsNullOrWhiteSpace(environment)) return environment;
        if (!File.Exists(path)) return "";
        return Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser));
    }
    public static void Save(string key, string provider = "OpenAI")
    {
        if (string.IsNullOrWhiteSpace(key)) throw new InvalidOperationException("Enter an API key before saving.");
        var path = KeyPath(provider);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(key.Trim()), null, DataProtectionScope.CurrentUser));
    }
    public static void Clear(string provider = "OpenAI") { var path = KeyPath(provider); if (File.Exists(path)) File.Delete(path); }
}
