using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace InstallerAnalyzer.Services;

internal sealed record SavedSandboxScript(string Template, bool Enabled, string ApplicationVersion, DateTimeOffset SavedAt);

internal sealed class SandboxScriptStore(string folder)
{
    internal const int MaximumCharacters = 2 * 1024 * 1024;
    private string ScriptPath(string key) => Path.Combine(folder, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))) + ".dat");

    internal SavedSandboxScript? Load(string key)
    {
        var path = ScriptPath(key);
        if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > 8 * 1024 * 1024) throw new InvalidDataException("The saved Sandbox script is too large.");
        var encrypted = Convert.FromBase64String(File.ReadAllText(path));
        var data = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        var saved = JsonSerializer.Deserialize<SavedSandboxScript>(data) ?? throw new InvalidDataException("The saved Sandbox script is empty.");
        if (saved.Template is null || saved.Template.Length > MaximumCharacters) throw new InvalidDataException("The saved Sandbox script is invalid.");
        return saved;
    }

    internal void Save(string key, SavedSandboxScript script)
    {
        if (script.Template is null || script.Template.Length > MaximumCharacters) throw new InvalidDataException("The Sandbox script exceeds 2 MiB of text.");
        var encrypted = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(script), null, DataProtectionScope.CurrentUser);
        Directory.CreateDirectory(folder);
        AnalysisArtifactWriter.Write(ScriptPath(key), Convert.ToBase64String(encrypted));
    }

    internal void Remove(string key) => File.Delete(ScriptPath(key));

    internal static void CheckLength(string? script)
    {
        if (string.IsNullOrWhiteSpace(script)) throw new InvalidDataException("The Sandbox script is empty.");
        if (script.Length > MaximumCharacters) throw new InvalidDataException("The Sandbox script exceeds 2 MiB of text.");
    }
}
