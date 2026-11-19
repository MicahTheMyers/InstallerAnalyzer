using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

internal sealed record InstallerPreferences(
    string Product, InstallerKind Kind, string Arguments, string AdditionalArguments,
    bool RequiresResponseFile, bool UseSandbox, DateTimeOffset SavedAt);

internal sealed class InstallerPreferenceStore(string path)
{
    private sealed class SavedPreferences
    {
        public Dictionary<string, InstallerPreferences> Installers { get; set; } = new();
        public Dictionary<string, string> ArchiveSelections { get; set; } = new();
    }

    internal static string Key(string hash, string? entry) => hash.ToUpperInvariant() + "|" + (entry ?? "").Replace('/', '\\').ToUpperInvariant();

    internal InstallerPreferences? Find(string key) => Read().Installers.GetValueOrDefault(key);
    internal string? FindArchiveEntry(string hash, string[] entries)
    {
        var previous = Read().ArchiveSelections.GetValueOrDefault(hash);
        return entries.FirstOrDefault(e => string.Equals(e, previous, StringComparison.OrdinalIgnoreCase));
    }

    internal void Save(string key, InstallerPreferences preferences, string? archiveHash, string? archiveEntry)
        => Update(data =>
        {
            data.Installers[key] = preferences;
            if (archiveHash is not null && archiveEntry is not null) data.ArchiveSelections[archiveHash] = archiveEntry;
            foreach (var expired in data.Installers.OrderByDescending(p => p.Value.SavedAt).Skip(500).Select(p => p.Key).ToArray())
                data.Installers.Remove(expired);
            foreach (var unused in data.ArchiveSelections.Keys.Where(hash => !data.Installers.Keys.Any(k => k.StartsWith(hash + "|", StringComparison.OrdinalIgnoreCase))).ToArray())
                data.ArchiveSelections.Remove(unused);
        });

    internal void Remove(string key, string? archiveHash) => Update(data =>
    {
        data.Installers.Remove(key);
        if (archiveHash is not null) data.ArchiveSelections.Remove(archiveHash);
    });

    private SavedPreferences Read()
    {
        if (!File.Exists(path)) return new();
        if (new FileInfo(path).Length > 8 * 1024 * 1024) throw new InvalidDataException("Saved installer settings exceed the supported size.");
        var encrypted = Convert.FromBase64String(File.ReadAllText(path));
        var bytes = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        var saved = JsonSerializer.Deserialize<SavedPreferences>(bytes) ?? new();
        if (saved.Installers is null || saved.ArchiveSelections is null) throw new InvalidDataException("Saved installer settings are invalid.");
        return saved;
    }

    private void Update(Action<SavedPreferences> edit)
    {
        // Merge the latest file while holding a per-user lock so two app windows retain each other's entries.
        var identity = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant())));
        using var mutex = new Mutex(false, @"Local\InstallerAnalyzer.Preferences." + identity);
        var held = false;
        try
        {
            try { held = mutex.WaitOne(TimeSpan.FromSeconds(2)); }
            catch (AbandonedMutexException) { held = true; }
            if (!held) throw new IOException("Saved installer settings are busy. Try again.");
            SavedPreferences saved;
            try { saved = Read(); }
            catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException or InvalidDataException)
            {
                // Retain the unreadable settings before rebuilding them from the current selection.
                File.Copy(path, path + ".unreadable-" + Guid.NewGuid().ToString("N"));
                saved = new();
            }
            edit(saved);
            var encrypted = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(saved), null, DataProtectionScope.CurrentUser);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            AnalysisArtifactWriter.Write(path, Convert.ToBase64String(encrypted));
        }
        finally { if (held) mutex.ReleaseMutex(); }
    }
}
