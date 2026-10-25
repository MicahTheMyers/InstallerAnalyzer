using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace InstallerAnalyzer.Services;

public sealed record UpdateInfo(Version Version, string Tag, string ReleaseNotes, string ReleasePage, ReleaseAsset? InstallerAsset);
public sealed record ReleaseAsset(string Name, string DownloadUrl, string? Digest);

public sealed class UpdateService
{
    public const string Owner = "MicahTheMyers";
    public const string Repository = "InstallerAnalyzer";
    public const string InstallerAssetName = "InstallerAnalyzer-Setup.exe";
    private const string LatestReleaseApi = "https://api.github.com/repos/MicahTheMyers/InstallerAnalyzer/releases/latest";
    private readonly HttpClient _http = new();

    public UpdateService()
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("InstallerAnalyzer/0.10.9");
        _http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        _http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        _http.Timeout = TimeSpan.FromSeconds(20);
    }

    public static Version CurrentVersion => Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);

    public async Task<UpdateInfo?> GetLatestAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _http.GetAsync(LatestReleaseApi, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null; // repository has no published releases yet
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var release = await JsonSerializer.DeserializeAsync<GitHubRelease>(stream, cancellationToken: cancellationToken)
                      ?? throw new InvalidOperationException("GitHub returned an empty release response.");
        var versionText = release.TagName.Trim().TrimStart('v', 'V');
        if (!Version.TryParse(versionText, out var version))
            throw new InvalidOperationException($"The latest GitHub release tag '{release.TagName}' is not a valid version.");
        var asset = release.Assets.FirstOrDefault(a => string.Equals(a.Name, InstallerAssetName, StringComparison.OrdinalIgnoreCase));
        return new UpdateInfo(version, release.TagName, release.Body ?? "", release.HtmlUrl ?? "", asset is null ? null : new ReleaseAsset(asset.Name, asset.BrowserDownloadUrl, asset.Digest));
    }

    public static bool IsNewer(UpdateInfo update) => update.Version > CurrentVersion;

    public async Task<string> DownloadInstallerAsync(UpdateInfo update, IProgress<double>? progress = null, CancellationToken cancellationToken = default)
    {
        var asset = update.InstallerAsset ?? throw new InvalidOperationException($"Release {update.Tag} does not contain {InstallerAssetName}.");
        var folder = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer", "Updates", update.Tag);
        Directory.CreateDirectory(folder);
        var destination = Path.Combine(folder, InstallerAssetName);
        using var response = await _http.GetAsync(asset.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        var total = response.Content.Headers.ContentLength;
        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using (var output = File.Create(destination))
        {
            var buffer = new byte[1024 * 128];
            long readTotal = 0;
            int read;
            while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
            {
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                readTotal += read;
                if (total > 0) progress?.Report(readTotal * 100d / total.Value);
            }
            await output.FlushAsync(cancellationToken);
        }

        // The download stream must be closed before SHA-256 verification or the
        // installer process can open the file on Windows.
        VerifyDigest(destination, asset.Digest);
        return destination;
    }

    private static void VerifyDigest(string path, string? digest)
    {
        if (string.IsNullOrWhiteSpace(digest) || !digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) return;
        var expected = digest[7..].Trim();
        using var stream = File.OpenRead(path);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            try { File.Delete(path); } catch { }
            throw new InvalidDataException("The downloaded update failed SHA-256 verification and was deleted.");
        }
    }

    public static void LaunchInstaller(string path)
    {
        Process.Start(new ProcessStartInfo { FileName = path, Arguments = "/SILENT /CLOSEAPPLICATIONS", UseShellExecute = true });
    }

    private sealed class GitHubRelease
    {
        [JsonPropertyName("tag_name")] public string TagName { get; set; } = "";
        [JsonPropertyName("body")] public string? Body { get; set; }
        [JsonPropertyName("html_url")] public string? HtmlUrl { get; set; }
        [JsonPropertyName("assets")] public List<GitHubAsset> Assets { get; set; } = [];
    }
    private sealed class GitHubAsset
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("browser_download_url")] public string BrowserDownloadUrl { get; set; } = "";
        [JsonPropertyName("digest")] public string? Digest { get; set; }
    }
}
