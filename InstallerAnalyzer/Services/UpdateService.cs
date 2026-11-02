using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed record UpdateInfo(Version Version, string Tag, string ReleaseNotes, string ReleasePage, ReleaseAsset? InstallerAsset);
public sealed record ReleaseAsset(string Name, string DownloadUrl, string? Digest);

public sealed class UpdateService
{
    public const string Owner = "MicahTheMyers";
    public const string Repository = "InstallerAnalyzer";
    public const string InstallerAssetName = "InstallerAnalyzer-Setup.exe";
    internal const string InstallerProductName = "Installer Analyzer for ImmyBot";
    private const string LatestReleaseApi = "https://api.github.com/repos/MicahTheMyers/InstallerAnalyzer/releases/latest";
    private readonly HttpClient _http;
    private readonly Func<string> _trustedPublisher;
    private readonly Func<string, InstallerIdentity> _inspectSignature;
    private readonly Action<ProcessStartInfo> _startInstaller;
    private readonly string _stagingRoot;
    private readonly long _maximumBytes;
    private readonly Func<string, (Version? Version, string Product)> _installerMetadata;

    public UpdateService() : this(new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }),
        RunningPublisher, InstallerIdentityService.Inspect,
        info => { using var process = Process.Start(info) ?? throw new InvalidOperationException("Windows did not start the update installer."); },
        Path.Combine(Path.GetTempPath(), "InstallerAnalyzer", "Updates")) { }

    internal UpdateService(HttpClient http, Func<string> trustedPublisher, Func<string, InstallerIdentity> inspectSignature,
        Action<ProcessStartInfo> startInstaller, string stagingRoot, long maximumBytes = 512L * 1024 * 1024,
        Func<string, (Version? Version, string Product)>? installerMetadata = null)
    {
        _http = http; _trustedPublisher = trustedPublisher; _inspectSignature = inspectSignature;
        _startInstaller = startInstaller; _stagingRoot = stagingRoot; _maximumBytes = maximumBytes;
        _installerMetadata = installerMetadata ?? ReadInstallerMetadata;
        if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("InstallerAnalyzer/0.12.10");
        _http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        _http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        _http.Timeout = TimeSpan.FromSeconds(20);
        _http.MaxResponseContentBufferSize = 1024 * 1024; // Release metadata only; downloads stream under their own limit.
    }

    public static Version CurrentVersion => Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);
    public static bool IsNewer(UpdateInfo update) => update.Version > CurrentVersion;

    public async Task<UpdateInfo?> GetLatestAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _http.GetAsync(LatestReleaseApi, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode(); // API redirects are deliberately not followed.
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var release = await JsonSerializer.DeserializeAsync<GitHubRelease>(stream, cancellationToken: cancellationToken)
                      ?? throw new InvalidDataException("GitHub returned an empty release response.");
        var version = ParseTag(release.TagName);
        var asset = release.Assets?.SingleOrDefault(a => a is not null && string.Equals(a.Name, InstallerAssetName, StringComparison.Ordinal));
        return new UpdateInfo(version, release.TagName, release.Body ?? "", release.HtmlUrl ?? "", asset is null ? null : new ReleaseAsset(asset.Name, asset.BrowserDownloadUrl, asset.Digest));
    }

    public async Task<VerifiedUpdate> DownloadInstallerAsync(UpdateInfo update, IProgress<double>? progress = null, CancellationToken cancellationToken = default)
    {
        var version = ParseTag(update.Tag);
        if (version != update.Version || !IsNewer(update)) throw new InvalidDataException("The update version is invalid or is not newer than the installed application.");
        var asset = update.InstallerAsset ?? throw new InvalidDataException("This release has no update installer.");
        if (asset.Name != InstallerAssetName) throw new InvalidDataException("The release installer name is invalid.");
        var expectedHash = RequiredDigest(asset.Digest); // Fail before network or filesystem writes.
        var origin = RequiredOrigin(asset.DownloadUrl, update.Tag);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(10));
        var token = timeout.Token;
        var publisher = await Task.Run(_trustedPublisher, token);
        if (string.IsNullOrWhiteSpace(publisher)) throw new InvalidDataException("The running application's trusted signing certificate could not be established.");

        // Release tags are never used in local paths, and concurrent downloads never share files.
        var folder = Path.Combine(_stagingRoot, Guid.NewGuid().ToString("N"));
        var destination = Path.Combine(folder, InstallerAssetName);
        FileStream? locked = null;
        try
        {
            using var response = await GetDownloadResponseAsync(origin, token);
            response.EnsureSuccessStatusCode();
            if (response.StatusCode != HttpStatusCode.OK) throw new InvalidDataException("The release server returned an unexpected download response.");
            var total = response.Content.Headers.ContentLength;
            if (total > _maximumBytes) throw new InvalidDataException("The update exceeds the download size limit.");
            Directory.CreateDirectory(folder);
            await using (var input = await response.Content.ReadAsStreamAsync(token))
            await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, true))
            {
                var buffer = new byte[131072]; long received = 0; int count;
                while ((count = await input.ReadAsync(buffer, token)) != 0)
                {
                    received += count;
                    if (received > _maximumBytes) throw new InvalidDataException("The update exceeds the download size limit.");
                    await output.WriteAsync(buffer.AsMemory(0, count), token);
                    if (total > 0) progress?.Report(Math.Min(100, received * 100d / total.Value));
                }
                if (received == 0 || total is not null && received != total) throw new InvalidDataException("The update download was empty or incomplete.");
                await output.FlushAsync(token);
            }
            // Keep a read lock from verification through CreateProcess to prevent file replacement.
            locked = new FileStream(destination, FileMode.Open, FileAccess.Read, FileShare.Read);
            await Task.Run(() => VerifyFile(locked, destination, expectedHash, publisher, version), token);
            token.ThrowIfCancellationRequested();
            var verified = new VerifiedUpdate(this, folder, destination, expectedHash, publisher, version, locked);
            locked = null;
            return verified;
        }
        catch { locked?.Dispose(); DeleteStagedFile(folder, destination); throw; }
    }

    public async Task LaunchInstallerAsync(VerifiedUpdate update, CancellationToken cancellationToken = default)
    {
        if (!ReferenceEquals(update.Owner, this)) throw new InvalidOperationException("The update was not verified by this updater.");
        await Task.Run(() =>
        {
            lock (update.Gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (update.Consumed) throw new InvalidOperationException("This update has already been launched or closed. Download it again.");
                update.Consumed = true;
                VerifyFile(update.LockedFile, update.Path, update.Hash, update.Publisher, update.Version);
                cancellationToken.ThrowIfCancellationRequested();
                _startInstaller(new ProcessStartInfo { FileName = update.Path, Arguments = "/SILENT /CLOSEAPPLICATIONS", WorkingDirectory = update.Folder, UseShellExecute = true });
            }
        }, cancellationToken);
    }

    private void VerifyFile(FileStream stream, string path, string expectedHash, string publisher, Version version)
    {
        if (!stream.CanRead) throw new InvalidOperationException("The verified update has been closed. Download it again.");
        stream.Position = 0;
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!actual.Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("The update failed SHA-256 verification. It will not be installed.");
        var signature = _inspectSignature(path);
        if (!signature.SignatureValid || !publisher.Equals(signature.SignerThumbprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The update's signature is invalid or does not match this application's signing certificate. It will not be installed.");
        var metadata = _installerMetadata(path);
        if (metadata.Version is null || NormalizeVersion(metadata.Version) != NormalizeVersion(version) || metadata.Product != InstallerProductName)
            throw new InvalidDataException("The signed installer does not match the expected application and release version. It will not be installed.");
    }

    private static Version NormalizeVersion(Version value) => new(value.Major, value.Minor, Math.Max(0, value.Build), Math.Max(0, value.Revision));
    private static (Version? Version, string Product) ReadInstallerMetadata(string path)
    {
        var info = FileVersionInfo.GetVersionInfo(path);
        Version.TryParse(info.FileVersion, out var version);
        return (version, info.ProductName ?? "");
    }

    private async Task<HttpResponseMessage> GetDownloadResponseAsync(Uri origin, CancellationToken token)
    {
        var current = origin;
        for (var redirects = 0; redirects <= 4; redirects++)
        {
            var response = await _http.GetAsync(current, HttpCompletionOption.ResponseHeadersRead, token);
            if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308)) return response;
            try
            {
                var location = response.Headers.Location ?? throw new InvalidDataException("The download redirect has no destination.");
                var next = location.IsAbsoluteUri ? location : new Uri(current, location);
                if (!IsSecureUri(next) || !(next == origin || next.Host is "release-assets.githubusercontent.com" or "objects.githubusercontent.com"))
                    throw new InvalidDataException("The update redirected outside the approved GitHub download hosts.");
                current = next;
            }
            finally { response.Dispose(); }
        }
        throw new InvalidDataException("The update download exceeded the redirect limit.");
    }

    private static bool IsSecureUri(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps && uri.Port == 443 &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment);

    private static Uri RequiredOrigin(string address, string tag)
    {
        var expectedPath = $"/{Owner}/{Repository}/releases/download/{tag}/{InstallerAssetName}";
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) || !IsSecureUri(uri) || uri.Host != "github.com" ||
            uri.AbsolutePath != expectedPath || uri.Query.Length != 0)
            throw new InvalidDataException("The update URL is not the expected HTTPS asset in the Installer Analyzer repository.");
        return uri;
    }

    private static Version ParseTag(string? tag)
    {
        if (tag is null || !Regex.IsMatch(tag, @"\A[vV]?\d+\.\d+\.\d+(?:\.\d+)?\z", RegexOptions.CultureInvariant) ||
            !Version.TryParse(tag.TrimStart('v', 'V'), out var version)) throw new InvalidDataException("The release tag is not a supported version.");
        return version;
    }

    private static string RequiredDigest(string? digest)
    {
        if (digest is null || !Regex.IsMatch(digest, @"\Asha256:[A-Fa-f0-9]{64}\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            throw new InvalidDataException("The release is missing a valid SHA-256 checksum. Automatic installation is blocked.");
        return digest[7..];
    }

    private static string RunningPublisher()
    {
        var path = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(path) || Path.GetFileNameWithoutExtension(path).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Automatic update installation requires a signed Installer Analyzer executable.");
        var identity = InstallerIdentityService.Inspect(path);
        if (!identity.SignatureValid || string.IsNullOrWhiteSpace(identity.SignerThumbprint))
            throw new InvalidOperationException("Automatic update installation is unavailable for this unsigned development build. Use a trusted signed release to enable it.");
        return identity.SignerThumbprint;
    }

    private static void DeleteStagedFile(string folder, string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        try { Directory.Delete(folder); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    public sealed class VerifiedUpdate : IDisposable
    {
        internal object Gate { get; } = new();
        internal bool Consumed { get; set; }
        private bool disposed;
        internal UpdateService Owner { get; }
        internal string Folder { get; }
        public string Path { get; }
        internal string Hash { get; }
        internal string Publisher { get; }
        internal Version Version { get; }
        internal FileStream LockedFile { get; }
        internal VerifiedUpdate(UpdateService owner, string folder, string path, string hash, string publisher, Version version, FileStream locked)
        { Owner = owner; Folder = folder; Path = path; Hash = hash; Publisher = publisher; Version = version; LockedFile = locked; }
        public void Dispose()
        {
            lock (Gate)
            {
                if (disposed) return;
                disposed = true; Consumed = true;
                LockedFile.Dispose(); DeleteStagedFile(Folder, Path);
            }
        }
    }

    private sealed class GitHubRelease
    {
        [JsonPropertyName("tag_name")] public string TagName { get; set; } = "";
        [JsonPropertyName("body")] public string? Body { get; set; }
        [JsonPropertyName("html_url")] public string? HtmlUrl { get; set; } = "";
        [JsonPropertyName("assets")] public List<GitHubAsset>? Assets { get; set; } = [];
    }
    private sealed class GitHubAsset
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("browser_download_url")] public string BrowserDownloadUrl { get; set; } = "";
        [JsonPropertyName("digest")] public string? Digest { get; set; }
    }
}
