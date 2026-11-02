using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class UpdateSecurityChecks
{
    private const string Origin = "https://github.com/MicahTheMyers/InstallerAnalyzer/releases/download/v99.0.0/InstallerAnalyzer-Setup.exe";
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("inert update fixture; not an executable");
    private static readonly string Digest = "sha256:" + Convert.ToHexString(SHA256.HashData(Payload));
    private static UpdateInfo Update(string? digest = null, string url = Origin, string tag = "v99.0.0", string name = UpdateService.InstallerAssetName) =>
        new(new Version(99, 0, 0), tag, "Fixture", "", new(name, url, digest ?? Digest));

    public static void Run(string root, Action<bool, string> check) => RunAsync(root, check).GetAwaiter().GetResult();

    private static async Task RunAsync(string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "update-security"); Directory.CreateDirectory(folder);
        var fixtureId = 0;
        Fixture Create(Func<HttpRequestMessage, int, HttpResponseMessage>? response = null, Func<string, InstallerIdentity>? signature = null,
            Func<string>? publisher = null, long maximum = 1024) => new(Path.Combine(folder, (++fixtureId).ToString()), response, signature, publisher, maximum);
        async Task Reject(Fixture fixture, UpdateInfo update, string message, bool beforeNetwork = false)
        {
            var rejected = false;
            try { using var download = await fixture.Service.DownloadInstallerAsync(update); }
            catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException or HttpRequestException or IOException) { rejected = true; }
            check(rejected && fixture.Launches.Count == 0 && (!beforeNetwork || fixture.Requests == 0) &&
                (!Directory.Exists(fixture.Root) || !Directory.EnumerateFiles(fixture.Root, "*", SearchOption.AllDirectories).Any()), message);
        }

        foreach (var badDigest in new string?[] { null, "", "sha1:" + new string('A', 40), "sha256:" + new string('A', 63), "sha256:" + new string('Z', 64), Digest + "\n" })
        {
            using var fixture = Create();
            var update = Update() with { InstallerAsset = new(UpdateService.InstallerAssetName, Origin, badDigest) };
            await Reject(fixture, update, "Missing, malformed or unsupported update checksums are rejected before downloading", true);
        }
        foreach (var address in new[] { Origin.Replace("https:", "http:"), Origin.Replace("github.com", "github.com.evil.invalid"),
            Origin.Replace("MicahTheMyers", "DifferentOwner"), Origin.Replace("v99.0.0", "v98.0.0"), Origin + "?download=1",
            Origin + "#fragment", Origin.Replace("github.com", "github.com:444"), Origin.Replace("github.com", "user:fixture@github.com"),
            "https://release-assets.githubusercontent.com/fixture" })
        {
            using var fixture = Create(); await Reject(fixture, Update(url: address), "Unexpected update origins cannot become executable downloads", true);
        }
        foreach (var update in new[] { Update(tag: "../../outside"), Update(tag: "v98.0.0"), Update(name: "Other.exe"),
            Update() with { Version = new Version(0, 1, 0), Tag = "v0.1.0" } })
        { using var fixture = Create(); await Reject(fixture, update, "Invalid version, traversal tag, installer name and downgrade are rejected", true); }

        using (var fixture = Create(publisher: () => throw new InvalidOperationException("Unsigned development build")))
            await Reject(fixture, Update(), "An untrusted running publisher blocks installation before network or staging writes", true);
        using (var fixture = Create(publisher: () => ""))
            await Reject(fixture, Update(), "An empty publisher pin cannot authorize an update", true);
        using (var fixture = Create())
            await Reject(fixture, Update(digest: "sha256:" + new string('0', 64)), "A checksum mismatch cleans the staged file and never launches");
        using (var fixture = Create(signature: _ => new() { SignatureStatus = "NotSigned", SignerThumbprint = "FIXTURE-PUBLISHER" }))
            await Reject(fixture, Update(), "An unsigned update cannot pass even when its bytes match the checksum");
        using (var fixture = Create(signature: _ => new() { SignatureStatus = "Valid", SignerThumbprint = "OTHER-PUBLISHER" }))
            await Reject(fixture, Update(), "A valid signature from a different publisher is rejected");
        using (var fixture = Create())
        {
            fixture.Metadata = _ => (new Version(98, 0, 0), UpdateService.InstallerProductName);
            await Reject(fixture, Update(), "A correctly signed older installer cannot be relabeled as a newer release");
        }
        using (var fixture = Create())
        {
            fixture.Metadata = _ => (new Version(99, 0, 0), "Other Product");
            await Reject(fixture, Update(), "A different product signed by the same certificate is not an application update");
        }

        foreach (var redirect in new[] { "http://release-assets.githubusercontent.com/fixture", "https://evil.invalid/fixture",
            "https://release-assets.githubusercontent.com.evil.invalid/fixture", "https://github.com/Other/Repo/releases/download/v99.0.0/file.exe",
            "https://user:fixture@release-assets.githubusercontent.com/fixture" })
        {
            using var fixture = Create((_, _) => Redirect(redirect));
            await Reject(fixture, Update(), "Redirects cannot escape the approved HTTPS GitHub hosts");
            check(fixture.Requests == 1, "A rejected redirect destination is never requested");
        }
        using (var fixture = Create((_, _) => Redirect("https://release-assets.githubusercontent.com/loop")))
        { await Reject(fixture, Update(), "Download redirect loops are bounded"); check(fixture.Requests == 5, "Redirect processing stops after the allowed hop count"); }
        using (var fixture = Create((_, _) => new(HttpStatusCode.NotFound)))
            await Reject(fixture, Update(), "HTTP download errors do not leave executable files");
        using (var fixture = Create((_, _) => { var response = Body(); response.Content.Headers.ContentLength = 2048; return response; }))
            await Reject(fixture, Update(), "An oversized declared download is rejected before staging");
        using (var fixture = Create((_, _) => new(HttpStatusCode.OK) { Content = new UnknownLengthContent(Payload) }, maximum: 8))
            await Reject(fixture, Update(), "Unknown-length downloads are still size limited and cleaned up");
        using (var fixture = Create((_, _) => { var response = Body(); response.Content.Headers.ContentLength = Payload.Length + 1; return response; }))
            await Reject(fixture, Update(), "A truncated download cannot be verified or retained");
        using (var fixture = Create((_, _) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(Array.Empty<byte>()) }))
            await Reject(fixture, Update(), "An empty update is rejected and cleaned up");
        using (var fixture = Create())
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel(); var rejected = false;
            try { using var update = await fixture.Service.DownloadInstallerAsync(Update(), cancellationToken: cancelled.Token); }
            catch (OperationCanceledException) { rejected = true; }
            check(rejected && fixture.Requests == 0 && fixture.Launches.Count == 0, "Cancellation prevents download and installer launch");
        }

        using (var fixture = Create((_, number) => number == 1 ? Redirect("https://release-assets.githubusercontent.com/fixture?token=fixture") : Body()))
        {
            string path;
            using (var downloaded = await fixture.Service.DownloadInstallerAsync(Update()))
            {
                path = downloaded.Path;
                check(File.ReadAllBytes(path).SequenceEqual(Payload) && fixture.SignatureCalls == 1 && fixture.Requests == 2,
                    "Approved GitHub redirect, correct checksum and expected valid signature produce a verified download");
                var writeBlocked = false;
                try { File.WriteAllBytes(path, new byte[] { 0 }); } catch (IOException) { writeBlocked = true; }
                check(writeBlocked, "The verified installer remains locked against replacement before launch");
                await fixture.Service.LaunchInstallerAsync(downloaded);
                check(fixture.SignatureCalls == 2 && fixture.Launches.Single().FileName == path && fixture.Launches.Single().Arguments == "/SILENT /CLOSEAPPLICATIONS",
                    "Launch rechecks checksum and publisher and passes only the verified path to the fake launcher");
                var repeated = false;
                try { await fixture.Service.LaunchInstallerAsync(downloaded); } catch (InvalidOperationException) { repeated = true; }
                check(repeated && fixture.Launches.Count == 1, "A verified update cannot start an installer more than once");
            }
            check(!File.Exists(path), "Disposing a verified download removes the inert staged fixture");
        }
        using (var fixture = Create())
        {
            using var first = await fixture.Service.DownloadInstallerAsync(Update());
            using var second = await fixture.Service.DownloadInstallerAsync(Update());
            check(first.Path != second.Path && !first.Path.Contains("v99.0.0"), "Downloads use isolated random staging folders rather than release-controlled paths");
        }
        using (var fixture = Create())
        {
            var calls = 0; fixture.Signature = _ => new() { SignatureStatus = ++calls == 1 ? "Valid" : "NotTrusted", SignerThumbprint = "FIXTURE-PUBLISHER" };
            using var downloaded = await fixture.Service.DownloadInstallerAsync(Update()); var rejected = false;
            try { await fixture.Service.LaunchInstallerAsync(downloaded); } catch (InvalidDataException) { rejected = true; }
            check(rejected && fixture.Launches.Count == 0, "Signature trust changes before launch prevent installer execution");
        }
        using (var fixture = Create())
        using (var other = Create())
        {
            var downloaded = await fixture.Service.DownloadInstallerAsync(Update());
            var wrongOwner = false;
            try { await other.Service.LaunchInstallerAsync(downloaded); } catch (InvalidOperationException) { wrongOwner = true; }
            downloaded.Dispose(); var disposed = false;
            try { await fixture.Service.LaunchInstallerAsync(downloaded); } catch (InvalidOperationException) { disposed = true; }
            check(wrongOwner && disposed && fixture.Launches.Count == 0 && other.Launches.Count == 0, "Unverified ownership and disposed downloads cannot be launched");
        }
        using (var fixture = Create((_, _) => new(HttpStatusCode.NotFound)))
            check(await fixture.Service.GetLatestAsync() is null, "A repository with no published release still has a supported update-check result");
        using (var fixture = Create((_, _) => Redirect("https://evil.invalid/api")))
        {
            var rejected = false; try { await fixture.Service.GetLatestAsync(); } catch (HttpRequestException) { rejected = true; }
            check(rejected && fixture.Requests == 1, "Release metadata requests do not follow an unexpected API redirect");
        }
    }

    private static HttpResponseMessage Body() => new(HttpStatusCode.OK) { Content = new ByteArrayContent(Payload) };
    private static HttpResponseMessage Redirect(string address)
    { var response = new HttpResponseMessage(HttpStatusCode.Redirect); response.Headers.Location = new Uri(address); return response; }

    private sealed class Fixture : IDisposable
    {
        public string Root { get; }
        public int Requests;
        public int SignatureCalls;
        public Func<string, InstallerIdentity> Signature;
        public Func<string, (Version? Version, string Product)> Metadata = _ => (new Version(99, 0, 0), UpdateService.InstallerProductName);
        public List<ProcessStartInfo> Launches { get; } = new();
        private readonly HttpClient client;
        public UpdateService Service { get; }
        public Fixture(string root, Func<HttpRequestMessage, int, HttpResponseMessage>? response, Func<string, InstallerIdentity>? signature,
            Func<string>? publisher, long maximum)
        {
            Root = root; Signature = signature ?? (_ => new() { SignatureStatus = "Valid", SignerThumbprint = "FIXTURE-PUBLISHER" });
            client = new HttpClient(new Handler(request => (response ?? ((_, _) => Body()))(request, ++Requests)));
            Service = new UpdateService(client, publisher ?? (() => "FIXTURE-PUBLISHER"), path => { SignatureCalls++; return Signature(path); }, Launches.Add, root, maximum, path => Metadata(path));
        }
        public void Dispose() => client.Dispose();
    }
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(respond(request)); }
    }
    private sealed class UnknownLengthContent(byte[] bytes) : HttpContent
    {
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(bytes).AsTask();
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new MemoryStream(bytes));
    }
}
